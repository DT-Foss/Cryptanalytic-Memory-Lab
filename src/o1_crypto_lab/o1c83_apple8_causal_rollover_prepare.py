"""Zero-call O1C-0083 Page-9 causal-rollover preparation.

Only sealed O1C-0082 output and frozen public bound inputs are consumed.  The
module has no native, solver, target, truth-key, model, or reveal interface.
Preparation is in-memory; publication is a separate atomic operation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
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
from .joint_score_sieve_v7 import joint_score_upper_bound
from .o1c80_archived_bound_census import THRESHOLD, load_public_bound_inputs
from .o1c82_apple8_parent_centered_prepare import (
    DEFAULT_PARENT_CAPSULE_RELATIVE as O1C82_SOURCE_CAPSULE_RELATIVE,
)
from .o1c82_apple8_parent_centered_prepare import (
    DEFAULT_PARENT_RESULT_RELATIVE as O1C82_SOURCE_RESULT_RELATIVE,
)
from .o1c82_apple8_parent_centered_prepare import (
    DEFAULT_SEED_MANIFEST_RELATIVE as O1C82_SEED_MANIFEST_RELATIVE,
)
from .o1c82_apple8_parent_centered_prepare import (
    PreparedParentCenteredArtifacts,
    prepare_o1c82_parent_centered,
)
from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultError,
    parse_threshold_no_good_vault,
    partial_assignment_from_vault_clause,
)


ATTEMPT_ID = "O1C-0083"
PARENT_ATTEMPT_ID = "O1C-0082"
PREPARATION_SCHEMA = "o1-256-o1c83-page9-causal-rollover-preparation-v1"
COMMON_CORE_AUDIT_SCHEMA = "o1-256-o1c83-common-signed-intersection-audit-v1"

DEFAULT_PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260720_143008_461948_O1C-0082_apple8-parent-centered-v1"
)
DEFAULT_PARENT_RESULT_RELATIVE = Path(
    "research/O1C0082_APPLE8_PARENT_CENTERED_RESULT_20260720.json"
)

PARENT_CAPSULE_MANIFEST_SHA256 = (
    "3256a85e1095ffeaee349d3248035cb53470b1921abd58dd230e1617696134e6"
)
PARENT_CAPSULE_ENTRY_COUNT = 26
PARENT_RESULT_SHA256 = (
    "013692cf836e594c8580734e0c95a9f0dd18ad7536c457274a1fe5684df1ad4f"
)
PARENT_VAULT_TELEMETRY_SHA256 = (
    "9c7705591948e1f3b4ee1589cf431c8bd9a5844bad670ddb1c713c4d1d3e5445"
)
PARENT_VAULT_TELEMETRY_BYTES = 5_160_861
PARENT_FINAL_BANK_SHA256 = (
    "05b8acf3ecd5423016e5d7ef7d649f790e758e3477a943fe7306280064a4c630"
)
PARENT_FINAL_BANK_BYTES = 24_576
PARENT_PRIORITY_STATE_SHA256 = (
    "e351258722638285684c1197ba0115c3699aa8feffe44ff61e526319e519bb0f"
)
PARENT_PRIORITY_STATE_BYTES = 51_949
CONTINUATION_RECORD_FORMAT = "<QddQQddQQddd"
CONTINUATION_RECORD = struct.Struct(CONTINUATION_RECORD_FORMAT)
CONTINUATION_RECORD_BYTES = 96
CONTINUATION_CANDIDATE_ORDER_SHA256 = (
    "8198e3662f8ea2647c85982585b51ef46154007397bdc67533615778d8741a44"
)

PAGE8_SHA256 = "89e085e7323ea9aaaa31ad1430c3f20ac03f9c21a49c6404374b75ddf59330f4"
PAGE8_CLAUSE_COUNT = 256
PAGE8_LITERAL_COUNT = 692_034
PAGE8_SERIALIZED_BYTES = 2_769_351
PAGE8_CLAUSE_AGGREGATE_SHA256 = (
    "0e82b7594901a38bb103358e484c0e75b22c31220279b7ef7fd00a127c82ac90"
)

NEW_CHUNK_SHA256 = "19e294822deb3b98904e9d14b944fe167cd3ff048f7d04d870c003b34cdadaf0"
NEW_CHUNK_CLAUSE_COUNT = 257
NEW_CHUNK_LITERAL_COUNT = 743_129
NEW_CHUNK_SERIALIZED_BYTES = 2_973_735

PAGE9_SHA256 = "8c3b8cc33badd4aa23920caabc5ea3fc5006675d93805578b74b2b20788c8204"
PAGE9_CLAUSE_COUNT = 255
PAGE9_LITERAL_COUNT = 721_187
PAGE9_SERIALIZED_BYTES = 2_885_959
PAGE9_ACTIVE_LIMIT = 255
PAGE9_CATEGORY_COUNTS = {
    "structural_root": 4,
    "pinned_core": 43,
    "inherited_debt": 0,
    "new_debt": 208,
    "hot_event": 0,
    "recycled": 0,
}
PAGE9_HEADROOM = {
    "clauses": 257,
    "literals": 878_813,
    "serialized_bytes": 5_502_649,
}

ATTIC_UNION_CLAUSE_COUNT = 807
ATTIC_OCCURRENCE_COUNT = 815
ATTIC_SUBSUMPTION_RELATION_COUNT = 9
ATTIC_UNDOMINATED_CLAUSE_COUNT = 801
PAGE9_RELATION_DOCUMENT_SHA256 = (
    "c599e44573e5c1be1740d1bd6fe40970cf562746e9e77ee927d7021030b58e43"
)

COMMON_CORE_LITERAL_COUNT = 2_764
COMMON_CORE_KEY_LITERAL_COUNT = 247
COMMON_CORE_INTERNAL_LITERAL_COUNT = 2_517
COMMON_CORE_CLAUSE_SHA256 = (
    "9aa383f819d1aa4b1216937ee341aa6a773d1d3456e1ea622494ef1a4345ea06"
)
COMMON_CORE_UPPER_BOUND = 18.66656376905567
COMMON_CORE_MARGIN = 4.0603849711627085
COMMON_CORE_TAIL_KEY_VARIABLES = (21, 24, 49, 55, 66, 90, 100, 153)
COMMON_CORE_UNIQUE_KEY_PROJECTIONS = 256

NEW_CHUNK_NAME = "lineage-22-new-chunk.vault"
ACTIVE_PROJECTION_NAME = "page-09-active.bin"
RESIDENCY_NAME = "residency.json"
ACTIVATION_LEDGER_NAME = "activation-ledger.json"
OCCURRENCES_NAME = "occurrence-ledger.json"
RELATIONS_NAME = "subsumption-relations.json"
COMMON_CORE_AUDIT_NAME = "common-signed-intersection-audit.json"
FINAL_BANK_NAME = "final-parent-centered-priority-bank.bin"
PREPARATION_MANIFEST_NAME = "causal-rollover-preparation-manifest.json"


class O1C83PreparationError(RuntimeError):
    """A source seal, deterministic replay, or publication invariant differs."""


@dataclass(frozen=True)
class PreparedCausalRolloverArtifacts:
    """Complete Page-9 preparation held only in memory."""

    state: CausalResidencyState
    artifacts: Mapping[str, bytes]
    manifest: Mapping[str, object]


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise O1C83PreparationError(f"{label} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise O1C83PreparationError(f"{label} differs")
    return cast(Sequence[object], value)


def _canonical_path(value: str | Path, label: str, *, directory: bool) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise O1C83PreparationError(f"{label} path is not canonical")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise O1C83PreparationError(f"{label} is unreadable") from exc
    expected = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if stat.S_ISLNK(metadata.st_mode) or not expected or path != resolved:
        raise O1C83PreparationError(f"{label} path is not canonical")
    return path


def _canonical_document(payload: bytes, label: str) -> Mapping[str, object]:
    try:
        value = _mapping(json.loads(payload), label)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C83PreparationError(f"{label} differs") from exc
    if canonical_json_bytes(value) != payload:
        raise O1C83PreparationError(f"{label} is not canonical JSON")
    return value


def _parse_capsule_manifest(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise O1C83PreparationError("parent capsule manifest differs") from exc
    entries: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise O1C83PreparationError("parent capsule manifest row differs")
        digest, relative = line[:64], line[66:]
        parts = Path(relative).parts
        if (
            any(character not in "0123456789abcdef" for character in digest)
            or len(digest) != 64
            or not relative
            or relative.startswith("/")
            or ".." in parts
            or relative in entries
        ):
            raise O1C83PreparationError("parent capsule manifest row differs")
        entries[relative] = digest
    if len(entries) != PARENT_CAPSULE_ENTRY_COUNT:
        raise O1C83PreparationError("parent capsule manifest inventory differs")
    return entries


def _validate_capsule_inventory(capsule: Path) -> dict[str, str]:
    manifest_path = capsule / "artifacts.sha256"
    try:
        metadata = manifest_path.lstat()
        payload = manifest_path.read_bytes()
    except OSError as exc:
        raise O1C83PreparationError("parent capsule manifest is unreadable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or sha256_bytes(payload) != PARENT_CAPSULE_MANIFEST_SHA256
    ):
        raise O1C83PreparationError("parent capsule manifest differs")
    entries = _parse_capsule_manifest(payload)
    observed: dict[str, str] = {}
    for candidate in capsule.rglob("*"):
        candidate_metadata = candidate.lstat()
        if stat.S_ISLNK(candidate_metadata.st_mode):
            raise O1C83PreparationError("parent capsule contains a symlink")
        if stat.S_ISREG(candidate_metadata.st_mode):
            relative = candidate.relative_to(capsule).as_posix()
            if relative != "artifacts.sha256":
                observed[relative] = hashlib.sha256(candidate.read_bytes()).hexdigest()
        elif not stat.S_ISDIR(candidate_metadata.st_mode):
            raise O1C83PreparationError("parent capsule contains a special file")
    if observed != entries:
        raise O1C83PreparationError("parent capsule inventory or digest differs")
    required = {
        "result.json": PARENT_RESULT_SHA256,
        "episodes/00/vault.json": PARENT_VAULT_TELEMETRY_SHA256,
        "episodes/00/final-parent-centered-priority-bank.bin": (
            PARENT_FINAL_BANK_SHA256
        ),
        "episodes/00/priority-state.json": PARENT_PRIORITY_STATE_SHA256,
        "initial/page-08-active.bin": PAGE8_SHA256,
    }
    if any(entries.get(name) != digest for name, digest in required.items()):
        raise O1C83PreparationError("parent capsule required seal differs")
    return entries


def _reconstruct_page8(capsule: Path) -> PreparedParentCenteredArtifacts:
    root = lab_root()
    try:
        prepared = prepare_o1c82_parent_centered(
            capsule_dir=(root / O1C82_SOURCE_CAPSULE_RELATIVE).resolve(strict=True),
            parent_result_path=(root / O1C82_SOURCE_RESULT_RELATIVE).resolve(
                strict=True
            ),
            seed_manifest_path=(root / O1C82_SEED_MANIFEST_RELATIVE).resolve(
                strict=True
            ),
        )
    except (OSError, RuntimeError, CausalAtticError, CausalResidencyError) as exc:
        raise O1C83PreparationError("Page-8 reconstruction differs") from exc
    initial = capsule / "initial"
    if set(prepared.artifacts) != {
        candidate.name for candidate in initial.iterdir() if candidate.is_file()
    }:
        raise O1C83PreparationError("Page-8 initial inventory differs")
    for name, payload in prepared.artifacts.items():
        path = initial / name
        try:
            metadata = path.lstat()
            sealed = path.read_bytes()
        except OSError as exc:
            raise O1C83PreparationError("Page-8 initial artifact differs") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or sealed != payload
        ):
            raise O1C83PreparationError("Page-8 initial artifact differs")
    state = prepared.state
    if (
        state.current_projection.lineage_ordinal != 21
        or state.active_projection.sha256 != PAGE8_SHA256
        or state.active_projection.clause_count != PAGE8_CLAUSE_COUNT
        or state.active_projection.literal_count != PAGE8_LITERAL_COUNT
        or state.active_projection.serialized_bytes != PAGE8_SERIALIZED_BYTES
    ):
        raise O1C83PreparationError("Page-8 reconstructed state differs")
    validate_activation_replay(state)
    return prepared


def _validate_parent_result(capsule: Path, result_path: Path) -> Mapping[str, object]:
    payload = result_path.read_bytes()
    if (
        sha256_bytes(payload) != PARENT_RESULT_SHA256
        or payload != (capsule / "result.json").read_bytes()
    ):
        raise O1C83PreparationError("parent result binding differs")
    result = _canonical_document(payload, "parent result")
    episodes = _sequence(result.get("episodes"), "parent result episodes")
    if len(episodes) != 1:
        raise O1C83PreparationError("parent completed-call contract differs")
    episode = _mapping(episodes[0], "parent episode")
    science = _mapping(episode.get("science"), "parent science")
    final_bank = _mapping(episode.get("final_priority_bank"), "parent final bank")
    archived = _mapping(
        episode.get("archived_native_components"), "parent archived components"
    )
    archived_state = _mapping(
        archived.get("priority-state.json"), "parent archived priority state"
    )
    if (
        result.get("schema") != "o1-256-apple8-parent-centered-result-v1"
        or result.get("attempt_id") != PARENT_ATTEMPT_ID
        or result.get("classification") != "PARENT_CENTERED_NOVEL_CLAUSE_GAIN"
        or result.get("stop_reason") != "globally-novel-clause"
        or result.get("science_gain") is not True
        or episode.get("completed") is not True
        or episode.get("native_call_issued") is not True
        or episode.get("native_calls_consumed") != 1
        or episode.get("lineage_call_ordinal") != 21
        or episode.get("page8_burned") is not True
        or episode.get("lineage21_burned") is not True
        or episode.get("retry_authorized") is not False
        or episode.get("replay_authorized") is not False
        or science.get("fully_emitted_clauses") != NEW_CHUNK_CLAUSE_COUNT
        or science.get("globally_novel_clauses") != NEW_CHUNK_CLAUSE_COUNT
        or science.get("active_page8_new_clauses") != NEW_CHUNK_CLAUSE_COUNT
        or science.get("science_gain") is not True
        or final_bank.get("sha256") != PARENT_FINAL_BANK_SHA256
        or final_bank.get("serialized_bytes") != PARENT_FINAL_BANK_BYTES
        or archived_state
        != {
            "path": "priority-state.json",
            "serialized_bytes": PARENT_PRIORITY_STATE_BYTES,
            "sha256": PARENT_PRIORITY_STATE_SHA256,
        }
    ):
        raise O1C83PreparationError("parent completed-call contract differs")
    return result


def _parse_parent_telemetry(
    capsule: Path, state: CausalResidencyState
) -> ParsedVaultTelemetry:
    payload = (capsule / "episodes/00/vault.json").read_bytes()
    if len(payload) != PARENT_VAULT_TELEMETRY_BYTES:
        raise O1C83PreparationError("parent vault telemetry size differs")
    try:
        telemetry = parse_vault_telemetry(
            payload,
            stream_id="o1c82-episode-00",
            expected_sha256=PARENT_VAULT_TELEMETRY_SHA256,
        )
    except CausalAtticError as exc:
        raise O1C83PreparationError("parent vault telemetry differs") from exc
    active = state.active_projection
    clause_aggregate = sha256_bytes(
        b"".join(clause.serialized for clause in active.clauses)
    )
    occurrences = telemetry.occurrences
    if (
        telemetry.input_identity != active.identity
        or telemetry.input_vault_sha256 != PAGE8_SHA256
        or telemetry.input_clause_count != PAGE8_CLAUSE_COUNT
        or telemetry.input_literal_count != PAGE8_LITERAL_COUNT
        or telemetry.input_serialized_bytes != PAGE8_SERIALIZED_BYTES
        or telemetry.input_clause_aggregate_sha256
        != PAGE8_CLAUSE_AGGREGATE_SHA256
        or clause_aggregate != PAGE8_CLAUSE_AGGREGATE_SHA256
        or len(occurrences) != NEW_CHUNK_CLAUSE_COUNT
        or len(telemetry.new_occurrences) != NEW_CHUNK_CLAUSE_COUNT
        or any(occurrence.classification != "new" for occurrence in occurrences)
        or len({occurrence.clause.serialized for occurrence in occurrences})
        != NEW_CHUNK_CLAUSE_COUNT
    ):
        raise O1C83PreparationError("Page-8 telemetry binding differs")
    return telemetry


def _new_chunk(
    state: CausalResidencyState, telemetry: ParsedVaultTelemetry
) -> ThresholdNoGoodVault:
    try:
        chunk = ThresholdNoGoodVault(
            telemetry.input_identity,
            state.active_projection.observed_variables,
            tuple(occurrence.clause for occurrence in telemetry.occurrences),
        )
        roundtrip = parse_threshold_no_good_vault(
            chunk.serialized,
            observed_variables=chunk.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1C83PreparationError("new immutable chunk differs") from exc
    if (
        roundtrip != chunk
        or chunk.sha256 != NEW_CHUNK_SHA256
        or chunk.clause_count != NEW_CHUNK_CLAUSE_COUNT
        or chunk.literal_count != NEW_CHUNK_LITERAL_COUNT
        or chunk.serialized_bytes != NEW_CHUNK_SERIALIZED_BYTES
    ):
        raise O1C83PreparationError("new immutable chunk seal differs")
    return chunk


def _advance_page9(
    previous: CausalResidencyState,
    chunk: ThresholdNoGoodVault,
    telemetry: ParsedVaultTelemetry,
) -> CausalResidencyState:
    try:
        state = advance_causal_residency(
            previous,
            chunk=chunk,
            occurrences=telemetry.occurrences,
            next_lineage_ordinal=22,
            next_active_limit=PAGE9_ACTIVE_LIMIT,
        )
        validate_activation_replay(state)
        replayed = replay_causal_residency(state.attic, state.describe())
        page_roundtrip = parse_threshold_no_good_vault(
            state.active_projection.serialized,
            observed_variables=state.active_projection.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
    except (CausalResidencyError, ThresholdNoGoodVaultError) as exc:
        raise O1C83PreparationError("Page-9 causal rollover differs") from exc
    attic = state.attic
    relation_payload = canonical_json_bytes(attic.relation_document())
    headroom = {
        "clauses": O1C66_VAULT_CAPS.maximum_clauses
        - state.active_projection.clause_count,
        "literals": O1C66_VAULT_CAPS.maximum_literals
        - state.active_projection.literal_count,
        "serialized_bytes": O1C66_VAULT_CAPS.maximum_serialized_bytes
        - state.active_projection.serialized_bytes,
    }
    if (
        page_roundtrip != state.active_projection
        or replayed != state
        or state.current_projection.lineage_ordinal != 22
        or state.active_limit != PAGE9_ACTIVE_LIMIT
        or state.active_projection.sha256 != PAGE9_SHA256
        or state.active_projection.clause_count != PAGE9_CLAUSE_COUNT
        or state.active_projection.literal_count != PAGE9_LITERAL_COUNT
        or state.active_projection.serialized_bytes != PAGE9_SERIALIZED_BYTES
        or state.current_projection.category_counts != PAGE9_CATEGORY_COUNTS
        or headroom != PAGE9_HEADROOM
        or len(attic.chunks) != len(previous.attic.chunks) + 1
        or attic.chunks[:-1] != previous.attic.chunks
        or attic.chunks[-1] != chunk
        or attic.union_vault.clauses[: previous.attic.union_vault.clause_count]
        != previous.attic.union_vault.clauses
        or attic.occurrences[: len(previous.attic.occurrences)]
        != previous.attic.occurrences
        or attic.union_vault.clause_count != ATTIC_UNION_CLAUSE_COUNT
        or len(attic.occurrences) != ATTIC_OCCURRENCE_COUNT
        or len(attic.relations) != ATTIC_SUBSUMPTION_RELATION_COUNT
        or len(attic.undominated_indices) != ATTIC_UNDOMINATED_CLAUSE_COUNT
        or sha256_bytes(relation_payload) != PAGE9_RELATION_DOCUMENT_SHA256
        or state.activation_ledger[:-1] != previous.activation_ledger
        or state.used_active_sha256[:-1] != previous.used_active_sha256
        or state.active_projection.sha256 in previous.used_active_sha256
    ):
        raise O1C83PreparationError("Page-9 rollover contract differs")
    return state


def _non_tautological_simple_resolvent_count(
    clauses: Sequence[ThresholdNoGoodClause],
) -> int:
    literal_sets = tuple(set(clause.literals) for clause in clauses)
    count = 0
    for left_index, left in enumerate(literal_sets):
        for right in literal_sets[left_index + 1 :]:
            complementary = sum(1 for literal in left if -literal in right)
            if complementary == 1:
                count += 1
    return count


def _common_core_audit(
    clauses: Sequence[ThresholdNoGoodClause],
) -> tuple[dict[str, object], bytes]:
    if len(clauses) != NEW_CHUNK_CLAUSE_COUNT:
        raise O1C83PreparationError("common-core source population differs")
    common = set(clauses[0].literals)
    for clause in clauses[1:]:
        common.intersection_update(clause.literals)
    try:
        common_clause = ThresholdNoGoodClause(
            tuple(sorted(common, key=lambda literal: abs(literal)))
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1C83PreparationError("common-core clause differs") from exc
    key_literals = tuple(
        literal for literal in common_clause.literals if abs(literal) <= 256
    )
    internal_literals = tuple(
        literal for literal in common_clause.literals if abs(literal) > 256
    )
    missing_keys = tuple(
        variable
        for variable in range(1, 257)
        if variable not in {abs(literal) for literal in key_literals}
    )
    key_projections = {
        tuple(literal for literal in clause.literals if abs(literal) <= 256)
        for clause in clauses
    }
    projection_payload = canonical_json_bytes(
        [list(projection) for projection in sorted(key_projections)]
    )
    resolvent_count = _non_tautological_simple_resolvent_count(clauses)
    try:
        bound_inputs = load_public_bound_inputs(lab_root())
        upper_bound = joint_score_upper_bound(
            bound_inputs.field,
            partial_assignment_from_vault_clause(common_clause),
            grouping=bound_inputs.grouping,
        )
    except (RuntimeError, ValueError) as exc:
        raise O1C83PreparationError("common-core public bound differs") from exc
    margin = upper_bound - THRESHOLD
    if (
        common_clause.literal_count != COMMON_CORE_LITERAL_COUNT
        or len(key_literals) != COMMON_CORE_KEY_LITERAL_COUNT
        or len(internal_literals) != COMMON_CORE_INTERNAL_LITERAL_COUNT
        or common_clause.sha256 != COMMON_CORE_CLAUSE_SHA256
        or missing_keys != (*COMMON_CORE_TAIL_KEY_VARIABLES, 241)
        or len(key_projections) != COMMON_CORE_UNIQUE_KEY_PROJECTIONS
        or resolvent_count != 0
        or upper_bound != COMMON_CORE_UPPER_BOUND
        or margin != COMMON_CORE_MARGIN
        or upper_bound <= THRESHOLD
    ):
        raise O1C83PreparationError("common-core audit contract differs")
    audit: dict[str, object] = {
        "schema": COMMON_CORE_AUDIT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "source": {
            "chunk_sha256": NEW_CHUNK_SHA256,
            "clause_count": len(clauses),
            "all_clauses_nonempty": all(clause.literal_count for clause in clauses),
            "all_clauses_non_tautological": True,
        },
        "signed_intersection": {
            "literal_count": common_clause.literal_count,
            "key_literal_count": len(key_literals),
            "internal_literal_count": len(internal_literals),
            "canonical_clause_sha256": common_clause.sha256,
            "signed_literals": list(common_clause.literals),
        },
        "key_cube": {
            "key_variable_domain": [1, 256],
            "common_tail_key_variables": list(COMMON_CORE_TAIL_KEY_VARIABLES),
            "publicly_unobserved_key_variables": [241],
            "missing_common_key_variables": list(missing_keys),
            "unique_key_projection_count": len(key_projections),
            "key_projection_set_sha256": sha256_bytes(projection_payload),
            "simple_non_tautological_resolvent_count": resolvent_count,
        },
        "public_bound": {
            "upper_bound": upper_bound,
            "upper_bound_f64le_hex": struct.pack("<d", upper_bound).hex(),
            "threshold": THRESHOLD,
            "threshold_f64le_hex": struct.pack("<d", THRESHOLD).hex(),
            "margin": margin,
            "margin_f64le_hex": struct.pack("<d", margin).hex(),
            "prunable": False,
            "rule": "joint_score_upper_bound-on-common-signed-intersection",
        },
        "zero_call": {
            "native_solver_calls": 0,
            "target_bytes_read": False,
            "truth_key_bytes_read": False,
            "reveal_calls": 0,
        },
    }
    payload = canonical_json_bytes(audit)
    if _canonical_document(payload, "common-core audit") != audit:
        raise O1C83PreparationError("common-core audit roundtrip differs")
    return audit, payload


def _validate_live_continuation_bank(
    capsule: Path, bank: bytes
) -> dict[str, object]:
    """Validate the evolved live bank against its sealed state receipt.

    The O1C-0082 seed parser intentionally caps initial census counts at 74.
    A post-solve bank has evolved counts and therefore uses this continuation
    contract instead of being mislabelled as a fresh seed-compiler image.
    """

    state_payload = (capsule / "episodes/00/priority-state.json").read_bytes()
    if (
        len(state_payload) != PARENT_PRIORITY_STATE_BYTES
        or sha256_bytes(state_payload) != PARENT_PRIORITY_STATE_SHA256
    ):
        raise O1C83PreparationError("live priority-state receipt differs")
    state = _canonical_document(state_payload, "live priority-state receipt")
    operator = _mapping(state.get("operator"), "live priority operator")
    operator_accounting = _mapping(
        operator.get("state_accounting"), "live priority operator accounting"
    )
    accounting = _mapping(
        state.get("state_accounting"), "live priority state accounting"
    )
    hexadecimal = state.get("bank_hex")
    if not isinstance(hexadecimal, str):
        raise O1C83PreparationError("live continuation bank hex differs")
    try:
        receipt_bank = bytes.fromhex(hexadecimal)
    except ValueError as exc:
        raise O1C83PreparationError("live continuation bank hex differs") from exc
    if (
        state.get("schema")
        != "o1-256-o1c82-live-parent-centered-priority-state-v1"
        or state.get("bank_encoding")
        != "256-variable-ordered-96-byte-records-little-endian"
        or state.get("bank_bytes") != PARENT_FINAL_BANK_BYTES
        or state.get("current_bank_sha256") != PARENT_FINAL_BANK_SHA256
        or receipt_bank != bank
        or state.get("candidate_population") != 255
        or state.get("candidate_order_rule")
        != "observed-key-variables-ascending;currently-unassigned-and-no-live-token"
        or state.get("candidate_order_sha256")
        != CONTINUATION_CANDIDATE_ORDER_SHA256
        or state.get("one_shot_rule")
        != "coordinate-consumed-on-first-return;release-does-not-rearm"
        or state.get("consumed_coordinate_count") != 255
        or state.get("parent_scans") != 512
        or state.get("callback_calls") != 512
        or state.get("nonzero_returns") != 255
        or state.get("zero_returns") != 257
        or state.get("last_parent_candidate_count") != 1
        or operator.get("belief_orientation_authorized") is not False
        or operator.get("proof_mining_action_only") is not True
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
    ):
        raise O1C83PreparationError("live continuation bank receipt differs")

    records: list[tuple[object, ...]] = []
    for variable in range(1, 257):
        offset = (variable - 1) * CONTINUATION_RECORD_BYTES
        values = CONTINUATION_RECORD.unpack_from(bank, offset)
        count = cast(int, values[0])
        raw_positive = cast(int, values[3])
        raw_zero = cast(int, values[4])
        centered_positive = cast(int, values[7])
        centered_zero = cast(int, values[8])
        floats = tuple(cast(float, value) for value in (*values[1:3], *values[5:7], *values[9:12]))
        if (
            any(not math.isfinite(value) for value in floats)
            or cast(float, values[2]) < 0.0
            or cast(float, values[6]) < 0.0
            or raw_positive + raw_zero > count
            or centered_positive + centered_zero > count
            or cast(float, values[10]) < abs(cast(float, values[9]))
            or cast(float, values[11]) < cast(float, values[10])
        ):
            raise O1C83PreparationError("live continuation bank record differs")
        records.append(values)
    counts = tuple(cast(int, record[0]) for record in records)
    if (
        bank[240 * CONTINUATION_RECORD_BYTES : 241 * CONTINUATION_RECORD_BYTES]
        != bytes(CONTINUATION_RECORD_BYTES)
        or counts[240] != 0
        or any(count == 0 for index, count in enumerate(counts) if index != 240)
        or sum(count >= 37 for count in counts) != 255
        or max(counts) <= 74
    ):
        raise O1C83PreparationError("live continuation bank population differs")
    return {
        "validation_contract": "o1c82-live-continuation-bank-with-state-receipt",
        "receipt_sha256": PARENT_PRIORITY_STATE_SHA256,
        "receipt_serialized_bytes": PARENT_PRIORITY_STATE_BYTES,
        "encoding": state["bank_encoding"],
        "coordinate_record_count": len(records),
        "record_bytes": CONTINUATION_RECORD_BYTES,
        "eligible_coordinate_count": sum(count >= 37 for count in counts),
        "zero_coordinate_variables": [241],
        "maximum_evolved_count": max(counts),
        "receipt_bank_hex_byte_equal": True,
        "fresh_seed_parser_compatible": False,
        "next_action_parser_gate": (
            "require-live-continuation-parser;do-not-use-fresh-seed-parser"
        ),
    }


def _artifact_row(payload: bytes, role: str) -> dict[str, object]:
    return {
        "role": role,
        "serialized_bytes": len(payload),
        "sha256": sha256_bytes(payload),
    }


def prepare_o1c83_causal_rollover(
    *,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Validate O1C-0082 and return the exact Page-9 artifact bundle in memory."""

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
    parent = _reconstruct_page8(capsule)
    telemetry = _parse_parent_telemetry(capsule, parent.state)
    chunk = _new_chunk(parent.state, telemetry)
    state = _advance_page9(parent.state, chunk, telemetry)
    audit, audit_payload = _common_core_audit(chunk.clauses)

    final_bank = (capsule / "episodes/00/final-parent-centered-priority-bank.bin").read_bytes()
    if (
        len(final_bank) != PARENT_FINAL_BANK_BYTES
        or sha256_bytes(final_bank) != PARENT_FINAL_BANK_SHA256
    ):
        raise O1C83PreparationError("final priority bank differs")
    continuation_receipt = _validate_live_continuation_bank(capsule, final_bank)

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
        FINAL_BANK_NAME: final_bank,
    }
    roles = {
        NEW_CHUNK_NAME: "immutable-all-new-lineage-21-evidence-chunk",
        ACTIVE_PROJECTION_NAME: "fresh-lineage-22-page9-science-input",
        RESIDENCY_NAME: "complete-causal-residency-state",
        ACTIVATION_LEDGER_NAME: "complete-replayable-activation-ledger",
        OCCURRENCES_NAME: "complete-compact-witness-occurrence-ledger",
        RELATIONS_NAME: "complete-strict-subsumption-closure",
        COMMON_CORE_AUDIT_NAME: "public-common-signed-intersection-bound-audit",
        FINAL_BANK_NAME: "sealed-live-continuation-bank-bytes",
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
            "page9_burned": False,
            "lineage22_burned": False,
            "page8_replay_authorized": False,
        },
        "parent": {
            "attempt_id": PARENT_ATTEMPT_ID,
            "capsule_manifest_sha256": PARENT_CAPSULE_MANIFEST_SHA256,
            "capsule_entry_count": len(entries),
            "result_sha256": PARENT_RESULT_SHA256,
            "source_lineage_ordinal": 21,
            "source_active_sha256": PAGE8_SHA256,
            "initial_artifacts_byte_equal_to_fresh_reconstruction": True,
            "activation_ledger_prefix_preserved": True,
        },
        "rollover": {
            "stream_id": telemetry.stream_id,
            "telemetry_sha256": telemetry.artifact_sha256,
            "chunk_sha256": chunk.sha256,
            "clause_count": chunk.clause_count,
            "literal_count": chunk.literal_count,
            "serialized_bytes": chunk.serialized_bytes,
            "all_occurrences_new": True,
            "all_occurrences_unique": True,
        },
        "attic": {
            "chunk_count": len(state.attic.chunks),
            "union_clause_count": state.attic.union_vault.clause_count,
            "occurrence_count": len(state.attic.occurrences),
            "strict_subsumption_pair_count": len(state.attic.relations),
            "undominated_clause_count": len(state.attic.undominated_indices),
        },
        "page9": {
            "lineage_ordinal": 22,
            "active_limit": state.active_limit,
            "active_sha256": state.active_projection.sha256,
            "clause_count": state.active_projection.clause_count,
            "literal_count": state.active_projection.literal_count,
            "serialized_bytes": state.active_projection.serialized_bytes,
            "category_counts": state.current_projection.category_counts,
            "headroom": PAGE9_HEADROOM,
            "fresh_identity": state.active_projection.sha256
            not in parent.state.used_active_sha256,
            "advance_api": "advance_causal_residency(next_active_limit=255)",
        },
        "common_core_audit": {
            "artifact": COMMON_CORE_AUDIT_NAME,
            "canonical_clause_sha256": COMMON_CORE_CLAUSE_SHA256,
            "upper_bound": COMMON_CORE_UPPER_BOUND,
            "threshold": THRESHOLD,
            "prunable": False,
        },
        "final_priority_bank": {
            "sha256": PARENT_FINAL_BANK_SHA256,
            "serialized_bytes": PARENT_FINAL_BANK_BYTES,
            "priority_is_key_bit_belief": False,
            "semantic_role": "sealed-live-continuation-bytes",
            **continuation_receipt,
        },
        "artifacts": {
            name: _artifact_row(payload, roles[name])
            for name, payload in sorted(artifacts.items())
        },
    }
    artifacts[PREPARATION_MANIFEST_NAME] = canonical_json_bytes(manifest)
    return PreparedCausalRolloverArtifacts(
        state=state,
        artifacts=artifacts,
        manifest=manifest,
    )


def preflight_o1c83_causal_rollover(
    *,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Run the full zero-call validation without publishing a directory."""

    return prepare_o1c83_causal_rollover(
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )


def _durable_write(path: Path, payload: bytes) -> None:
    try:
        with path.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise O1C83PreparationError("causal-rollover artifact write failed") from exc


def write_prepared_o1c83_causal_rollover(
    prepared: PreparedCausalRolloverArtifacts, output_dir: str | Path
) -> None:
    """Atomically publish a validated in-memory bundle to a fresh directory."""

    if not isinstance(prepared, PreparedCausalRolloverArtifacts):
        raise O1C83PreparationError("prepared causal-rollover bundle differs")
    output = Path(output_dir)
    if output.name in ("", ".", ".."):
        raise O1C83PreparationError("causal-rollover output name differs")
    try:
        if output.is_symlink():
            raise O1C83PreparationError("causal-rollover output is a symlink")
        if output.exists():
            raise O1C83PreparationError("causal-rollover output already exists")
        output.parent.mkdir(parents=True, exist_ok=True)
        parent = output.parent.resolve(strict=True)
        if output.parent.absolute() != parent:
            raise O1C83PreparationError("causal-rollover output parent is a symlink")
    except O1C83PreparationError:
        raise
    except OSError as exc:
        raise O1C83PreparationError("causal-rollover output parent differs") from exc
    target = parent / output.name
    stage = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.", suffix=".tmp", dir=parent)
    )
    try:
        for name, payload in prepared.artifacts.items():
            if Path(name).name != name:
                raise O1C83PreparationError("causal-rollover artifact name differs")
            _durable_write(stage / name, payload)
        stage_fd = os.open(stage, os.O_RDONLY)
        try:
            os.fsync(stage_fd)
        finally:
            os.close(stage_fd)
        if target.exists() or target.is_symlink():
            raise O1C83PreparationError("causal-rollover output already exists")
        os.rename(stage, target)
        directory_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def prepare_and_write_o1c83_causal_rollover(
    *,
    output_dir: str | Path,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Prepare, validate, and atomically publish the Page-9 bundle."""

    prepared = prepare_o1c83_causal_rollover(
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )
    write_prepared_o1c83_causal_rollover(prepared, output_dir)
    return prepared


def _parser() -> argparse.ArgumentParser:
    root = lab_root()
    parser = argparse.ArgumentParser(
        description="Preflight or prepare O1C-0083's zero-call Page-9 rollover"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("preflight", "prepare"):
        child = subparsers.add_parser(command)
        child.add_argument(
            "--capsule",
            default=(root / DEFAULT_PARENT_CAPSULE_RELATIVE).as_posix(),
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
        prepared = prepare_o1c83_causal_rollover(
            capsule_dir=args.capsule,
            parent_result_path=args.parent_result,
        )
        if args.command == "prepare":
            write_prepared_o1c83_causal_rollover(prepared, args.output_dir)
    except (O1C83PreparationError, CausalAtticError, CausalResidencyError) as exc:
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
    "COMMON_CORE_AUDIT_NAME",
    "DEFAULT_PARENT_CAPSULE_RELATIVE",
    "DEFAULT_PARENT_RESULT_RELATIVE",
    "FINAL_BANK_NAME",
    "NEW_CHUNK_NAME",
    "O1C83PreparationError",
    "OCCURRENCES_NAME",
    "PREPARATION_MANIFEST_NAME",
    "PreparedCausalRolloverArtifacts",
    "RELATIONS_NAME",
    "RESIDENCY_NAME",
    "main",
    "preflight_o1c83_causal_rollover",
    "prepare_and_write_o1c83_causal_rollover",
    "prepare_o1c83_causal_rollover",
    "write_prepared_o1c83_causal_rollover",
]
