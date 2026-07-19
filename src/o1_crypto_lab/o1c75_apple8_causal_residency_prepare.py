"""Zero-call preparation of O1C-0075 causal-residency artifacts.

Only the sealed O1C-0074 capsule is consumed.  Its six immutable chunks,
including empty rollover boundaries, all witness occurrences, and the complete
subsumption closure are replayed before either residency page is constructed.
No native adapter, target broker, truth key, or reveal surface is imported.
"""

from __future__ import annotations

import argparse
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

from .causal_attic_v1 import (
    CAUSAL_ATTIC_OCCURRENCE_SCHEMA,
    CausalAttic,
    CausalAtticError,
    ClauseOccurrence,
    canonical_json_bytes,
    parse_self_scoping_vault,
    reproject_causal_attic,
    sha256_bytes,
)
from .causal_residency_v1 import (
    ACTIVATION_LEDGER_SCHEMA,
    CAUSAL_RESIDENCY_SCHEMA,
    CausalResidencyError,
    CausalResidencyState,
    initialize_causal_residency,
    replay_causal_residency,
    reproject_causal_residency,
    validate_activation_replay,
)
from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultError,
    parse_threshold_no_good_vault,
)


ATTEMPT_ID = "O1C-0075"
PREPARATION_SCHEMA = "o1-256-apple8-causal-residency-preparation-v1"
MANIFEST_SCHEMA = "o1-256-apple8-causal-residency-manifest-v1"
ARTIFACT_SET_SCHEMA = "o1-256-apple8-causal-residency-artifact-set-v1"
PROJECTION_PLAN_SCHEMA = "o1-256-causal-residency-projection-plan-v1"
RECIPROCAL_PAIR_SCHEMA = "o1-score-threshold-reciprocal-nearest-pairs-v1"
KEY_FLIP_PAIR_SCHEMA = "o1-score-threshold-clean-key-flip-pairs-v1"
ORIENTED_PAIR_SCHEMA = "o1-score-threshold-witness-oriented-key-flips-v1"
ORIENTATION_SUMMARY_SCHEMA = "o1-score-threshold-key-orientation-summary-v1"
RESOLVENT_RECORD_SCHEMA = "o1-score-threshold-exact-resolution-record-v1"
RESOLVENT_SET_SCHEMA = "o1-score-threshold-exact-resolvent-set-v1"

ACTIVE_CLAUSE_LIMIT = 256
PARENT_LINEAGE_ORDINAL = 13
FIRST_LINEAGE_ORDINAL = 14
SECOND_LINEAGE_ORDINAL = 15

DEFAULT_PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260719_231823_O1C-0074_apple8-causal-attic-stream-v1"
)
DEFAULT_PARENT_RESULT_RELATIVE = Path(
    "research/O1C0074_APPLE8_CAUSAL_ATTIC_STREAM_RESULT_20260719.json"
)

CHUNK_NAMES = tuple(f"chunk-{index:02d}.vault" for index in range(6))
PARENT_ACTIVE_NAME = "parent-final-active.bin"
ACTIVE_PROJECTION_NAME = "page-01-active.bin"
ZERO_EVENT_PAGE_NAME = "page-02-zero-event.bin"
OCCURRENCES_NAME = "witness-occurrences.json"
RELATIONS_NAME = "subsumption-relations.json"
ACTIVATION_LEDGER_NAME = "activation-ledger.json"
PROJECTION_PLAN_NAME = "projection-plan.json"
RECIPROCAL_PAIRS_NAME = "later-only-reciprocal-nearest-pairs.json"
KEY_FLIP_PAIRS_NAME = "later-only-clean-key-flip-pairs.json"
ORIENTED_PAIRS_NAME = "later-only-witness-oriented-key-flips.json"
ORIENTATION_SUMMARY_NAME = "later-only-key-orientation-summary.json"
RESOLVENT_RECORD_NAME = "later-only-pair-109-110-resolution.json"
RESOLVENT_VAULT_NAME = "later-only-pair-109-110-resolvent.vault"
RESOLVENT_SET_NAME = "later-only-ten-resolvents.json"
RESOLVENT_SET_VAULT_NAME = "later-only-ten-resolvents.vault"
MANIFEST_NAME = "causal-residency-manifest.json"

EXPECTED_PARENT_RESULT_SHA256 = (
    "b6bc2895459e3256fa4c857b67bd786b36d80ab5018a9c73709a2096cd169127"
)
EXPECTED_PARENT_MANIFEST_SHA256 = (
    "7a3f272268296005c5c6e532d377eb100244f38e941a102876abbfd732a8049b"
)
EXPECTED_O1C74_RUNNER_SHA256 = (
    "24d7c30ae69059b006127ec2eccee131615d42bbc8fd7ac40f76a78e879f3ecc"
)
EXPECTED_RANK_SOURCE_SHA256 = (
    "cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858"
)
EXPECTED_PARENT_ACTIVE_SHA256 = (
    "78696f2b662beda4b371aa547350cc66b2105bc4dcaf0b982af2d1279e3012ed"
)
EXPECTED_PARENT_UNION_AGGREGATE_SHA256 = (
    "840cc5cecdfe998fe1b0b2d4b7c4dbc3ee554112fc9ec550b0720c765f9c1911"
)
EXPECTED_PAGE1_SHA256 = (
    "82b1512a393f9d595a1207253e2b623ee8ece9bd2f5b92f8283857c3dd9b2911"
)
EXPECTED_PAGE1_AGGREGATE_SHA256 = (
    "83fc23233b6e63b5755bda4a3354d10602d2440db3f3c7b16f2b3b4dde6910e7"
)
EXPECTED_PAGE2_SHA256 = (
    "db3acd5e6b7eb27529fd141a99865623530258f3aa2f7db6e84f03f16ecf4f0f"
)
EXPECTED_PAGE2_AGGREGATE_SHA256 = (
    "d1a0f2a4d9730f4174d412cf1946ead73b3e6bb06d2cccf4bcea9f4319995085"
)
EXPECTED_RESOLVENT_SHA256 = (
    "c26dd0bdc72e3087aef76c6075cd0e201ec1141245fc30b87d0bd615f60a6839"
)
EXPECTED_RESOLVENT_VAULT_SHA256 = (
    "a7d73d9fbc6ad9f5a98937792d84425a3398b4a6fe2e9a47243fa7b9df5f9766"
)
EXPECTED_RESOLVENT_SET_AGGREGATE_SHA256 = (
    "363c171f7d769cb0802cc6ce40a6ebc9e5da347b12d0facca9ad7da3ad9b19b5"
)
EXPECTED_RESOLVENT_SET_VAULT_SHA256 = (
    "01811dd834b6ec4fc4dd65a8c94e65fb985320a6c4af34cd43c0e67f8564b8b6"
)
EXPECTED_PREPARED_MANIFEST_SHA256 = (
    "342e31fbf3112c5469e460ceb0c0d549428ad498c20a3ff063401bab95b2ce33"
)

REFERENCE_ANALYTIC_DOCUMENTS = {
    RECIPROCAL_PAIRS_NAME: {
        "serialized_bytes": 56_497,
        "sha256": "93a74f5c4686ebe0134dd879032dc55b31b2c485f8a64d22724c0e689ff3bd98",
    },
    KEY_FLIP_PAIRS_NAME: {
        "serialized_bytes": 29_604,
        "sha256": "63da891bbfc2046d0af7e26662895f487c20867826b99b3618a284940e7590e1",
    },
    ORIENTED_PAIRS_NAME: {
        "serialized_bytes": 45_277,
        "sha256": "b25730ef053951aac7287c29044a456cc958af74e01b088da12eb5a219585d54",
    },
    ORIENTATION_SUMMARY_NAME: {
        "serialized_bytes": 2_052,
        "sha256": "85e2f9c0217f640bd58f33f806d1da7f3e209a31acb5da30febd7fa8e1f07e03",
    },
}


class O1C75PreparationError(RuntimeError):
    """A sealed parent, deterministic projection, or artifact differs."""


@dataclass(frozen=True)
class PreparedResidency:
    directory: Path | None
    manifest: Mapping[str, object]
    manifest_bytes: bytes
    manifest_sha256: str
    state: CausalResidencyState

    @property
    def rank_source(self) -> ThresholdNoGoodVault:
        return self.state.attic.chunks[0]


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(
        isinstance(key, str) for key in value
    ):
        raise O1C75PreparationError(f"{field} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(
        value, (str, bytes, bytearray)
    ):
        raise O1C75PreparationError(f"{field} differs")
    return cast(Sequence[object], value)


def _nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise O1C75PreparationError(f"{field} differs")
    return value


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C75PreparationError(f"{field} differs")
    return value


def _regular_file(path: Path, field: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise O1C75PreparationError(f"{field} is unreadable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise O1C75PreparationError(f"{field} is not a sealed regular file")
    return path


def _parse_artifact_manifest(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise O1C75PreparationError("parent manifest encoding differs") from exc
    entries: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise O1C75PreparationError("parent manifest row differs")
        digest, relative = line[:64], line[66:]
        if (
            any(character not in "0123456789abcdef" for character in digest)
            or not relative
            or relative.startswith("/")
            or ".." in Path(relative).parts
            or relative in entries
        ):
            raise O1C75PreparationError("parent manifest row differs")
        entries[relative] = digest
    if not entries:
        raise O1C75PreparationError("parent manifest is empty")
    return entries


def _read_json_bytes(payload: bytes, field: str) -> Mapping[str, object]:
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C75PreparationError(f"{field} JSON differs") from exc
    document = _mapping(value, field)
    if canonical_json_bytes(document) != payload:
        raise O1C75PreparationError(f"{field} is not canonical")
    return document


def _recover_parent_state(
    capsule: Path, parent_result_path: Path
) -> tuple[CausalAttic, Mapping[str, object], str]:
    """Replay O1C74 with its hash-pinned private recovery surface."""

    manifest_path = _regular_file(capsule / "artifacts.sha256", "parent manifest")
    manifest_payload = manifest_path.read_bytes()
    if sha256_bytes(manifest_payload) != EXPECTED_PARENT_MANIFEST_SHA256:
        raise O1C75PreparationError("parent capsule manifest differs")
    entries = _parse_artifact_manifest(manifest_payload)
    observed_files: dict[str, str] = {}
    for path in capsule.rglob("*"):
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise O1C75PreparationError("parent capsule inventory differs") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise O1C75PreparationError("parent capsule contains a symlink")
        if stat.S_ISREG(metadata.st_mode):
            relative = path.relative_to(capsule).as_posix()
            if relative != "artifacts.sha256":
                observed_files[relative] = sha256_bytes(path.read_bytes())
        elif not stat.S_ISDIR(metadata.st_mode):
            raise O1C75PreparationError("parent capsule contains a special file")
    if len(entries) != 54 or observed_files != entries:
        raise O1C75PreparationError("parent capsule inventory or digest differs")
    result_path = _regular_file(parent_result_path, "parent result")
    result_payload = result_path.read_bytes()
    if (
        sha256_bytes(result_payload) != EXPECTED_PARENT_RESULT_SHA256
        or result_payload != (capsule / "result.json").read_bytes()
        or entries.get("result.json") != EXPECTED_PARENT_RESULT_SHA256
    ):
        raise O1C75PreparationError("parent result binding differs")
    result = _read_json_bytes(result_payload, "parent result")

    runner_path = _regular_file(
        lab_root() / "src/o1_crypto_lab/o1c74_apple8_causal_attic_stream_run.py",
        "O1C74 recovery runner",
    )
    if sha256_bytes(runner_path.read_bytes()) != EXPECTED_O1C74_RUNNER_SHA256:
        raise O1C75PreparationError("O1C74 recovery runner digest differs")
    from . import o1c74_apple8_causal_attic_stream_run as parent_runner

    invocation_path = _regular_file(capsule / "invocation.json", "parent invocation")
    invocation_payload = invocation_path.read_bytes()
    invocation = _read_json_bytes(invocation_payload, "parent invocation")
    try:
        state = parent_runner._rebuild_initial_from_capsule(
            capsule, _mapping(invocation.get("initial_artifacts"), "initial artifacts")
        )
        for raw in _sequence(result.get("episodes"), "parent episodes"):
            state = parent_runner._recover_completed_episode(
                capsule=capsule,
                state=state,
                expected=_mapping(raw, "parent episode"),
                invocation_sha256=sha256_bytes(invocation_payload),
            )
    except Exception as exc:
        raise O1C75PreparationError("sealed parent replay differs") from exc
    if (
        state.describe() != result.get("final_attic")
        or state.active_projection.sha256 != EXPECTED_PARENT_ACTIVE_SHA256
        or state.chunks[0].sha256 != EXPECTED_RANK_SOURCE_SHA256
    ):
        raise O1C75PreparationError("sealed parent terminal state differs")
    return state, result, sha256_bytes(manifest_payload)


def _parse_occurrence_document(
    value: object, *, clauses: tuple[ThresholdNoGoodClause, ...]
) -> tuple[ClauseOccurrence, ...]:
    document = _mapping(value, "occurrence document")
    if document.get("schema") != CAUSAL_ATTIC_OCCURRENCE_SCHEMA:
        raise O1C75PreparationError("occurrence schema differs")
    records = _sequence(document.get("records"), "occurrence records")
    occurrences: list[ClauseOccurrence] = []
    for ordinal, raw in enumerate(records):
        row = _mapping(raw, "occurrence record")
        union_index = _nonnegative_int(
            row.get("union_clause_index"), "occurrence union index"
        )
        if row.get("ordinal") != ordinal or union_index >= len(clauses):
            raise O1C75PreparationError("occurrence ordinal differs")
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
            raise O1C75PreparationError("occurrence record differs") from exc
        if occurrence.describe(ordinal=ordinal, union_clause_index=union_index) != dict(
            row
        ):
            raise O1C75PreparationError("occurrence record differs")
        occurrences.append(occurrence)
    if (
        document.get("occurrence_count") != len(occurrences)
        or document.get("unique_clause_count") != len(clauses)
    ):
        raise O1C75PreparationError("occurrence ledger differs")
    return tuple(occurrences)


def _inherited_event_indices(attic: CausalAttic) -> tuple[int, ...]:
    selected: list[int] = []
    seen: set[int] = set()
    for occurrence, union_index in zip(
        attic.occurrences, attic.occurrence_union_indices, strict=True
    ):
        if occurrence.stream_id.startswith("o1c74-episode-") and union_index not in seen:
            seen.add(union_index)
            selected.append(union_index)
    return tuple(selected)


def _symmetric_distance(left: frozenset[int], right: frozenset[int]) -> int:
    return len(left.symmetric_difference(right))


def _first_occurrences(attic: CausalAttic) -> dict[int, ClauseOccurrence]:
    first: dict[int, ClauseOccurrence] = {}
    for occurrence, index in zip(
        attic.occurrences, attic.occurrence_union_indices, strict=True
    ):
        first.setdefault(index, occurrence)
    return first


def _later_only_breadcrumbs(
    attic: CausalAttic,
) -> tuple[dict[str, bytes], dict[str, object]]:
    clauses = attic.union_vault.clauses
    literal_sets = tuple(frozenset(clause.literals) for clause in clauses)
    nearest: list[int] = []
    nearest_distances: list[int] = []
    for left_index, left in enumerate(literal_sets):
        candidates = (
            (
                _symmetric_distance(left, right),
                clauses[right_index].sha256,
                right_index,
            )
            for right_index, right in enumerate(literal_sets)
            if right_index != left_index
        )
        distance, _sha, right_index = min(candidates)
        nearest.append(right_index)
        nearest_distances.append(distance)
    reciprocal = tuple(
        (left, right)
        for left, right in enumerate(nearest)
        if left < right and nearest[right] == left
    )
    pair_rows = [
        {
            "left_union_index": left,
            "left_clause_sha256": clauses[left].sha256,
            "left_literal_count": clauses[left].literal_count,
            "right_union_index": right,
            "right_clause_sha256": clauses[right].sha256,
            "right_literal_count": clauses[right].literal_count,
            "signed_symmetric_distance": nearest_distances[left],
        }
        for left, right in reciprocal
    ]
    distances = sorted(row["signed_symmetric_distance"] for row in pair_rows)
    pair_document = {
        "schema": RECIPROCAL_PAIR_SCHEMA,
        "selection_input": False,
        "definition": (
            "signed-literal-set symmetric distance; nearest by distance,"
            "clause-sha256,index; retain reciprocal directed choices once"
        ),
        "source_union_clause_aggregate_sha256": (
            attic.union_vault.clause_aggregate_sha256
        ),
        "pair_count": len(pair_rows),
        "clause_coverage_count": 2 * len(pair_rows),
        "distance_min": min(distances),
        "distance_median": distances[len(distances) // 2],
        "distance_max": max(distances),
        "distance_at_most_32_count": sum(distance <= 32 for distance in distances),
        "distance_two_pair_count": sum(distance == 2 for distance in distances),
        "pairs": pair_rows,
    }

    clean_rows: list[dict[str, object]] = []
    for row in pair_rows:
        left = cast(int, row["left_union_index"])
        right = cast(int, row["right_union_index"])
        key_difference = {
            literal
            for literal in literal_sets[left].symmetric_difference(
                literal_sets[right]
            )
            if abs(literal) <= 256
        }
        if (
            len(key_difference) == 2
            and {abs(literal) for literal in key_difference}
            == {abs(next(iter(key_difference)))}
            and sum(key_difference) == 0
        ):
            variable = abs(next(iter(key_difference)))
            clean_rows.append(
                {
                    **row,
                    "key_variable": variable,
                    "left_key_literal": next(
                        literal
                        for literal in clauses[left].literals
                        if abs(literal) == variable
                    ),
                    "right_key_literal": next(
                        literal
                        for literal in clauses[right].literals
                        if abs(literal) == variable
                    ),
                    "nonkey_symmetric_distance": cast(
                        int, row["signed_symmetric_distance"]
                    )
                    - 2,
                }
            )
    key_variables = sorted({cast(int, row["key_variable"]) for row in clean_rows})
    clean_document = {
        "schema": KEY_FLIP_PAIR_SCHEMA,
        "selection_input": False,
        "definition": (
            "reciprocal-nearest pair whose key-variable signed difference is "
            "exactly {-v,+v}; nonkey differences remain descriptive"
        ),
        "pair_count": len(clean_rows),
        "key_variable_count": len(key_variables),
        "key_variables": key_variables,
        "pairs": clean_rows,
    }

    first = _first_occurrences(attic)
    oriented_rows: list[dict[str, object]] = []
    for row in clean_rows:
        left = cast(int, row["left_union_index"])
        right = cast(int, row["right_union_index"])
        left_occurrence, right_occurrence = first[left], first[right]
        if left_occurrence.witness_score == right_occurrence.witness_score:
            preferred_index = min(left, right)
            tie = True
        else:
            preferred_index = (
                left
                if left_occurrence.witness_score > right_occurrence.witness_score
                else right
            )
            tie = False
        variable = cast(int, row["key_variable"])
        preferred_literal = next(
            literal
            for literal in clauses[preferred_index].literals
            if abs(literal) == variable
        )
        oriented_rows.append(
            {
                **row,
                "left_first_witness_score": left_occurrence.witness_score,
                "left_first_witness_score_f64le_hex": (
                    left_occurrence.witness_score_f64le_hex
                ),
                "right_first_witness_score": right_occurrence.witness_score,
                "right_first_witness_score_f64le_hex": (
                    right_occurrence.witness_score_f64le_hex
                ),
                "higher_witness_union_index": preferred_index,
                "witness_tie": tie,
                "soft_preferred_pruned_trail_assignment_literal": (
                    -preferred_literal
                ),
            }
        )
    oriented_document = {
        "schema": ORIENTED_PAIR_SCHEMA,
        "selection_input": False,
        "claim_boundary": (
            "soft local orientation only; witness U certifies clauses but does "
            "not make this orientation an exact key claim"
        ),
        "orientation_rule": (
            "higher first-occurrence witness U; prefer pruned-trail assignment "
            "equal to the negation of that clause's key literal"
        ),
        "pair_count": len(oriented_rows),
        "pairs": oriented_rows,
    }

    summary_rows: list[dict[str, object]] = []
    for variable in key_variables:
        rows = [
            row
            for row in oriented_rows
            if cast(int, row["key_variable"]) == variable
        ]
        assignments = Counter(
            cast(int, row["soft_preferred_pruned_trail_assignment_literal"])
            for row in rows
        )
        summary_rows.append(
            {
                "key_variable": variable,
                "pair_count": len(rows),
                "preferred_negative_count": assignments.get(-variable, 0),
                "preferred_positive_count": assignments.get(variable, 0),
                "unanimous": len(assignments) == 1,
                "soft_preferred_assignment_literal": (
                    next(iter(assignments)) if len(assignments) == 1 else None
                ),
            }
        )
    summary_document = {
        "schema": ORIENTATION_SUMMARY_SCHEMA,
        "selection_input": False,
        "key_variable_count": len(summary_rows),
        "unanimous_key_variable_count": sum(
            cast(bool, row["unanimous"]) for row in summary_rows
        ),
        "mixed_key_variables": [
            row["key_variable"] for row in summary_rows if not row["unanimous"]
        ],
        "rows": summary_rows,
    }

    resolvents: list[tuple[int, int, int, ThresholdNoGoodClause]] = []
    for row in clean_rows:
        left = cast(int, row["left_union_index"])
        right = cast(int, row["right_union_index"])
        variable = cast(int, row["key_variable"])
        merged = (literal_sets[left] | literal_sets[right]) - {variable, -variable}
        if any(-literal in merged for literal in merged):
            continue
        ordered = tuple(sorted(merged, key=lambda literal: abs(literal)))
        resolvents.append((left, right, variable, ThresholdNoGoodClause(ordered)))
    resolvent_set_vault = ThresholdNoGoodVault(
        attic.union_vault.identity,
        attic.union_vault.observed_variables,
        tuple(resolvent for _left, _right, _variable, resolvent in resolvents),
    )
    resolvent_set_document = {
        "schema": RESOLVENT_SET_SCHEMA,
        "selection_input": False,
        "claim_boundary": (
            "exact resolution consequences of certified clauses; not observed "
            "science gain and not admitted to the O1C75 attic or residency"
        ),
        "clean_pair_count": len(clean_rows),
        "non_tautological_resolvent_count": len(resolvents),
        "resolvent_vault": resolvent_set_vault.describe(),
        "records": [
            {
                "left_union_index": left,
                "right_union_index": right,
                "pivot_variable": variable,
                "resolvent_clause_sha256": resolvent.sha256,
                "resolvent_literal_count": resolvent.literal_count,
            }
            for left, right, variable, resolvent in resolvents
        ],
    }
    focus = next(
        item for item in resolvents if item[0] == 109 and item[1] == 110
    )
    left, right, variable, resolvent = focus
    one_vault = ThresholdNoGoodVault(
        attic.union_vault.identity,
        attic.union_vault.observed_variables,
        (resolvent,),
    )
    resolution_document = {
        "schema": RESOLVENT_RECORD_SCHEMA,
        "selection_input": False,
        "claim_boundary": (
            "exact logical resolution consequence; later-only breadcrumb, not "
            "an O1C75 selected clause or empirical cryptanalytic gain"
        ),
        "left_union_index": left,
        "left_clause_sha256": clauses[left].sha256,
        "left_first_witness_score": first[left].witness_score,
        "right_union_index": right,
        "right_clause_sha256": clauses[right].sha256,
        "right_first_witness_score": first[right].witness_score,
        "signed_symmetric_difference": sorted(
            literal_sets[left].symmetric_difference(literal_sets[right]),
            key=lambda literal: abs(literal),
        ),
        "pivot_variable": variable,
        "resolvent_clause_sha256": resolvent.sha256,
        "resolvent_literal_count": resolvent.literal_count,
        "resolvent_vault": one_vault.describe(),
    }
    documents = {
        RECIPROCAL_PAIRS_NAME: canonical_json_bytes(pair_document),
        KEY_FLIP_PAIRS_NAME: canonical_json_bytes(clean_document),
        ORIENTED_PAIRS_NAME: canonical_json_bytes(oriented_document),
        ORIENTATION_SUMMARY_NAME: canonical_json_bytes(summary_document),
        RESOLVENT_RECORD_NAME: canonical_json_bytes(resolution_document),
        RESOLVENT_VAULT_NAME: one_vault.serialized,
        RESOLVENT_SET_NAME: canonical_json_bytes(resolvent_set_document),
        RESOLVENT_SET_VAULT_NAME: resolvent_set_vault.serialized,
    }
    summary = {
        "reciprocal_pair_count": len(pair_rows),
        "reciprocal_clause_coverage_count": 2 * len(pair_rows),
        "distance_min_median_max": [
            min(distances),
            distances[len(distances) // 2],
            max(distances),
        ],
        "distance_at_most_32_count": sum(distance <= 32 for distance in distances),
        "distance_two_pair_count": sum(distance == 2 for distance in distances),
        "clean_key_flip_pair_count": len(clean_rows),
        "clean_key_variables": key_variables,
        "unanimous_key_variable_count": sum(
            cast(bool, row["unanimous"]) for row in summary_rows
        ),
        "mixed_key_variables": [
            row["key_variable"] for row in summary_rows if not row["unanimous"]
        ],
        "non_tautological_resolvent_count": len(resolvents),
        "focus_resolvent_clause_sha256": resolvent.sha256,
        "focus_resolvent_vault_sha256": one_vault.sha256,
        "resolvent_set_vault_sha256": resolvent_set_vault.sha256,
    }
    return documents, summary


def _validate_release(
    attic: CausalAttic,
    initial: CausalResidencyState,
    zero_event: CausalResidencyState,
    breadcrumb_summary: Mapping[str, object],
) -> None:
    parent = set(attic.selected_union_indices)
    page1 = set(initial.current_projection.selected_union_indices)
    page2 = set(zero_event.current_projection.selected_union_indices)
    facts = {
        "chunk_clause_counts": tuple(chunk.clause_count for chunk in attic.chunks),
        "rank_source_sha256": attic.chunks[0].sha256,
        "union_clause_count": attic.union_vault.clause_count,
        "union_literal_count": attic.union_vault.literal_count,
        "union_aggregate_sha256": attic.union_vault.clause_aggregate_sha256,
        "occurrence_count": len(attic.occurrences),
        "duplicate_occurrence_count": attic.duplicate_occurrence_count,
        "undominated_clause_count": len(attic.undominated_indices),
        "parent_active_sha256": attic.active_projection.sha256,
        "pinned_core_count": len(initial.pinned_core_indices),
        "initial_inherited_debt_count": len(initial.inherited_debt_indices),
        "page1_sha256": initial.active_projection.sha256,
        "page1_aggregate_sha256": initial.active_projection.clause_aggregate_sha256,
        "page1_clause_count": initial.active_projection.clause_count,
        "page1_literal_count": initial.active_projection.literal_count,
        "page1_serialized_bytes": initial.active_projection.serialized_bytes,
        "page1_parent_overlap": len(parent & page1),
        "parent_page1_joint": len(parent | page1),
        "page1_remaining_debt": len(initial.never_resident_undominated_indices),
        "page2_sha256": zero_event.active_projection.sha256,
        "page2_aggregate_sha256": (
            zero_event.active_projection.clause_aggregate_sha256
        ),
        "page2_clause_count": zero_event.active_projection.clause_count,
        "page2_literal_count": zero_event.active_projection.literal_count,
        "page2_serialized_bytes": zero_event.active_projection.serialized_bytes,
        "page2_page1_overlap": len(page1 & page2),
        "page2_parent_overlap": len(parent & page2),
        "three_page_union": len(parent | page1 | page2),
        "page2_remaining_debt": len(zero_event.never_resident_undominated_indices),
        **dict(breadcrumb_summary),
    }
    expected = {
        "chunk_clause_counts": (202, 311, 0, 37, 0, 0),
        "rank_source_sha256": EXPECTED_RANK_SOURCE_SHA256,
        "union_clause_count": 550,
        "union_literal_count": 1_488_224,
        "union_aggregate_sha256": EXPECTED_PARENT_UNION_AGGREGATE_SHA256,
        "occurrence_count": 558,
        "duplicate_occurrence_count": 8,
        "undominated_clause_count": 545,
        "parent_active_sha256": EXPECTED_PARENT_ACTIVE_SHA256,
        "pinned_core_count": 46,
        "initial_inherited_debt_count": 289,
        "page1_sha256": EXPECTED_PAGE1_SHA256,
        "page1_aggregate_sha256": EXPECTED_PAGE1_AGGREGATE_SHA256,
        "page1_clause_count": 256,
        "page1_literal_count": 703_070,
        "page1_serialized_bytes": 2_813_495,
        "page1_parent_overlap": 46,
        "parent_page1_joint": 466,
        "page1_remaining_debt": 79,
        "page2_sha256": EXPECTED_PAGE2_SHA256,
        "page2_aggregate_sha256": EXPECTED_PAGE2_AGGREGATE_SHA256,
        "page2_clause_count": 256,
        "page2_literal_count": 684_922,
        "page2_serialized_bytes": 2_740_903,
        "page2_page1_overlap": 46,
        "page2_parent_overlap": 177,
        "three_page_union": 545,
        "page2_remaining_debt": 0,
        "reciprocal_pair_count": 223,
        "reciprocal_clause_coverage_count": 446,
        "distance_min_median_max": [2, 16, 44],
        "distance_at_most_32_count": 219,
        "distance_two_pair_count": 1,
        "clean_key_flip_pair_count": 93,
        "clean_key_variables": [
            32,
            59,
            73,
            106,
            115,
            133,
            193,
            201,
            210,
            244,
            246,
            249,
            251,
            255,
        ],
        "unanimous_key_variable_count": 13,
        "mixed_key_variables": [251],
        "non_tautological_resolvent_count": 10,
        "focus_resolvent_clause_sha256": EXPECTED_RESOLVENT_SHA256,
        "focus_resolvent_vault_sha256": EXPECTED_RESOLVENT_VAULT_SHA256,
        "resolvent_set_vault_sha256": EXPECTED_RESOLVENT_SET_VAULT_SHA256,
    }
    if facts != expected:
        differing = sorted(key for key in facts if facts[key] != expected.get(key))
        raise O1C75PreparationError(
            f"O1C-0075 release contract differs: {','.join(differing)}"
        )


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
        raise O1C75PreparationError("causal-residency artifact write failed") from exc


def _publish_directory(output_dir: Path, files: Mapping[str, bytes]) -> None:
    if output_dir.exists():
        raise O1C75PreparationError("causal-residency output already exists")
    try:
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        parent = output_dir.parent.resolve(strict=True)
    except OSError as exc:
        raise O1C75PreparationError("causal-residency output parent differs") from exc
    if output_dir.name in ("", ".", ".."):
        raise O1C75PreparationError("causal-residency output name differs")
    stage = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}.", suffix=".tmp", dir=parent)
    )
    try:
        for name, payload in files.items():
            if Path(name).name != name:
                raise O1C75PreparationError(
                    "causal-residency artifact name differs"
                )
            _durable_write(stage / name, payload)
        os.replace(stage, output_dir)
        directory_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def prepare_o1c75_causal_residency(
    *,
    capsule_dir: str | Path,
    parent_result_path: str | Path,
    output_dir: str | Path,
    enforce_release_contract: bool = True,
) -> dict[str, object]:
    """Replay the sealed parent and atomically publish the zero-call seed."""

    if not isinstance(enforce_release_contract, bool):
        raise O1C75PreparationError("release-contract flag differs")
    capsule = Path(capsule_dir).resolve(strict=True)
    parent_state, _parent_result, parent_manifest_sha = _recover_parent_state(
        capsule, Path(parent_result_path).resolve(strict=True)
    )
    events = _inherited_event_indices(parent_state)
    try:
        initial = initialize_causal_residency(
            parent_state,
            parent_active_indices=parent_state.selected_union_indices,
            inherited_event_indices=events,
            parent_lineage_ordinal=PARENT_LINEAGE_ORDINAL,
            first_lineage_ordinal=FIRST_LINEAGE_ORDINAL,
            active_limit=ACTIVE_CLAUSE_LIMIT,
        )
        zero_event = reproject_causal_residency(
            parent_state,
            previous_state=initial,
            fully_emitted_union_indices=(),
            next_lineage_ordinal=SECOND_LINEAGE_ORDINAL,
        )
    except CausalResidencyError as exc:
        raise O1C75PreparationError("initial residency projection differs") from exc
    breadcrumb_artifacts, breadcrumb_summary = _later_only_breadcrumbs(parent_state)
    if enforce_release_contract:
        _validate_release(parent_state, initial, zero_event, breadcrumb_summary)

    occurrence_payload = canonical_json_bytes(parent_state.occurrence_document())
    relation_payload = canonical_json_bytes(parent_state.relation_document())
    ledger_payload = canonical_json_bytes(initial.activation_ledger_document())
    plan_payload = canonical_json_bytes(
        {
            "schema": PROJECTION_PLAN_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "maximum_native_solver_calls": 2,
            "requested_conflicts_per_call": 128,
            "lineage_ordinals": [FIRST_LINEAGE_ORDINAL, SECOND_LINEAGE_ORDINAL],
            "initial_page": initial.current_projection.describe(),
            "zero_event_second_page": zero_event.current_projection.describe(),
            "zero_event_activation_ledger": (
                zero_event.activation_ledger_document()
            ),
            "zero_event_three_page_undominated_coverage_count": 545,
            "zero_event_inherited_debt_after_page2": 0,
            "selection_input_excludes_later_only_breadcrumbs": True,
        }
    )
    artifacts: dict[str, bytes] = {
        **{
            name: chunk.serialized
            for name, chunk in zip(CHUNK_NAMES, parent_state.chunks, strict=True)
        },
        PARENT_ACTIVE_NAME: parent_state.active_projection.serialized,
        ACTIVE_PROJECTION_NAME: initial.active_projection.serialized,
        ZERO_EVENT_PAGE_NAME: zero_event.active_projection.serialized,
        OCCURRENCES_NAME: occurrence_payload,
        RELATIONS_NAME: relation_payload,
        ACTIVATION_LEDGER_NAME: ledger_payload,
        PROJECTION_PLAN_NAME: plan_payload,
        **breadcrumb_artifacts,
    }
    roles = {
        **{name: "immutable-parent-attic-chunk" for name in CHUNK_NAMES},
        PARENT_ACTIVE_NAME: "inherited-parent-final-active-projection",
        ACTIVE_PROJECTION_NAME: "initial-science-input-residency-page",
        ZERO_EVENT_PAGE_NAME: "zero-event-second-page-fixture",
        OCCURRENCES_NAME: "complete-compact-witness-occurrence-ledger",
        RELATIONS_NAME: "complete-strict-subsumption-closure",
        ACTIVATION_LEDGER_NAME: "compact-replayable-activation-ledger",
        PROJECTION_PLAN_NAME: "two-call-residency-projection-plan",
        RECIPROCAL_PAIRS_NAME: "later-only-reciprocal-nearest-breadcrumb",
        KEY_FLIP_PAIRS_NAME: "later-only-clean-key-flip-breadcrumb",
        ORIENTED_PAIRS_NAME: "later-only-soft-orientation-breadcrumb",
        ORIENTATION_SUMMARY_NAME: "later-only-soft-orientation-summary",
        RESOLVENT_RECORD_NAME: "later-only-exact-resolution-record",
        RESOLVENT_VAULT_NAME: "later-only-exact-one-clause-vault",
        RESOLVENT_SET_NAME: "later-only-exact-resolution-set-record",
        RESOLVENT_SET_VAULT_NAME: "later-only-exact-ten-clause-vault",
    }
    artifact_rows = {
        name: _artifact_row(payload, roles[name])
        for name, payload in sorted(artifacts.items())
    }
    generated_reference_comparison = {
        name: {
            "reference": reference,
            "published": {
                "serialized_bytes": len(artifacts[name]),
                "sha256": sha256_bytes(artifacts[name]),
            },
            "status": "semantic-match-schema-reconstructed-not-byte-identity",
        }
        for name, reference in REFERENCE_ANALYTIC_DOCUMENTS.items()
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
        "parent": {
            "attempt_id": "O1C-0074",
            "result_sha256": EXPECTED_PARENT_RESULT_SHA256,
            "manifest_sha256": parent_manifest_sha,
            "recovery_runner_sha256": EXPECTED_O1C74_RUNNER_SHA256,
            "final_active_sha256": EXPECTED_PARENT_ACTIVE_SHA256,
            "rank_source_sha256": EXPECTED_RANK_SOURCE_SHA256,
        },
        "residency_schema": CAUSAL_RESIDENCY_SCHEMA,
        "activation_ledger_schema": ACTIVATION_LEDGER_SCHEMA,
        "residency": initial.describe(),
        "zero_event_projection": zero_event.current_projection.describe(),
        "later_only_breadcrumbs": {
            "selection_input": False,
            "summary": breadcrumb_summary,
            "reference_digest_note": (
                "The analyst's ephemeral JSON field layout was not recoverable; "
                "published versioned documents freeze the same semantic facts "
                "under a new canonical schema. Binary clause/vault identities "
                "remain encoding-defined and match their references."
            ),
            "reference_vs_published": generated_reference_comparison,
        },
        "artifact_set": {
            "schema": ARTIFACT_SET_SCHEMA,
            "artifact_count": len(artifact_rows),
            "artifacts": artifact_rows,
        },
    }
    manifest_payload = canonical_json_bytes(manifest)
    _publish_directory(Path(output_dir), {**artifacts, MANIFEST_NAME: manifest_payload})
    return manifest


def load_prepared_residency(
    directory: str | Path, *, expected_manifest_sha256: str
) -> PreparedResidency:
    """Rebuild every prepared artifact and replay the activation ledger."""

    prepared = Path(directory).resolve(strict=True)
    if not prepared.is_dir() or prepared.is_symlink():
        raise O1C75PreparationError("prepared causal-residency directory differs")
    manifest_path = _regular_file(prepared / MANIFEST_NAME, "prepared manifest")
    manifest_bytes = manifest_path.read_bytes()
    expected = _sha256(expected_manifest_sha256, "prepared manifest SHA-256")
    if sha256_bytes(manifest_bytes) != expected:
        raise O1C75PreparationError("prepared causal-residency manifest differs")
    manifest = _read_json_bytes(manifest_bytes, "prepared manifest")
    if (
        manifest.get("schema") != MANIFEST_SCHEMA
        or manifest.get("preparation_schema") != PREPARATION_SCHEMA
        or manifest.get("attempt_id") != ATTEMPT_ID
        or manifest.get("residency_schema") != CAUSAL_RESIDENCY_SCHEMA
    ):
        raise O1C75PreparationError("prepared manifest contract differs")
    artifact_set = _mapping(manifest.get("artifact_set"), "prepared artifact set")
    rows = _mapping(artifact_set.get("artifacts"), "prepared artifacts")
    expected_names = set(CHUNK_NAMES) | {
        PARENT_ACTIVE_NAME,
        ACTIVE_PROJECTION_NAME,
        ZERO_EVENT_PAGE_NAME,
        OCCURRENCES_NAME,
        RELATIONS_NAME,
        ACTIVATION_LEDGER_NAME,
        PROJECTION_PLAN_NAME,
        RECIPROCAL_PAIRS_NAME,
        KEY_FLIP_PAIRS_NAME,
        ORIENTED_PAIRS_NAME,
        ORIENTATION_SUMMARY_NAME,
        RESOLVENT_RECORD_NAME,
        RESOLVENT_VAULT_NAME,
        RESOLVENT_SET_NAME,
        RESOLVENT_SET_VAULT_NAME,
    }
    if set(rows) != expected_names or artifact_set.get("artifact_count") != len(rows):
        raise O1C75PreparationError("prepared artifact inventory differs")
    actual_paths = tuple(prepared.iterdir())
    if (
        {path.name for path in actual_paths}
        != expected_names | {MANIFEST_NAME}
        or any(path.is_symlink() or not path.is_file() for path in actual_paths)
    ):
        raise O1C75PreparationError("prepared directory inventory differs")
    payloads: dict[str, bytes] = {}
    for name in sorted(expected_names):
        row = _mapping(rows[name], f"prepared artifact {name}")
        payload = _regular_file(prepared / name, f"prepared artifact {name}").read_bytes()
        if (
            row.get("sha256") != sha256_bytes(payload)
            or row.get("serialized_bytes") != len(payload)
        ):
            raise O1C75PreparationError(f"prepared artifact {name} differs")
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
        seen: set[bytes] = set()
        for chunk in chunks:
            for clause in chunk.clauses:
                if clause.serialized not in seen:
                    seen.add(clause.serialized)
                    union_clauses.append(clause)
        occurrence_value = json.loads(payloads[OCCURRENCES_NAME])
        occurrences = _parse_occurrence_document(
            occurrence_value, clauses=tuple(union_clauses)
        )
        attic = reproject_causal_attic(
            tuple(chunks), occurrences, active_limit=ACTIVE_CLAUSE_LIMIT
        )
        state = replay_causal_residency(
            attic, _mapping(manifest.get("residency"), "prepared residency")
        )
        parent_active = parse_threshold_no_good_vault(
            payloads[PARENT_ACTIVE_NAME],
            observed_variables=rank.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
        active = parse_threshold_no_good_vault(
            payloads[ACTIVE_PROJECTION_NAME],
            observed_variables=rank.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
        zero_event_vault = parse_threshold_no_good_vault(
            payloads[ZERO_EVENT_PAGE_NAME],
            observed_variables=rank.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
        zero_event = reproject_causal_residency(
            attic,
            previous_state=state,
            fully_emitted_union_indices=(),
            next_lineage_ordinal=SECOND_LINEAGE_ORDINAL,
        )
    except (
        CausalAtticError,
        CausalResidencyError,
        ThresholdNoGoodVaultError,
        json.JSONDecodeError,
    ) as exc:
        raise O1C75PreparationError("prepared residency reconstruction differs") from exc
    if (
        attic.occurrence_document() != occurrence_value
        or canonical_json_bytes(attic.relation_document()) != payloads[RELATIONS_NAME]
        or canonical_json_bytes(state.activation_ledger_document())
        != payloads[ACTIVATION_LEDGER_NAME]
        or parent_active.serialized != attic.active_projection.serialized
        or active.serialized != state.active_projection.serialized
        or zero_event_vault.serialized != zero_event.active_projection.serialized
        or zero_event.current_projection.describe()
        != manifest.get("zero_event_projection")
    ):
        raise O1C75PreparationError("prepared residency projection differs")
    validate_activation_replay(state)
    return PreparedResidency(
        directory=prepared,
        manifest=dict(manifest),
        manifest_bytes=manifest_bytes,
        manifest_sha256=expected,
        state=state,
    )


def _parser() -> argparse.ArgumentParser:
    root = lab_root()
    parser = argparse.ArgumentParser(
        description="Prepare O1C-0075's zero-call causal residency"
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
        manifest = prepare_o1c75_causal_residency(
            capsule_dir=args.capsule,
            parent_result_path=args.parent_result,
            output_dir=args.output_dir,
        )
    except (O1C75PreparationError, CausalResidencyError) as exc:
        print(f"{ATTEMPT_ID}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(manifest, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ACTIVE_CLAUSE_LIMIT",
    "ACTIVE_PROJECTION_NAME",
    "ACTIVATION_LEDGER_NAME",
    "CHUNK_NAMES",
    "DEFAULT_PARENT_CAPSULE_RELATIVE",
    "DEFAULT_PARENT_RESULT_RELATIVE",
    "EXPECTED_PAGE1_SHA256",
    "EXPECTED_PAGE2_SHA256",
    "EXPECTED_PREPARED_MANIFEST_SHA256",
    "MANIFEST_NAME",
    "MANIFEST_SCHEMA",
    "O1C75PreparationError",
    "OCCURRENCES_NAME",
    "PARENT_ACTIVE_NAME",
    "PROJECTION_PLAN_NAME",
    "PreparedResidency",
    "RELATIONS_NAME",
    "ZERO_EVENT_PAGE_NAME",
    "lab_root",
    "load_prepared_residency",
    "main",
    "prepare_o1c75_causal_residency",
]
