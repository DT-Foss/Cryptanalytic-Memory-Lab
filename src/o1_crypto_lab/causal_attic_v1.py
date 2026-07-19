"""Deterministic active projection over immutable threshold-no-good chunks.

The v1 threshold-no-good vault is an append-only, first-emission archive.  An
active projection has different semantics: it may omit exact duplicates and
clauses that are dominated by a strict signed-literal subset.  This module
keeps those roles separate.  It validates compact witness ledgers, constructs
immutable archive chunks, records the full subsumption closure, and selects a
bounded active projection without relabelling that projection as a cumulative
vault-v1 archive.

Selection is target-free.  A clause covers an observed exclusion exactly when
its signed literals are a subset of that exclusion's clause.  Candidates that
are themselves covered by a stronger clause are never active candidates.  The
remaining candidates are greedily ordered by new unique exclusions covered,
new witness occurrences covered, shorter length, then ascending clause SHA.
Selected clauses are serialized in global first-occurrence order.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Mapping, Sequence, cast

from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    THRESHOLD_NO_GOOD_VAULT_HEADER_BYTES,
    THRESHOLD_NO_GOOD_VAULT_MAGIC,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultError,
    ThresholdNoGoodVaultIdentity,
    VaultCaps,
    parse_threshold_no_good_vault,
    validate_threshold_no_good_vault_caps,
)


CAUSAL_ATTIC_SCHEMA = "o1-score-threshold-causal-attic-v1"
CAUSAL_ATTIC_OCCURRENCE_SCHEMA = "o1-score-threshold-causal-occurrences-v1"
CAUSAL_ATTIC_RELATION_SCHEMA = "o1-score-threshold-causal-relations-v1"
ACTIVE_PROJECTION_SCHEMA = "o1-score-threshold-active-vault-projection-v1"
VAULT_TELEMETRY_SCHEMA = "o1-256-cadical-score-threshold-no-good-vault-telemetry-v1"
ACTIVE_SELECTION_RULE = (
    "global-first-occurrence-exact-dedup;strict-signed-literal-subsumption;"
    "undominated-candidates;greedy-lexicographic:new-unique-coverage-desc,"
    "new-occurrence-coverage-desc,literal-count-asc,clause-sha256-asc;"
    "serialize-global-first-occurrence-order"
)

_SOURCE_CODES = {"trail_upper_bound": 1, "complete_model_score": 2}
_CLASSIFICATIONS = {"new", "input_duplicate", "current_duplicate"}
_EMISSION_FIELDS = {
    "classification",
    "clause_sha256",
    "index",
    "literal_count",
    "literals",
    "source",
    "witness_score",
    "witness_score_f64le_hex",
    "witness_sha256",
}
_LEDGER_FIELDS = {
    "fully_emitted_clause_count",
    "fully_emitted_literal_count",
    "emitted_new_clause_count",
    "emitted_new_literal_count",
    "emitted_input_duplicate_clause_count",
    "emitted_input_duplicate_literal_count",
    "emitted_current_duplicate_clause_count",
    "emitted_current_duplicate_literal_count",
    "terminal_empty_clause_count",
}


class CausalAtticError(ValueError):
    """A chunk, witness ledger, relation, or active-selection invariant differs."""


def canonical_json_bytes(value: object) -> bytes:
    """Return the repository's compact, finite, ASCII JSON representation."""

    try:
        return (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CausalAtticError("causal-attic JSON value differs") from exc


def sha256_bytes(payload: bytes) -> str:
    """Return the lowercase SHA-256 of bytes."""

    if not isinstance(payload, bytes):
        raise CausalAtticError("causal-attic hash payload differs")
    return hashlib.sha256(payload).hexdigest()


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CausalAtticError(f"causal-attic {field} differs")
    return value


def _nonnegative_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CausalAtticError(f"causal-attic {field} differs")
    return value


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise CausalAtticError(f"causal-attic {field} differs")
    return cast(Mapping[str, object], value)


def _stream_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789-_."
            for character in value
        )
    ):
        raise CausalAtticError("causal-attic stream id differs")
    return value


@dataclass(frozen=True)
class ClauseOccurrence:
    """One fully emitted witness occurrence with exact binary64 provenance."""

    stream_id: str
    source_index: int
    classification: str
    source: str
    witness_score_f64le_hex: str
    clause: ThresholdNoGoodClause
    clause_sha256: str
    witness_sha256: str

    def __post_init__(self) -> None:
        _stream_id(self.stream_id)
        _nonnegative_integer(self.source_index, "occurrence source index")
        if (
            not isinstance(self.classification, str)
            or self.classification not in _CLASSIFICATIONS
        ):
            raise CausalAtticError("causal-attic occurrence classification differs")
        source_code = (
            _SOURCE_CODES.get(self.source) if isinstance(self.source, str) else None
        )
        if source_code is None:
            raise CausalAtticError("causal-attic occurrence source differs")
        if not isinstance(self.clause, ThresholdNoGoodClause):
            raise CausalAtticError("causal-attic occurrence clause differs")
        if (
            not isinstance(self.witness_score_f64le_hex, str)
            or len(self.witness_score_f64le_hex) != 16
        ):
            raise CausalAtticError("causal-attic occurrence witness bits differ")
        try:
            witness_bytes = bytes.fromhex(self.witness_score_f64le_hex)
            witness_score = struct.unpack("<d", witness_bytes)[0]
        except (ValueError, struct.error) as exc:
            raise CausalAtticError(
                "causal-attic occurrence witness bits differ"
            ) from exc
        if not math.isfinite(witness_score):
            raise CausalAtticError("causal-attic occurrence witness differs")
        expected_clause_sha = sha256_bytes(self.clause.serialized)
        expected_witness_sha = sha256_bytes(
            bytes((source_code,)) + witness_bytes + self.clause.serialized
        )
        if (
            _sha256(self.clause_sha256, "occurrence clause SHA-256")
            != expected_clause_sha
            or _sha256(self.witness_sha256, "occurrence witness SHA-256")
            != expected_witness_sha
        ):
            raise CausalAtticError("causal-attic occurrence digest differs")

    @property
    def witness_score(self) -> float:
        return struct.unpack("<d", bytes.fromhex(self.witness_score_f64le_hex))[0]

    def describe(self, *, ordinal: int, union_clause_index: int) -> dict[str, object]:
        return {
            "ordinal": ordinal,
            "stream_id": self.stream_id,
            "source_index": self.source_index,
            "classification": self.classification,
            "source": self.source,
            "witness_score_f64le_hex": self.witness_score_f64le_hex,
            "clause_sha256": self.clause_sha256,
            "witness_sha256": self.witness_sha256,
            "union_clause_index": union_clause_index,
        }


@dataclass(frozen=True)
class ParsedVaultTelemetry:
    """Encoding- and ledger-validated native vault telemetry."""

    stream_id: str
    artifact_sha256: str
    input_identity: ThresholdNoGoodVaultIdentity
    input_vault_sha256: str
    input_clause_count: int
    input_literal_count: int
    input_serialized_bytes: int
    input_clause_aggregate_sha256: str
    occurrences: tuple[ClauseOccurrence, ...]

    @property
    def new_occurrences(self) -> tuple[ClauseOccurrence, ...]:
        return tuple(
            occurrence
            for occurrence in self.occurrences
            if occurrence.classification == "new"
        )

    def source_description(self) -> dict[str, object]:
        return {
            "stream_id": self.stream_id,
            "artifact_sha256": self.artifact_sha256,
            "input_vault_sha256": self.input_vault_sha256,
            "fully_emitted_clause_count": len(self.occurrences),
            "new_clause_count": len(self.new_occurrences),
        }


def parse_vault_telemetry(
    payload: bytes,
    *,
    stream_id: str,
    expected_sha256: str,
) -> ParsedVaultTelemetry:
    """Validate one sealed native emission ledger without score recomputation.

    This verifies the artifact digest, exact clause/witness encodings,
    classifications as reported by the native ledger, and every aggregate
    counter.  Score certification remains the responsibility of the sealed
    native result that produced the manifested artifact.
    """

    normalized_stream = _stream_id(stream_id)
    expected_artifact = _sha256(expected_sha256, "telemetry SHA-256")
    if not isinstance(payload, bytes) or sha256_bytes(payload) != expected_artifact:
        raise CausalAtticError("causal-attic telemetry artifact differs")
    try:
        raw = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CausalAtticError("causal-attic telemetry JSON differs") from exc
    telemetry = _mapping(raw, "telemetry root")
    if telemetry.get("schema") != VAULT_TELEMETRY_SCHEMA:
        raise CausalAtticError("causal-attic telemetry schema differs")
    if telemetry.get("binary_magic_hex") != THRESHOLD_NO_GOOD_VAULT_MAGIC.hex():
        raise CausalAtticError("causal-attic telemetry magic differs")

    threshold_hex = telemetry.get("input_threshold_f64le_hex")
    if not isinstance(threshold_hex, str) or len(threshold_hex) != 16:
        raise CausalAtticError("causal-attic telemetry threshold differs")
    try:
        threshold = struct.unpack("<d", bytes.fromhex(threshold_hex))[0]
    except (ValueError, struct.error) as exc:
        raise CausalAtticError("causal-attic telemetry threshold differs") from exc
    if (
        not math.isfinite(threshold)
        or struct.pack("<d", threshold).hex() != threshold_hex
    ):
        raise CausalAtticError("causal-attic telemetry threshold differs")
    try:
        identity = ThresholdNoGoodVaultIdentity(
            cnf_sha256=_sha256(telemetry.get("input_cnf_sha256"), "input CNF"),
            potential_sha256=_sha256(
                telemetry.get("input_potential_sha256"), "input potential"
            ),
            grouping_sha256=_sha256(
                telemetry.get("input_grouping_sha256"), "input grouping"
            ),
            observed_variables_sha256=_sha256(
                telemetry.get("input_observed_variables_sha256"),
                "input observed variables",
            ),
            bound_rule_sha256=_sha256(
                telemetry.get("input_bound_rule_sha256"), "input bound rule"
            ),
            threshold=threshold,
        )
    except ThresholdNoGoodVaultError as exc:
        raise CausalAtticError("causal-attic telemetry identity differs") from exc

    emitted = telemetry.get("fully_emitted_clauses")
    if not isinstance(emitted, list):
        raise CausalAtticError("causal-attic telemetry emissions differ")
    occurrences: list[ClauseOccurrence] = []
    aggregate = bytearray()
    class_clause_counts: Counter[str] = Counter()
    class_literal_counts: Counter[str] = Counter()
    total_literals = 0
    for expected_index, value in enumerate(emitted):
        row = _mapping(value, "telemetry emission")
        if set(row) != _EMISSION_FIELDS:
            raise CausalAtticError("causal-attic telemetry emission fields differ")
        index = _nonnegative_integer(row["index"], "telemetry emission index")
        literal_count = _nonnegative_integer(
            row["literal_count"], "telemetry literal count"
        )
        literals_raw = row["literals"]
        witness_score = row["witness_score"]
        if (
            index != expected_index
            or not isinstance(literals_raw, list)
            or len(literals_raw) != literal_count
            or any(
                isinstance(literal, bool) or not isinstance(literal, int)
                for literal in literals_raw
            )
            or isinstance(witness_score, bool)
            or not isinstance(witness_score, (int, float))
            or not math.isfinite(float(witness_score))
        ):
            raise CausalAtticError("causal-attic telemetry emission differs")
        witness = float(witness_score)
        witness_hex = struct.pack("<d", witness).hex()
        if row["witness_score_f64le_hex"] != witness_hex:
            raise CausalAtticError("causal-attic telemetry witness bits differ")
        try:
            clause = ThresholdNoGoodClause(tuple(cast(list[int], literals_raw)))
        except ThresholdNoGoodVaultError as exc:
            raise CausalAtticError("causal-attic telemetry clause differs") from exc
        occurrence = ClauseOccurrence(
            stream_id=normalized_stream,
            source_index=index,
            classification=cast(str, row["classification"]),
            source=cast(str, row["source"]),
            witness_score_f64le_hex=witness_hex,
            clause=clause,
            clause_sha256=cast(str, row["clause_sha256"]),
            witness_sha256=cast(str, row["witness_sha256"]),
        )
        occurrences.append(occurrence)
        aggregate.extend(clause.serialized)
        total_literals += clause.literal_count
        class_clause_counts[occurrence.classification] += 1
        class_literal_counts[occurrence.classification] += clause.literal_count

    ledgers = {
        field: _nonnegative_integer(telemetry.get(field), f"telemetry {field}")
        for field in _LEDGER_FIELDS
    }
    expected_ledgers = {
        "fully_emitted_clause_count": len(occurrences),
        "fully_emitted_literal_count": total_literals,
        "emitted_new_clause_count": class_clause_counts["new"],
        "emitted_new_literal_count": class_literal_counts["new"],
        "emitted_input_duplicate_clause_count": class_clause_counts["input_duplicate"],
        "emitted_input_duplicate_literal_count": class_literal_counts[
            "input_duplicate"
        ],
        "emitted_current_duplicate_clause_count": class_clause_counts[
            "current_duplicate"
        ],
        "emitted_current_duplicate_literal_count": class_literal_counts[
            "current_duplicate"
        ],
        "terminal_empty_clause_count": 0,
    }
    if ledgers != expected_ledgers or telemetry.get(
        "fully_emitted_aggregate_sha256"
    ) != sha256_bytes(bytes(aggregate)):
        raise CausalAtticError("causal-attic telemetry ledger differs")

    return ParsedVaultTelemetry(
        stream_id=normalized_stream,
        artifact_sha256=expected_artifact,
        input_identity=identity,
        input_vault_sha256=_sha256(
            telemetry.get("input_sha256"), "telemetry input vault"
        ),
        input_clause_count=_nonnegative_integer(
            telemetry.get("input_clause_count"), "telemetry input clauses"
        ),
        input_literal_count=_nonnegative_integer(
            telemetry.get("input_literal_count"), "telemetry input literals"
        ),
        input_serialized_bytes=_nonnegative_integer(
            telemetry.get("input_serialized_bytes"), "telemetry input bytes"
        ),
        input_clause_aggregate_sha256=_sha256(
            telemetry.get("input_clause_aggregate_sha256"),
            "telemetry input clause aggregate",
        ),
        occurrences=tuple(occurrences),
    )


def parse_self_scoping_vault(
    payload: bytes, *, caps: VaultCaps = O1C66_VAULT_CAPS
) -> ThresholdNoGoodVault:
    """Infer the observed scope from a nonempty vault, then use the v1 parser.

    The observed-variable digest still gates the result.  This helper is useful
    for a sealed capsule that carries the canonical vault but not a separate
    observed-variable table.  It rejects a vault whose clauses do not expose
    its complete bound scope.
    """

    if not isinstance(payload, bytes) or not isinstance(caps, VaultCaps):
        raise CausalAtticError("causal-attic vault input differs")
    if len(payload) < THRESHOLD_NO_GOOD_VAULT_HEADER_BYTES or not payload.startswith(
        THRESHOLD_NO_GOOD_VAULT_MAGIC
    ):
        raise CausalAtticError("causal-attic vault header differs")
    cursor = THRESHOLD_NO_GOOD_VAULT_HEADER_BYTES - 4
    try:
        clause_count = struct.unpack_from("<I", payload, cursor)[0]
    except struct.error as exc:
        raise CausalAtticError("causal-attic vault clause count differs") from exc
    cursor += 4
    observed: set[int] = set()
    for _ in range(clause_count):
        try:
            length = struct.unpack_from("<I", payload, cursor)[0]
        except struct.error as exc:
            raise CausalAtticError("causal-attic vault clause differs") from exc
        cursor += 4
        if not length or cursor > len(payload) or length > (len(payload) - cursor) // 4:
            raise CausalAtticError("causal-attic vault clause differs")
        try:
            literals = struct.unpack_from(f"<{length}i", payload, cursor)
            clause = ThresholdNoGoodClause(tuple(literals))
        except (struct.error, ThresholdNoGoodVaultError) as exc:
            raise CausalAtticError("causal-attic vault clause differs") from exc
        cursor += 4 * length
        observed.update(abs(literal) for literal in clause.literals)
    if cursor != len(payload) or not observed:
        raise CausalAtticError("causal-attic vault payload differs")
    try:
        return parse_threshold_no_good_vault(
            payload,
            observed_variables=tuple(sorted(observed)),
            caps=caps,
        )
    except ThresholdNoGoodVaultError as exc:
        raise CausalAtticError(
            "causal-attic vault does not expose its complete observed scope"
        ) from exc


@dataclass(frozen=True, order=True)
class SubsumptionRelation:
    """One strict signed-literal subset relation in the unique clause union."""

    subsumer_index: int
    subsumed_index: int

    def describe(self, clauses: tuple[ThresholdNoGoodClause, ...]) -> dict[str, object]:
        subsumer = clauses[self.subsumer_index]
        subsumed = clauses[self.subsumed_index]
        return {
            "subsumer_index": self.subsumer_index,
            "subsumer_clause_sha256": subsumer.sha256,
            "subsumer_literal_count": subsumer.literal_count,
            "subsumed_index": self.subsumed_index,
            "subsumed_clause_sha256": subsumed.sha256,
            "subsumed_literal_count": subsumed.literal_count,
            "literal_delta": subsumed.literal_count - subsumer.literal_count,
        }


def strict_subsumption_relations(
    clauses: Sequence[ThresholdNoGoodClause],
) -> tuple[SubsumptionRelation, ...]:
    """Return the deterministic transitive closure of strict subset relations."""

    normalized = tuple(clauses)
    if not normalized or any(
        not isinstance(clause, ThresholdNoGoodClause) for clause in normalized
    ):
        raise CausalAtticError("causal-attic relation clauses differ")
    if len(set(normalized)) != len(normalized):
        raise CausalAtticError("causal-attic relation clauses are not unique")
    count = len(normalized)
    containing: defaultdict[int, int] = defaultdict(int)
    for index, clause in enumerate(normalized):
        bit = 1 << index
        for literal in clause.literals:
            containing[literal] |= bit
    all_mask = (1 << count) - 1
    relations: list[SubsumptionRelation] = []
    for subsumer_index, clause in enumerate(normalized):
        supersets = all_mask
        for literal in clause.literals:
            supersets &= containing[literal]
            if not supersets:
                break
        supersets &= ~(1 << subsumer_index)
        while supersets:
            bit = supersets & -supersets
            subsumed_index = bit.bit_length() - 1
            supersets -= bit
            if clause.literal_count >= normalized[subsumed_index].literal_count:
                raise CausalAtticError("causal-attic equal subset differs")
            relations.append(SubsumptionRelation(subsumer_index, subsumed_index))
    return tuple(sorted(relations))


@dataclass(frozen=True)
class CausalAttic:
    """Immutable chunks, compact causal ledger, and one bounded projection."""

    chunks: tuple[ThresholdNoGoodVault, ...]
    union_vault: ThresholdNoGoodVault
    active_projection: ThresholdNoGoodVault
    occurrences: tuple[ClauseOccurrence, ...]
    chunk_clause_union_indices: tuple[tuple[int, ...], ...]
    occurrence_union_indices: tuple[int, ...]
    relations: tuple[SubsumptionRelation, ...]
    undominated_indices: tuple[int, ...]
    selection_order: tuple[int, ...]
    selected_union_indices: tuple[int, ...]
    unique_coverage_count: int
    occurrence_coverage_count: int
    active_limit: int

    @property
    def retained_chunk(self) -> ThresholdNoGoodVault:
        """Return the immutable rank-source chunk for the two-chunk prepare path."""

        return self.chunks[0]

    @property
    def novel_chunk(self) -> ThresholdNoGoodVault:
        """Return the O1C73 rollover chunk for the two-chunk prepare path."""

        if len(self.chunks) != 2:
            raise CausalAtticError("causal-attic does not have one novel chunk")
        return self.chunks[1]

    @property
    def duplicate_occurrence_count(self) -> int:
        return len(self.occurrence_union_indices) - len(
            set(self.occurrence_union_indices)
        )

    def occurrence_document(self) -> dict[str, object]:
        return {
            "schema": CAUSAL_ATTIC_OCCURRENCE_SCHEMA,
            "occurrence_count": len(self.occurrences),
            "unique_clause_count": self.union_vault.clause_count,
            "duplicate_occurrence_count": self.duplicate_occurrence_count,
            "records": [
                occurrence.describe(
                    ordinal=ordinal,
                    union_clause_index=self.occurrence_union_indices[ordinal],
                )
                for ordinal, occurrence in enumerate(self.occurrences)
            ],
        }

    def relation_document(self) -> dict[str, object]:
        clauses = self.union_vault.clauses
        subsumed = {relation.subsumed_index for relation in self.relations}
        return {
            "schema": CAUSAL_ATTIC_RELATION_SCHEMA,
            "strict_subsumption_pair_count": len(self.relations),
            "undominated_clause_count": len(self.undominated_indices),
            "dominated_clause_count": len(subsumed),
            "undominated_indices": list(self.undominated_indices),
            "relations": [relation.describe(clauses) for relation in self.relations],
        }

    def describe(self) -> dict[str, object]:
        return {
            "schema": CAUSAL_ATTIC_SCHEMA,
            "archive_rule": "immutable-vault-v1-chunks;no-chunk-relabel-or-mutation",
            "chunks": [
                {
                    "chunk_index": index,
                    **chunk.describe(),
                    "union_clause_indices": list(
                        self.chunk_clause_union_indices[index]
                    ),
                }
                for index, chunk in enumerate(self.chunks)
            ],
            "retained_chunk": self.retained_chunk.describe(),
            "novel_chunk": (
                self.novel_chunk.describe() if len(self.chunks) == 2 else None
            ),
            "union": self.union_vault.describe(),
            "occurrence_count": len(self.occurrences),
            "duplicate_occurrence_count": self.duplicate_occurrence_count,
            "strict_subsumption_pair_count": len(self.relations),
            "active_projection": {
                "schema": ACTIVE_PROJECTION_SCHEMA,
                "encoding_only": self.active_projection.describe(),
                "is_cumulative_vault_v1": False,
                "maximum_clause_count": self.active_limit,
                "selection_rule": ACTIVE_SELECTION_RULE,
                "candidate_clause_count": len(self.undominated_indices),
                "selected_union_indices": list(self.selected_union_indices),
                "selection_order": list(self.selection_order),
                "unique_coverage_count": self.unique_coverage_count,
                "occurrence_coverage_count": self.occurrence_coverage_count,
            },
        }


def _coverage_masks(
    clause_count: int, relations: tuple[SubsumptionRelation, ...]
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    supersets = [1 << index for index in range(clause_count)]
    subsumed = set()
    for relation in relations:
        supersets[relation.subsumer_index] |= 1 << relation.subsumed_index
        subsumed.add(relation.subsumed_index)
    undominated = tuple(index for index in range(clause_count) if index not in subsumed)
    return tuple(supersets), undominated


def _active_limit(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= O1C66_VAULT_CAPS.maximum_clauses
    ):
        raise CausalAtticError("causal-attic active limit differs")
    return value


def reproject_causal_attic(
    chunks: Sequence[ThresholdNoGoodVault],
    occurrences: Sequence[ClauseOccurrence],
    *,
    active_limit: int = 256,
) -> CausalAttic:
    """Globally deduplicate arbitrary immutable chunks and recompute projection.

    Empty rollover chunks are valid and preserve episode ordering.  Clauses
    repeated across chunks retain only their earliest union position, while all
    witness occurrences remain in the compact causal ledger.
    """

    normalized_limit = _active_limit(active_limit)
    normalized_chunks = tuple(chunks)
    normalized_occurrences = tuple(occurrences)
    if not normalized_chunks or any(
        not isinstance(chunk, ThresholdNoGoodVault) for chunk in normalized_chunks
    ):
        raise CausalAtticError("causal-attic chunk sequence differs")
    identity = normalized_chunks[0].identity
    observed_variables = normalized_chunks[0].observed_variables
    try:
        for chunk in normalized_chunks:
            if (
                chunk.identity != identity
                or chunk.observed_variables != observed_variables
            ):
                raise CausalAtticError("causal-attic chunk identity differs")
            validate_threshold_no_good_vault_caps(chunk, caps=O1C66_VAULT_CAPS)
    except ThresholdNoGoodVaultError as exc:
        raise CausalAtticError("causal-attic chunk cap differs") from exc
    if not normalized_occurrences or any(
        not isinstance(occurrence, ClauseOccurrence)
        for occurrence in normalized_occurrences
    ):
        raise CausalAtticError("causal-attic occurrence sequence differs")

    union_clauses: list[ThresholdNoGoodClause] = []
    clause_indices: dict[bytes, int] = {}
    chunk_indices: list[tuple[int, ...]] = []
    for chunk in normalized_chunks:
        local_indices: list[int] = []
        for clause in chunk.clauses:
            key = clause.serialized
            index = clause_indices.get(key)
            if index is None:
                index = len(union_clauses)
                clause_indices[key] = index
                union_clauses.append(clause)
            local_indices.append(index)
        chunk_indices.append(tuple(local_indices))
    if not union_clauses:
        raise CausalAtticError("causal-attic unique clause union is empty")
    occurrence_indices: list[int] = []
    for occurrence in normalized_occurrences:
        index = clause_indices.get(occurrence.clause.serialized)
        if index is None:
            raise CausalAtticError("causal-attic occurrence lacks an immutable chunk")
        occurrence_indices.append(index)
    if set(occurrence_indices) != set(range(len(union_clauses))):
        raise CausalAtticError("causal-attic chunk lacks a witness occurrence")

    try:
        union_vault = ThresholdNoGoodVault(
            identity,
            observed_variables,
            tuple(union_clauses),
        )
    except ThresholdNoGoodVaultError as exc:
        raise CausalAtticError("causal-attic union construction differs") from exc
    relations = strict_subsumption_relations(union_vault.clauses)
    coverage_masks, undominated = _coverage_masks(union_vault.clause_count, relations)
    occurrence_counts: Counter[int] = Counter(occurrence_indices)

    def weighted_coverage(mask: int) -> int:
        total = 0
        while mask:
            bit = mask & -mask
            total += occurrence_counts[bit.bit_length() - 1]
            mask -= bit
        return total

    selected: list[int] = []
    remaining = set(undominated)
    covered = 0
    selected_literals = 0
    selected_bytes = THRESHOLD_NO_GOOD_VAULT_HEADER_BYTES
    while remaining and len(selected) < normalized_limit:
        feasible = {
            index
            for index in remaining
            if selected_literals + union_vault.clauses[index].literal_count
            <= O1C66_VAULT_CAPS.maximum_literals
            and selected_bytes + 4 + 4 * union_vault.clauses[index].literal_count
            <= O1C66_VAULT_CAPS.maximum_serialized_bytes
        }
        if not feasible:
            break

        def selection_key(index: int) -> tuple[int, int, int, str]:
            marginal = coverage_masks[index] & ~covered
            clause = union_vault.clauses[index]
            return (
                -marginal.bit_count(),
                -weighted_coverage(marginal),
                clause.literal_count,
                clause.sha256,
            )

        best = min(feasible, key=selection_key)
        selected.append(best)
        remaining.remove(best)
        clause = union_vault.clauses[best]
        selected_literals += clause.literal_count
        selected_bytes += 4 + 4 * clause.literal_count
        covered |= coverage_masks[best]

    selected_indices = tuple(sorted(selected))
    active_clauses = tuple(union_vault.clauses[index] for index in selected_indices)
    try:
        active_projection = ThresholdNoGoodVault(
            identity,
            observed_variables,
            active_clauses,
        )
        validate_threshold_no_good_vault_caps(active_projection, caps=O1C66_VAULT_CAPS)
    except ThresholdNoGoodVaultError as exc:
        raise CausalAtticError("causal-attic active projection differs") from exc

    return CausalAttic(
        chunks=normalized_chunks,
        union_vault=union_vault,
        active_projection=active_projection,
        occurrences=normalized_occurrences,
        chunk_clause_union_indices=tuple(chunk_indices),
        occurrence_union_indices=tuple(occurrence_indices),
        relations=relations,
        undominated_indices=undominated,
        selection_order=tuple(selected),
        selected_union_indices=selected_indices,
        unique_coverage_count=covered.bit_count(),
        occurrence_coverage_count=weighted_coverage(covered),
        active_limit=normalized_limit,
    )


def build_causal_attic(
    retained_vault: ThresholdNoGoodVault,
    *,
    retained_occurrences: Sequence[ClauseOccurrence],
    current_occurrences: Sequence[ClauseOccurrence],
    active_limit: int = 256,
) -> CausalAttic:
    """Build the initial retained/current chunks and delegate reprojection."""

    if not isinstance(retained_vault, ThresholdNoGoodVault):
        raise CausalAtticError("causal-attic retained vault differs")
    normalized_limit = _active_limit(active_limit)
    try:
        validate_threshold_no_good_vault_caps(retained_vault, caps=O1C66_VAULT_CAPS)
    except ThresholdNoGoodVaultError as exc:
        raise CausalAtticError("causal-attic retained vault cap differs") from exc
    retained_events = tuple(retained_occurrences)
    current_events = tuple(current_occurrences)
    if (
        len(retained_events) != retained_vault.clause_count
        or any(event.classification != "new" for event in retained_events)
        or tuple(event.clause for event in retained_events) != retained_vault.clauses
    ):
        raise CausalAtticError("causal-attic retained witness lineage differs")
    observed = set(retained_vault.observed_variables)
    if any(
        abs(literal) not in observed
        for event in retained_events + current_events
        for literal in event.clause.literals
    ):
        raise CausalAtticError("causal-attic occurrence scope differs")

    retained_keys = {clause.serialized for clause in retained_vault.clauses}
    current_new_keys: set[bytes] = set()
    novel_clauses: list[ThresholdNoGoodClause] = []
    for event in current_events:
        key = event.clause.serialized
        if key in retained_keys:
            expected_classification = "input_duplicate"
        elif key in current_new_keys:
            expected_classification = "current_duplicate"
        else:
            expected_classification = "new"
            current_new_keys.add(key)
            novel_clauses.append(event.clause)
        if event.classification != expected_classification:
            raise CausalAtticError("causal-attic current classification differs")
    try:
        novel_chunk = ThresholdNoGoodVault(
            retained_vault.identity,
            retained_vault.observed_variables,
            tuple(novel_clauses),
        )
        validate_threshold_no_good_vault_caps(novel_chunk, caps=O1C66_VAULT_CAPS)
    except ThresholdNoGoodVaultError as exc:
        raise CausalAtticError("causal-attic chunk construction differs") from exc

    return reproject_causal_attic(
        (retained_vault, novel_chunk),
        retained_events + current_events,
        active_limit=normalized_limit,
    )


__all__ = [
    "ACTIVE_PROJECTION_SCHEMA",
    "ACTIVE_SELECTION_RULE",
    "CAUSAL_ATTIC_OCCURRENCE_SCHEMA",
    "CAUSAL_ATTIC_RELATION_SCHEMA",
    "CAUSAL_ATTIC_SCHEMA",
    "CausalAttic",
    "CausalAtticError",
    "ClauseOccurrence",
    "ParsedVaultTelemetry",
    "SubsumptionRelation",
    "build_causal_attic",
    "canonical_json_bytes",
    "parse_self_scoping_vault",
    "parse_vault_telemetry",
    "reproject_causal_attic",
    "sha256_bytes",
    "strict_subsumption_relations",
]
