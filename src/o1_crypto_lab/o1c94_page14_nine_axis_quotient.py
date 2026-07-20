"""Deterministic, zero-call quotient of O1C-0092's Page-14 clauses.

The quotient is a representation result only.  It reads the immutable O1C-0092
vault telemetry, validates every canonical clause and witness identity, factors
the 261 rows into a shared signed core, five explicit prefix residuals, and a
256-row nine-axis tail, and then reconstructs the original emission ledger.
It never starts a solver or preflight and never reads a target, truth key,
reveal, refit, model, MPS, or GPU artifact.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import stat
import struct
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence, cast

from .causal_attic_v1 import (
    CausalAtticError,
    ClauseOccurrence,
    canonical_json_bytes,
    parse_vault_telemetry,
)
from .threshold_no_good_vault_v1 import (
    ThresholdNoGoodClause,
    ThresholdNoGoodVaultError,
)


ATTEMPT_ID = "O1C-0094"
CONFIG_SCHEMA = "o1-256-o1c94-page14-nine-axis-quotient-config-v1"
QUOTIENT_SCHEMA = "o1-256-o1c94-page14-nine-axis-quotient-v1"
RESULT_SCHEMA = "o1-256-o1c94-page14-nine-axis-quotient-result-v1"

CONFIG_RELATIVE = Path("configs/o1c94_page14_nine_axis_quotient_v1.json")
RESULT_RELATIVE = Path(
    "research/O1C0094_PAGE14_NINE_AXIS_QUOTIENT_RESULT_20260720.json"
)
INTERPRETATION_RELATIVE = Path(
    "research/O1C0094_PAGE14_NINE_AXIS_QUOTIENT_INTERPRETATION_20260720.md"
)
SOURCE_CAPSULE_RELATIVE = Path(
    "runs/20260720_205659_306771_O1C-0092_apple8-parent-centered-continuation-v1"
)
SOURCE_VAULT_RELATIVE = SOURCE_CAPSULE_RELATIVE / "episodes/00/vault.json"
SOURCE_MANIFEST_RELATIVE = SOURCE_CAPSULE_RELATIVE / "artifacts.sha256"
SOURCE_RESULT_RELATIVE = SOURCE_CAPSULE_RELATIVE / "result.json"

SOURCE_PATHS: Mapping[str, str] = {
    "module": "src/o1_crypto_lab/o1c94_page14_nine_axis_quotient.py",
    "tests": "tests/test_o1c94_page14_nine_axis_quotient.py",
}

SOURCE_VAULT_BYTES = 5_265_088
SOURCE_VAULT_SHA256 = "8cb5123d0867923a778ef08d64f73b71f51f8c41003b913da183f21e91dbd61b"
SOURCE_MANIFEST_BYTES = 2_768
SOURCE_MANIFEST_SHA256 = (
    "b91e23706c1a019c30f4de016f4f78e8da3494416e9a5fc69043b5c2fb890eae"
)
SOURCE_RESULT_BYTES = 11_768
SOURCE_RESULT_SHA256 = (
    "04c4d7673898dd35d9c613ed0f1676dd8f3a60f01b04167b02660b93adfcc16c"
)
SOURCE_VAULT_SCHEMA = "o1-256-cadical-score-threshold-no-good-vault-telemetry-v1"
SOURCE_CLAUSE_COUNT = 261
SOURCE_LITERAL_COUNT = 756_414
SOURCE_AGGREGATE_SHA256 = (
    "dad3883312e769efb4a650557a8cd0fdf0e53e0ca6ecbc840fb335c76730fce0"
)

SOURCE_CNF_SHA256 = "e1fc0ac93724004291c960ea06e5584c598853b9ea8370552be09f29e73e2432"
SOURCE_POTENTIAL_SHA256 = (
    "8c6101b49c7050caf895bd9c496c05bcea9f43a2b27f378d7306be38b00d5390"
)
SOURCE_GROUPING_SHA256 = (
    "3da85bae132d829252a68f0e3fd99220ea7d1ef365042806af810ff02f75f636"
)
SOURCE_OBSERVED_VARIABLES_SHA256 = (
    "86b80faf204a81015a16e14ce695f3becdb6b06967b5a987c1537d03711e9fc5"
)
SOURCE_BOUND_RULE_SHA256 = (
    "0683778d9c5a447f415f5de962e2f92f76263d96187339e1af5e4a7495da48d2"
)
SOURCE_THRESHOLD_F64LE_HEX = "2ef540115d362d40"

PREFIX_ROW_COUNT = 5
TAIL_FIRST_INDEX = 5
TAIL_ROW_COUNT = 256
TAIL_LITERAL_COUNT = 2_898
AXES = (15, 18, 23, 28, 100, 118, 181, 216, 238)
EIGHT_AXES = AXES[:-1]
SHARED_CORE_COUNT = 2_709
SHARED_CORE_SHA256 = "80778216ca840ef50729fe16c146c235841e16e70bd86b87ba37edd674e16b19"
TAIL_CORE_COUNT = 2_780
TAIL_CORE_SHA256 = "cf45b2d8579e49592590346fed334da66588e889115abadbff1f1ddafa6e9380"
SWITCHING_VARIABLE_COUNT = 118
COPY_COMPLEMENT_MAP_BYTES = 1_574
COPY_COMPLEMENT_MAP_SHA256 = (
    "c3103ef67f4edf1cb93f7443e1c3f7866bdb30af53c7866ca9376be396618185"
)
FULL_KEY_PROJECTION_SET_SHA256 = (
    "7c3d76baea7bc37271955b6c55da8960db9d1cca215f62dabf5f2662bdd5d255"
)
EIGHT_AXIS_PROJECTION_SET_SHA256 = (
    "4a636f3bd41a00b65530dfeddafdab63df678da776e6978c621fcc1369b1d396"
)
TAIL_NINE_AXIS_PROJECTION_SET_SHA256 = (
    "77b966b9ccc19bfdc05a318556b393818f9d9728af3ad2e1b9965bd800107439"
)

PREFIX_LITERAL_ENTRIES = 14_526
TAIL_RESIDUAL_ENTRIES = TAIL_ROW_COUNT * SWITCHING_VARIABLE_COUNT
FACTORED_LITERAL_ENTRIES = 47_514
SAVED_LITERAL_ENTRIES = SOURCE_LITERAL_COUNT - FACTORED_LITERAL_ENTRIES
COMPRESSION_RATIO = SOURCE_LITERAL_COUNT / FACTORED_LITERAL_ENTRIES
REDUCTION_PERCENT = 100.0 * SAVED_LITERAL_ENTRIES / SOURCE_LITERAL_COUNT

SUBSUMER_INDEX = 3
SUBSUMED_INDEX = 2
SUBSUMPTION_EXTRA_LITERALS = (
    94_539,
    -95_733,
    -126_413,
    -126_415,
    126_417,
    -127_605,
    -127_606,
    -127_607,
    -127_608,
    -190_157,
    -190_159,
    190_161,
    -191_350,
    -191_351,
    -191_352,
    253_899,
    -255_093,
)

# Packed-state accounting describes a purpose-built decoder, not CPython.
PACKED_LITERAL_BYTES = 4
PACKED_PREFIX_OFFSET_COUNT = PREFIX_ROW_COUNT + 1
PACKED_PREFIX_OFFSET_BYTES = 4
PACKED_MAP_TAG_BYTES = 1
PACKED_CODEWORD_BYTES = (TAIL_ROW_COUNT * len(AXES) + 7) // 8
PACKED_WITNESS_BYTES = SOURCE_CLAUSE_COUNT * 8
MAXIMUM_RECONSTRUCTION_ROW_LITERALS = 2_933


class O1C94QuotientError(ValueError):
    """A seal, quotient invariant, or reconstruction identity differs."""


@dataclass(frozen=True)
class ValidatedConfig:
    """Canonical configuration plus its exact byte identity."""

    document: Mapping[str, object]
    path: Path
    serialized_bytes: int
    sha256: str
    source_sha256: Mapping[str, str]


@dataclass(frozen=True)
class SealedSource:
    """Validated O1C-0092 telemetry and its canonical occurrences."""

    occurrences: tuple[ClauseOccurrence, ...]
    telemetry: Mapping[str, object]


@dataclass(frozen=True)
class PrefixResidual:
    """One prefix row minus the family-wide shared signed core."""

    index: int
    residual: tuple[int, ...]
    witness_score_f64le_hex: str


@dataclass(frozen=True)
class AxisCopy:
    """Decode one switching variable from one axis and optional inversion."""

    variable: int
    inversion_bit: int
    axis_mask: int

    @property
    def axis_position(self) -> int:
        return self.axis_mask.bit_length() - 1

    def row(self) -> list[int]:
        return [self.variable, self.inversion_bit, self.axis_mask]


@dataclass(frozen=True)
class NineAxisQuotient:
    """Complete lossless data needed to reconstruct all 261 occurrences."""

    shared_signed_core: tuple[int, ...]
    prefix_rows: tuple[PrefixResidual, ...]
    tail_fixed_residual: tuple[int, ...]
    copy_complement_map: tuple[AxisCopy, ...]
    tail_codewords: tuple[int, ...]
    tail_witness_score_f64le_hex: tuple[str, ...]


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise O1C94QuotientError(f"{field} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise O1C94QuotientError(f"{field} differs")
    return cast(Sequence[object], value)


def _integer(value: object, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise O1C94QuotientError(f"{field} differs")
    return value


def _regular_file(path: Path, field: str) -> Path:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise O1C94QuotientError(f"{field} is unreadable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise O1C94QuotientError(f"{field} is not a sealed regular file")
    return resolved


def _read_exact_file(
    path: Path,
    field: str,
    *,
    expected_bytes: int | None = None,
    expected_sha256: str | None = None,
) -> bytes:
    regular = _regular_file(path, field)
    try:
        payload = regular.read_bytes()
    except OSError as exc:
        raise O1C94QuotientError(f"{field} is unreadable") from exc
    if expected_bytes is not None and len(payload) != expected_bytes:
        raise O1C94QuotientError(f"{field} byte count differs")
    if expected_sha256 is not None and _sha256(payload) != expected_sha256:
        raise O1C94QuotientError(f"{field} digest differs")
    return payload


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise O1C94QuotientError("JSON contains a duplicate key")
        result[key] = value
    return result


def _canonical_document(payload: bytes, field: str) -> Mapping[str, object]:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                O1C94QuotientError(f"{field} contains {token}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C94QuotientError(f"{field} is not JSON") from exc
    document = _mapping(value, field)
    if canonical_json_bytes(document) != payload:
        raise O1C94QuotientError(f"{field} is not canonical JSON")
    return document


def _relative_path(root: Path, value: object, field: str) -> Path:
    if not isinstance(value, str):
        raise O1C94QuotientError(f"{field} differs")
    relative = Path(value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise O1C94QuotientError(f"{field} escapes the lab")
    candidate = root / relative
    resolved = _regular_file(candidate, field)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise O1C94QuotientError(f"{field} escapes the lab") from exc
    return resolved


def load_config(
    path: str | Path = CONFIG_RELATIVE,
    *,
    root: str | Path | None = None,
    verify_source_seals: bool = True,
) -> ValidatedConfig:
    """Load the canonical zero-call contract and optionally verify source seals."""

    base = (lab_root() if root is None else Path(root)).resolve(strict=True)
    candidate = Path(path)
    config_path = candidate if candidate.is_absolute() else base / candidate
    config_path = _regular_file(config_path, "O1C94 config")
    try:
        config_path.relative_to(base)
    except ValueError as exc:
        raise O1C94QuotientError("O1C94 config escapes the lab") from exc
    payload = _read_exact_file(config_path, "O1C94 config")
    document = _canonical_document(payload, "O1C94 config")
    if set(document) != {
        "attempt_id",
        "claim_boundary",
        "input",
        "next_action",
        "outputs",
        "quotient_contract",
        "schema",
        "scope",
        "source",
    }:
        raise O1C94QuotientError("config fields differ")
    if (
        document.get("schema") != CONFIG_SCHEMA
        or document.get("attempt_id") != ATTEMPT_ID
    ):
        raise O1C94QuotientError("config identity differs")

    input_row = _mapping(document["input"], "config input")
    expected_input: Mapping[str, object] = {
        "capsule_manifest": SOURCE_MANIFEST_RELATIVE.as_posix(),
        "capsule_manifest_bytes": SOURCE_MANIFEST_BYTES,
        "capsule_manifest_sha256": SOURCE_MANIFEST_SHA256,
        "capsule_result": SOURCE_RESULT_RELATIVE.as_posix(),
        "capsule_result_bytes": SOURCE_RESULT_BYTES,
        "capsule_result_sha256": SOURCE_RESULT_SHA256,
        "fully_emitted_aggregate_sha256": SOURCE_AGGREGATE_SHA256,
        "fully_emitted_clause_count": SOURCE_CLAUSE_COUNT,
        "fully_emitted_literal_count": SOURCE_LITERAL_COUNT,
        "path": SOURCE_VAULT_RELATIVE.as_posix(),
        "schema": SOURCE_VAULT_SCHEMA,
        "serialized_bytes": SOURCE_VAULT_BYTES,
        "sha256": SOURCE_VAULT_SHA256,
    }
    if input_row != expected_input:
        raise O1C94QuotientError("config input seal differs")

    contract = _mapping(document["quotient_contract"], "config quotient contract")
    expected_contract: Mapping[str, object] = {
        "axis_order": list(AXES),
        "copy_complement_map_bytes": COPY_COMPLEMENT_MAP_BYTES,
        "copy_complement_map_sha256": COPY_COMPLEMENT_MAP_SHA256,
        "factored_literal_entries_before_bit_packing": FACTORED_LITERAL_ENTRIES,
        "prefix_row_count": PREFIX_ROW_COUNT,
        "raw_literal_entries": SOURCE_LITERAL_COUNT,
        "shared_signed_core_count": SHARED_CORE_COUNT,
        "shared_signed_core_sha256": SHARED_CORE_SHA256,
        "switching_variable_count": SWITCHING_VARIABLE_COUNT,
        "tail_first_index": TAIL_FIRST_INDEX,
        "tail_literal_count": TAIL_LITERAL_COUNT,
        "tail_row_count": TAIL_ROW_COUNT,
        "tail_signed_core_count": TAIL_CORE_COUNT,
        "tail_signed_core_sha256": TAIL_CORE_SHA256,
    }
    if contract != expected_contract:
        raise O1C94QuotientError("config quotient contract differs")

    scope = _mapping(document["scope"], "config scope")
    expected_scope: Mapping[str, object] = {
        "fresh_targets": 0,
        "gpu_calls": 0,
        "mps_calls": 0,
        "native_solver_calls": 0,
        "preflight_calls": 0,
        "public_verification_calls": 0,
        "refits": 0,
        "reveal_calls": 0,
        "science_calls": 0,
        "target_bytes_read": False,
        "truth_key_bytes_read": False,
    }
    if scope != expected_scope:
        raise O1C94QuotientError("config zero-call scope differs")
    if document["claim_boundary"] != (
        "compression-only-until-bound-cnf-copy-complement-equivalences-are-proved"
    ):
        raise O1C94QuotientError("config claim boundary differs")
    if document["outputs"] != {
        "interpretation": INTERPRETATION_RELATIVE.as_posix(),
        "result": RESULT_RELATIVE.as_posix(),
    }:
        raise O1C94QuotientError("config outputs differ")
    if not isinstance(document["next_action"], str) or not document["next_action"]:
        raise O1C94QuotientError("config next action differs")

    source = _mapping(document["source"], "config source")
    if set(source) != {"expected_sha256", "paths"}:
        raise O1C94QuotientError("config source fields differ")
    paths = _mapping(source["paths"], "config source paths")
    expected_digests = _mapping(source["expected_sha256"], "config source seals")
    if dict(paths) != dict(SOURCE_PATHS) or set(expected_digests) != set(SOURCE_PATHS):
        raise O1C94QuotientError("config source inventory differs")
    normalized_digests: dict[str, str] = {}
    for name, relative in SOURCE_PATHS.items():
        expected = expected_digests[name]
        if not _is_sha256(expected):
            raise O1C94QuotientError(f"config {name} source seal differs")
        normalized_digests[name] = cast(str, expected)
        if verify_source_seals:
            source_path = _relative_path(base, relative, f"{name} source")
            if _sha256(source_path.read_bytes()) != expected:
                raise O1C94QuotientError(f"{name} source digest differs")

    return ValidatedConfig(
        document=document,
        path=config_path,
        serialized_bytes=len(payload),
        sha256=_sha256(payload),
        source_sha256=normalized_digests,
    )


def _validate_source_capsule(base: Path) -> None:
    manifest = _read_exact_file(
        base / SOURCE_MANIFEST_RELATIVE,
        "O1C92 capsule manifest",
        expected_bytes=SOURCE_MANIFEST_BYTES,
        expected_sha256=SOURCE_MANIFEST_SHA256,
    )
    result_payload = _read_exact_file(
        base / SOURCE_RESULT_RELATIVE,
        "O1C92 capsule result",
        expected_bytes=SOURCE_RESULT_BYTES,
        expected_sha256=SOURCE_RESULT_SHA256,
    )
    result = _canonical_document(result_payload, "O1C92 capsule result")
    if (
        result.get("attempt_id") != "O1C-0092"
        or result.get("capsule") != SOURCE_CAPSULE_RELATIVE.as_posix()
        or result.get("schema")
        != "o1-256-apple8-parent-centered-continuation-result-v1"
    ):
        raise O1C94QuotientError("O1C92 capsule result binding differs")

    rows: dict[str, str] = {}
    try:
        text = manifest.decode("ascii")
    except UnicodeError as exc:
        raise O1C94QuotientError("O1C92 capsule manifest is not ASCII") from exc
    for line in text.splitlines():
        parts = line.split("  ", 1)
        if len(parts) != 2 or not _is_sha256(parts[0]) or parts[1] in rows:
            raise O1C94QuotientError("O1C92 capsule manifest differs")
        rows[parts[1]] = parts[0]
    if len(rows) != 29:
        raise O1C94QuotientError("O1C92 capsule manifest inventory differs")
    if (
        rows.get("episodes/00/vault.json") != SOURCE_VAULT_SHA256
        or rows.get("result.json") != SOURCE_RESULT_SHA256
    ):
        raise O1C94QuotientError("O1C92 capsule manifest binding differs")


def load_sealed_source(root: str | Path | None = None) -> SealedSource:
    """Load and fully validate the only scientific input."""

    base = (lab_root() if root is None else Path(root)).resolve(strict=True)
    _validate_source_capsule(base)
    payload = _read_exact_file(
        base / SOURCE_VAULT_RELATIVE,
        "O1C92 sealed vault telemetry",
        expected_bytes=SOURCE_VAULT_BYTES,
        expected_sha256=SOURCE_VAULT_SHA256,
    )
    telemetry = _canonical_document(payload, "O1C92 sealed vault telemetry")
    try:
        parsed = parse_vault_telemetry(
            payload, stream_id="o1c92-page14", expected_sha256=SOURCE_VAULT_SHA256
        )
    except (CausalAtticError, ThresholdNoGoodVaultError) as exc:
        raise O1C94QuotientError("O1C92 sealed telemetry differs") from exc
    identity = parsed.input_identity
    if (
        telemetry.get("schema") != SOURCE_VAULT_SCHEMA
        or len(parsed.occurrences) != SOURCE_CLAUSE_COUNT
        or sum(row.clause.literal_count for row in parsed.occurrences)
        != SOURCE_LITERAL_COUNT
        or telemetry.get("fully_emitted_aggregate_sha256") != SOURCE_AGGREGATE_SHA256
        or identity.cnf_sha256 != SOURCE_CNF_SHA256
        or identity.potential_sha256 != SOURCE_POTENTIAL_SHA256
        or identity.grouping_sha256 != SOURCE_GROUPING_SHA256
        or identity.observed_variables_sha256 != SOURCE_OBSERVED_VARIABLES_SHA256
        or identity.bound_rule_sha256 != SOURCE_BOUND_RULE_SHA256
        or identity.threshold_f64le_hex != SOURCE_THRESHOLD_F64LE_HEX
        or any(
            row.source_index != index
            or row.classification != "new"
            or row.source != "trail_upper_bound"
            for index, row in enumerate(parsed.occurrences)
        )
        or len({row.clause_sha256 for row in parsed.occurrences}) != SOURCE_CLAUSE_COUNT
        or len({row.witness_sha256 for row in parsed.occurrences})
        != SOURCE_CLAUSE_COUNT
        or len({row.witness_score_f64le_hex for row in parsed.occurrences})
        != SOURCE_CLAUSE_COUNT
    ):
        raise O1C94QuotientError("O1C92 sealed population differs")
    aggregate = _sha256(b"".join(row.clause.serialized for row in parsed.occurrences))
    if aggregate != SOURCE_AGGREGATE_SHA256:
        raise O1C94QuotientError("O1C92 canonical clause aggregate differs")
    return SealedSource(occurrences=parsed.occurrences, telemetry=telemetry)


def _signed_intersection(rows: Sequence[Sequence[int]]) -> tuple[int, ...]:
    if not rows:
        raise O1C94QuotientError("signed intersection population is empty")
    common = set(rows[0])
    for row in rows[1:]:
        common.intersection_update(row)
    return tuple(sorted(common, key=abs))


def _literal_block(literals: Sequence[int]) -> dict[str, object]:
    normalized = ThresholdNoGoodClause(tuple(literals)).literals
    payload = b"".join(struct.pack("<i", literal) for literal in normalized)
    return {
        "count": len(normalized),
        "i32le_base64": base64.b64encode(payload).decode("ascii"),
    }


def _decode_literal_block(
    value: object, field: str, *, allow_empty: bool = False
) -> tuple[int, ...]:
    row = _mapping(value, field)
    if set(row) != {"count", "i32le_base64"}:
        raise O1C94QuotientError(f"{field} fields differ")
    count = _integer(row["count"], f"{field} count")
    encoded = row["i32le_base64"]
    if not isinstance(encoded, str) or not encoded.isascii():
        raise O1C94QuotientError(f"{field} encoding differs")
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise O1C94QuotientError(f"{field} encoding differs") from exc
    if len(payload) != count * PACKED_LITERAL_BYTES:
        raise O1C94QuotientError(f"{field} byte count differs")
    literals = tuple(
        struct.unpack_from("<i", payload, offset)[0]
        for offset in range(0, len(payload), PACKED_LITERAL_BYTES)
    )
    if not literals and allow_empty:
        return ()
    try:
        return ThresholdNoGoodClause(literals).literals
    except ThresholdNoGoodVaultError as exc:
        raise O1C94QuotientError(f"{field} literals differ") from exc


def _merge_literals(*parts: Sequence[int]) -> tuple[int, ...]:
    literals = tuple(sorted((literal for part in parts for literal in part), key=abs))
    try:
        return ThresholdNoGoodClause(literals).literals
    except ThresholdNoGoodVaultError as exc:
        raise O1C94QuotientError("quotient literal merge differs") from exc


def _positive_bit(row: Sequence[int], variable: int) -> int:
    for literal in row:
        if abs(literal) == variable:
            return int(literal > 0)
    raise O1C94QuotientError(f"axis variable {variable} is absent")


def _codeword(row: Sequence[int]) -> int:
    value = 0
    for position, variable in enumerate(AXES):
        value |= _positive_bit(row, variable) << position
    return value


def _codeword_text(value: int) -> str:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < (1 << len(AXES))
    ):
        raise O1C94QuotientError("nine-bit codeword differs")
    return "".join(
        "1" if value & (1 << position) else "0" for position in range(len(AXES))
    )


def _parse_codeword(value: object, field: str) -> int:
    if (
        not isinstance(value, str)
        or len(value) != len(AXES)
        or any(bit not in "01" for bit in value)
    ):
        raise O1C94QuotientError(f"{field} differs")
    result = 0
    for position, bit in enumerate(value):
        result |= int(bit) << position
    return result


def build_quotient(occurrences: Sequence[ClauseOccurrence]) -> NineAxisQuotient:
    """Factor a validated 261-row occurrence ledger into the exact quotient."""

    if len(occurrences) != SOURCE_CLAUSE_COUNT:
        raise O1C94QuotientError("quotient source row count differs")
    rows = tuple(row.clause.literals for row in occurrences)
    shared = _signed_intersection(rows)
    if (
        len(shared) != SHARED_CORE_COUNT
        or ThresholdNoGoodClause(shared).sha256 != SHARED_CORE_SHA256
    ):
        raise O1C94QuotientError("shared signed core differs")
    shared_set = set(shared)

    prefix = tuple(
        PrefixResidual(
            index=index,
            residual=tuple(
                literal for literal in rows[index] if literal not in shared_set
            ),
            witness_score_f64le_hex=occurrences[index].witness_score_f64le_hex,
        )
        for index in range(PREFIX_ROW_COUNT)
    )
    if sum(len(row.residual) for row in prefix) != 981:
        raise O1C94QuotientError("prefix residual population differs")

    tail_rows = rows[TAIL_FIRST_INDEX:]
    supports = tuple(tuple(abs(literal) for literal in row) for row in tail_rows)
    if (
        len(tail_rows) != TAIL_ROW_COUNT
        or any(len(row) != TAIL_LITERAL_COUNT for row in tail_rows)
        or any(support != supports[0] for support in supports[1:])
    ):
        raise O1C94QuotientError("equal-support tail differs")
    tail_core = _signed_intersection(tail_rows)
    if (
        len(tail_core) != TAIL_CORE_COUNT
        or ThresholdNoGoodClause(tail_core).sha256 != TAIL_CORE_SHA256
    ):
        raise O1C94QuotientError("tail signed core differs")
    tail_fixed_residual = tuple(
        literal for literal in tail_core if literal not in shared_set
    )
    if len(tail_fixed_residual) != TAIL_CORE_COUNT - SHARED_CORE_COUNT:
        raise O1C94QuotientError("tail fixed residual differs")

    tail_core_variables = {abs(literal) for literal in tail_core}
    switching_variables = tuple(
        variable for variable in supports[0] if variable not in tail_core_variables
    )
    if len(switching_variables) != SWITCHING_VARIABLE_COUNT:
        raise O1C94QuotientError("tail switching-variable population differs")
    patterns = {
        variable: tuple(_positive_bit(row, variable) for row in tail_rows)
        for variable in switching_variables
    }
    axis_patterns = {axis: patterns[axis] for axis in AXES}
    mapping: list[AxisCopy] = []
    for variable in switching_variables:
        pattern = patterns[variable]
        matches: list[tuple[int, int]] = []
        for position, axis in enumerate(AXES):
            axis_pattern = axis_patterns[axis]
            if pattern == axis_pattern:
                matches.append((position, 0))
            if all(
                left != right for left, right in zip(pattern, axis_pattern, strict=True)
            ):
                matches.append((position, 1))
        if len(matches) != 1:
            raise O1C94QuotientError("copy/complement decoder is not unique")
        position, inversion = matches[0]
        mapping.append(AxisCopy(variable, inversion, 1 << position))
    mapping_tuple = tuple(mapping)
    map_payload = canonical_json_bytes([row.row() for row in mapping_tuple])
    if (
        len(map_payload) != COPY_COMPLEMENT_MAP_BYTES
        or _sha256(map_payload) != COPY_COMPLEMENT_MAP_SHA256
    ):
        raise O1C94QuotientError("copy/complement map seal differs")

    quotient = NineAxisQuotient(
        shared_signed_core=shared,
        prefix_rows=prefix,
        tail_fixed_residual=tail_fixed_residual,
        copy_complement_map=mapping_tuple,
        tail_codewords=tuple(_codeword(row) for row in tail_rows),
        tail_witness_score_f64le_hex=tuple(
            row.witness_score_f64le_hex for row in occurrences[TAIL_FIRST_INDEX:]
        ),
    )
    validate_quotient_structure(quotient)
    return quotient


def _validate_witness_hex(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 16:
        raise O1C94QuotientError(f"{field} differs")
    try:
        score = struct.unpack("<d", bytes.fromhex(value))[0]
    except (ValueError, struct.error) as exc:
        raise O1C94QuotientError(f"{field} differs") from exc
    if not math.isfinite(score) or struct.pack("<d", score).hex() != value:
        raise O1C94QuotientError(f"{field} differs")
    return value


def validate_quotient_structure(quotient: NineAxisQuotient) -> None:
    """Reject malformed or internally inconsistent quotient state."""

    if not isinstance(quotient, NineAxisQuotient):
        raise O1C94QuotientError("quotient type differs")
    if (
        len(quotient.shared_signed_core) != SHARED_CORE_COUNT
        or ThresholdNoGoodClause(quotient.shared_signed_core).sha256
        != SHARED_CORE_SHA256
        or len(quotient.prefix_rows) != PREFIX_ROW_COUNT
        or tuple(row.index for row in quotient.prefix_rows)
        != tuple(range(PREFIX_ROW_COUNT))
        or len(quotient.tail_fixed_residual) != TAIL_CORE_COUNT - SHARED_CORE_COUNT
        or len(quotient.copy_complement_map) != SWITCHING_VARIABLE_COUNT
        or len(quotient.tail_codewords) != TAIL_ROW_COUNT
        or len(quotient.tail_witness_score_f64le_hex) != TAIL_ROW_COUNT
    ):
        raise O1C94QuotientError("quotient dimensions differ")
    for row in quotient.prefix_rows:
        _validate_witness_hex(row.witness_score_f64le_hex, "prefix witness bits")
        _merge_literals(quotient.shared_signed_core, row.residual)
    tail_core = _merge_literals(
        quotient.shared_signed_core, quotient.tail_fixed_residual
    )
    if (
        len(tail_core) != TAIL_CORE_COUNT
        or ThresholdNoGoodClause(tail_core).sha256 != TAIL_CORE_SHA256
    ):
        raise O1C94QuotientError("decoded tail core differs")
    variables: list[int] = []
    map_rows: list[list[int]] = []
    for item in quotient.copy_complement_map:
        if (
            not isinstance(item, AxisCopy)
            or item.variable <= 0
            or item.inversion_bit not in (0, 1)
            or item.axis_mask <= 0
            or item.axis_mask & (item.axis_mask - 1)
            or item.axis_position >= len(AXES)
        ):
            raise O1C94QuotientError("copy/complement map row differs")
        variables.append(item.variable)
        map_rows.append(item.row())
    if variables != sorted(variables) or len(set(variables)) != len(variables):
        raise O1C94QuotientError("copy/complement map order differs")
    if set(variables) & {abs(literal) for literal in tail_core}:
        raise O1C94QuotientError("copy/complement support overlaps tail core")
    map_payload = canonical_json_bytes(map_rows)
    if (
        len(map_payload) != COPY_COMPLEMENT_MAP_BYTES
        or _sha256(map_payload) != COPY_COMPLEMENT_MAP_SHA256
    ):
        raise O1C94QuotientError("copy/complement map seal differs")
    for codeword in quotient.tail_codewords:
        _codeword_text(codeword)
    for value in quotient.tail_witness_score_f64le_hex:
        _validate_witness_hex(value, "tail witness bits")


def quotient_document(quotient: NineAxisQuotient) -> dict[str, object]:
    """Return the canonical, self-contained quotient representation."""

    validate_quotient_structure(quotient)
    tail_core = _merge_literals(
        quotient.shared_signed_core, quotient.tail_fixed_residual
    )
    return {
        "classification": "new",
        "literal_block_encoding": "canonical-signed-i32le-base64",
        "prefix_rows": [
            {
                "index": row.index,
                "residual": _literal_block(row.residual),
                "witness_score_f64le_hex": row.witness_score_f64le_hex,
            }
            for row in quotient.prefix_rows
        ],
        "row_count": SOURCE_CLAUSE_COUNT,
        "schema": QUOTIENT_SCHEMA,
        "shared_signed_core": {
            **_literal_block(quotient.shared_signed_core),
            "clause_sha256": SHARED_CORE_SHA256,
        },
        "tail": {
            "axis_order": list(AXES),
            "codeword_encoding": (
                "nine-characters-in-axis-order;1=positive-axis-literal"
            ),
            "codewords": [_codeword_text(value) for value in quotient.tail_codewords],
            "copy_complement_map": [row.row() for row in quotient.copy_complement_map],
            "copy_complement_map_encoding": (
                "[variable,inversion_bit,one_hot_axis_mask]"
            ),
            "copy_complement_map_sha256": COPY_COMPLEMENT_MAP_SHA256,
            "first_index": TAIL_FIRST_INDEX,
            "fixed_residual": _literal_block(quotient.tail_fixed_residual),
            "literal_count_per_row": TAIL_LITERAL_COUNT,
            "row_count": TAIL_ROW_COUNT,
            "signed_core_count": len(tail_core),
            "signed_core_sha256": ThresholdNoGoodClause(tail_core).sha256,
            "witness_score_f64le_hex": list(quotient.tail_witness_score_f64le_hex),
        },
        "witness_source": "trail_upper_bound",
        "witness_source_code": 1,
    }


def quotient_from_document(value: object) -> NineAxisQuotient:
    """Decode a canonical quotient object, enforcing every structural seal."""

    document = _mapping(value, "quotient")
    if set(document) != {
        "classification",
        "literal_block_encoding",
        "prefix_rows",
        "row_count",
        "schema",
        "shared_signed_core",
        "tail",
        "witness_source",
        "witness_source_code",
    }:
        raise O1C94QuotientError("quotient fields differ")
    if (
        document["schema"] != QUOTIENT_SCHEMA
        or document["classification"] != "new"
        or document["literal_block_encoding"] != "canonical-signed-i32le-base64"
        or document["row_count"] != SOURCE_CLAUSE_COUNT
        or document["witness_source"] != "trail_upper_bound"
        or document["witness_source_code"] != 1
    ):
        raise O1C94QuotientError("quotient identity differs")
    shared_row = _mapping(document["shared_signed_core"], "shared signed core")
    if (
        set(shared_row) != {"clause_sha256", "count", "i32le_base64"}
        or shared_row["clause_sha256"] != SHARED_CORE_SHA256
    ):
        raise O1C94QuotientError("shared signed core metadata differs")
    shared = _decode_literal_block(
        {key: shared_row[key] for key in ("count", "i32le_base64")},
        "shared signed core",
    )

    prefix_values = _sequence(document["prefix_rows"], "prefix rows")
    prefix: list[PrefixResidual] = []
    for expected_index, value_row in enumerate(prefix_values):
        row = _mapping(value_row, "prefix row")
        if (
            set(row) != {"index", "residual", "witness_score_f64le_hex"}
            or row["index"] != expected_index
        ):
            raise O1C94QuotientError("prefix row metadata differs")
        prefix.append(
            PrefixResidual(
                index=expected_index,
                residual=_decode_literal_block(row["residual"], "prefix residual"),
                witness_score_f64le_hex=_validate_witness_hex(
                    row["witness_score_f64le_hex"], "prefix witness bits"
                ),
            )
        )

    tail = _mapping(document["tail"], "quotient tail")
    if set(tail) != {
        "axis_order",
        "codeword_encoding",
        "codewords",
        "copy_complement_map",
        "copy_complement_map_encoding",
        "copy_complement_map_sha256",
        "first_index",
        "fixed_residual",
        "literal_count_per_row",
        "row_count",
        "signed_core_count",
        "signed_core_sha256",
        "witness_score_f64le_hex",
    }:
        raise O1C94QuotientError("quotient tail fields differ")
    if (
        tail["axis_order"] != list(AXES)
        or tail["codeword_encoding"]
        != "nine-characters-in-axis-order;1=positive-axis-literal"
        or tail["copy_complement_map_encoding"]
        != "[variable,inversion_bit,one_hot_axis_mask]"
        or tail["copy_complement_map_sha256"] != COPY_COMPLEMENT_MAP_SHA256
        or tail["first_index"] != TAIL_FIRST_INDEX
        or tail["literal_count_per_row"] != TAIL_LITERAL_COUNT
        or tail["row_count"] != TAIL_ROW_COUNT
        or tail["signed_core_count"] != TAIL_CORE_COUNT
        or tail["signed_core_sha256"] != TAIL_CORE_SHA256
    ):
        raise O1C94QuotientError("quotient tail metadata differs")
    map_values = _sequence(tail["copy_complement_map"], "copy/complement map")
    mapping: list[AxisCopy] = []
    for value_row in map_values:
        map_row = _sequence(value_row, "copy/complement map row")
        if len(map_row) != 3:
            raise O1C94QuotientError("copy/complement map row differs")
        mapping.append(
            AxisCopy(
                variable=_integer(map_row[0], "map variable", minimum=1),
                inversion_bit=_integer(map_row[1], "map inversion"),
                axis_mask=_integer(map_row[2], "map axis mask", minimum=1),
            )
        )
    codeword_values = _sequence(tail["codewords"], "tail codewords")
    witness_values = _sequence(tail["witness_score_f64le_hex"], "tail witness bits")
    quotient = NineAxisQuotient(
        shared_signed_core=shared,
        prefix_rows=tuple(prefix),
        tail_fixed_residual=_decode_literal_block(
            tail["fixed_residual"], "tail fixed residual"
        ),
        copy_complement_map=tuple(mapping),
        tail_codewords=tuple(
            _parse_codeword(value_row, "tail codeword") for value_row in codeword_values
        ),
        tail_witness_score_f64le_hex=tuple(
            _validate_witness_hex(value_row, "tail witness bits")
            for value_row in witness_values
        ),
    )
    validate_quotient_structure(quotient)
    return quotient


def reconstruct_occurrences(
    quotient: NineAxisQuotient,
) -> tuple[ClauseOccurrence, ...]:
    """Reconstruct canonical rows using only the quotient state."""

    validate_quotient_structure(quotient)
    reconstructed: list[ClauseOccurrence] = []
    for row in quotient.prefix_rows:
        clause = ThresholdNoGoodClause(
            _merge_literals(quotient.shared_signed_core, row.residual)
        )
        witness_payload = (
            b"\x01" + bytes.fromhex(row.witness_score_f64le_hex) + clause.serialized
        )
        reconstructed.append(
            ClauseOccurrence(
                stream_id="o1c94-reconstruction",
                source_index=row.index,
                classification="new",
                source="trail_upper_bound",
                witness_score_f64le_hex=row.witness_score_f64le_hex,
                clause=clause,
                clause_sha256=clause.sha256,
                witness_sha256=_sha256(witness_payload),
            )
        )

    tail_core = _merge_literals(
        quotient.shared_signed_core, quotient.tail_fixed_residual
    )
    for tail_offset, (codeword, witness_hex) in enumerate(
        zip(
            quotient.tail_codewords,
            quotient.tail_witness_score_f64le_hex,
            strict=True,
        )
    ):
        switching: list[int] = []
        for decoder in quotient.copy_complement_map:
            bit = int(bool(codeword & decoder.axis_mask))
            positive = bool(bit ^ decoder.inversion_bit)
            switching.append(decoder.variable if positive else -decoder.variable)
        clause = ThresholdNoGoodClause(_merge_literals(tail_core, switching))
        witness_payload = b"\x01" + bytes.fromhex(witness_hex) + clause.serialized
        reconstructed.append(
            ClauseOccurrence(
                stream_id="o1c94-reconstruction",
                source_index=TAIL_FIRST_INDEX + tail_offset,
                classification="new",
                source="trail_upper_bound",
                witness_score_f64le_hex=witness_hex,
                clause=clause,
                clause_sha256=clause.sha256,
                witness_sha256=_sha256(witness_payload),
            )
        )
    return tuple(reconstructed)


def verify_reconstruction_seals(
    reconstructed: Sequence[ClauseOccurrence],
    *,
    source: Sequence[ClauseOccurrence] | None = None,
) -> dict[str, object]:
    """Verify row order, canonical identities, witnesses, and aggregate."""

    if len(reconstructed) != SOURCE_CLAUSE_COUNT:
        raise O1C94QuotientError("reconstructed row count differs")
    if any(row.source_index != index for index, row in enumerate(reconstructed)):
        raise O1C94QuotientError("reconstructed row order differs")
    clauses = tuple(row.clause_sha256 for row in reconstructed)
    witnesses = tuple(row.witness_sha256 for row in reconstructed)
    if (
        len(set(clauses)) != SOURCE_CLAUSE_COUNT
        or len(set(witnesses)) != SOURCE_CLAUSE_COUNT
    ):
        raise O1C94QuotientError("reconstructed identity uniqueness differs")
    literal_count = sum(row.clause.literal_count for row in reconstructed)
    aggregate = _sha256(b"".join(row.clause.serialized for row in reconstructed))
    if literal_count != SOURCE_LITERAL_COUNT or aggregate != SOURCE_AGGREGATE_SHA256:
        raise O1C94QuotientError("reconstructed canonical aggregate differs")
    if source is not None:
        if len(source) != len(reconstructed):
            raise O1C94QuotientError("source/reconstruction row count differs")
        for expected, actual in zip(source, reconstructed, strict=True):
            if (
                expected.source_index != actual.source_index
                or expected.classification != actual.classification
                or expected.source != actual.source
                or expected.witness_score_f64le_hex != actual.witness_score_f64le_hex
                or expected.clause.literals != actual.clause.literals
                or expected.clause_sha256 != actual.clause_sha256
                or expected.witness_sha256 != actual.witness_sha256
            ):
                raise O1C94QuotientError(
                    f"reconstructed row {actual.source_index} differs"
                )
    return {
        "aggregate_matches_sealed_source": True,
        "clause_count": len(reconstructed),
        "clause_identity_ledger_sha256": _sha256(canonical_json_bytes(list(clauses))),
        "distinct_clause_identity_count": len(set(clauses)),
        "distinct_witness_identity_count": len(set(witnesses)),
        "fully_emitted_aggregate_sha256": aggregate,
        "literal_count": literal_count,
        "per_row_clause_identities_match_sealed_source": source is not None,
        "per_row_witness_identities_match_sealed_source": source is not None,
        "row_order_and_multiplicity_preserved": True,
        "witness_identity_ledger_sha256": _sha256(
            canonical_json_bytes(list(witnesses))
        ),
    }


def _projection(row: Sequence[int], axes: Sequence[int]) -> tuple[int, ...]:
    signs = {abs(literal): literal for literal in row}
    try:
        return tuple(signs[axis] for axis in axes)
    except KeyError as exc:
        raise O1C94QuotientError("projection axis is absent") from exc


def _geometry(rows: Sequence[Sequence[int]]) -> dict[str, object]:
    eight_patterns = [
        "".join(str(_positive_bit(row, axis)) for axis in EIGHT_AXES) for row in rows
    ]
    tail_nine_patterns = [
        "".join(str(_positive_bit(row, axis)) for axis in AXES)
        for row in rows[TAIL_FIRST_INDEX:]
    ]
    multiplicities = Counter(eight_patterns)
    histogram = Counter(multiplicities.values())
    full_key_set = sorted(
        {tuple(literal for literal in row if abs(literal) <= 256) for row in rows}
    )
    eight_axis_set = sorted({_projection(row, EIGHT_AXES) for row in rows})
    tail_nine_axis_set = sorted(
        {_projection(row, AXES) for row in rows[TAIL_FIRST_INDEX:]}
    )
    if (
        len(full_key_set) != 259
        or _sha256(canonical_json_bytes([list(row) for row in full_key_set]))
        != FULL_KEY_PROJECTION_SET_SHA256
        or len(eight_axis_set) != 256
        or _sha256(canonical_json_bytes([list(row) for row in eight_axis_set]))
        != EIGHT_AXIS_PROJECTION_SET_SHA256
        or len(tail_nine_axis_set) != 256
        or _sha256(canonical_json_bytes([list(row) for row in tail_nine_axis_set]))
        != TAIL_NINE_AXIS_PROJECTION_SET_SHA256
        or histogram != Counter({1: 253, 2: 2, 4: 1})
    ):
        raise O1C94QuotientError("cube geometry differs")
    tail_eight_set = set(eight_patterns[TAIL_FIRST_INDEX:])
    all_cells = {format(value, "08b") for value in range(256)}
    holes = sorted(all_cells - tail_eight_set)
    if holes != ["00000110", "01000110"]:
        raise O1C94QuotientError("tail cube holes differ")
    duplicate_patterns = {
        pattern: multiplicity
        for pattern, multiplicity in sorted(multiplicities.items())
        if multiplicity > 1
    }
    if duplicate_patterns != {"00000000": 2, "00000110": 4, "10000000": 2}:
        raise O1C94QuotientError("cube multiplicities differ")
    if tail_nine_patterns[254:] != ["000000000", "100000000"]:
        raise O1C94QuotientError("tail marker intrusions differ")
    return {
        "axis_order": list(EIGHT_AXES),
        "base_8_cube_multiplicities": {
            "duplicate_patterns": duplicate_patterns,
            "multiplicity_histogram": {
                str(multiplicity): count
                for multiplicity, count in sorted(histogram.items())
            },
            "unique_cell_count": len(eight_axis_set),
        },
        "full_key_projection": {
            "distinct_count": len(full_key_set),
            "set_sha256": FULL_KEY_PROJECTION_SET_SHA256,
        },
        "tail": {
            "eight_axis_holes": holes,
            "nine_axis_distinct_count": len(tail_nine_axis_set),
            "nine_axis_set_sha256": TAIL_NINE_AXIS_PROJECTION_SET_SHA256,
            "negative_238_intrusions": [
                {
                    "clause_sha256": (
                        "fc5241329354bdf3c4e637a5092ccaa8d450737ad388dfac039bef0b6dda232e"
                    ),
                    "eight_axis_pattern": "00000000",
                    "index": 259,
                },
                {
                    "clause_sha256": (
                        "52fbc38425dd92098a082481c245f8be144c2fa5abdb821448e0b4c7014580d8"
                    ),
                    "eight_axis_pattern": "10000000",
                    "index": 260,
                },
            ],
        },
        "unique_eight_axis_set_sha256": EIGHT_AXIS_PROJECTION_SET_SHA256,
    }


def _subsumption(rows: Sequence[ClauseOccurrence]) -> dict[str, object]:
    signed_sets = tuple(set(row.clause.literals) for row in rows)
    relations: list[tuple[int, int]] = []
    for left in range(len(rows)):
        for right in range(len(rows)):
            if left != right and signed_sets[left] < signed_sets[right]:
                relations.append((left, right))
    if relations != [(SUBSUMER_INDEX, SUBSUMED_INDEX)]:
        raise O1C94QuotientError("proper signed-set subsumption differs")
    extra = tuple(
        literal
        for literal in rows[SUBSUMED_INDEX].clause.literals
        if literal not in signed_sets[SUBSUMER_INDEX]
    )
    if extra != SUBSUMPTION_EXTRA_LITERALS:
        raise O1C94QuotientError("subsumption literal delta differs")
    return {
        "formula_preserving_deletion_available": True,
        "lossless_quotient_retains_subsumed_row": True,
        "proper_relation_count": 1,
        "relation": {
            "additional_literals": list(extra),
            "additional_literal_count": len(extra),
            "subsumed_clause_sha256": rows[SUBSUMED_INDEX].clause_sha256,
            "subsumed_index": SUBSUMED_INDEX,
            "subsumer_clause_sha256": rows[SUBSUMER_INDEX].clause_sha256,
            "subsumer_index": SUBSUMER_INDEX,
        },
    }


def _state_accounting(quotient: NineAxisQuotient) -> dict[str, object]:
    literal_pool_entries = (
        len(quotient.shared_signed_core)
        + sum(len(row.residual) for row in quotient.prefix_rows)
        + len(quotient.tail_fixed_residual)
        + len(quotient.copy_complement_map)
    )
    literal_pool_bytes = literal_pool_entries * PACKED_LITERAL_BYTES
    prefix_offsets_bytes = PACKED_PREFIX_OFFSET_COUNT * PACKED_PREFIX_OFFSET_BYTES
    map_tag_bytes = len(quotient.copy_complement_map) * PACKED_MAP_TAG_BYTES
    retained_bytes = (
        literal_pool_bytes
        + prefix_offsets_bytes
        + map_tag_bytes
        + PACKED_CODEWORD_BYTES
        + PACKED_WITNESS_BYTES
    )
    row_scratch_bytes = MAXIMUM_RECONSTRUCTION_ROW_LITERALS * PACKED_LITERAL_BYTES
    return {
        "construction_source_dom_excluded": True,
        "decoder_asymptotic_live_state": "O(quotient-state + maximum-row-width)",
        "literal_pool": {
            "entries": literal_pool_entries,
            "packed_i32le_bytes": literal_pool_bytes,
        },
        "maximum_live_decoder_bytes": retained_bytes + row_scratch_bytes,
        "maximum_row_scratch_bytes": row_scratch_bytes,
        "maximum_row_scratch_literal_entries": MAXIMUM_RECONSTRUCTION_ROW_LITERALS,
        "packed_codeword_bytes": PACKED_CODEWORD_BYTES,
        "packed_map_tag_bytes": map_tag_bytes,
        "packed_prefix_offset_bytes": prefix_offsets_bytes,
        "packed_retained_quotient_bytes": retained_bytes,
        "packed_witness_score_bytes": PACKED_WITNESS_BYTES,
        "raw_flat_clause_materialization_required": False,
        "streaming_reconstruction": True,
    }


def generate_result(
    root: str | Path | None = None,
    *,
    config_path: str | Path = CONFIG_RELATIVE,
    verify_source_seals: bool = True,
) -> dict[str, object]:
    """Generate the deterministic target/truth-free O1C-0094 result."""

    base = (lab_root() if root is None else Path(root)).resolve(strict=True)
    config = load_config(
        config_path, root=base, verify_source_seals=verify_source_seals
    )
    source = load_sealed_source(base)
    quotient = build_quotient(source.occurrences)
    quotient_value = quotient_document(quotient)
    quotient_payload = canonical_json_bytes(quotient_value)
    decoded = quotient_from_document(quotient_value)
    reconstructed = reconstruct_occurrences(decoded)
    round_trip = verify_reconstruction_seals(reconstructed, source=source.occurrences)
    rows = tuple(row.clause.literals for row in source.occurrences)
    tail_core = _merge_literals(
        quotient.shared_signed_core, quotient.tail_fixed_residual
    )
    storage = {
        "conservative_before_bit_packing": {
            "factored_literal_entries": FACTORED_LITERAL_ENTRIES,
            "five_prefix_rows": PREFIX_LITERAL_ENTRIES,
            "one_tail_signed_core": TAIL_CORE_COUNT,
            "raw_literal_entries": SOURCE_LITERAL_COUNT,
            "reduction_percent": REDUCTION_PERCENT,
            "saved_literal_entries": SAVED_LITERAL_ENTRIES,
            "tail_residuals": TAIL_RESIDUAL_ENTRIES,
            "times_smaller": COMPRESSION_RATIO,
        },
        "serialized_quotient_json": {
            "comparison_to_source_json_claimed": False,
            "reason": (
                "canonical quotient JSON includes audit metadata and base64 overhead; "
                "the exact literal-entry ratio is the format-independent claim"
            ),
            "serialized_bytes": len(quotient_payload),
            "sha256": _sha256(quotient_payload),
        },
    }
    result: dict[str, object] = {
        "attempt_id": ATTEMPT_ID,
        "claim_boundary": {
            "attacker_valid_domain_reduction": 0,
            "cnf_copy_complement_equivalences_proved": False,
            "compression_only": True,
            "entropy_gain_bits": 0.0,
            "key_bit_claims": 0,
            "logical_substitution_authorized": False,
            "strict_rule": (
                "copy/complement observations are representation relations only "
                "until the bound CNF supplies a checkable proof of every equivalence"
            ),
        },
        "classification": "LOSSLESS_NINE_AXIS_COMPRESSION_QUOTIENT",
        "config_seal": {
            "path": config.path.relative_to(base).as_posix(),
            "serialized_bytes": config.serialized_bytes,
            "sha256": config.sha256,
        },
        "geometry": _geometry(rows),
        "input": {
            "capsule_manifest_sha256": SOURCE_MANIFEST_SHA256,
            "capsule_result_sha256": SOURCE_RESULT_SHA256,
            "fully_emitted_aggregate_sha256": SOURCE_AGGREGATE_SHA256,
            "fully_emitted_clause_count": SOURCE_CLAUSE_COUNT,
            "fully_emitted_literal_count": SOURCE_LITERAL_COUNT,
            "path": SOURCE_VAULT_RELATIVE.as_posix(),
            "schema": SOURCE_VAULT_SCHEMA,
            "semantic_identity": {
                "bound_rule_sha256": SOURCE_BOUND_RULE_SHA256,
                "cnf_sha256": SOURCE_CNF_SHA256,
                "grouping_sha256": SOURCE_GROUPING_SHA256,
                "observed_variables_sha256": SOURCE_OBSERVED_VARIABLES_SHA256,
                "potential_sha256": SOURCE_POTENTIAL_SHA256,
                "threshold_f64le_hex": SOURCE_THRESHOLD_F64LE_HEX,
            },
            "serialized_bytes": SOURCE_VAULT_BYTES,
            "sha256": SOURCE_VAULT_SHA256,
        },
        "next_action": config.document["next_action"],
        "quotient": quotient_value,
        "round_trip": round_trip,
        "schema": RESULT_SCHEMA,
        "scope": config.document["scope"],
        "source_seals": {
            name: {"path": SOURCE_PATHS[name], "sha256": digest}
            for name, digest in sorted(config.source_sha256.items())
        },
        "state_accounting": _state_accounting(quotient),
        "storage": storage,
        "structural_summary": {
            "axis_count": len(AXES),
            "axis_order": list(AXES),
            "copy_complement_function_count": 2 * len(AXES),
            "copy_complement_map_bytes": COPY_COMPLEMENT_MAP_BYTES,
            "copy_complement_map_sha256": COPY_COMPLEMENT_MAP_SHA256,
            "prefix_residual_literal_count": sum(
                len(row.residual) for row in quotient.prefix_rows
            ),
            "prefix_row_count": len(quotient.prefix_rows),
            "shared_signed_core": {
                "key_literal_count": sum(
                    abs(literal) <= 256 for literal in quotient.shared_signed_core
                ),
                "literal_count": len(quotient.shared_signed_core),
                "sha256": ThresholdNoGoodClause(quotient.shared_signed_core).sha256,
            },
            "switching_variable_count": len(quotient.copy_complement_map),
            "tail": {
                "equal_unsigned_support": True,
                "first_index": TAIL_FIRST_INDEX,
                "literal_count_per_row": TAIL_LITERAL_COUNT,
                "row_count": TAIL_ROW_COUNT,
                "signed_core_literal_count": len(tail_core),
                "signed_core_sha256": ThresholdNoGoodClause(tail_core).sha256,
                "unique_nine_bit_codeword_count": len(set(quotient.tail_codewords)),
            },
        },
        "subsumption": _subsumption(source.occurrences),
    }
    return result


def serialize_result(result: Mapping[str, object]) -> bytes:
    try:
        return canonical_json_bytes(result)
    except (TypeError, ValueError) as exc:
        raise O1C94QuotientError("result JSON differs") from exc


def render_interpretation(result: Mapping[str, object]) -> bytes:
    """Render the deterministic human interpretation from the result."""

    storage = _mapping(result["storage"], "result storage")
    conservative = _mapping(
        storage["conservative_before_bit_packing"], "conservative accounting"
    )
    summary = _mapping(result["structural_summary"], "structural summary")
    shared = _mapping(summary["shared_signed_core"], "shared core")
    tail = _mapping(summary["tail"], "tail")
    state = _mapping(result["state_accounting"], "state accounting")
    subsumption = _mapping(result["subsumption"], "subsumption")
    relation = _mapping(subsumption["relation"], "subsumption relation")
    geometry = _mapping(result["geometry"], "geometry")
    cube = _mapping(geometry["base_8_cube_multiplicities"], "cube")
    round_trip = _mapping(result["round_trip"], "round trip")
    quotient_value = _mapping(result["quotient"], "quotient")
    quotient_payload = canonical_json_bytes(quotient_value)
    lines = [
        "# O1C-0094 — Page-14 nine-axis quotient",
        "",
        "## Outcome",
        "",
        (
            "O1C-0094 builds a deterministic, lossless quotient of all 261 sealed "
            "O1C-0092 Page-14 emissions. Reconstruction preserves row order, every "
            "canonical clause identity, every exact witness identity, and aggregate "
            f"`{round_trip['fully_emitted_aggregate_sha256']}`."
        ),
        "",
        "No solver, preflight, target, truth, reveal, refit, public-verification, "
        "MPS, or GPU call occurred.",
        "",
        "## Exact quotient",
        "",
        (
            f"- Shared signed core: `{shared['literal_count']}` literals "
            f"(`{shared['key_literal_count']}` key, the remainder internal), SHA-256 "
            f"`{shared['sha256']}`."
        ),
        "- Prefix rows `0..4` remain separate and losslessly reconstructible.",
        (
            f"- Tail rows `5..260`: `{tail['row_count']}` equal-support rows of "
            f"`{tail['literal_count_per_row']}` literals with a "
            f"`{tail['signed_core_literal_count']}`-literal signed core."
        ),
        f"- Ordered axes: `{tuple(_sequence(summary['axis_order'], 'axis order'))}`.",
        (
            f"- Exact decoder: `{summary['switching_variable_count']}` switching "
            f"variables, `{summary['copy_complement_function_count']}` observed "
            "copy/complement functions, and 256 unique nine-bit codewords."
        ),
        (
            f"- Canonical quotient object: `{len(quotient_payload)}` bytes, SHA-256 "
            f"`{_sha256(quotient_payload)}`. This is an artifact seal, not the "
            "format-independent compression ratio."
        ),
        "",
        "## Eight-axis cube multiplicities",
        "",
        (
            "Across all 261 rows, the eight-axis projection covers every one of the "
            "256 cells: 253 cells occur once, `00000000` and `10000000` occur "
            "twice, and `00000110` occurs four times."
        ),
        (
            f"The multiplicity histogram is `{cube['multiplicity_histogram']}`. "
            "Tail-only holes `00000110` and `01000110` are supplied by the five "
            "prefix rows; rows 259 and 260 are the two `-238` intrusions."
        ),
        "",
        "## Exact subsumption",
        "",
        (
            f"There is one proper signed-set relation: clause `{relation['subsumer_index']}` "
            f"subsumes clause `{relation['subsumed_index']}` by "
            f"`{relation['additional_literal_count']}` literals. Removing row 2 would "
            "preserve the conjunction, but this lossless quotient deliberately retains "
            "it so the original row multiplicity and aggregate remain exact."
        ),
        "",
        "## Storage and live-state bounds",
        "",
        (
            f"The conservative pre-bit-packing accounting is "
            f"`{conservative['raw_literal_entries']}` → "
            f"`{conservative['factored_literal_entries']}` literal entries: "
            f"`{conservative['reduction_percent']:.10f}%` removed and "
            f"`{conservative['times_smaller']:.10f}x` smaller. It is exactly "
            "14,526 prefix entries + 2,780 tail-core entries + 30,208 tail "
            "residual entries."
        ),
        (
            f"A purpose-built packed streaming decoder retains at most "
            f"`{state['packed_retained_quotient_bytes']}` bytes and uses at most "
            f"`{state['maximum_row_scratch_bytes']}` bytes for one canonical row, "
            f"for a bounded total of `{state['maximum_live_decoder_bytes']}` bytes. "
            "Offline parsing of the sealed source JSON is excluded from this live "
            "decoder bound."
        ),
        "",
        "## Claim boundary",
        "",
        (
            "This is compression only. Co-variation in 256 observed rows does not "
            "prove a CNF equivalence, authorize internal-variable substitution, or "
            "establish a key bit, entropy gain, posterior, closure, model, or domain "
            "reduction. Logical substitution remains forbidden until the same bound "
            "CNF supplies a checkable proof for every copy/complement relation."
        ),
        "",
        "## Sealed inputs",
        "",
        f"- O1C-0092 vault: `{SOURCE_VAULT_BYTES}` bytes / `{SOURCE_VAULT_SHA256}`",
        f"- O1C-0092 capsule manifest: `{SOURCE_MANIFEST_SHA256}`",
        f"- O1C-0092 capsule result: `{SOURCE_RESULT_SHA256}`",
        f"- O1C-0092 emitted aggregate: `{SOURCE_AGGREGATE_SHA256}`",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Recompute O1C-0094's deterministic Page-14 quotient with zero calls"
        )
    )
    parser.add_argument("--root", default=lab_root().as_posix())
    parser.add_argument("--config", default=CONFIG_RELATIVE.as_posix())
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument(
        "--check", help="fail unless this file equals the fresh selected format"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = generate_result(args.root, config_path=args.config)
        payload = (
            serialize_result(result)
            if args.format == "json"
            else render_interpretation(result)
        )
        if args.check:
            checked = _regular_file(Path(args.check), "checked O1C94 output")
            if checked.read_bytes() != payload:
                raise O1C94QuotientError(
                    "checked output differs from fresh deterministic output"
                )
            sys.stdout.buffer.write(
                canonical_json_bytes(
                    {
                        "bytes": len(payload),
                        "checked": checked.as_posix(),
                        "format": args.format,
                        "matches": True,
                        "sha256": _sha256(payload),
                    }
                )
            )
        else:
            sys.stdout.buffer.write(payload)
    except (O1C94QuotientError, OSError) as exc:
        print(f"{ATTEMPT_ID} nine-axis quotient: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ATTEMPT_ID",
    "AXES",
    "CONFIG_RELATIVE",
    "CONFIG_SCHEMA",
    "FACTORED_LITERAL_ENTRIES",
    "NineAxisQuotient",
    "O1C94QuotientError",
    "QUOTIENT_SCHEMA",
    "RESULT_SCHEMA",
    "SOURCE_AGGREGATE_SHA256",
    "SOURCE_LITERAL_COUNT",
    "SOURCE_VAULT_SHA256",
    "build_quotient",
    "generate_result",
    "lab_root",
    "load_config",
    "load_sealed_source",
    "main",
    "quotient_document",
    "quotient_from_document",
    "reconstruct_occurrences",
    "render_interpretation",
    "serialize_result",
    "verify_reconstruction_seals",
]
