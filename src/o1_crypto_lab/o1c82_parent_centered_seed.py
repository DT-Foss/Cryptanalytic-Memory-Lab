"""Deterministic, target-free O1C-0082 parent-centered seed compiler.

The emitted bank is deliberately headerless: exactly 256 variable-ordered
records of 96 bytes each.  Its self-description and provenance live in the
separate canonical JSON manifest.  Compilation accepts only the sealed O1C-0081
census and independently regenerates that census through its sealed O1C-0080
reader before emitting bytes.  No solver, target, truth key, reveal, refit,
public verifier, MPS/GPU service, or network resource is used.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import stat
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence, cast

from . import o1c81_bound_differential_analysis as o1c81
from .causal_attic_v1 import canonical_json_bytes


ATTEMPT_ID = "O1C-0082"
PARENT_ATTEMPT_ID = "O1C-0081"
MANIFEST_SCHEMA = "o1-256-o1c82-parent-centered-seed-manifest-v1"
IMPORT_MAGIC = "O1C82-PCP-SEED1"
IMPORT_SCHEMA = "o1-256-o1c82-parent-centered-priority-seed-v1"
NATIVE_IMPORT_HEADER_RELATIVE = Path("native/o1c82_parent_centered_priority.hpp")
FORMAT_VERSION = 1

CENSUS_RELATIVE = Path("research/O1C0081_BOUND_DIFFERENTIAL_CENSUS_20260720.json")
CENSUS_BYTES = 203_761
CENSUS_SHA256 = "666854f8ba323fcbf100d86457fbc4eaa3cb3b6bab12d9e47982f4b28a86a389"

COORDINATE_COUNT = 256
MISSING_VARIABLE = 241
RECORDED_EVENT_COUNT = 16_384
RECORDED_PARENT_COUNT = 74
ELIGIBILITY_MINIMUM_COUNT = 37
EXPECTED_ELIGIBLE_COORDINATE_COUNT = 225

RECORD_FORMAT = "<QddQQddQQddd"
RECORD_STRUCT = struct.Struct(RECORD_FORMAT)
RECORD_BYTES = 96
BANK_BYTES = 24_576
PARENT_SCRATCH_ENTRY_BYTES = 16
PARENT_SCRATCH_BYTES = 4_096
LIVE_STATE_BYTES = 28_672

# Frozen from the sealed O1C-0081 census by this module's exact codec.
EXPECTED_BANK_SHA256 = (
    "86787bda89f29587525ffbc071d2229608a5bff5c3243361086794379f77e21c"
)
EXPECTED_MANIFEST_BYTES = 3_669
EXPECTED_MANIFEST_SHA256 = (
    "ce288800e6a41ef6c5e0fabebeb700dd35adcc21b8140126f1ae298256310431"
)

PACKED_FIELDS = (
    ("count", "u64", 0),
    ("raw_mean", "f64", 8),
    ("raw_M2", "f64", 16),
    ("raw_positive_count", "u64", 24),
    ("raw_zero_count", "u64", 32),
    ("centered_mean", "f64", 40),
    ("centered_M2", "f64", 48),
    ("centered_positive_count", "u64", 56),
    ("centered_zero_count", "u64", 64),
    ("robust_z_mean", "f64", 72),
    ("robust_abs_z_mean", "f64", 80),
    ("robust_abs_z_max", "f64", 88),
)

_ROW_KEYS = frozenset(
    {
        "centered_directional_stability",
        "centered_mean",
        "centered_negative_fraction",
        "centered_positive_fraction",
        "centered_signed_consistency",
        "centered_variance",
        "centered_zero_fraction",
        "count",
        "query_priority_score",
        "raw_directional_stability",
        "raw_mean",
        "raw_negative_fraction",
        "raw_positive_fraction",
        "raw_variance",
        "raw_zero_fraction",
        "robust_abs_z_max",
        "robust_abs_z_mean",
        "robust_z_mean",
        "variable",
    }
)
_NULLABLE_ZERO_ROW_FIELDS = _ROW_KEYS - {"count", "variable"}


class O1C82ParentCenteredSeedError(ValueError):
    """A seal, census invariant, packed record, or manifest differs."""


@dataclass(frozen=True)
class SealedCensusSpec:
    """Exact byte identity of the canonical O1C-0081 census."""

    relative: Path
    file_bytes: int
    file_sha256: str
    schema: str


SEALED_CENSUS = SealedCensusSpec(
    relative=CENSUS_RELATIVE,
    file_bytes=CENSUS_BYTES,
    file_sha256=CENSUS_SHA256,
    schema=o1c81.REPORT_SCHEMA,
)


def _positive_zero(value: float) -> bool:
    return value == 0.0 and math.copysign(1.0, value) == 1.0


def _require_u64(value: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**64:
        raise O1C82ParentCenteredSeedError(f"{label} is not a u64")
    return value


def _require_f64(value: float, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, float)
        or not math.isfinite(value)
    ):
        raise O1C82ParentCenteredSeedError(f"{label} is not a finite f64")
    return value


@dataclass(frozen=True)
class CoordinateRecord:
    """One variable-bound 96-byte coordinate accumulator."""

    variable: int
    count: int
    raw_mean: float
    raw_m2: float
    raw_positive_count: int
    raw_zero_count: int
    centered_mean: float
    centered_m2: float
    centered_positive_count: int
    centered_zero_count: int
    robust_z_mean: float
    robust_abs_z_mean: float
    robust_abs_z_max: float

    def __post_init__(self) -> None:
        if not 1 <= self.variable <= COORDINATE_COUNT:
            raise O1C82ParentCenteredSeedError("record variable differs")
        count = _require_u64(self.count, "record count")
        integer_counts = (
            _require_u64(self.raw_positive_count, "raw positive count"),
            _require_u64(self.raw_zero_count, "raw zero count"),
            _require_u64(self.centered_positive_count, "centered positive count"),
            _require_u64(self.centered_zero_count, "centered zero count"),
        )
        floats = (
            _require_f64(self.raw_mean, "raw mean"),
            _require_f64(self.raw_m2, "raw M2"),
            _require_f64(self.centered_mean, "centered mean"),
            _require_f64(self.centered_m2, "centered M2"),
            _require_f64(self.robust_z_mean, "robust-z mean"),
            _require_f64(self.robust_abs_z_mean, "robust absolute-z mean"),
            _require_f64(self.robust_abs_z_max, "robust absolute-z maximum"),
        )
        if count == 0:
            if (
                self.variable != MISSING_VARIABLE
                or any(integer_counts)
                or not all(_positive_zero(value) for value in floats)
            ):
                raise O1C82ParentCenteredSeedError("zero coordinate record differs")
            return
        if self.variable == MISSING_VARIABLE or count > RECORDED_PARENT_COUNT:
            raise O1C82ParentCenteredSeedError("observed coordinate count differs")
        if (
            self.raw_positive_count + self.raw_zero_count > count
            or self.centered_positive_count + self.centered_zero_count > count
        ):
            raise O1C82ParentCenteredSeedError("coordinate sign counts differ")
        if self.raw_m2 < 0.0 or self.centered_m2 < 0.0:
            raise O1C82ParentCenteredSeedError("coordinate M2 differs")
        if self.robust_abs_z_mean < 0.0 or self.robust_abs_z_max < 0.0:
            raise O1C82ParentCenteredSeedError("coordinate absolute-z differs")
        if self.robust_abs_z_mean < abs(self.robust_z_mean):
            raise O1C82ParentCenteredSeedError("coordinate robust-z mean differs")
        if self.robust_abs_z_max < self.robust_abs_z_mean:
            raise O1C82ParentCenteredSeedError("coordinate robust-z maximum differs")

    def to_bytes(self) -> bytes:
        """Serialize the record without embedding its ordinal variable."""

        return RECORD_STRUCT.pack(
            self.count,
            self.raw_mean,
            self.raw_m2,
            self.raw_positive_count,
            self.raw_zero_count,
            self.centered_mean,
            self.centered_m2,
            self.centered_positive_count,
            self.centered_zero_count,
            self.robust_z_mean,
            self.robust_abs_z_mean,
            self.robust_abs_z_max,
        )


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _regular_file(path: Path, label: str) -> Path:
    try:
        status = path.lstat()
    except OSError as exc:
        raise O1C82ParentCenteredSeedError(f"{label} is absent") from exc
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        raise O1C82ParentCenteredSeedError(f"{label} is not a sealed regular file")
    return path


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise O1C82ParentCenteredSeedError(f"{label} is not an object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise O1C82ParentCenteredSeedError(f"{label} is not an array")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise O1C82ParentCenteredSeedError(f"{label} is not an integer")
    return value


def _number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise O1C82ParentCenteredSeedError(f"{label} is not numeric")
    result = float(value)
    if not math.isfinite(result):
        raise O1C82ParentCenteredSeedError(f"{label} is not finite")
    return result


def _require_equal(actual: object, expected: object, label: str) -> None:
    if actual != expected:
        raise O1C82ParentCenteredSeedError(f"{label} differs")


def _read_sealed_census_bytes(
    root: Path, spec: SealedCensusSpec = SEALED_CENSUS
) -> bytes:
    path = _regular_file(root / spec.relative, "sealed O1C-0081 census")
    payload = path.read_bytes()
    _require_equal(len(payload), spec.file_bytes, "census byte count")
    _require_equal(_sha256(payload), spec.file_sha256, "census digest")
    return payload


def _fraction_count(value: object, count: int, label: str) -> int:
    fraction = _number(value, label)
    if not 0.0 <= fraction <= 1.0:
        raise O1C82ParentCenteredSeedError(f"{label} is outside [0,1]")
    scaled = fraction * count
    if not math.isfinite(scaled) or not scaled.is_integer():
        raise O1C82ParentCenteredSeedError(
            f"{label} times count is not exactly integral"
        )
    result = int(scaled)
    if not 0 <= result <= count:
        raise O1C82ParentCenteredSeedError(f"{label} count differs")
    return result


def _zero_record(variable: int) -> CoordinateRecord:
    return CoordinateRecord(
        variable=variable,
        count=0,
        raw_mean=0.0,
        raw_m2=0.0,
        raw_positive_count=0,
        raw_zero_count=0,
        centered_mean=0.0,
        centered_m2=0.0,
        centered_positive_count=0,
        centered_zero_count=0,
        robust_z_mean=0.0,
        robust_abs_z_mean=0.0,
        robust_abs_z_max=0.0,
    )


def _compile_row(row: Mapping[str, object], variable: int) -> CoordinateRecord:
    if frozenset(row) != _ROW_KEYS:
        raise O1C82ParentCenteredSeedError(f"coordinate {variable} fields differ")
    _require_equal(row.get("variable"), variable, "coordinate variable order")
    count = _integer(row.get("count"), f"coordinate {variable} count")
    _require_u64(count, f"coordinate {variable} count")
    if count == 0:
        if variable != MISSING_VARIABLE or any(
            row.get(field) is not None for field in _NULLABLE_ZERO_ROW_FIELDS
        ):
            raise O1C82ParentCenteredSeedError("missing coordinate row differs")
        return _zero_record(variable)
    if variable == MISSING_VARIABLE or count > RECORDED_PARENT_COUNT:
        raise O1C82ParentCenteredSeedError("coordinate observation count differs")

    raw_positive = _fraction_count(
        row.get("raw_positive_fraction"), count, "raw positive fraction"
    )
    raw_zero = _fraction_count(row.get("raw_zero_fraction"), count, "raw zero fraction")
    raw_negative = _fraction_count(
        row.get("raw_negative_fraction"), count, "raw negative fraction"
    )
    centered_positive = _fraction_count(
        row.get("centered_positive_fraction"),
        count,
        "centered positive fraction",
    )
    centered_zero = _fraction_count(
        row.get("centered_zero_fraction"), count, "centered zero fraction"
    )
    centered_negative = _fraction_count(
        row.get("centered_negative_fraction"),
        count,
        "centered negative fraction",
    )
    if raw_positive + raw_zero + raw_negative != count:
        raise O1C82ParentCenteredSeedError("raw sign partition differs")
    if centered_positive + centered_zero + centered_negative != count:
        raise O1C82ParentCenteredSeedError("centered sign partition differs")

    raw_variance = _number(row.get("raw_variance"), "raw variance")
    centered_variance = _number(row.get("centered_variance"), "centered variance")
    if raw_variance < 0.0 or centered_variance < 0.0:
        raise O1C82ParentCenteredSeedError("coordinate variance differs")
    raw_m2 = raw_variance * count
    centered_m2 = centered_variance * count
    if not math.isfinite(raw_m2) or not math.isfinite(centered_m2):
        raise O1C82ParentCenteredSeedError("derived coordinate M2 is not finite")

    return CoordinateRecord(
        variable=variable,
        count=count,
        raw_mean=_number(row.get("raw_mean"), "raw mean"),
        raw_m2=raw_m2,
        raw_positive_count=raw_positive,
        raw_zero_count=raw_zero,
        centered_mean=_number(row.get("centered_mean"), "centered mean"),
        centered_m2=centered_m2,
        centered_positive_count=centered_positive,
        centered_zero_count=centered_zero,
        robust_z_mean=_number(row.get("robust_z_mean"), "robust-z mean"),
        robust_abs_z_mean=_number(
            row.get("robust_abs_z_mean"), "robust absolute-z mean"
        ),
        robust_abs_z_max=_number(
            row.get("robust_abs_z_max"), "robust absolute-z maximum"
        ),
    )


def _validate_census_document(document: Mapping[str, object]) -> None:
    _require_equal(document.get("attempt_id"), PARENT_ATTEMPT_ID, "census attempt")
    _require_equal(document.get("schema"), SEALED_CENSUS.schema, "census schema")
    census_input = _mapping(document.get("input"), "census input")
    reader = o1c81.SEALED_READER
    expected_reader = {
        "gzip_bytes": reader.gzip_bytes,
        "gzip_sha256": reader.gzip_sha256,
        "raw_bytes": reader.raw_bytes,
        "raw_sha256": reader.raw_sha256,
        "relative_path": reader.relative.as_posix(),
        "schema": reader.schema,
    }
    _require_equal(census_input, expected_reader, "sealed O1C-0080 reader binding")

    scope = _mapping(document.get("scope"), "census scope")
    expected_scope = {
        "fresh_targets": 0,
        "mps_or_gpu_calls": 0,
        "native_solver_calls": 0,
        "public_verification_calls": 0,
        "refits": 0,
        "reveal_calls": 0,
        "science_calls": 0,
        "truth_key_bytes_read": False,
        "unrecorded_event_values_inferred": False,
    }
    _require_equal(scope, expected_scope, "census target-free scope")

    accounting = _mapping(document.get("state_accounting"), "state accounting")
    expected_accounting = {
        "coordinate_capacity": COORDINATE_COUNT,
        "packed_bytes_per_coordinate": RECORD_BYTES,
        "coordinate_state_bytes": BANK_BYTES,
        "parent_scratch_entry_bytes": PARENT_SCRATCH_ENTRY_BYTES,
        "parent_scratch_capacity": COORDINATE_COUNT,
        "parent_scratch_bytes": PARENT_SCRATCH_BYTES,
        "live_packed_state_bytes": LIVE_STATE_BYTES,
    }
    for key, expected in expected_accounting.items():
        _require_equal(accounting.get(key), expected, f"state accounting {key}")
    _require_equal(
        accounting.get("coordinate_packed_fields"),
        [name for name, _, _ in PACKED_FIELDS],
        "packed field order",
    )

    analysis = _mapping(document.get("recorded_prefix_analysis"), "census analysis")
    _require_equal(analysis.get("parent_count"), RECORDED_PARENT_COUNT, "parent count")
    priority = _mapping(analysis.get("query_priority"), "query priority")
    _require_equal(
        priority.get("minimum_parent_observations"),
        ELIGIBILITY_MINIMUM_COUNT,
        "eligibility threshold",
    )
    _require_equal(
        priority.get("belief_orientation_authorized"),
        False,
        "belief orientation",
    )
    _require_equal(
        priority.get("priority_only_not_bit_polarity"),
        True,
        "priority-only contract",
    )
    conclusion = _mapping(document.get("conclusion"), "census conclusion")
    _require_equal(conclusion.get("key_bit_claims"), 0, "census key-bit claims")
    _require_equal(conclusion.get("full_key_recovery"), False, "full-key recovery")
    _require_equal(
        conclusion.get("belief_orientation"),
        "WITHHELD_NO_TARGET_FREE_POLARITY_CALIBRATION",
        "census belief orientation",
    )


def load_sealed_o1c81_census(
    root: str | Path | None = None, *, verify_fresh: bool = True
) -> Mapping[str, object]:
    """Load the canonical census and optionally reproduce it from O1C-0080."""

    base = lab_root() if root is None else Path(root)
    payload = _read_sealed_census_bytes(base)
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C82ParentCenteredSeedError("census JSON differs") from exc
    document = _mapping(decoded, "census document")
    try:
        canonical = canonical_json_bytes(document)
    except (TypeError, ValueError) as exc:
        raise O1C82ParentCenteredSeedError("census canonical JSON differs") from exc
    _require_equal(canonical, payload, "census canonical byte encoding")
    _validate_census_document(document)
    if verify_fresh:
        try:
            fresh_report = o1c81.generate_bound_differential_census(base)
            fresh_payload = o1c81.serialize_bound_differential_census(fresh_report)
        except o1c81.O1C81BoundDifferentialError as exc:
            raise O1C82ParentCenteredSeedError(
                "sealed O1C-0080 reader validation failed"
            ) from exc
        _require_equal(fresh_payload, payload, "fresh O1C-0081 census")
    return document


def compile_coordinate_records(
    census: Mapping[str, object],
) -> tuple[CoordinateRecord, ...]:
    """Compile and strictly validate all 256 variable-ordered census rows."""

    _validate_census_document(census)
    analysis = _mapping(census.get("recorded_prefix_analysis"), "census analysis")
    rows = _sequence(analysis.get("coordinate_accumulators"), "coordinate rows")
    _require_equal(len(rows), COORDINATE_COUNT, "coordinate row count")
    records = tuple(
        _compile_row(_mapping(value, f"coordinate {variable}"), variable)
        for variable, value in enumerate(rows, start=1)
    )
    _validate_record_bank(records)
    eligible_count = sum(
        record.count >= ELIGIBILITY_MINIMUM_COUNT for record in records
    )
    _require_equal(
        eligible_count,
        EXPECTED_ELIGIBLE_COORDINATE_COUNT,
        "eligible coordinate count",
    )
    return records


def _validate_record_bank(records: Sequence[CoordinateRecord]) -> None:
    _require_equal(len(records), COORDINATE_COUNT, "packed coordinate count")
    _require_equal(
        tuple(record.variable for record in records),
        tuple(range(1, COORDINATE_COUNT + 1)),
        "packed coordinate order",
    )
    zero_variables = tuple(record.variable for record in records if record.count == 0)
    _require_equal(zero_variables, (MISSING_VARIABLE,), "zero coordinate population")
    _require_equal(
        sum(record.count for record in records),
        RECORDED_EVENT_COUNT,
        "packed observation count",
    )


def serialize_seed_bank(records: Sequence[CoordinateRecord]) -> bytes:
    """Serialize exactly 256 headerless records in variable order."""

    _validate_record_bank(records)
    payload = b"".join(record.to_bytes() for record in records)
    _require_equal(len(payload), BANK_BYTES, "packed bank byte count")
    return payload


def parse_seed_bank(
    payload: bytes, *, expected_sha256: str | None = EXPECTED_BANK_SHA256
) -> tuple[CoordinateRecord, ...]:
    """Strictly parse an O1C-0082 bank and bind its digest when supplied."""

    if not isinstance(payload, bytes) or len(payload) != BANK_BYTES:
        raise O1C82ParentCenteredSeedError("serialized seed bank length differs")
    if expected_sha256 is not None:
        if len(expected_sha256) != 64:
            raise O1C82ParentCenteredSeedError("expected seed bank digest differs")
        _require_equal(_sha256(payload), expected_sha256, "seed bank digest")
    records: list[CoordinateRecord] = []
    for variable in range(1, COORDINATE_COUNT + 1):
        offset = (variable - 1) * RECORD_BYTES
        values = RECORD_STRUCT.unpack_from(payload, offset)
        records.append(
            CoordinateRecord(
                variable=variable,
                count=values[0],
                raw_mean=values[1],
                raw_m2=values[2],
                raw_positive_count=values[3],
                raw_zero_count=values[4],
                centered_mean=values[5],
                centered_m2=values[6],
                centered_positive_count=values[7],
                centered_zero_count=values[8],
                robust_z_mean=values[9],
                robust_abs_z_mean=values[10],
                robust_abs_z_max=values[11],
            )
        )
    result = tuple(records)
    _validate_record_bank(result)
    _require_equal(serialize_seed_bank(result), payload, "seed bank round trip")
    return result


def compile_parent_centered_seed(
    root: str | Path | None = None, *, verify_fresh: bool = True
) -> bytes:
    """Return the exact headerless seed bank without writing an artifact."""

    census = load_sealed_o1c81_census(root, verify_fresh=verify_fresh)
    payload = serialize_seed_bank(compile_coordinate_records(census))
    _require_equal(_sha256(payload), EXPECTED_BANK_SHA256, "compiled bank digest")
    return payload


def _format_header() -> dict[str, object]:
    return {
        "bank_is_headerless": True,
        "bank_payload_offset": 0,
        "byte_order": "little-endian",
        "coordinate_count": COORDINATE_COUNT,
        "coordinate_order": "record-index-zero-based-plus-one-is-variable",
        "fields": [
            {"name": name, "offset": offset, "type": field_type}
            for name, field_type, offset in PACKED_FIELDS
        ],
        "import_magic": IMPORT_MAGIC,
        "import_schema": IMPORT_SCHEMA,
        "record_bytes": RECORD_BYTES,
        "record_struct": RECORD_FORMAT,
        "version": FORMAT_VERSION,
    }


def generate_parent_centered_seed_manifest(
    root: str | Path | None = None,
) -> dict[str, object]:
    """Generate the separate, self-describing canonical seed manifest."""

    bank = compile_parent_centered_seed(root, verify_fresh=True)
    records = parse_seed_bank(bank, expected_sha256=_sha256(bank))
    reader = o1c81.SEALED_READER
    return {
        "attempt_id": ATTEMPT_ID,
        "bank": {
            "record_bytes": RECORD_BYTES,
            "record_count": COORDINATE_COUNT,
            "roundtrip_byte_exact": serialize_seed_bank(records) == bank,
            "serialized_bytes": len(bank),
            "sha256": _sha256(bank),
            "variable_241_all_zero": bank[
                (MISSING_VARIABLE - 1) * RECORD_BYTES : MISSING_VARIABLE * RECORD_BYTES
            ]
            == bytes(RECORD_BYTES),
            "variable_241_record_sha256": _sha256(bytes(RECORD_BYTES)),
            "zero_record_variables": [MISSING_VARIABLE],
        },
        "classification": "TARGET_FREE_ZERO_SOLVER_PARENT_CENTERED_SEED",
        "derivation": {
            "centered_M2": "centered_variance*count in binary64",
            "fraction_count_rule": (
                "fraction*count must be finite, within range, and exactly integral; "
                "no tolerance or rounding"
            ),
            "raw_M2": "raw_variance*count in binary64",
            "variable_241_rule": "unseen census row maps to one 96-byte all-zero record",
        },
        "eligibility": {
            "belief_orientation_authorized": False,
            "eligible_coordinate_count": sum(
                record.count >= ELIGIBILITY_MINIMUM_COUNT for record in records
            ),
            "minimum_count": ELIGIBILITY_MINIMUM_COUNT,
            "priority_only_not_bit_polarity": True,
            "rule": "count>=37",
        },
        "header": _format_header(),
        "input": {
            "o1c80_reader": {
                "gzip_bytes": reader.gzip_bytes,
                "gzip_sha256": reader.gzip_sha256,
                "raw_bytes": reader.raw_bytes,
                "raw_sha256": reader.raw_sha256,
                "relative_path": reader.relative.as_posix(),
                "schema": reader.schema,
            },
            "o1c81_census": {
                "canonical_bytes": CENSUS_BYTES,
                "canonical_sha256": CENSUS_SHA256,
                "fresh_report_byte_equal": True,
                "relative_path": CENSUS_RELATIVE.as_posix(),
                "schema": SEALED_CENSUS.schema,
            },
        },
        "import_contract": {
            "magic": IMPORT_MAGIC,
            "native_header_relative_path": NATIVE_IMPORT_HEADER_RELATIVE.as_posix(),
            "payload_bytes": len(bank),
            "payload_sha256": _sha256(bank),
            "record_layout_byte_exact": True,
            "schema": IMPORT_SCHEMA,
        },
        "lineage": {
            "parent_attempt_id": PARENT_ATTEMPT_ID,
            "seed_role": "target-free-preload-for-fresh-lineage-21",
            "source_attempt_id": o1c81.PARENT_ATTEMPT_ID,
            "source_lineage_call_ordinal": 20,
        },
        "orientation_contract": {
            "belief_orientation": "DISABLED",
            "emitted_key_bits": 0,
            "signed_statistics_are_not_key_bit_beliefs": True,
        },
        "schema": MANIFEST_SCHEMA,
        "scope": {
            "fresh_targets": 0,
            "mps_or_gpu_calls": 0,
            "native_solver_calls": 0,
            "network_calls": 0,
            "public_verification_calls": 0,
            "refits": 0,
            "reveal_calls": 0,
            "science_calls": 0,
            "target_bytes_read": False,
            "truth_key_bytes_read": False,
        },
        "state_accounting": {
            "asymptotic_live_state": "O(256)",
            "coordinate_bank_bytes": BANK_BYTES,
            "live_packed_state_bytes": LIVE_STATE_BYTES,
            "manifest_and_offline_input_materialization_excluded": True,
            "parent_scratch_bytes": PARENT_SCRATCH_BYTES,
            "parent_scratch_capacity": COORDINATE_COUNT,
            "parent_scratch_entry_bytes": PARENT_SCRATCH_ENTRY_BYTES,
        },
    }


def serialize_parent_centered_seed_manifest(report: Mapping[str, object]) -> bytes:
    """Serialize a manifest as canonical JSON."""

    try:
        return canonical_json_bytes(report)
    except (TypeError, ValueError) as exc:
        raise O1C82ParentCenteredSeedError("seed manifest JSON differs") from exc


def render_parent_centered_seed_markdown(report: Mapping[str, object]) -> bytes:
    """Render the compact human-readable companion to the JSON manifest."""

    bank = _mapping(report.get("bank"), "manifest bank")
    header = _mapping(report.get("header"), "manifest header")
    eligibility = _mapping(report.get("eligibility"), "manifest eligibility")
    state = _mapping(report.get("state_accounting"), "manifest state accounting")
    input_block = _mapping(report.get("input"), "manifest input")
    census = _mapping(input_block.get("o1c81_census"), "manifest census")
    reader = _mapping(input_block.get("o1c80_reader"), "manifest reader")
    fields = _sequence(header.get("fields"), "manifest fields")
    lines = [
        "# O1C-0082 — Parent-centered seed manifest",
        "",
        "## Outcome",
        "",
        (
            "A deterministic, target-free, zero-solver compiler emits an exact "
            f"`{bank['serialized_bytes']}`-byte bank with SHA-256 "
            f"`{bank['sha256']}`. The binary bank is returned by the API/CLI and "
            "is not persisted as a research artifact."
        ),
        "",
        "## Sealed provenance",
        "",
        (
            f"- Canonical O1C-0081 census: `{census['canonical_bytes']}` bytes / "
            f"`{census['canonical_sha256']}`; freshly regenerated byte-for-byte."
        ),
        (
            f"- Sealed O1C-0080 reader: gzip `{reader['gzip_sha256']}` / raw "
            f"`{reader['raw_sha256']}`."
        ),
        "",
        "## Headerless bank format",
        "",
        (
            f"The separate manifest is the header. The bank contains exactly "
            f"`{header['coordinate_count']}` variable-ordered records, each "
            f"`{header['record_bytes']}` bytes, encoded fixed-width little-endian "
            f"with `{header['record_struct']}`. Record index + 1 is the variable."
        ),
        (
            f"The C++ importer receives magic `{header['import_magic']}` and schema "
            f"`{header['import_schema']}` separately from the headerless payload."
        ),
        "",
        "| field | type | byte offset |",
        "|---|---:|---:|",
    ]
    for value in fields:
        field = _mapping(value, "manifest field")
        lines.append(f"| {field['name']} | {field['type']} | {field['offset']} |")
    lines.extend(
        [
            "",
            (
                "`raw_M2` and `centered_M2` are derived as variance times count. "
                "Every fraction-derived count must be exactly integral; no rounding "
                "or tolerance is allowed. Variable `241` is one all-zero record."
            ),
            "",
            "## Fixed live-state accounting",
            "",
            f"- Coordinate bank: `{state['coordinate_bank_bytes']}` bytes",
            f"- One-parent scratch: `{state['parent_scratch_bytes']}` bytes",
            f"- Total live packed state: `{state['live_packed_state_bytes']}` bytes",
            "",
            "## Eligibility and information boundary",
            "",
            (
                f"Eligibility is `{eligibility['rule']}`: "
                f"`{eligibility['eligible_coordinate_count']}` coordinates qualify. "
                "The bank carries query-priority statistics only. Belief orientation "
                "is disabled and no key bit is emitted."
            ),
            "",
            (
                "No solver, target, truth key, reveal, refit, public verifier, "
                "MPS/GPU service, or network call occurs."
            ),
        ]
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Compile O1C-0082's exact target-free parent-centered seed with "
            "zero solver calls"
        )
    )
    parser.add_argument("--root", default=lab_root().as_posix())
    parser.add_argument(
        "--format", choices=("bank", "manifest", "markdown"), default="manifest"
    )
    parser.add_argument("--check", help="fail unless this file equals fresh output")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.format == "bank":
            payload = compile_parent_centered_seed(args.root, verify_fresh=True)
        else:
            report = generate_parent_centered_seed_manifest(args.root)
            payload = (
                serialize_parent_centered_seed_manifest(report)
                if args.format == "manifest"
                else render_parent_centered_seed_markdown(report)
            )
        if args.check:
            checked = _regular_file(Path(args.check), "checked seed output")
            _require_equal(
                checked.read_bytes(), payload, "checked fresh deterministic output"
            )
            receipt = {
                "bytes": len(payload),
                "checked": checked.as_posix(),
                "format": args.format,
                "matches": True,
                "sha256": _sha256(payload),
            }
            sys.stdout.buffer.write(canonical_json_bytes(receipt))
        else:
            sys.stdout.buffer.write(payload)
    except (O1C82ParentCenteredSeedError, OSError) as exc:
        print(f"{ATTEMPT_ID} parent-centered seed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ATTEMPT_ID",
    "BANK_BYTES",
    "CENSUS_SHA256",
    "CoordinateRecord",
    "ELIGIBILITY_MINIMUM_COUNT",
    "EXPECTED_BANK_SHA256",
    "EXPECTED_MANIFEST_BYTES",
    "EXPECTED_MANIFEST_SHA256",
    "IMPORT_MAGIC",
    "IMPORT_SCHEMA",
    "LIVE_STATE_BYTES",
    "MANIFEST_SCHEMA",
    "O1C82ParentCenteredSeedError",
    "PACKED_FIELDS",
    "PARENT_SCRATCH_BYTES",
    "RECORD_BYTES",
    "RECORD_FORMAT",
    "SEALED_CENSUS",
    "compile_coordinate_records",
    "compile_parent_centered_seed",
    "generate_parent_centered_seed_manifest",
    "load_sealed_o1c81_census",
    "main",
    "parse_seed_bank",
    "render_parent_centered_seed_markdown",
    "serialize_parent_centered_seed_manifest",
    "serialize_seed_bank",
]
