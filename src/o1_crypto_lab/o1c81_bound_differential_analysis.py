"""Target-free O1C-0081 analysis of O1C-0080 bound differentials.

Only the 16,384 probe events retained in O1C-0080's sealed reader artifact
are analyzed.  The 285,725-event full trace is represented only by its sealed
count, byte count, digest, and separately serialized global-minimum witness.
No value is reconstructed or inferred for an omitted event.  This module
never starts a solver and never reads a target, truth key, reveal, or model.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import math
import stat
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from statistics import median
from typing import Mapping, Sequence, cast

from .causal_attic_v1 import canonical_json_bytes


ATTEMPT_ID = "O1C-0081"
PARENT_ATTEMPT_ID = "O1C-0080"
REPORT_SCHEMA = "o1-256-o1c81-bound-differential-census-v1"

READER_RELATIVE = Path(
    "runs/20260720_124516_O1C-0080_apple8-bound-crossing-v1/"
    "episodes/00/one-bit-bound-reader.json.gz"
)
READER_SCHEMA = "o1-256-exact-one-bit-child-bound-reader-v1"
READER_GZIP_BYTES = 902_733
READER_GZIP_SHA256 = "3b8466634e35ff526dbd3fa86ee8d4ddab3383250bd7237c97f0f80ada669e48"
READER_RAW_BYTES = 25_917_187
READER_RAW_SHA256 = "8673b9097034d4634bb432705974b904c402862fa175ca841bf36eb1be63ebf5"

THRESHOLD = 14.606178797892962
THRESHOLD_F64LE_HEX = "2ef540115d362d40"
RECORDED_EVENT_COUNT = 16_384
OMITTED_EVENT_COUNT = 269_341
FULL_TRACE_COUNT = 285_725
FULL_TRACE_BYTES = 16_286_325
FULL_TRACE_SHA256 = "c6f6c2a9ecf17bdd8f74891f5ffc7fba7f9658c4c95310d0c2f00f8b65093f5c"
FULL_MINIMUM_PROBE = 37_567
FULL_MINIMUM_CALL = 413
FULL_MINIMUM_VARIABLE = 115
FULL_MINIMUM_UPPER = 18.464862193097684
FULL_MINIMUM_MARGIN = 3.8586833952047215

KEY_VARIABLES = tuple(range(1, 257))
MISSING_KEY_VARIABLES = (241,)
NORMAL_MAD_SCALE = 1.4826
ROBUST_SCALE_FLOOR = 2.0**-40
CONTROL_DOMAIN = "o1c81-within-parent-cyclic-permutation-v1"

# A live operator needs one fixed bank and one current-parent scratchpad.  The
# accounting is for a packed representation, not CPython object overhead.
PACKED_SCALAR_BYTES = 8
PACKED_COORDINATE_SCALARS = 12
PACKED_COORDINATE_STATE_BYTES = PACKED_SCALAR_BYTES * PACKED_COORDINATE_SCALARS
PACKED_PARENT_SCRATCH_ENTRY_BYTES = 16
PACKED_COORDINATE_BANK_BYTES = 256 * PACKED_COORDINATE_STATE_BYTES
PACKED_PARENT_SCRATCH_BYTES = 256 * PACKED_PARENT_SCRATCH_ENTRY_BYTES
PACKED_LIVE_STATE_BYTES = PACKED_COORDINATE_BANK_BYTES + PACKED_PARENT_SCRATCH_BYTES


class O1C81BoundDifferentialError(ValueError):
    """A sealed input or target-free analysis invariant differs."""


@dataclass(frozen=True)
class SealedReaderSpec:
    """Exact byte identity of the only O1C-0081 evidence input."""

    relative: Path
    gzip_bytes: int
    gzip_sha256: str
    raw_bytes: int
    raw_sha256: str
    schema: str


SEALED_READER = SealedReaderSpec(
    relative=READER_RELATIVE,
    gzip_bytes=READER_GZIP_BYTES,
    gzip_sha256=READER_GZIP_SHA256,
    raw_bytes=READER_RAW_BYTES,
    raw_sha256=READER_RAW_SHA256,
    schema=READER_SCHEMA,
)


@dataclass(frozen=True)
class ProbeObservation:
    """One exact, retained O1C-0080 same-parent child-bound pair."""

    call: int
    coordinate_index: int
    parent_assignment_sha256: str
    parent_level: int
    probe: int
    upper_zero: float
    upper_one: float
    variable: int

    @property
    def differential(self) -> float:
        """Return d = U0 - U1; positive means bit-1 has the lower bound."""

        return self.upper_zero - self.upper_one


@dataclass(frozen=True)
class ReaderEvidence:
    """Validated retained events plus strictly separated full-trace metadata."""

    events: tuple[ProbeObservation, ...]
    full_minimum_witness: Mapping[str, object]
    source_document: Mapping[str, object]


@dataclass
class CoordinateAccumulator:
    """Constant-size online moments for one coordinate."""

    count: int = 0
    raw_mean: float = 0.0
    raw_m2: float = 0.0
    raw_positive_count: int = 0
    raw_zero_count: int = 0
    centered_mean: float = 0.0
    centered_m2: float = 0.0
    centered_positive_count: int = 0
    centered_zero_count: int = 0
    robust_z_mean: float = 0.0
    robust_abs_z_mean: float = 0.0
    robust_abs_z_max: float = 0.0

    def update(self, raw: float, centered: float, robust_z: float) -> None:
        """Stream one observation with Welford moments."""

        if not all(math.isfinite(value) for value in (raw, centered, robust_z)):
            raise O1C81BoundDifferentialError("non-finite streamed differential")
        self.count += 1
        raw_delta = raw - self.raw_mean
        self.raw_mean += raw_delta / self.count
        self.raw_m2 += raw_delta * (raw - self.raw_mean)
        if raw > 0.0:
            self.raw_positive_count += 1
        elif raw == 0.0:
            self.raw_zero_count += 1

        centered_delta = centered - self.centered_mean
        self.centered_mean += centered_delta / self.count
        self.centered_m2 += centered_delta * (centered - self.centered_mean)
        if centered > 0.0:
            self.centered_positive_count += 1
        elif centered == 0.0:
            self.centered_zero_count += 1

        z_delta = robust_z - self.robust_z_mean
        self.robust_z_mean += z_delta / self.count
        absolute_z = abs(robust_z)
        abs_delta = absolute_z - self.robust_abs_z_mean
        self.robust_abs_z_mean += abs_delta / self.count
        self.robust_abs_z_max = max(self.robust_abs_z_max, absolute_z)

    def report(self, variable: int) -> dict[str, object]:
        """Return a finite canonical row, using null for an unseen coordinate."""

        if self.count == 0:
            return {
                "centered_directional_stability": None,
                "centered_mean": None,
                "centered_negative_fraction": None,
                "centered_positive_fraction": None,
                "centered_signed_consistency": None,
                "centered_variance": None,
                "centered_zero_fraction": None,
                "count": 0,
                "query_priority_score": None,
                "raw_directional_stability": None,
                "raw_mean": None,
                "raw_negative_fraction": None,
                "raw_positive_fraction": None,
                "raw_variance": None,
                "raw_zero_fraction": None,
                "robust_abs_z_max": None,
                "robust_abs_z_mean": None,
                "robust_z_mean": None,
                "variable": variable,
            }

        count = self.count
        raw_negative = count - self.raw_positive_count - self.raw_zero_count
        centered_negative = (
            count - self.centered_positive_count - self.centered_zero_count
        )
        raw_positive_fraction = self.raw_positive_count / count
        raw_negative_fraction = raw_negative / count
        centered_positive_fraction = self.centered_positive_count / count
        centered_negative_fraction = centered_negative / count
        centered_stability = max(centered_positive_fraction, centered_negative_fraction)
        query_priority = abs(self.robust_z_mean) * math.sqrt(count) * centered_stability
        return {
            "centered_directional_stability": centered_stability,
            "centered_mean": self.centered_mean,
            "centered_negative_fraction": centered_negative_fraction,
            "centered_positive_fraction": centered_positive_fraction,
            "centered_signed_consistency": (
                self.centered_positive_count - centered_negative
            )
            / count,
            "centered_variance": max(0.0, self.centered_m2 / count),
            "centered_zero_fraction": self.centered_zero_count / count,
            "count": count,
            "query_priority_score": query_priority,
            "raw_directional_stability": max(
                raw_positive_fraction, raw_negative_fraction
            ),
            "raw_mean": self.raw_mean,
            "raw_negative_fraction": raw_negative_fraction,
            "raw_positive_fraction": raw_positive_fraction,
            "raw_variance": max(0.0, self.raw_m2 / count),
            "raw_zero_fraction": self.raw_zero_count / count,
            "robust_abs_z_max": self.robust_abs_z_max,
            "robust_abs_z_mean": self.robust_abs_z_mean,
            "robust_z_mean": self.robust_z_mean,
            "variable": variable,
        }


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _f64le_hex(value: float) -> str:
    if not math.isfinite(value):
        raise O1C81BoundDifferentialError("non-finite binary64 value")
    return struct.pack("<d", value).hex()


def _regular_file(path: Path, label: str) -> Path:
    try:
        status = path.lstat()
    except OSError as exc:
        raise O1C81BoundDifferentialError(f"{label} is absent") from exc
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        raise O1C81BoundDifferentialError(f"{label} is not a sealed regular file")
    return path


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise O1C81BoundDifferentialError(f"{label} is not an object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise O1C81BoundDifferentialError(f"{label} is not an array")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise O1C81BoundDifferentialError(f"{label} is not an integer")
    return value


def _number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise O1C81BoundDifferentialError(f"{label} is not numeric")
    result = float(value)
    if not math.isfinite(result):
        raise O1C81BoundDifferentialError(f"{label} is not finite")
    return result


def _string(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise O1C81BoundDifferentialError(f"{label} is not a string")
    return value


def _require_equal(actual: object, expected: object, label: str) -> None:
    if actual != expected:
        raise O1C81BoundDifferentialError(f"{label} differs")


def _read_sealed_reader_bytes(
    root: Path, spec: SealedReaderSpec = SEALED_READER
) -> bytes:
    path = _regular_file(root / spec.relative, "sealed O1C-0080 reader")
    payload = path.read_bytes()
    _require_equal(len(payload), spec.gzip_bytes, "reader gzip byte count")
    _require_equal(_sha256(payload), spec.gzip_sha256, "reader gzip digest")
    try:
        raw = gzip.decompress(payload)
    except (OSError, EOFError) as exc:
        raise O1C81BoundDifferentialError("reader gzip differs") from exc
    _require_equal(len(raw), spec.raw_bytes, "reader raw byte count")
    _require_equal(_sha256(raw), spec.raw_sha256, "reader raw digest")
    return raw


def _parse_probe_event(value: object, expected_probe: int) -> ProbeObservation:
    event = _mapping(value, f"probe event {expected_probe}")
    probe = _integer(event.get("probe"), "event probe")
    _require_equal(probe, expected_probe, "contiguous recorded probe ordinal")
    call = _integer(event.get("call"), "event call")
    coordinate_index = _integer(event.get("coordinate_index"), "event coordinate index")
    parent_level = _integer(event.get("parent_level"), "event parent level")
    variable = _integer(event.get("variable"), "event variable")
    upper_zero = _number(event.get("upper_zero"), "event U0")
    upper_one = _number(event.get("upper_one"), "event U1")
    parent_sha256 = _string(
        event.get("parent_assignment_sha256"), "parent assignment digest"
    )
    if len(parent_sha256) != 64:
        raise O1C81BoundDifferentialError("parent assignment digest differs")
    if call < 1 or coordinate_index < 0 or parent_level < 0:
        raise O1C81BoundDifferentialError("negative or zero event ordinal")
    if variable not in KEY_VARIABLES or variable in MISSING_KEY_VARIABLES:
        raise O1C81BoundDifferentialError("event variable differs")
    _require_equal(event.get("state_unchanged"), True, "same-parent state flag")
    _require_equal(event.get("state_before"), event.get("state_after"), "state")
    _require_equal(event.get("selection_class"), "NEITHER_PRUNABLE", "selection class")
    for label in ("losing_bit", "losing_literal", "losing_spin"):
        _require_equal(event.get(label), None, label)
    _require_equal(event.get("threshold"), THRESHOLD, "event threshold")
    _require_equal(
        event.get("threshold_f64le_hex"),
        THRESHOLD_F64LE_HEX,
        "event threshold encoding",
    )
    _require_equal(
        event.get("upper_zero_f64le_hex"),
        _f64le_hex(upper_zero),
        "event U0 encoding",
    )
    _require_equal(
        event.get("upper_one_f64le_hex"),
        _f64le_hex(upper_one),
        "event U1 encoding",
    )
    return ProbeObservation(
        call=call,
        coordinate_index=coordinate_index,
        parent_assignment_sha256=parent_sha256,
        parent_level=parent_level,
        probe=probe,
        upper_zero=upper_zero,
        upper_one=upper_one,
        variable=variable,
    )


def _validate_reader_document(document: Mapping[str, object]) -> ReaderEvidence:
    _require_equal(document.get("schema"), READER_SCHEMA, "reader schema")
    expected_scalars = {
        "candidate_count": 255,
        "child_bound_evaluations": 571_450,
        "key_variable_count": 256,
        "minimum_child_margin": FULL_MINIMUM_MARGIN,
        "minimum_child_upper": FULL_MINIMUM_UPPER,
        "minimum_child_variable": FULL_MINIMUM_VARIABLE,
        "omitted_candidate_count": 0,
        "omitted_probe_event_count": OMITTED_EVENT_COUNT,
        "parent_scans": 1_587,
        "probe_count": FULL_TRACE_COUNT,
        "probe_trace_bytes": FULL_TRACE_BYTES,
        "probe_trace_count": FULL_TRACE_COUNT,
        "probe_trace_sha256": FULL_TRACE_SHA256,
        "ranked_candidate_count": 255,
        "recorded_probe_event_count": RECORDED_EVENT_COUNT,
        "threshold": THRESHOLD,
        "threshold_f64le_hex": THRESHOLD_F64LE_HEX,
    }
    for key, expected in expected_scalars.items():
        _require_equal(document.get(key), expected, f"reader {key}")
    _require_equal(
        document.get("class_counts"),
        {
            "BOTH_PRUNABLE": 0,
            "NEITHER_PRUNABLE": FULL_TRACE_COUNT,
            "ONE_PRUNABLE": 0,
            "ZERO_PRUNABLE": 0,
        },
        "reader class counts",
    )

    values = _sequence(document.get("probe_events"), "probe events")
    _require_equal(len(values), RECORDED_EVENT_COUNT, "retained event count")
    events = tuple(
        _parse_probe_event(value, index) for index, value in enumerate(values, start=1)
    )
    calls: dict[int, list[ProbeObservation]] = {}
    for event in events:
        calls.setdefault(event.call, []).append(event)
    _require_equal(tuple(calls), tuple(range(1, 75)), "retained call population")
    for call, rows in calls.items():
        coordinate_indices = [row.coordinate_index for row in rows]
        if coordinate_indices != sorted(set(coordinate_indices)) or any(
            index >= 255 for index in coordinate_indices
        ):
            raise O1C81BoundDifferentialError(f"call {call} coordinate order differs")
        if len({row.variable for row in rows}) != len(rows):
            raise O1C81BoundDifferentialError(f"call {call} repeats a coordinate")
        if len({row.parent_level for row in rows}) != 1:
            raise O1C81BoundDifferentialError(f"call {call} level differs")
        if len({row.parent_assignment_sha256 for row in rows}) != 1:
            raise O1C81BoundDifferentialError(f"call {call} parent differs")

    _require_equal(events[0].probe, 1, "first retained probe")
    _require_equal(events[-1].probe, RECORDED_EVENT_COUNT, "last retained probe")
    _require_equal(events[0].parent_level, 0, "first retained level")
    _require_equal(events[-1].parent_level, 73, "last retained level")
    _require_equal(
        len({event.variable for event in events}),
        255,
        "retained coordinate population",
    )

    witness = _mapping(document.get("minimum_witness"), "minimum witness")
    witness_expected = {
        "call": FULL_MINIMUM_CALL,
        "probe": FULL_MINIMUM_PROBE,
        "variable": FULL_MINIMUM_VARIABLE,
        "upper_one": FULL_MINIMUM_UPPER,
        "threshold": THRESHOLD,
        "state_unchanged": True,
        "selection_class": "NEITHER_PRUNABLE",
    }
    for key, expected in witness_expected.items():
        _require_equal(witness.get(key), expected, f"minimum witness {key}")
    if FULL_MINIMUM_PROBE <= RECORDED_EVENT_COUNT:
        raise O1C81BoundDifferentialError(
            "global minimum unexpectedly belongs to retained prefix"
        )
    return ReaderEvidence(
        events=events,
        full_minimum_witness=witness,
        source_document=document,
    )


def load_sealed_o1c80_reader(
    root: str | Path | None = None,
) -> ReaderEvidence:
    """Load and semantically validate the single sealed evidence artifact."""

    base = lab_root() if root is None else Path(root)
    raw = _read_sealed_reader_bytes(base)
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C81BoundDifferentialError("reader JSON differs") from exc
    return _validate_reader_document(_mapping(decoded, "reader document"))


def _moments(values: Sequence[float]) -> dict[str, object]:
    if not values:
        return {
            "count": 0,
            "maximum": None,
            "mean": None,
            "minimum": None,
            "negative_count": 0,
            "positive_count": 0,
            "positive_fraction": None,
            "variance": None,
            "zero_count": 0,
        }
    mean = math.fsum(values) / len(values)
    positive = sum(value > 0.0 for value in values)
    zero = sum(value == 0.0 for value in values)
    return {
        "count": len(values),
        "maximum": max(values),
        "mean": mean,
        "minimum": min(values),
        "negative_count": len(values) - positive - zero,
        "positive_count": positive,
        "positive_fraction": positive / len(values),
        "variance": math.fsum((value - mean) ** 2 for value in values) / len(values),
        "zero_count": zero,
    }


def _pearson(left: Sequence[float], right: Sequence[float]) -> float | None:
    if len(left) != len(right) or len(left) < 2:
        return None
    left_mean = math.fsum(left) / len(left)
    right_mean = math.fsum(right) / len(right)
    left_centered = [value - left_mean for value in left]
    right_centered = [value - right_mean for value in right]
    denominator = math.sqrt(
        math.fsum(value * value for value in left_centered)
        * math.fsum(value * value for value in right_centered)
    )
    if denominator == 0.0:
        return None
    return (
        math.fsum(
            first * second
            for first, second in zip(left_centered, right_centered, strict=True)
        )
        / denominator
    )


def _new_bank() -> dict[int, CoordinateAccumulator]:
    return {variable: CoordinateAccumulator() for variable in KEY_VARIABLES}


def _rank_rows(
    rows: Sequence[Mapping[str, object]], minimum_count: int, limit: int = 16
) -> list[dict[str, object]]:
    eligible: list[Mapping[str, object]] = []
    for row in rows:
        count = _integer(row.get("count"), "coordinate count")
        score = row.get("query_priority_score")
        if count >= minimum_count and isinstance(score, (int, float)):
            eligible.append(row)
    eligible.sort(
        key=lambda row: (
            -_number(row.get("query_priority_score"), "priority score"),
            -_integer(row.get("count"), "priority count"),
            _integer(row.get("variable"), "priority variable"),
        )
    )
    return [
        {
            "centered_directional_stability": row["centered_directional_stability"],
            "centered_mean": row["centered_mean"],
            "count": row["count"],
            "query_priority_score": row["query_priority_score"],
            "robust_z_mean": row["robust_z_mean"],
            "variable": row["variable"],
        }
        for row in eligible[:limit]
    ]


def _control_offset(call: int, parent_sha256: str, count: int) -> int:
    if count <= 1:
        return 0
    seed = hashlib.sha256(
        f"{CONTROL_DOMAIN}:{call}:{parent_sha256}".encode("ascii")
    ).digest()
    return 1 + int.from_bytes(seed[:8], "little") % (count - 1)


def _bank_rows(
    bank: Mapping[int, CoordinateAccumulator],
) -> list[dict[str, object]]:
    return [bank[variable].report(variable) for variable in KEY_VARIABLES]


def _finite_rows_by_variable(
    rows: Sequence[Mapping[str, object]], field: str, minimum_count: int
) -> dict[int, float]:
    result: dict[int, float] = {}
    for row in rows:
        if _integer(row.get("count"), "coordinate count") < minimum_count:
            continue
        value = row.get(field)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            numeric = float(value)
            if math.isfinite(numeric):
                result[_integer(row.get("variable"), "variable")] = numeric
    return result


def analyze_probe_events(
    events: Sequence[ProbeObservation],
) -> dict[str, object]:
    """Analyze a retained prefix with bounded per-coordinate stream state."""

    if not events:
        raise O1C81BoundDifferentialError("recorded prefix is empty")
    by_call: dict[int, list[ProbeObservation]] = {}
    for event in events:
        by_call.setdefault(event.call, []).append(event)
    calls = tuple(by_call)
    if calls != tuple(range(calls[0], calls[-1] + 1)):
        raise O1C81BoundDifferentialError("recorded call population is not contiguous")

    observed_bank = _new_bank()
    permuted_bank = _new_bank()
    first_half_bank = _new_bank()
    second_half_bank = _new_bank()
    parent_rows: list[dict[str, object]] = []
    raw_values: list[float] = []
    centered_values: list[float] = []
    robust_z_values: list[float] = []
    control_offsets: list[dict[str, object]] = []
    parent_medians: list[float] = []
    parent_mads: list[float] = []
    midpoint = calls[(len(calls) - 1) // 2]

    for call, parent_events in by_call.items():
        ordered = sorted(parent_events, key=lambda event: event.coordinate_index)
        differentials = [event.differential for event in ordered]
        parent_median = float(median(differentials))
        absolute_deviations = [abs(value - parent_median) for value in differentials]
        parent_mad = float(median(absolute_deviations))
        robust_scale = max(NORMAL_MAD_SCALE * parent_mad, ROBUST_SCALE_FLOOR)
        centered = [value - parent_median for value in differentials]
        robust_z = [value / robust_scale for value in centered]
        parent_medians.append(parent_median)
        parent_mads.append(parent_mad)
        raw_values.extend(differentials)
        centered_values.extend(centered)
        robust_z_values.extend(robust_z)

        for event, raw, residual, z_value in zip(
            ordered, differentials, centered, robust_z, strict=True
        ):
            observed_bank[event.variable].update(raw, residual, z_value)
            split_bank = first_half_bank if call <= midpoint else second_half_bank
            split_bank[event.variable].update(raw, residual, z_value)

        offset = _control_offset(
            call, ordered[0].parent_assignment_sha256, len(ordered)
        )
        for receiver_index, event in enumerate(ordered):
            donor_index = (receiver_index + offset) % len(ordered)
            permuted_bank[event.variable].update(
                differentials[donor_index],
                centered[donor_index],
                robust_z[donor_index],
            )
        control_offsets.append({"call": call, "count": len(ordered), "offset": offset})
        raw_parent = _moments(differentials)
        centered_parent = _moments(centered)
        parent_rows.append(
            {
                "call": call,
                "candidate_count": len(ordered),
                "centered_mean": centered_parent["mean"],
                "centered_positive_fraction": centered_parent["positive_fraction"],
                "mad": parent_mad,
                "median_common_mode": parent_median,
                "parent_assignment_sha256": ordered[0].parent_assignment_sha256,
                "parent_level": ordered[0].parent_level,
                "raw_mean": raw_parent["mean"],
                "raw_positive_fraction": raw_parent["positive_fraction"],
                "robust_scale": robust_scale,
            }
        )

    observed_rows = _bank_rows(observed_bank)
    permuted_rows = _bank_rows(permuted_bank)
    first_rows = _bank_rows(first_half_bank)
    second_rows = _bank_rows(second_half_bank)
    persistence_minimum = math.ceil(len(calls) / 2)
    observed_top = _rank_rows(observed_rows, persistence_minimum)
    permuted_top = _rank_rows(permuted_rows, persistence_minimum)
    observed_top_variables = {
        _integer(row["variable"], "observed top variable") for row in observed_top
    }
    permuted_top_variables = {
        _integer(row["variable"], "permuted top variable") for row in permuted_top
    }
    observed_scores = _finite_rows_by_variable(
        observed_rows, "query_priority_score", persistence_minimum
    )
    permuted_scores = _finite_rows_by_variable(
        permuted_rows, "query_priority_score", persistence_minimum
    )
    shared_score_variables = sorted(observed_scores.keys() & permuted_scores.keys())

    split_minimum = 8
    first_means = _finite_rows_by_variable(first_rows, "centered_mean", split_minimum)
    second_means = _finite_rows_by_variable(second_rows, "centered_mean", split_minimum)
    shared_split = sorted(first_means.keys() & second_means.keys())
    nonzero_split = [
        variable
        for variable in shared_split
        if first_means[variable] != 0.0 and second_means[variable] != 0.0
    ]
    split_sign_agreement = sum(
        math.copysign(1.0, first_means[variable])
        == math.copysign(1.0, second_means[variable])
        for variable in nonzero_split
    )
    first_top = _rank_rows(first_rows, split_minimum)
    second_top = _rank_rows(second_rows, split_minimum)
    first_top_variables = {
        _integer(row["variable"], "first-half top variable") for row in first_top
    }
    second_top_variables = {
        _integer(row["variable"], "second-half top variable") for row in second_top
    }

    raw_energy = math.fsum(value * value for value in raw_values)
    centered_energy = math.fsum(value * value for value in centered_values)
    return {
        "common_mode_diagnostics": {
            "centered_differential": _moments(centered_values),
            "median_centered_energy_fraction_of_raw": (
                centered_energy / raw_energy if raw_energy > 0.0 else None
            ),
            "median_centered_energy_reduction_fraction": (
                1.0 - centered_energy / raw_energy if raw_energy > 0.0 else None
            ),
            "parent_mad": _moments(parent_mads),
            "parent_median_common_mode": _moments(parent_medians),
            "raw_differential": _moments(raw_values),
            "robust_z": _moments(robust_z_values),
        },
        "coordinate_accumulators": observed_rows,
        "parent_count": len(calls),
        "parent_rows": parent_rows,
        "query_priority": {
            "belief_orientation_authorized": False,
            "minimum_parent_observations": persistence_minimum,
            "priority_only_not_bit_polarity": True,
            "ranking_rule": (
                "abs(mean(parent-median-centered robust-z))*sqrt(count)*"
                "max(centered-positive-fraction,centered-negative-fraction);"
                "score-desc,count-desc,variable-asc"
            ),
            "top_coordinates": observed_top,
        },
        "target_free_controls": {
            "temporal_parent_split": {
                "first_call_range": [calls[0], midpoint],
                "last_recorded_call_event_count": len(by_call[calls[-1]]),
                "mean_correlation": _pearson(
                    [first_means[variable] for variable in shared_split],
                    [second_means[variable] for variable in shared_split],
                ),
                "minimum_observations_per_half": split_minimum,
                "nonzero_mean_coordinate_count": len(nonzero_split),
                "second_call_range": [midpoint + 1, calls[-1]],
                "second_half_is_a_capped_prefix_not_a_balanced_sample": True,
                "shared_coordinate_count": len(shared_split),
                "sign_agreement_count": split_sign_agreement,
                "sign_agreement_fraction": (
                    split_sign_agreement / len(nonzero_split) if nonzero_split else None
                ),
                "top16_overlap_count": len(first_top_variables & second_top_variables),
                "top16_overlap_variables": sorted(
                    first_top_variables & second_top_variables
                ),
            },
            "within_parent_coordinate_permutation": {
                "control_domain": CONTROL_DOMAIN,
                "coordinate_association_only_is_permuted": True,
                "global_value_multiset_preserved": True,
                "minimum_parent_observations": persistence_minimum,
                "observed_max_priority": (
                    max(observed_scores.values()) if observed_scores else None
                ),
                "offset_ledger_sha256": _sha256(canonical_json_bytes(control_offsets)),
                "permutation_count": 1,
                "permuted_max_priority": (
                    max(permuted_scores.values()) if permuted_scores else None
                ),
                "priority_correlation": _pearson(
                    [observed_scores[variable] for variable in shared_score_variables],
                    [permuted_scores[variable] for variable in shared_score_variables],
                ),
                "single_control_has_no_p_value": True,
                "top16_overlap_count": len(
                    observed_top_variables & permuted_top_variables
                ),
                "top16_overlap_variables": sorted(
                    observed_top_variables & permuted_top_variables
                ),
                "top_coordinates": permuted_top,
            },
        },
    }


def generate_bound_differential_census(
    root: str | Path | None = None,
) -> dict[str, object]:
    """Generate the deterministic target-free O1C-0081 report."""

    evidence = load_sealed_o1c80_reader(root)
    analysis = analyze_probe_events(evidence.events)
    observed = cast(Mapping[str, object], analysis["common_mode_diagnostics"])
    raw = _mapping(observed["raw_differential"], "raw diagnostics")
    centered = _mapping(observed["centered_differential"], "centered diagnostics")
    return {
        "attempt_id": ATTEMPT_ID,
        "classification": "TARGET_FREE_BOUND_DIFFERENTIAL_MECHANISM_CENSUS",
        "conclusion": {
            "belief_orientation": "WITHHELD_NO_TARGET_FREE_POLARITY_CALIBRATION",
            "full_key_recovery": False,
            "key_bit_claims": 0,
            "mechanism_evidence": True,
            "next_operator": "PARENT_CENTERED_SIGNED_BOUND_DIFFERENTIAL_STREAM",
            "query_priority_available": True,
            "science_gain": False,
        },
        "differential_contract": {
            "center": "within-parent median of d",
            "d": "U0-U1",
            "raw_positive_meaning": "bit-1 child has lower exact upper bound",
            "robust_scale": ("max(1.4826*within-parent-MAD,2^-40)"),
            "warning": (
                "neither raw nor centered sign is a key-bit posterior without "
                "independent target-free polarity calibration"
            ),
        },
        "input": {
            "gzip_bytes": SEALED_READER.gzip_bytes,
            "gzip_sha256": SEALED_READER.gzip_sha256,
            "raw_bytes": SEALED_READER.raw_bytes,
            "raw_sha256": SEALED_READER.raw_sha256,
            "relative_path": SEALED_READER.relative.as_posix(),
            "schema": SEALED_READER.schema,
        },
        "operator_recommendation": {
            "belief_field": {
                "action": "do-not-orient-or-emit-key-bits",
                "reason": (
                    "95-percent-class raw polarity can be common mode; this "
                    "target-free census contains no correctness labels"
                ),
            },
            "coordinate_binding": (
                "bind residual evidence to public key-coordinate identity only; "
                "never bind a hidden key value"
            ),
            "query_priority_field": {
                "action": "eligible-for-a-fresh-target-blind-operator-fixture",
                "evidence": (
                    "rank persistent coordinates by centered robust residual "
                    "magnitude and stability, then let live surprise choose where "
                    "to query; do not convert its sign to a bit"
                ),
            },
            "separate_fields": True,
        },
        "population_boundary": {
            "full_trace": {
                "event_count": FULL_TRACE_COUNT,
                "per_event_values_available": False,
                "retained_prefix_is_complete_trace": False,
                "serialized_bytes": FULL_TRACE_BYTES,
                "sha256": FULL_TRACE_SHA256,
            },
            "omitted_suffix": {
                "event_count": OMITTED_EVENT_COUNT,
                "first_probe": RECORDED_EVENT_COUNT + 1,
                "values_inferred": False,
            },
            "recorded_prefix": {
                "call_range": [evidence.events[0].call, evidence.events[-1].call],
                "coordinate_count": len({event.variable for event in evidence.events}),
                "event_count": len(evidence.events),
                "exact_event_values_available": True,
                "missing_key_variables": list(MISSING_KEY_VARIABLES),
                "parent_level_range": [
                    evidence.events[0].parent_level,
                    evidence.events[-1].parent_level,
                ],
                "probe_range": [
                    evidence.events[0].probe,
                    evidence.events[-1].probe,
                ],
            },
            "separate_global_minimum_witness": {
                "call": FULL_MINIMUM_CALL,
                "excluded_from_accumulators": True,
                "margin_above_threshold": FULL_MINIMUM_MARGIN,
                "probe": FULL_MINIMUM_PROBE,
                "selection_class": evidence.full_minimum_witness["selection_class"],
                "state_unchanged": evidence.full_minimum_witness["state_unchanged"],
                "upper_one": evidence.full_minimum_witness["upper_one"],
                "upper_zero": evidence.full_minimum_witness["upper_zero"],
                "variable": FULL_MINIMUM_VARIABLE,
            },
        },
        "recorded_prefix_analysis": analysis,
        "schema": REPORT_SCHEMA,
        "scope": {
            "fresh_targets": 0,
            "mps_or_gpu_calls": 0,
            "native_solver_calls": 0,
            "public_verification_calls": 0,
            "refits": 0,
            "reveal_calls": 0,
            "science_calls": 0,
            "truth_key_bytes_read": False,
            "unrecorded_event_values_inferred": False,
        },
        "state_accounting": {
            "asymptotic_state": "O(256)",
            "coordinate_capacity": 256,
            "coordinate_packed_fields": [
                "count",
                "raw_mean",
                "raw_M2",
                "raw_positive_count",
                "raw_zero_count",
                "centered_mean",
                "centered_M2",
                "centered_positive_count",
                "centered_zero_count",
                "robust_z_mean",
                "robust_abs_z_mean",
                "robust_abs_z_max",
            ],
            "coordinate_state_bytes": PACKED_COORDINATE_BANK_BYTES,
            "input_artifact_materialization_excluded": True,
            "live_packed_state_bytes": PACKED_LIVE_STATE_BYTES,
            "packed_bytes_per_coordinate": PACKED_COORDINATE_STATE_BYTES,
            "parent_scratch_bytes": PACKED_PARENT_SCRATCH_BYTES,
            "parent_scratch_capacity": 256,
            "parent_scratch_entry_bytes": PACKED_PARENT_SCRATCH_ENTRY_BYTES,
        },
        "summary": {
            "centered_mean": centered["mean"],
            "centered_positive_fraction": centered["positive_fraction"],
            "raw_maximum": raw["maximum"],
            "raw_mean": raw["mean"],
            "raw_minimum": raw["minimum"],
            "raw_positive_count": raw["positive_count"],
            "raw_positive_fraction": raw["positive_fraction"],
            "recorded_event_count": RECORDED_EVENT_COUNT,
        },
    }


def serialize_bound_differential_census(report: Mapping[str, object]) -> bytes:
    try:
        return canonical_json_bytes(report)
    except (TypeError, ValueError) as exc:
        raise O1C81BoundDifferentialError("census JSON differs") from exc


def render_bound_differential_markdown(report: Mapping[str, object]) -> bytes:
    """Render a compact human ledger from the canonical report."""

    summary = _mapping(report["summary"], "summary")
    population = _mapping(report["population_boundary"], "population")
    recorded = _mapping(population["recorded_prefix"], "recorded prefix")
    full_trace = _mapping(population["full_trace"], "full trace")
    global_minimum = _mapping(
        population["separate_global_minimum_witness"], "global minimum"
    )
    analysis = _mapping(report["recorded_prefix_analysis"], "analysis")
    priority = _mapping(analysis["query_priority"], "query priority")
    top = _sequence(priority["top_coordinates"], "top coordinates")
    controls = _mapping(analysis["target_free_controls"], "controls")
    permutation = _mapping(
        controls["within_parent_coordinate_permutation"], "permutation control"
    )
    temporal = _mapping(controls["temporal_parent_split"], "temporal control")
    accounting = _mapping(report["state_accounting"], "state accounting")
    lines = [
        "# O1C-0081 — Target-free bound-differential census",
        "",
        "## Outcome",
        "",
        (
            "The sealed O1C-0080 retained prefix supports a new **query-priority "
            "mechanism candidate**, not key-bit orientation or recovery. No solver, "
            "target, truth, reveal, refit, MPS, or GPU call occurred."
        ),
        "",
        "## Population boundary",
        "",
        f"- Exact retained events analyzed: `{recorded['event_count']}`",
        f"- Retained probes: `{recorded['probe_range']}`; calls: `{recorded['call_range']}`",
        f"- Full trace: `{full_trace['event_count']}` events / `{full_trace['serialized_bytes']}` bytes / `{full_trace['sha256']}`",
        (
            "- Omitted suffix values: unavailable and **not inferred**; the full "
            "trace is used only through count/bytes/digest metadata"
        ),
        (
            f"- Separate global minimum witness: probe `{global_minimum['probe']}`, "
            f"call `{global_minimum['call']}`, variable `{global_minimum['variable']}`, "
            f"minimum `{global_minimum['upper_one']}`, margin above threshold "
            f"`{global_minimum['margin_above_threshold']}`; excluded from all "
            "prefix accumulators"
        ),
        "",
        "## Recorded-prefix signal",
        "",
        f"- Raw `d=U0-U1`: min `{summary['raw_minimum']}`, max `{summary['raw_maximum']}`, mean `{summary['raw_mean']}`",
        f"- Raw positive: `{summary['raw_positive_count']}/{summary['recorded_event_count']}` = `{summary['raw_positive_fraction']}`",
        f"- After within-parent median centering: mean `{summary['centered_mean']}`, positive fraction `{summary['centered_positive_fraction']}`",
        (
            "- Interpretation: the large raw positive majority is common-mode "
            "contaminated. Raw sign is therefore not a posterior."
        ),
        "",
        "## Persistent query-priority candidates",
        "",
        (
            "Ranking is target-free. Eligibility first requires at least "
            f"`{priority['minimum_parent_observations']}` retained-parent observations; "
            "within that persistent population the score is `abs(mean robust-z) * "
            "sqrt(count) * directional stability`. Its sign is deliberately not "
            "mapped to a key bit."
        ),
        "",
        "| rank | variable | count | centered mean | robust-z mean | stability | score |",
        "|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for rank, value in enumerate(top, start=1):
        row = _mapping(value, "top coordinate")
        lines.append(
            f"| {rank} | {row['variable']} | {row['count']} | "
            f"{row['centered_mean']} | {row['robust_z_mean']} | "
            f"{row['centered_directional_stability']} | "
            f"{row['query_priority_score']} |"
        )
    lines.extend(
        [
            "",
            "## Target-free controls",
            "",
            (
                f"- Within-parent cyclic permutation: top-16 overlap "
                f"`{permutation['top16_overlap_count']}`, priority correlation "
                f"`{permutation['priority_correlation']}`. This is one deterministic "
                "control, not a p-value."
            ),
            (
                f"- Temporal split: `{temporal['first_call_range']}` versus "
                f"`{temporal['second_call_range']}`, centered-mean correlation "
                f"`{temporal['mean_correlation']}`, sign agreement "
                f"`{temporal['sign_agreement_fraction']}`, top-16 overlap "
                f"`{temporal['top16_overlap_count']}`."
            ),
            "",
            "## Bounded-state operator",
            "",
            (
                f"A packed live bank is `{accounting['live_packed_state_bytes']}` "
                f"bytes: `{accounting['coordinate_state_bytes']}` bytes for 256 "
                f"coordinate accumulators plus `{accounting['parent_scratch_bytes']}` "
                "bytes of one-parent median/MAD scratch. This excludes offline JSON "
                "materialization and remains `O(256)`."
            ),
            "",
            "## Next action",
            "",
            (
                "Implement the parent-centered signed-differential stream as a fresh, "
                "target-blind query-priority operator. Keep belief orientation as a "
                "separate disabled field until independently calibrated. Do not replay "
                "Page 7 / lineage 20 and do not infer omitted trace values."
            ),
        ]
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Recompute O1C-0081's target-free bound-differential census with "
            "zero solver calls"
        )
    )
    parser.add_argument("--root", default=lab_root().as_posix())
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument(
        "--check", help="fail unless this file equals the fresh selected format"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = generate_bound_differential_census(args.root)
        payload = (
            serialize_bound_differential_census(report)
            if args.format == "json"
            else render_bound_differential_markdown(report)
        )
        if args.check:
            checked = _regular_file(Path(args.check), "checked census")
            if checked.read_bytes() != payload:
                raise O1C81BoundDifferentialError(
                    "checked census differs from fresh deterministic output"
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
    except (O1C81BoundDifferentialError, OSError) as exc:
        print(f"{ATTEMPT_ID} bound differential census: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ATTEMPT_ID",
    "CONTROL_DOMAIN",
    "FULL_TRACE_COUNT",
    "O1C81BoundDifferentialError",
    "PACKED_LIVE_STATE_BYTES",
    "ProbeObservation",
    "RECORDED_EVENT_COUNT",
    "REPORT_SCHEMA",
    "SEALED_READER",
    "SealedReaderSpec",
    "analyze_probe_events",
    "generate_bound_differential_census",
    "lab_root",
    "load_sealed_o1c80_reader",
    "main",
    "render_bound_differential_markdown",
    "serialize_bound_differential_census",
]
