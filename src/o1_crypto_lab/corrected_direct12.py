"""Corrected W46 Direct12 codec, legacy reader replay, and O1 bridge ladder.

The loader reads only a SHA-256 allowlist from the sibling research snapshot,
copies every consumed byte into the active lab capsule, validates the exact
word0-bits-20-through-31 codec, and reproduces A355/A356 with the historical
NumPy reader arithmetic.  Its tournament then records the failed literal
O1C-0005 transfer and qualifies bounded DC-complete adaptive successors before
any new challenge is generated.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping, Sequence

import numpy as np

from .adaptive_dc_spectral import (
    AdaptiveDCExecution,
    AdaptiveDCTemplate,
    PASS_INTEGRITY_LOGICAL_STATE_BYTES,
    execute_adaptive_dc,
)
from .direct12 import (
    A268_PREFLIGHT,
    A272_PROTOCOL,
    CHANNEL_NAMES,
    HORIZONS,
    Direct12Adapter,
    Direct12Error,
)
from .quantized_spectral import DIRECT12_SIZE, _quantize
from .run_capsule import RunCapsuleManager
from .shape532 import (
    BASE_FEATURE_NAMES,
    FEATURE_NAMES,
    RAW_CHANNELS,
    SIGNED_RATIO_PAIRS,
    direct12_order,
    direct12_order_uint16be_sha256,
)
from .spectral_experiment import QuantizedArm
from .stage3 import BoundedZstdDecoder, Stage3Error
from .walsh_memory import score_field_sha256


ArtifactWriter = Callable[[str, bytes], object]

SCHEMA = "o1-crypto-corrected-codec-bridge-config-v1"
RESULT_SCHEMA = "o1-crypto-corrected-codec-bridge-result-v1"
SOURCE_SNAPSHOT_SCHEMA = "o1-crypto-corrected-source-snapshot-v1"
FUTURE_TEMPLATE_SCHEMA = "o1-crypto-corrected-recovery-memory-template-v1"
CODEC_SCHEMA = "o1-crypto-w46-word0-20-through-31-codec-v1"
SELECTED_READER = "A340_selected8_global_raw"
EXPECTED_INDICES = (502, 504, 505, 508, 509, 510, 511, 514)
LOW4_COORDINATES = (23, 22, 21, 20)
HIGH8_COORDINATES = (31, 30, 29, 28, 27, 26, 25, 24)
SYNTHETIC_SOURCE_INDICES = (*range(12), *range(24, 32))
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
FORBIDDEN_SOURCE_FRAGMENTS = (
    "a345_progress",
    "a349_order_prospective_recovery_a350",
    "a350_",
    "a358_",
)
A355_DESIGN_MEMBER = (
    "research/configs/"
    "chacha20_round20_w46_corrected_group_direct12_reader_a355_design_v1.json"
)
A355_IMPLEMENTATION_MEMBER = (
    "research/configs/"
    "chacha20_round20_w46_corrected_group_direct12_reader_a355_implementation_v1.json"
)
A356_DESIGN_MEMBER = (
    "research/configs/"
    "chacha20_round20_w46_corrected_group_a345_transfer_a356_design_v1.json"
)
A356_IMPLEMENTATION_MEMBER = (
    "research/configs/"
    "chacha20_round20_w46_corrected_group_a345_transfer_a356_implementation_v1.json"
)
FROZEN_SELECTION_RULE = {
    "eligibility": [
        "maximum_online_state_bytes",
        "maximum_serialized_logical_mechanism_state_bytes",
        "zero_clips",
        "minimum_rank_spearman",
        "minimum_rank_kendall",
        "minimum_top32_overlap",
        "minimum_top128_overlap",
    ],
    "lexicographic_objective": [
        "maximize_minimum_top8_overlap",
        "maximize_minimum_top32_overlap",
        "maximize_minimum_top128_overlap",
        "maximize_minimum_rank_spearman",
        "minimize_maximum_serialized_logical_mechanism_state_bytes",
        "minimize_arm_id_ascii",
    ],
}


class CorrectedDirect12Error(ValueError):
    """A source, codec, score, or freeze invariant differs."""


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CorrectedDirect12Error("value is not canonical finite ASCII JSON") from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise CorrectedDirect12Error(f"{field} must be a lowercase SHA-256")
    return value


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise CorrectedDirect12Error(f"{field} must be an object")
    return value


def _sequence(value: object, field: str) -> list[object]:
    if not isinstance(value, list):
        raise CorrectedDirect12Error(f"{field} must be a list")
    return value


def _integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CorrectedDirect12Error(f"{field} must be an integer")
    return value


def _finite(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CorrectedDirect12Error(f"{field} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise CorrectedDirect12Error(f"{field} must be finite")
    return 0.0 if result == 0.0 else result


def _safe_member(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise CorrectedDirect12Error(f"{field} must be text")
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\x00" in value
    ):
        raise CorrectedDirect12Error(f"unsafe source member: {value!r}")
    lowered = value.lower()
    if any(fragment in lowered for fragment in FORBIDDEN_SOURCE_FRAGMENTS):
        raise CorrectedDirect12Error(f"forbidden active source member: {value}")
    if (
        value.startswith("research/results/")
        and "fresh_w46_factor2_replication_a345_v1.json" in value
    ):
        raise CorrectedDirect12Error("A345 result access is forbidden")
    return value


def _order_bytes(order: Sequence[int]) -> bytes:
    values = tuple(order)
    if len(values) != DIRECT12_SIZE or set(values) != set(range(DIRECT12_SIZE)):
        raise CorrectedDirect12Error("order must be a complete 4096-cell permutation")
    return b"".join(value.to_bytes(2, "big") for value in values)


def _historical_field_sha256(scores: Sequence[float]) -> str:
    return _canonical_sha256(list(scores))


def _validate_measurement_summary(
    summary: object,
    *,
    attempt_id: str,
) -> Mapping[str, object]:
    expected: dict[str, object]
    if attempt_id == "A355":
        expected = {
            "candidate_assignments_executed": 0,
            "complete_direct12_cells": 4096,
            "concurrent_workers": 8,
            "high8_cells_per_slice": 256,
            "low4_slices": 16,
            "measured_assignment_bit_interval": [20, 31],
            "solver_stages": 16384,
            "status_counts": {"sat": 0, "unknown": 4096, "unsat": 0},
            "target_labels_used_during_measurement": 0,
        }
    elif attempt_id == "A356":
        expected = {
            "A355_selected_view_read": False,
            "candidate_assignments_executed": 0,
            "complete_direct12_cells": 4096,
            "high8_cells_per_slice": 256,
            "low4_slices": 16,
            "measured_assignment_bit_interval": [20, 31],
            "reader_refits": 0,
            "solver_stages": 16384,
            "status_counts": {"sat": 0, "unknown": 4096, "unsat": 0},
            "target_labels_used": 0,
        }
    else:
        raise CorrectedDirect12Error("unknown corrected measurement summary")
    value = _mapping(summary, f"{attempt_id}.measurement_summary")
    if dict(value) != expected:
        raise CorrectedDirect12Error(f"{attempt_id} measurement summary differs")
    return value


def _validate_implementation_document(
    document: Mapping[str, object],
    *,
    schema: str,
    design_sha256: str,
    implementation_sha256: str,
) -> str:
    if document.get("schema") != schema:
        raise CorrectedDirect12Error("historical implementation schema differs")
    if document.get("design_sha256") != design_sha256:
        raise CorrectedDirect12Error("historical implementation design pin differs")
    commitment = _sha256(
        document.get("implementation_commitment_sha256"),
        "implementation_commitment_sha256",
    )
    unsigned = {
        key: value
        for key, value in document.items()
        if key != "implementation_commitment_sha256"
    }
    if _canonical_sha256(unsigned) != commitment:
        raise CorrectedDirect12Error("historical implementation commitment differs")
    if not SHA256_RE.fullmatch(implementation_sha256):
        raise CorrectedDirect12Error("historical implementation file pin differs")
    return commitment


def _validate_historical_commitment_chain(
    *,
    documents: Mapping[str, Mapping[str, object]],
    member_pins: Mapping[str, str],
    a355: Mapping[str, object],
    a356_measurement: Mapping[str, object],
    a356_order: Mapping[str, object],
    a355_result_member: str,
    a356_measurement_member: str,
) -> dict[str, object]:
    a355_design = documents[A355_DESIGN_MEMBER]
    a355_implementation = documents[A355_IMPLEMENTATION_MEMBER]
    a356_design = documents[A356_DESIGN_MEMBER]
    a356_implementation = documents[A356_IMPLEMENTATION_MEMBER]
    a355_design_sha = member_pins[A355_DESIGN_MEMBER]
    a355_implementation_sha = member_pins[A355_IMPLEMENTATION_MEMBER]
    a356_design_sha = member_pins[A356_DESIGN_MEMBER]
    a356_implementation_sha = member_pins[A356_IMPLEMENTATION_MEMBER]
    if a355_design.get("schema") != (
        "chacha20-round20-w46-corrected-group-direct12-reader-a355-design-v1"
    ) or a356_design.get("schema") != (
        "chacha20-round20-w46-corrected-group-a345-transfer-a356-design-v1"
    ):
        raise CorrectedDirect12Error("historical design schema differs")
    for design_name, design in (("A355", a355_design), ("A356", a356_design)):
        anchors = _mapping(design.get("source_anchors"), f"{design_name}.source_anchors")
        for key, path in anchors.items():
            if not key.endswith("_path") or not isinstance(path, str):
                continue
            pin = member_pins.get(path)
            if pin is not None and anchors.get(f"{key[:-5]}_sha256") != pin:
                raise CorrectedDirect12Error(
                    f"{design_name} source anchor differs for {path}"
                )
    a355_implementation_commitment = _validate_implementation_document(
        a355_implementation,
        schema="chacha20-round20-w46-corrected-group-direct12-reader-a355-implementation-v1",
        design_sha256=a355_design_sha,
        implementation_sha256=a355_implementation_sha,
    )
    a356_implementation_commitment = _validate_implementation_document(
        a356_implementation,
        schema="chacha20-round20-w46-corrected-group-a345-transfer-a356-implementation-v1",
        design_sha256=a356_design_sha,
        implementation_sha256=a356_implementation_sha,
    )
    if (
        a355.get("design_sha256") != a355_design_sha
        or a355.get("implementation_sha256") != a355_implementation_sha
        or a355.get("implementation_commitment_sha256")
        != a355_implementation_commitment
    ):
        raise CorrectedDirect12Error("A355 design/implementation chain differs")
    a355_summary = _validate_measurement_summary(
        a355.get("measurement_summary"), attempt_id="A355"
    )
    a355_measurement_commitment = _canonical_sha256(
        {
            "summary": a355_summary,
            "ledger": a355.get("measurement_ledger"),
        }
    )
    if a355.get("measurement_sha256") != a355_measurement_commitment:
        raise CorrectedDirect12Error("A355 measurement commitment differs")
    scoring_contract = _mapping(
        a355_design.get("scoring_contract"), "A355.design.scoring_contract"
    )
    a355_selection_commitment = _canonical_sha256(
        {
            "selection_rule": scoring_contract.get("primary_selection"),
            "tie_break": scoring_contract.get("selection_tie_break"),
            "confirmed_prefix12": a355.get("confirmed_prefix12"),
            "rank_panel": a355.get("rank_panel"),
            "selected_view": a355.get("selected_view"),
        }
    )
    if a355.get("selection_commitment_sha256") != a355_selection_commitment:
        raise CorrectedDirect12Error("A355 selection commitment differs")

    if (
        a356_measurement.get("design_sha256") != a356_design_sha
        or a356_measurement.get("implementation_sha256") != a356_implementation_sha
        or a356_measurement.get("implementation_commitment_sha256")
        != a356_implementation_commitment
    ):
        raise CorrectedDirect12Error("A356 design/implementation chain differs")
    if a356_measurement.get("evidence_stage") != (
        "PRE_A345_RESULT_COMPLETE_UNLABELED_CORRECTED_GROUP_MEASUREMENT"
    ):
        raise CorrectedDirect12Error("A356 measurement evidence stage differs")
    a356_summary = _validate_measurement_summary(
        a356_measurement.get("measurement_summary"), attempt_id="A356"
    )
    challenge_sha = _sha256(
        a356_measurement.get("A345_public_challenge_sha256"),
        "A345_public_challenge_sha256",
    )
    design_anchors = _mapping(
        a356_design.get("source_anchors"), "A356.design.source_anchors"
    )
    if design_anchors.get("A345_public_challenge_sha256") != challenge_sha:
        raise CorrectedDirect12Error("A356 public challenge chain differs")
    a356_measurement_commitment = _canonical_sha256(
        {
            "evidence_stage": a356_measurement.get("evidence_stage"),
            "A345_public_challenge_sha256": challenge_sha,
            "measurement_summary": a356_summary,
            "measurement_ledger": a356_measurement.get("measurement_ledger"),
            "synthetic_reader_mapping_sha256": a356_measurement.get(
                "synthetic_reader_mapping_sha256"
            ),
        }
    )
    if (
        a356_measurement.get("measurement_commitment_sha256")
        != a356_measurement_commitment
    ):
        raise CorrectedDirect12Error("A356 measurement commitment differs")
    if a356_order.get("evidence_stage") != (
        "PRE_A345_RESULT_ZERO_REFIT_CORRECTED_GROUP_ORDER_FROZEN"
    ):
        raise CorrectedDirect12Error("A356 order evidence stage differs")
    if (
        a356_order.get("design_sha256") != a356_design_sha
        or a356_order.get("implementation_sha256") != a356_implementation_sha
        or a356_order.get("implementation_commitment_sha256")
        != a356_implementation_commitment
        or a356_order.get("measurement_sha256")
        != member_pins[a356_measurement_member]
        or a356_order.get("measurement_commitment_sha256")
        != a356_measurement_commitment
        or a356_order.get("A355_result_sha256")
        != member_pins[a355_result_member]
        or a356_order.get("A355_selection_commitment_sha256")
        != a355_selection_commitment
    ):
        raise CorrectedDirect12Error("A356 order source chain differs")
    order_commitment = _canonical_sha256(
        {
            "evidence_stage": a356_order.get("evidence_stage"),
            "A345_public_challenge_sha256": challenge_sha,
            "measurement_commitment_sha256": a356_measurement_commitment,
            "A355_selection_commitment_sha256": a355_selection_commitment,
            "selected_view": a356_order.get("selected_view"),
            "selected_score_field_sha256": a356_order.get(
                "selected_score_field_sha256"
            ),
            "selected_order_uint16be_sha256": a356_order.get(
                "selected_order_uint16be_sha256"
            ),
            "target_labels_used": 0,
            "reader_refits": 0,
        }
    )
    if a356_order.get("order_commitment_sha256") != order_commitment:
        raise CorrectedDirect12Error("A356 order commitment differs")
    return {
        "schema": "o1-crypto-corrected-historical-commitment-chain-v1",
        "A355_measurement_commitment_sha256": a355_measurement_commitment,
        "A355_selection_commitment_sha256": a355_selection_commitment,
        "A356_measurement_commitment_sha256": a356_measurement_commitment,
        "A356_order_commitment_sha256": order_commitment,
        "all_internal_commitments_recomputed": True,
    }


@dataclass(frozen=True)
class SourceReceipt:
    member: str
    snapshot_member: str
    role: str
    sha256: str
    bytes: int

    def describe(self) -> dict[str, object]:
        return {
            "member": self.member,
            "snapshot_member": self.snapshot_member,
            "role": self.role,
            "sha256": self.sha256,
            "bytes": self.bytes,
        }


class PinnedSourceSnapshot:
    """Read each allowlisted sibling byte once, then write only into the capsule."""

    def __init__(
        self,
        root: Path,
        members: Sequence[Mapping[str, object]],
        *,
        writer: ArtifactWriter | None,
    ) -> None:
        if root.is_symlink():
            raise CorrectedDirect12Error("source repository root cannot be a symlink")
        resolved = root.resolve()
        if not resolved.is_dir():
            raise CorrectedDirect12Error("source repository must be a real directory")
        self.root = resolved
        self.writer = writer
        self._rows: dict[str, Mapping[str, object]] = {}
        self._bytes: dict[str, bytes] = {}
        self.receipts: list[SourceReceipt] = []
        for index, raw_row in enumerate(members):
            row = _mapping(raw_row, f"source.members[{index}]")
            member = _safe_member(row.get("path"), f"source.members[{index}].path")
            if member in self._rows:
                raise CorrectedDirect12Error(f"duplicate source member: {member}")
            role = row.get("role")
            if role not in {
                "mechanism",
                "measurements_unlabeled",
                "calibration_labeled",
                "deployment",
            }:
                raise CorrectedDirect12Error(f"invalid source role for {member}")
            _sha256(row.get("sha256"), f"source.members[{index}].sha256")
            size = _integer(row.get("bytes"), f"source.members[{index}].bytes")
            if size < 1:
                raise CorrectedDirect12Error("source byte count must be positive")
            self._rows[member] = row

    def _read_exact(
        self,
        member: str,
        *,
        sha256: str,
        size: int,
        role: str,
    ) -> bytes:
        path = self.root.joinpath(*PurePosixPath(member).parts)
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise CorrectedDirect12Error(f"source member is missing: {member}") from exc
        try:
            resolved.relative_to(self.root)
        except ValueError as exc:
            raise CorrectedDirect12Error(f"source member escapes repository: {member}") from exc
        if path.is_symlink() or not resolved.is_file():
            raise CorrectedDirect12Error(f"source member must be a regular file: {member}")
        raw = resolved.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if len(raw) != size or digest != sha256:
            raise CorrectedDirect12Error(f"source member differs from its pin: {member}")
        snapshot_member = f"source_snapshot/{role}/{member}"
        if self.writer is not None:
            self.writer(snapshot_member, raw)
        self.receipts.append(
            SourceReceipt(member, snapshot_member, role, digest, len(raw))
        )
        return raw

    def read(self, member: str) -> bytes:
        member = _safe_member(member, "source member")
        if member in self._bytes:
            return self._bytes[member]
        try:
            row = self._rows[member]
        except KeyError as exc:
            raise CorrectedDirect12Error(f"member is not predeclared: {member}") from exc
        raw = self._read_exact(
            member,
            sha256=str(row["sha256"]),
            size=int(row["bytes"]),
            role=str(row["role"]),
        )
        self._bytes[member] = raw
        return raw

    def read_dynamic_shard(
        self,
        row: Mapping[str, object],
        *,
        required_prefix: str,
    ) -> bytes:
        member = _safe_member(row.get("path"), "measurement_ledger.path")
        if not member.startswith(required_prefix) or not member.endswith(".json.zst"):
            raise CorrectedDirect12Error("measurement shard path differs from its dataset root")
        if member in self._bytes:
            raise CorrectedDirect12Error(f"measurement shard repeated: {member}")
        raw = self._read_exact(
            member,
            sha256=_sha256(row.get("compressed_sha256"), "compressed_sha256"),
            size=_integer(row.get("compressed_bytes"), "compressed_bytes"),
            role="measurements_unlabeled",
        )
        self._bytes[member] = raw
        return raw

    def descriptor(self) -> dict[str, object]:
        rows = [item.describe() for item in sorted(self.receipts, key=lambda item: item.member)]
        value = {
            "schema": SOURCE_SNAPSHOT_SCHEMA,
            "members": rows,
            "member_count": len(rows),
            "total_bytes": sum(item.bytes for item in self.receipts),
            "source_reads": len(rows),
            "sibling_repository_writes": 0,
            "capsule_snapshot_copies": len(rows) if self.writer is not None else 0,
            "active_progress_or_outcome_reads": 0,
        }
        value["snapshot_sha256"] = _canonical_sha256(value)
        return value


def _load_json(raw: bytes, field: str) -> Mapping[str, object]:
    try:
        return _mapping(json.loads(raw), field)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CorrectedDirect12Error(f"{field} is not valid UTF-8 JSON") from exc


def _source_mapping(preflight: Mapping[str, object], field: str) -> tuple[int, ...]:
    source = tuple(
        _integer(value, f"{field}.source_one_literals_bit0_upward")
        for value in _sequence(
            preflight.get("source_one_literals_bit0_upward"),
            f"{field}.source_one_literals_bit0_upward",
        )
    )
    if len(source) != 46 or len({abs(value) for value in source}) != 46:
        raise CorrectedDirect12Error(f"{field} source mapping is not a 46-variable bijection")
    if _canonical_sha256(list(source)) != _sha256(
        preflight.get("source_mapping_sha256"), f"{field}.source_mapping_sha256"
    ):
        raise CorrectedDirect12Error(f"{field} source mapping commitment differs")
    return source


def _corrected_mapping(source: Sequence[int]) -> tuple[int, ...]:
    return tuple(int(source[index]) for index in SYNTHETIC_SOURCE_INDICES)


def _fixed_units(source: Sequence[int], low4: int) -> tuple[int, ...]:
    if not 0 <= low4 < 16:
        raise CorrectedDirect12Error("low4 must be in 0..15")
    return tuple(
        int(source[coordinate])
        if (low4 >> (3 - offset)) & 1
        else -int(source[coordinate])
        for offset, coordinate in enumerate(LOW4_COORDINATES)
    )


def _legacy_channel_value(row: Mapping[str, object], channel: str) -> float:
    metrics = ("conflicts", "decisions", "search_propagations")
    if row.get("metric_names") != list(metrics):
        raise CorrectedDirect12Error("legacy reader metric order differs")
    if channel in metrics:
        values = _sequence(row.get("metrics_stage_delta"), "metrics_stage_delta")
        return float(values[metrics.index(channel)])
    if channel in {
        "learned_clause_length_mean",
        "learned_clause_length_std",
        "learned_clause_length_max",
    }:
        raw_lengths = _sequence(
            row.get("learned_clause_lengths_stage"),
            "learned_clause_lengths_stage",
        )
        lengths = np.asarray(raw_lengths, dtype=np.float64)
        if channel == "learned_clause_length_mean":
            return float(lengths.mean()) if len(lengths) else 0.0
        if channel == "learned_clause_length_std":
            return float(lengths.std()) if len(lengths) else 0.0
        return float(max(raw_lengths)) if raw_lengths else 0.0
    return _finite(row.get(channel), channel)


def _legacy_shape_vector(channel_values: Mapping[str, np.ndarray]) -> np.ndarray:
    values: list[float] = []
    for channel in RAW_CHANNELS:
        raw = np.asarray(channel_values[channel], dtype=np.float64)
        scale = float(np.abs(raw).sum())
        profile = raw / scale if scale > 0.0 else np.zeros(4, dtype=np.float64)
        values.extend(profile)
        values.extend(np.diff(profile))
        values.extend(np.diff(profile, n=2))
    for numerator, denominator in SIGNED_RATIO_PAIRS:
        left = np.asarray(channel_values[numerator], dtype=np.float64)
        right = np.asarray(channel_values[denominator], dtype=np.float64)
        scale = np.abs(left) + np.abs(right)
        ratio = np.divide(
            left - right,
            scale,
            out=np.zeros_like(left),
            where=scale > 0.0,
        )
        values.extend(ratio)
    result = np.asarray(values, dtype=np.float64)
    if result.shape != (len(BASE_FEATURE_NAMES),) or not np.isfinite(result).all():
        raise CorrectedDirect12Error("legacy 133-feature vector differs")
    return result


def _legacy_orbit_matrix(base: np.ndarray) -> np.ndarray:
    if base.shape != (256, len(BASE_FEATURE_NAMES)):
        raise CorrectedDirect12Error("legacy reader base matrix differs")
    means = base.mean(axis=0)
    scales = base.std(axis=0)
    constant = scales <= np.maximum(1e-12, np.abs(means) * 1e-12)
    scales[constant] = 1.0
    standardized = (base - means) / scales
    standardized[:, constant] = 0.0
    neighbors = np.stack(
        [
            standardized[np.arange(256, dtype=np.uint16) ^ (1 << bit)]
            for bit in range(8)
        ],
        axis=1,
    )
    differences = standardized[:, None, :] - neighbors
    result = np.stack(
        (
            standardized,
            differences.mean(axis=1),
            np.sqrt(np.mean(np.square(differences), axis=1)),
            np.max(np.abs(differences), axis=1),
        ),
        axis=2,
    ).reshape(256, -1)
    if result.shape != (256, len(FEATURE_NAMES)) or not np.isfinite(result).all():
        raise CorrectedDirect12Error("legacy 532-feature orbit differs")
    return result


def _legacy_selected8_scores(
    measurement: Mapping[str, object],
    *,
    means: Sequence[float],
    scales: Sequence[float],
    coefficients: Sequence[float],
    indices: Sequence[int],
) -> tuple[float, ...]:
    run = _mapping(measurement.get("run"), "measurement.run")
    stage_rows = _sequence(run.get("stages"), "measurement.run.stages")
    rows = {
        (
            int(str(_mapping(raw, "stage")["prefix8"]), 2),
            _integer(_mapping(raw, "stage").get("horizon"), "stage.horizon"),
        ): _mapping(raw, "stage")
        for raw in stage_rows
    }
    expected = {(candidate, horizon) for candidate in range(256) for horizon in HORIZONS}
    if set(rows) != expected:
        raise CorrectedDirect12Error("legacy stage cover differs")
    base = np.empty((256, len(BASE_FEATURE_NAMES)), dtype=np.float64)
    for candidate in range(256):
        channel_values = {
            channel: np.asarray(
                [
                    _legacy_channel_value(rows[(candidate, horizon)], channel)
                    for horizon in HORIZONS
                ],
                dtype=np.float64,
            )
            for channel in RAW_CHANNELS
        }
        base[candidate] = _legacy_shape_vector(channel_values)
    matrix = _legacy_orbit_matrix(base)
    center = np.asarray(means, dtype=np.float64)
    scale = np.asarray(scales, dtype=np.float64)
    coefficient = np.asarray(coefficients, dtype=np.float64)
    if (
        center.shape != (532,)
        or scale.shape != (532,)
        or coefficient.shape != (532,)
        or np.any(scale <= 0.0)
    ):
        raise CorrectedDirect12Error("frozen model geometry differs")
    contributions = ((matrix - center) / scale) * coefficient
    selected = contributions[:, np.asarray(tuple(indices), dtype=np.int64)].sum(axis=1)
    if selected.shape != (256,) or not np.isfinite(selected).all():
        raise CorrectedDirect12Error("legacy selected8 scores differ")
    return tuple(float(value) for value in selected)


@dataclass(frozen=True)
class CorrectedField:
    attempt_id: str
    scores: tuple[float, ...]
    historical_field_sha256: str
    walsh_field_sha256: str
    order: tuple[int, ...]
    order_uint16be_sha256: str
    measurement_shards: int
    raw_measurement_bytes: int
    compressed_measurement_bytes: int
    synthetic_mapping_sha256: str

    def describe(self, *, include_scores: bool = False) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": "o1-crypto-corrected-score-field-v1",
            "attempt_id": self.attempt_id,
            "reader": SELECTED_READER,
            "historical_field_sha256": self.historical_field_sha256,
            "walsh_float64be_field_sha256": self.walsh_field_sha256,
            "order_uint16be_sha256": self.order_uint16be_sha256,
            "measurement_shards": self.measurement_shards,
            "cells": len(self.scores),
            "solver_stages": len(self.scores) * len(HORIZONS),
            "raw_measurement_bytes": self.raw_measurement_bytes,
            "compressed_measurement_bytes": self.compressed_measurement_bytes,
            "synthetic_mapping_sha256": self.synthetic_mapping_sha256,
            "target_labels_used_for_scoring": 0,
        }
        if include_scores:
            value["scores"] = list(self.scores)
            value["order"] = list(self.order)
        value["field_document_sha256"] = _canonical_sha256(value)
        return value


def _validate_ledger(value: object, attempt_id: str) -> tuple[Mapping[str, object], ...]:
    rows = tuple(
        _mapping(row, f"{attempt_id}.measurement_ledger[{index}]")
        for index, row in enumerate(_sequence(value, f"{attempt_id}.measurement_ledger"))
    )
    low4_values = tuple(
        _integer(row.get("low4"), f"{attempt_id}.measurement_ledger.low4")
        for row in rows
    )
    if len(rows) != 16 or low4_values != tuple(range(16)):
        raise CorrectedDirect12Error(f"{attempt_id} ledger must cover low4 0..15")
    for row in rows:
        if row.get("resumed") is not False:
            raise CorrectedDirect12Error(f"{attempt_id} resumed shard is outside the corpus")
        _sha256(row.get("compressed_sha256"), "compressed_sha256")
        _sha256(row.get("raw_sha256"), "raw_sha256")
        if _integer(row.get("compressed_bytes"), "compressed_bytes") < 1:
            raise CorrectedDirect12Error("compressed byte count must be positive")
        if _integer(row.get("raw_bytes"), "raw_bytes") < 1:
            raise CorrectedDirect12Error("raw byte count must be positive")
    return rows


def _decode_shard(
    compressed: bytes,
    row: Mapping[str, object],
    decoder: BoundedZstdDecoder,
) -> Mapping[str, object]:
    raw_bytes = _integer(row.get("raw_bytes"), "raw_bytes")
    try:
        raw = decoder.decode(compressed, max_output_bytes=raw_bytes)
    except Stage3Error as exc:
        raise CorrectedDirect12Error(str(exc)) from exc
    if len(raw) != raw_bytes or hashlib.sha256(raw).hexdigest() != row.get("raw_sha256"):
        raise CorrectedDirect12Error("decoded shard differs from its raw ledger")
    value = _load_json(raw, "measurement shard")
    if _canonical_bytes(value) != raw:
        raise CorrectedDirect12Error("measurement shard is not canonical JSON")
    return value


def _load_corrected_field(
    *,
    attempt_id: str,
    metadata: Mapping[str, object],
    source_mapping: Sequence[int],
    snapshot: PinnedSourceSnapshot,
    decoder: BoundedZstdDecoder,
    means: Sequence[float],
    scales: Sequence[float],
    coefficients: Sequence[float],
    indices: Sequence[int],
    schema_key: str,
    shard_prefix: str,
    expected_field_sha256: str,
    expected_order_sha256: str,
) -> CorrectedField:
    ledger = _validate_ledger(metadata.get("measurement_ledger"), attempt_id)
    corrected = _corrected_mapping(source_mapping)
    mapping_sha = _canonical_sha256(list(corrected))
    declared_mapping = (
        _mapping(metadata.get("coordinate_contract"), "coordinate_contract").get(
            "synthetic_reader_mapping_sha256"
        )
        if attempt_id == "A355"
        else metadata.get("synthetic_reader_mapping_sha256")
    )
    if mapping_sha != _sha256(declared_mapping, "synthetic_reader_mapping_sha256"):
        raise CorrectedDirect12Error(f"{attempt_id} corrected mapping hash differs")
    expected_variables = tuple(abs(int(source_mapping[index])) for index in HIGH8_COORDINATES)
    scores = [0.0] * DIRECT12_SIZE
    total_raw = 0
    total_compressed = 0
    for low4, row in enumerate(ledger):
        compressed = snapshot.read_dynamic_shard(row, required_prefix=shard_prefix)
        measurement = _decode_shard(compressed, row, decoder)
        if attempt_id == "A356" and measurement.get(
            "selected_A355_view_available_to_measurement"
        ) is not False:
            raise CorrectedDirect12Error(
                "A356 selected A355 view was available during measurement"
            )
        try:
            Direct12Adapter._validate_run_and_extract(
                measurement,
                attempt_id=attempt_id,
                schema_key=schema_key,
                slice_id=f"slice_{low4:02x}",
                low4=low4,
                expected_assumption_variables=expected_variables,
                expected_fixed_unit_literals=_fixed_units(source_mapping, low4),
            )
        except Direct12Error as exc:
            raise CorrectedDirect12Error(str(exc)) from exc
        local = _legacy_selected8_scores(
            measurement,
            means=means,
            scales=scales,
            coefficients=coefficients,
            indices=indices,
        )
        for high8, score in enumerate(local):
            scores[(high8 << 4) | low4] = score
        total_raw += int(row["raw_bytes"])
        total_compressed += int(row["compressed_bytes"])
    frozen_scores = tuple(scores)
    historical_sha = _historical_field_sha256(frozen_scores)
    order = direct12_order(frozen_scores)
    order_sha = direct12_order_uint16be_sha256(order)
    if historical_sha != expected_field_sha256:
        raise CorrectedDirect12Error(f"{attempt_id} historical score field was not reproduced")
    if order_sha != expected_order_sha256:
        raise CorrectedDirect12Error(f"{attempt_id} historical order was not reproduced")
    return CorrectedField(
        attempt_id=attempt_id,
        scores=frozen_scores,
        historical_field_sha256=historical_sha,
        walsh_field_sha256=score_field_sha256(frozen_scores),
        order=order,
        order_uint16be_sha256=order_sha,
        measurement_shards=len(ledger),
        raw_measurement_bytes=total_raw,
        compressed_measurement_bytes=total_compressed,
        synthetic_mapping_sha256=mapping_sha,
    )


def _top_fraction(execution: AdaptiveDCExecution, k: int) -> float:
    rows = execution.evaluation.top_k_overlap
    for row in rows:
        if row.k == k:
            return row.fraction
    raise CorrectedDirect12Error(f"missing top-{k} metric")


def _matched_direct_quantized_table(
    execution: AdaptiveDCExecution,
    scores: Sequence[float],
) -> dict[str, object]:
    direct_scores = tuple(
        execution.plan.slot_scales[address & 0xF]
        * _quantize(
            float(score),
            execution.plan.slot_scales[address & 0xF],
            execution.plan.quantizer_max,
        )[0]
        for address, score in enumerate(scores)
    )
    if direct_scores != execution.frozen.reconstruct():
        raise CorrectedDirect12Error(
            "full-basis Walsh register differs from its direct quantized-table inverse"
        )
    payload_bytes = (DIRECT12_SIZE * execution.plan.input_bits + 7) // 8
    online_bytes = (
        payload_bytes
        + execution.plan.serialized_coverage_bytes
        + execution.plan.serialized_clip_telemetry_bytes
    )
    maximum_logical_bytes = (
        online_bytes
        + execution.plan.serialized_static_plan_bytes
        + PASS_INTEGRITY_LOGICAL_STATE_BYTES
    )
    return {
        "schema": "o1-crypto-matched-direct-quantized-table-baseline-v1",
        "representation": "candidate-indexed-packed-signed-quantized-values",
        "candidate_values": DIRECT12_SIZE,
        "input_bits": execution.plan.input_bits,
        "serialized_value_payload_bytes": payload_bytes,
        "serialized_online_state_bytes": online_bytes,
        "maximum_serialized_logical_mechanism_state_bytes": maximum_logical_bytes,
        "order_uint16be_sha256": execution.order_uint16be_sha256,
        "evaluation_identical_to_full_basis_spectral_register": True,
        "explicit_candidate_indexed_table": True,
        "mechanism_claim_eligible": False,
    }


def _global_z_atan(scores: Sequence[float], bound: float) -> tuple[float, ...]:
    mean = math.fsum(scores) / len(scores)
    variance = math.fsum((value - mean) ** 2 for value in scores) / len(scores)
    scale = math.sqrt(variance)
    if scale <= max(1e-12, abs(mean) * 1e-12):
        raise CorrectedDirect12Error("global-z control has zero variance")
    return tuple(
        bound * (2.0 / math.pi) * math.atan((value - mean) / scale)
        for value in scores
    )


@dataclass(frozen=True)
class CorrectedBridgeResult:
    report: Mapping[str, object]
    source_snapshot: Mapping[str, object]
    fields: tuple[CorrectedField, ...]
    adaptive_executions: Mapping[str, Mapping[str, AdaptiveDCExecution]]
    fixed_controls: Mapping[str, Mapping[str, object]]
    fixed_control_orders: Mapping[str, Mapping[str, tuple[int, ...]]]
    future_template: Mapping[str, object]
    success_gate_passed: bool

    def metrics(self) -> dict[str, object]:
        return {
            "schema": "o1-crypto-corrected-codec-bridge-metrics-v1",
            "success_gate_passed": self.success_gate_passed,
            "selected_arm": self.report["selection"]["selected_arm"],  # type: ignore[index]
            "fields": {
                field.attempt_id: field.describe() for field in self.fields
            },
            "selection": self.report["selection"],
            "source_snapshot": {
                "snapshot_sha256": self.source_snapshot["snapshot_sha256"],
                "members": self.source_snapshot[
                    "total_member_count_with_local_anchors"
                ],
                "bytes": self.source_snapshot["total_bytes_with_local_anchors"],
            },
            "costs": self.report["costs"],
            "labels": self.report["labels"],
        }


def run_corrected_codec_bridge(
    config_path: Path,
    *,
    lab_root: Path,
    artifact_writer: ArtifactWriter | None = None,
) -> CorrectedBridgeResult:
    requested_config = config_path
    try:
        config_path = config_path.resolve(strict=True)
        expected_config = (
            lab_root.resolve(strict=True) / "configs/corrected_codec_bridge_v1.json"
        ).resolve(strict=True)
    except OSError as exc:
        raise CorrectedDirect12Error("corrected bridge config path is missing") from exc
    if requested_config.is_symlink() or not config_path.is_file() or config_path != expected_config:
        raise CorrectedDirect12Error("corrected bridge requires its canonical lab config")
    config = _load_json(config_path.read_bytes(), "config")
    if config.get("schema") != SCHEMA or config.get("attempt_id") != "O1C-0006":
        raise CorrectedDirect12Error("corrected bridge config identity differs")

    source_config = _mapping(config.get("source"), "config.source")
    requested_source_root = lab_root / str(source_config.get("repository"))
    if requested_source_root.is_symlink():
        raise CorrectedDirect12Error("source repository root cannot be a symlink")
    source_root = requested_source_root.resolve()
    members = tuple(
        _mapping(row, f"source.members[{index}]")
        for index, row in enumerate(_sequence(source_config.get("members"), "source.members"))
    )
    member_pins = {
        str(row["path"]): _sha256(row.get("sha256"), f"source pin {row['path']}")
        for row in members
    }
    snapshot = PinnedSourceSnapshot(
        source_root,
        members,
        writer=artifact_writer,
    )
    # Consume every predeclared dependency before scoring.  This makes the
    # capsule a complete byte-for-byte source snapshot rather than a JSON-only
    # reconstruction whose Python mechanisms still live in the sibling tree.
    source_bytes = {
        str(row["path"]): snapshot.read(str(row["path"])) for row in members
    }
    direct_documents = {
        path: _load_json(raw, path)
        for path, raw in source_bytes.items()
        if path.endswith(".json")
    }

    anchors = _mapping(config.get("anchors"), "config.anchors")
    o1c3 = (lab_root / str(anchors.get("o1c_0003_capsule"))).resolve()
    o1c5 = (lab_root / str(anchors.get("o1c_0005_capsule"))).resolve()
    manager = RunCapsuleManager(lab_root)
    for name, capsule, expected in (
        ("O1C-0003", o1c3, anchors.get("o1c_0003_manifest_sha256")),
        ("O1C-0005", o1c5, anchors.get("o1c_0005_manifest_sha256")),
    ):
        verification = manager.verify(capsule)
        if not verification.ok or verification.manifest_sha256 != _sha256(
            expected, f"{name} manifest"
        ):
            raise CorrectedDirect12Error(f"{name} immutable capsule verification failed")

    o1c3_prefix = o1c3 / "artifacts/source_snapshot"
    a268_path = o1c3_prefix / A268_PREFLIGHT
    a272_path = o1c3_prefix / A272_PROTOCOL
    future_path = o1c5 / str(anchors.get("o1c_0005_future_plan_member"))
    local_sources = (
        ("immutable_o1c3/A268_preflight.json", a268_path, anchors.get("a268_sha256")),
        ("immutable_o1c3/A272_protocol.json", a272_path, anchors.get("a272_protocol_sha256")),
        ("immutable_o1c5/o1o_frozen_future_plan.json", future_path, anchors.get("o1c_0005_future_plan_sha256")),
    )
    local_bytes: dict[str, bytes] = {}
    for snapshot_member, path, expected in local_sources:
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != _sha256(expected, snapshot_member):
            raise CorrectedDirect12Error(f"immutable local anchor differs: {snapshot_member}")
        local_bytes[snapshot_member] = raw
        if artifact_writer is not None:
            artifact_writer(f"source_snapshot/{snapshot_member}", raw)

    a268 = _load_json(local_bytes["immutable_o1c3/A268_preflight.json"], "A268")
    protocol = _load_json(local_bytes["immutable_o1c3/A272_protocol.json"], "A272")
    frozen_model = _mapping(a268.get("frozen_model"), "A268.frozen_model")
    model = _mapping(frozen_model.get("model"), "A268.frozen_model.model")
    if frozen_model.get("model_sha256") != anchors.get("model_sha256"):
        raise CorrectedDirect12Error("A268 model commitment differs")
    selected = _mapping(protocol.get("selected_hypothesis"), "A272.selected_hypothesis")
    indices = tuple(int(value) for value in _sequence(selected.get("feature_indices"), "feature_indices"))
    if indices != EXPECTED_INDICES or selected.get("mode") != "direct_additive_contribution":
        raise CorrectedDirect12Error("A340 selected8 reader identity differs")
    means = tuple(float(value) for value in _sequence(model.get("means"), "model.means"))
    scales = tuple(float(value) for value in _sequence(model.get("scales"), "model.scales"))
    coefficients = tuple(
        float(value) for value in _sequence(model.get("coefficients"), "model.coefficients")
    )
    if not (len(means) == len(scales) == len(coefficients) == 532):
        raise CorrectedDirect12Error("A268 model must contain 532 aligned values")

    paths = _mapping(source_config.get("roles"), "source.roles")
    a340 = direct_documents[str(paths["a340_preflight"])]
    a349 = direct_documents[str(paths["a349_preflight"])]
    a355 = direct_documents[str(paths["a355_result"])]
    a356_measurement = direct_documents[str(paths["a356_measurement"])]
    a356_order = direct_documents[str(paths["a356_order"])]
    a355_mapping = _source_mapping(a340, "A340")
    a356_mapping = _source_mapping(a349, "A349")

    expected = _mapping(config.get("expected"), "config.expected")
    if np.__version__ != expected.get("numpy_version"):
        raise CorrectedDirect12Error("NumPy version differs from the legacy scorer pin")
    if a355.get("schema") != "chacha20-round20-w46-corrected-group-direct12-reader-a355-v1":
        raise CorrectedDirect12Error("A355 result schema differs")
    if a356_measurement.get("schema") != "chacha20-round20-w46-corrected-group-a345-transfer-a356-measurement-v1":
        raise CorrectedDirect12Error("A356 measurement schema differs")
    if a356_order.get("schema") != "chacha20-round20-w46-corrected-group-a345-transfer-a356-order-v1":
        raise CorrectedDirect12Error("A356 order schema differs")
    if a356_measurement.get("measurement_summary") != a356_order.get("measurement_gate"):
        raise CorrectedDirect12Error("A356 measurement/order gate differs")
    commitment_chain = _validate_historical_commitment_chain(
        documents=direct_documents,
        member_pins=member_pins,
        a355=a355,
        a356_measurement=a356_measurement,
        a356_order=a356_order,
        a355_result_member=str(paths["a355_result"]),
        a356_measurement_member=str(paths["a356_measurement"]),
    )
    if (
        a356_order.get("target_labels_used") != 0
        or a356_order.get("reader_refits") != 0
        or a356_order.get("candidate_assignments_executed") != 0
        or a356_order.get("A345_result_available_at_order_freeze") is not False
        or a356_order.get("A345_candidate_or_prefix_read_before_order_freeze") is not False
    ):
        raise CorrectedDirect12Error("A356 prospective information boundary differs")
    if (
        a356_order.get("A355_selection_commitment_sha256")
        != a355.get("selection_commitment_sha256")
        or a356_order.get("selected_view") != a355.get("selected_view")
        or _mapping(a355.get("selected_view"), "A355.selected_view").get("name")
        != SELECTED_READER
    ):
        raise CorrectedDirect12Error("A355-to-A356 selected reader transfer differs")
    a355_historical_field_sha = _sha256(
        _mapping(a355.get("score_field_sha256"), "A355.score_field_sha256").get(
            SELECTED_READER
        ),
        "A355 selected score field",
    )
    a356_historical_field_sha = _sha256(
        a356_order.get("selected_score_field_sha256"),
        "A356 selected score field",
    )
    a355_historical_order_sha = _sha256(
        _mapping(a355.get("selected_view"), "A355.selected_view").get(
            "order_uint16be_sha256"
        ),
        "A355 selected order",
    )
    a356_historical_order_sha = _sha256(
        a356_order.get("selected_order_uint16be_sha256"),
        "A356 selected order",
    )
    for field_name, configured, historical in (
        ("A355 field", expected.get("a355_field_sha256"), a355_historical_field_sha),
        ("A355 order", expected.get("a355_order_sha256"), a355_historical_order_sha),
        ("A356 field", expected.get("a356_field_sha256"), a356_historical_field_sha),
        ("A356 order", expected.get("a356_order_sha256"), a356_historical_order_sha),
    ):
        if _sha256(configured, field_name) != historical:
            raise CorrectedDirect12Error(f"{field_name} config/artifact commitment differs")

    decoder = BoundedZstdDecoder()
    fields = (
        _load_corrected_field(
            attempt_id="A355",
            metadata=a355,
            source_mapping=a355_mapping,
            snapshot=snapshot,
            decoder=decoder,
            means=means,
            scales=scales,
            coefficients=coefficients,
            indices=indices,
            schema_key="A355_MEASUREMENT",
            shard_prefix="research/results/v1/chacha20_round20_w46_corrected_group_direct12_reader_a355_v1/",
            expected_field_sha256=a355_historical_field_sha,
            expected_order_sha256=a355_historical_order_sha,
        ),
        _load_corrected_field(
            attempt_id="A356",
            metadata=a356_measurement,
            source_mapping=a356_mapping,
            snapshot=snapshot,
            decoder=decoder,
            means=means,
            scales=scales,
            coefficients=coefficients,
            indices=indices,
            schema_key="A356_MEASUREMENT",
            shard_prefix="research/results/v1/chacha20_round20_w46_corrected_group_a345_transfer_a356_v1/",
            expected_field_sha256=a356_historical_field_sha,
            expected_order_sha256=a356_historical_order_sha,
        ),
    )
    if tuple(a355.get("orders", {}).get(SELECTED_READER, ())) != fields[0].order:
        raise CorrectedDirect12Error("A355 published selected order differs")
    if tuple(a356_order.get("selected_order", ())) != fields[1].order:
        raise CorrectedDirect12Error("A356 published selected order differs")

    future = _load_json(
        local_bytes["immutable_o1c5/o1o_frozen_future_plan.json"],
        "O1C-0005 future plan",
    )
    original_arm = QuantizedArm.from_template(
        _mapping(future.get("selected_template"), "O1C-0005 selected_template")
    )
    raw_top_ks = _sequence(
        _mapping(config.get("tournament"), "config.tournament").get("top_ks"),
        "tournament.top_ks",
    )
    if any(isinstance(value, bool) or not isinstance(value, int) for value in raw_top_ks):
        raise CorrectedDirect12Error("tournament top-k values must be exact integers")
    top_ks = tuple(raw_top_ks)
    if top_ks != (1, 8, 32, 128, 512):
        raise CorrectedDirect12Error("tournament top-k panel differs from its freeze")
    fixed_controls: dict[str, dict[str, object]] = {}
    fixed_control_orders: dict[str, dict[str, tuple[int, ...]]] = {}
    literal_raw_abs_spearman: list[float] = []
    literal_raw_top32: list[float] = []
    for field in fields:
        raw_execution = original_arm.execute(field.scores, top_ks=top_ks)
        bound = min(original_arm.slot_scales) * 7.0
        atan_scores = _global_z_atan(field.scores, bound)
        atan_execution = original_arm.execute(atan_scores, top_ks=top_ks)
        raw_description = raw_execution.describe(include_plan=False)
        raw_description["historical_o1c5_template_o1o_eligible"] = (
            raw_description.pop("o1o_eligible")
        )
        raw_description["o1c_0006_selection_eligible"] = False
        atan_description = atan_execution.describe(include_plan=False)
        atan_description["historical_o1c5_template_o1o_eligible"] = (
            atan_description.pop("o1o_eligible")
        )
        atan_description["o1c_0006_selection_eligible"] = False
        atan_description["compression_mechanism_claim_eligible"] = False
        fixed_controls[field.attempt_id] = {
            "frozen_o1c5_raw_identity": raw_description,
            "global_z_atan_control": atan_description,
            "global_z_atan_input_contract_valid": False,
            "reason": "global raw slots are not per-low4 centered; O1C-0005 omits DC",
        }
        fixed_control_orders[field.attempt_id] = {
            "frozen-o1c5-raw-identity": raw_execution.order,
            "global-z-atan-invalid-contract": atan_execution.order,
        }
        literal_raw_abs_spearman.append(
            abs(float(raw_execution.evaluation["rank_spearman"]))
        )
        literal_raw_top32.append(
            next(
                float(row["fraction"])
                for row in raw_execution.evaluation["top_k_overlap"]
                if row["k"] == 32
            )
        )

    negative_gates = _mapping(
        config.get("negative_control_gates"), "config.negative_control_gates"
    )
    literal_raw_maximum_abs_spearman = max(literal_raw_abs_spearman)
    literal_raw_maximum_top32 = max(literal_raw_top32)
    literal_o1c5_failure_verified = (
        literal_raw_maximum_abs_spearman
        <= _finite(
            negative_gates.get("maximum_literal_o1c5_absolute_spearman"),
            "maximum_literal_o1c5_absolute_spearman",
        )
        and literal_raw_maximum_top32
        <= _finite(
            negative_gates.get("maximum_literal_o1c5_top32_overlap"),
            "maximum_literal_o1c5_top32_overlap",
        )
    )

    tournament = _mapping(config.get("tournament"), "config.tournament")
    raw_bits = _sequence(tournament.get("adaptive_input_bits"), "adaptive_input_bits")
    raw_headrooms = _sequence(
        tournament.get("headroom_factors"), "headroom_factors"
    )
    if any(isinstance(value, bool) or not isinstance(value, int) for value in raw_bits):
        raise CorrectedDirect12Error("adaptive input bits must be exact integers")
    if any(not isinstance(value, float) for value in raw_headrooms):
        raise CorrectedDirect12Error("adaptive headrooms must be exact JSON floats")
    bits = tuple(raw_bits)
    headrooms = tuple(raw_headrooms)
    if (
        tuple(sorted(set(bits))) != bits
        or tuple(sorted(set(headrooms))) != headrooms
        or not bits
        or not headrooms
    ):
        raise CorrectedDirect12Error("adaptive tournament grid must be unique and sorted")
    if _mapping(tournament.get("selection_rule"), "tournament.selection_rule") != FROZEN_SELECTION_RULE:
        raise CorrectedDirect12Error("adaptive selection rule differs from its freeze")
    budgets = _mapping(config.get("budgets"), "config.budgets")
    gates = _mapping(tournament.get("gates"), "tournament.gates")
    if (
        len(bits) * len(headrooms)
        > _integer(budgets.get("maximum_adaptive_arms"), "maximum_adaptive_arms")
        or _integer(
            budgets.get("maximum_source_passes_per_arm_per_field"),
            "maximum_source_passes_per_arm_per_field",
        )
        != 2
        or _integer(budgets.get("maximum_new_solver_calls"), "maximum_new_solver_calls")
        != 0
        or _integer(budgets.get("maximum_gpu_seconds"), "maximum_gpu_seconds") != 0
        or _integer(
            budgets.get("maximum_target_labels_for_bridge_selection"),
            "maximum_target_labels_for_bridge_selection",
        )
        != 0
        or _integer(gates.get("maximum_online_state_bytes"), "maximum_online_state_bytes")
        != _integer(
            budgets.get("maximum_online_state_bytes"), "budget.maximum_online_state_bytes"
        )
        or _integer(
            gates.get("maximum_serialized_logical_mechanism_state_bytes"),
            "maximum_serialized_logical_mechanism_state_bytes",
        )
        != _integer(
            budgets.get("maximum_serialized_logical_mechanism_state_bytes"),
            "budget.maximum_serialized_logical_mechanism_state_bytes",
        )
    ):
        raise CorrectedDirect12Error("adaptive tournament differs from frozen budgets")
    executions: dict[str, dict[str, AdaptiveDCExecution]] = {}
    aggregate: list[dict[str, object]] = []
    for input_bits in bits:
        for headroom in headrooms:
            arm_id = f"adaptive-dc-{input_bits}bit-h{headroom:g}"
            template = AdaptiveDCTemplate(input_bits, headroom, name=arm_id)
            by_field = {
                field.attempt_id: execute_adaptive_dc(
                    field.scores,
                    template,
                    top_ks=top_ks,
                )
                for field in fields
            }
            executions[arm_id] = by_field
            min_spearman = min(item.evaluation.rank_spearman for item in by_field.values())
            min_kendall = min(item.evaluation.rank_kendall for item in by_field.values())
            min_top8 = min(_top_fraction(item, 8) for item in by_field.values())
            min_top32 = min(_top_fraction(item, 32) for item in by_field.values())
            min_top128 = min(_top_fraction(item, 128) for item in by_field.values())
            state_bytes = next(iter(by_field.values())).plan.serialized_online_state_bytes
            maximum_logical_state_bytes = next(
                iter(by_field.values())
            ).plan.maximum_serialized_logical_mechanism_state_bytes
            clips = sum(item.frozen.clip_count for item in by_field.values())
            eligible = (
                state_bytes
                <= _integer(gates.get("maximum_online_state_bytes"), "maximum_online_state_bytes")
                and maximum_logical_state_bytes
                <= _integer(
                    gates.get("maximum_serialized_logical_mechanism_state_bytes"),
                    "maximum_serialized_logical_mechanism_state_bytes",
                )
                and clips == 0
                and min_spearman
                >= _finite(gates.get("minimum_rank_spearman"), "minimum_rank_spearman")
                and min_kendall
                >= _finite(gates.get("minimum_rank_kendall"), "minimum_rank_kendall")
                and min_top32
                >= _finite(gates.get("minimum_top32_overlap"), "minimum_top32_overlap")
                and min_top128
                >= _finite(gates.get("minimum_top128_overlap"), "minimum_top128_overlap")
            )
            aggregate.append(
                {
                    "arm_id": arm_id,
                    "template_sha256": template.template_sha256,
                    "input_bits": input_bits,
                    "headroom": headroom,
                    "serialized_online_state_bytes": state_bytes,
                    "maximum_serialized_logical_mechanism_state_bytes": (
                        maximum_logical_state_bytes
                    ),
                    "clip_count_both_fields": clips,
                    "minimum_rank_spearman": min_spearman,
                    "minimum_rank_kendall": min_kendall,
                    "minimum_top8_overlap": min_top8,
                    "minimum_top32_overlap": min_top32,
                    "minimum_top128_overlap": min_top128,
                    "eligible": eligible,
                    "fields": {
                        name: {
                            **execution.describe(include_plan=False),
                            "matched_direct_quantized_table": (
                                _matched_direct_quantized_table(
                                    execution,
                                    next(
                                        field.scores
                                        for field in fields
                                        if field.attempt_id == name
                                    ),
                                )
                            ),
                        }
                        for name, execution in by_field.items()
                    },
                }
            )
    eligible = [row for row in aggregate if row["eligible"] is True]
    if not eligible:
        raise CorrectedDirect12Error("no adaptive DC arm passed the frozen state/fidelity gates")
    selected = min(
        eligible,
        key=lambda row: (
            -float(row["minimum_top8_overlap"]),
            -float(row["minimum_top32_overlap"]),
            -float(row["minimum_top128_overlap"]),
            -float(row["minimum_rank_spearman"]),
            int(row["maximum_serialized_logical_mechanism_state_bytes"]),
            str(row["arm_id"]),
        ),
    )
    selected_arm_id = str(selected["arm_id"])
    selected_template = executions[selected_arm_id]["A355"].template
    selected_direct_table_bytes = max(
        int(
            _mapping(
                _mapping(row, "selected field").get("matched_direct_quantized_table"),
                "matched direct table",
            )["maximum_serialized_logical_mechanism_state_bytes"]
        )
        for row in _mapping(selected.get("fields"), "selected.fields").values()
    )
    future_template: dict[str, object] = {
        "schema": FUTURE_TEMPLATE_SCHEMA,
        "freeze_state": "FROZEN_AFTER_A355_A356_DEVELOPMENT_BEFORE_NEW_CHALLENGE",
        "selected_template": selected_template.describe(),
        "selection_rule": FROZEN_SELECTION_RULE,
        "role": "FULL_BASIS_FIXED_DOMAIN_REFERENCE_CEILING_ONLY",
        "fresh_primary_mechanism_eligible": False,
        "compression_claim_eligible": False,
        "development_fields": {
            field.attempt_id: {
                "historical_field_sha256": field.historical_field_sha256,
                "order_uint16be_sha256": field.order_uint16be_sha256,
            }
            for field in fields
        },
        "future_field_binding": "UNBOUND",
        "fresh_test_rules": {
            "same_field_scale_calibration_is_label_free_and_predeclared": True,
            "two_canonical_source_passes_required": True,
            "no_parameter_change_after_public_challenge": True,
            "no_fallback_after_fresh_fidelity_or_rank": True,
            "all_orders_persisted_before_recovery": True,
            "target_labels_allowed_before_order_freeze": 0,
            "compact_successor_required_before_fresh_challenge": True,
        },
        "o1c_0005_template_sha256": original_arm.template_sha256,
        "labels_used_for_selection": 0,
    }
    future_template["future_template_sha256"] = _canonical_sha256(future_template)

    codec_map = [
        {
            "cell": cell,
            "high8": cell >> 4,
            "low4": cell & 0xF,
            "recovery_prefix12": cell,
            "assignment_word0_bits20_through31": cell,
        }
        for cell in range(DIRECT12_SIZE)
    ]
    codec = {
        "schema": CODEC_SCHEMA,
        "cell_formula": "(high8 << 4) | low4",
        "assignment_formula": "(assignment >> 20) & 0xfff",
        "high8_coordinates": list(HIGH8_COORDINATES),
        "low4_coordinates": list(LOW4_COORDINATES),
        "permutation": codec_map,
    }
    codec["codec_sha256"] = _canonical_sha256(codec)

    source_descriptor = snapshot.descriptor()
    source_descriptor = dict(source_descriptor)
    source_descriptor["immutable_local_members"] = [
        {
            "snapshot_member": f"source_snapshot/{name}",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        }
        for name, raw in sorted(local_bytes.items())
    ]
    source_descriptor["total_bytes_with_local_anchors"] = int(
        source_descriptor["total_bytes"]
    ) + sum(len(raw) for raw in local_bytes.values())
    source_descriptor["total_member_count_with_local_anchors"] = int(
        source_descriptor["member_count"]
    ) + len(local_bytes)
    source_descriptor["capsule_snapshot_copies"] = (
        int(source_descriptor["total_member_count_with_local_anchors"])
        if artifact_writer is not None
        else 0
    )
    if artifact_writer is not None and source_descriptor["capsule_snapshot_copies"] != 64:
        raise CorrectedDirect12Error(
            "writer-mode source snapshot must contain 61 sibling members and 3 local anchors"
        )
    source_descriptor["snapshot_sha256"] = _canonical_sha256(
        {key: value for key, value in source_descriptor.items() if key != "snapshot_sha256"}
    )

    selected_spectral_bytes = int(
        selected["maximum_serialized_logical_mechanism_state_bytes"]
    )
    full_rank_table_equivalence = (
        selected_template.describe()["spectral_bank"]["accumulator_count"]
        == DIRECT12_SIZE
    )
    spectral_ceiling_larger_than_direct = (
        selected_spectral_bytes > selected_direct_table_bytes
    )

    report: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": "O1C-0006",
        "claim_level": "VALIDATION",
        "codec": {
            "codec_sha256": codec["codec_sha256"],
            "cells": DIRECT12_SIZE,
            "is_identity_permutation_to_recovery_group": True,
            "A355_mapping_sha256": fields[0].synthetic_mapping_sha256,
            "A356_mapping_sha256": fields[1].synthetic_mapping_sha256,
        },
        "reader": {
            "name": SELECTED_READER,
            "feature_indices": list(indices),
            "model_sha256": frozen_model["model_sha256"],
            "numpy_version": np.__version__,
            "historical_float_fields_reproduced_exactly": True,
            "historical_complete_orders_reproduced_exactly": True,
        },
        "historical_commitment_chain": commitment_chain,
        "fields": {field.attempt_id: field.describe() for field in fields},
        "negative_breadcrumbs": {
            "literal_o1c_0005_raw_transfer": fixed_controls,
            "literal_failure_verified": literal_o1c5_failure_verified,
            "literal_maximum_absolute_spearman": literal_raw_maximum_abs_spearman,
            "literal_maximum_top32_overlap": literal_raw_maximum_top32,
            "frozen_failure_gates": dict(negative_gates),
            "finding": (
                "the historical fixed 4-bit non-DC scale composition is incompatible with "
                "corrected global raw fields; because scale regime, DC support, and bit depth "
                "change together, this control does not attribute causality to one component"
            ),
        },
        "adaptive_tournament": aggregate,
        "selection": {
            "selected_arm": selected_arm_id,
            "selected_role": "full-basis-fixed-domain-reference-ceiling",
            "fresh_primary_mechanism_eligible": False,
            "selected_template_sha256": selected_template.template_sha256,
            "selection_rule": future_template["selection_rule"],
            "selected_metrics": selected,
            "eligible_arms": len(eligible),
            "candidate_arms": len(aggregate),
        },
        "future_template": future_template,
        "source_snapshot_sha256": source_descriptor["snapshot_sha256"],
        "labels": {
            "A354_calibration_labeled_codec_audit_consumed": 1,
            "A355_calibration_label_present_in_historical_result": 1,
            "A355_calibration_label_used_for_reader_identity_before_A356": 1,
            "A355_or_A356_labels_used_for_bridge_fidelity_selection": 0,
            "A356_target_labels_used": 0,
            "fresh_target_labels_used": 0,
            "claim_scope": "post-hoc development validation with monotone upstream calibration provenance",
        },
        "claim_boundary": {
            "full_rank_fixed_domain_transform": True,
            "spectral_degrees_of_freedom": DIRECT12_SIZE,
            "candidate_domain_size": DIRECT12_SIZE,
            "sublinear_in_candidate_domain": False,
            "bounded_only_with_respect_to_stream_length_for_fixed_direct12_domain": True,
            "explicit_candidate_rows_inside_frozen_state": 0,
            "information_equivalent_to_quantized_direct_table": (
                full_rank_table_equivalence
            ),
            "selected_spectral_ceiling_maximum_serialized_logical_bytes": (
                selected_spectral_bytes
            ),
            "matched_direct_table_maximum_serialized_logical_bytes": (
                selected_direct_table_bytes
            ),
            "selected_spectral_ceiling_is_smaller_than_direct_table": (
                selected_spectral_bytes < selected_direct_table_bytes
            ),
            "selected_spectral_ceiling_is_larger_than_direct_table": (
                spectral_ceiling_larger_than_direct
            ),
            "spectral_to_direct_logical_state_ratio": (
                selected_spectral_bytes / selected_direct_table_bytes
            ),
            "compression_or_domain_independent_memory_claim": False,
            "serialized_logical_state_is_not_python_process_rss": True,
            "physical_runtime_memory_measured": False,
            "materialized_validation_score_fields_are_external_workspace": True,
            "external_workspace_excluded_from_mechanism_state_accounting": True,
            "zero_clip_gate_is_construction_integrity_not_robustness_evidence": True,
            "fresh_generalization_claim": False,
            "recovery_claim": False,
            "sota_claim": False,
        },
        "costs": {
            "measurement_shards_reused": 32,
            "solver_stages_reused": 32768,
            "new_solver_calls": 0,
            "gpu_seconds": 0,
            "legacy_reader_cells": 8192,
            "adaptive_candidate_arms": len(aggregate),
            "adaptive_source_field_reads": len(aggregate) * len(fields) * 8192,
            "selected_online_state_bytes": int(selected["serialized_online_state_bytes"]),
            "selected_maximum_serialized_logical_mechanism_state_bytes": int(
                selected["maximum_serialized_logical_mechanism_state_bytes"]
            ),
            "matched_direct_quantized_table_maximum_serialized_logical_bytes": (
                selected_direct_table_bytes
            ),
            "selected_first_pass_logical_state_bytes": 234,
            "selected_source_passes": 2,
            "retained_candidate_rows": 0,
            "retained_key_value_entries": 0,
        },
        "success_gates": {
            "corrected_codec_complete": True,
            "A355_historical_field_and_order_exact": True,
            "A356_historical_field_and_order_exact": True,
            "literal_O1C5_failure_retained_and_verified": literal_o1c5_failure_verified,
            "adaptive_arm_under_8192_bytes": int(selected["serialized_online_state_bytes"]) <= 8192,
            "adaptive_arm_maximum_serialized_logical_state_under_8192_bytes": int(
                selected["maximum_serialized_logical_mechanism_state_bytes"]
            )
            <= 8192,
            "adaptive_arm_zero_clips_both_fields": int(selected["clip_count_both_fields"]) == 0,
            "adaptive_arm_minimum_spearman_at_least_0_99": float(selected["minimum_rank_spearman"]) >= 0.99,
            "adaptive_arm_minimum_kendall_at_least_0_91": float(selected["minimum_rank_kendall"]) >= 0.91,
            "adaptive_arm_minimum_top32_at_least_0_70": float(selected["minimum_top32_overlap"]) >= 0.70,
            "adaptive_arm_minimum_top128_at_least_0_75": float(selected["minimum_top128_overlap"]) >= 0.75,
            "future_template_unbound_before_fresh_target": True,
            "full_rank_table_equivalence_disclosed": full_rank_table_equivalence,
            "spectral_ceiling_larger_than_matched_direct_table_disclosed": (
                spectral_ceiling_larger_than_direct
            ),
            "compression_claim_withheld": True,
            "compact_successor_required_before_fresh_challenge": True,
            "no_active_sibling_progress_or_outcome_reads": True,
            "no_sibling_writes": True,
        },
        "next_action": config.get("next_action"),
    }
    report["success_gate_passed"] = all(report["success_gates"].values())  # type: ignore[union-attr]
    report["report_sha256"] = _canonical_sha256(report)
    if artifact_writer is not None:
        artifact_writer("source_snapshot.json", _canonical_bytes(source_descriptor) + b"\n")
        artifact_writer("codec_map.json", _canonical_bytes(codec) + b"\n")
    return CorrectedBridgeResult(
        report=report,
        source_snapshot=source_descriptor,
        fields=fields,
        adaptive_executions=executions,
        fixed_controls=fixed_controls,
        fixed_control_orders=fixed_control_orders,
        future_template=future_template,
        success_gate_passed=bool(report["success_gate_passed"]),
    )
