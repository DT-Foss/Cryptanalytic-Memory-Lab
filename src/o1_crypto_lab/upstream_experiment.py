"""O1C-0007 upstream solver-evidence calibration and prospective order freeze.

The experiment consumes only immutable O1C-0006 capsule members.  It first
builds and externally persists every target-blind A355 panel order, then opens
the single retrospective A355 truth, performs exact 4096-label selection-null
enumeration, freezes one compact evidence-memory contract, and only afterwards
opens the unlabeled A356 deployment measurements.  No A356 outcome or progress
artifact is addressable by this module.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Iterator, Mapping, Sequence

from .artifacts import ReadOnlyArtifactSource
from .direct12 import CHANNEL_NAMES, HORIZONS, Direct12Adapter, Direct12Error
from .ising_memory import FrozenIsingMemory, IsingEvidenceMemory, IsingMemoryPlan
from .shape532 import direct12_order
from .stage3 import BoundedZstdDecoder, Stage3Error
from .upstream_panel import (
    DOMAIN_SIZE,
    PANEL_VIEW_COUNT,
    RAW_CHANNEL_NAMES,
    SELECTION_ELIGIBLE_VIEW_COUNT,
    ExactLabelEnumeration,
    PanelViewResult,
    PanelViewSpec,
    UpstreamPanelResult,
    UpstreamRawField,
    bind_target,
    exact_label_enumeration_fwer,
    iter_base_channel_values,
    project_view,
    run_upstream_panel,
)


CONFIG_SCHEMA = "o1-crypto-upstream-ising-retrospective-config-v1"
RESULT_SCHEMA = "o1-crypto-upstream-ising-retrospective-result-v1"
SOURCE_SCHEMA = "o1-crypto-o1c0007-source-receipts-v1"
PANEL_INVENTORY_SCHEMA = "o1-crypto-o1c0007-target-blind-panel-inventory-v1"
FUTURE_TEMPLATE_SCHEMA = "o1-crypto-o1c0007-frozen-evidence-template-v1"
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
ArtifactWriter = Callable[[str, bytes], object]
PanelPersistence = Callable[[Mapping[str, object], bytes], Mapping[str, object]]
SelectionPersistence = Callable[
    [Mapping[str, object], bytes, bytes], Mapping[str, object]
]
DeploymentPersistence = Callable[
    [Mapping[str, object], bytes, bytes], Mapping[str, object]
]


class UpstreamExperimentError(ValueError):
    """A source, chronology, panel, state, or expected result differs."""


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
        raise UpstreamExperimentError(
            "value is not canonical finite ASCII JSON"
        ) from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise UpstreamExperimentError(f"{field} must be an object")
    return value


def _sequence(value: object, field: str) -> list[object]:
    if not isinstance(value, list):
        raise UpstreamExperimentError(f"{field} must be a list")
    return value


def _integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise UpstreamExperimentError(f"{field} must be an integer")
    return value


def _finite(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise UpstreamExperimentError(f"{field} must be finite numeric")
    result = float(value)
    if not math.isfinite(result):
        raise UpstreamExperimentError(f"{field} must be finite numeric")
    return result


def _sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise UpstreamExperimentError(f"{field} must be a lowercase SHA-256")
    return value


def _safe_member(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise UpstreamExperimentError(f"{field} must be text")
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\x00" in value
    ):
        raise UpstreamExperimentError(f"unsafe member {value!r}")
    lowered = value.lower()
    if any(fragment in lowered for fragment in ("progress", "outcome", "a358")):
        raise UpstreamExperimentError(f"forbidden active/outcome member: {value}")
    return value


def _load_json(raw: bytes, field: str) -> Mapping[str, object]:
    try:
        return _mapping(json.loads(raw), field)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpstreamExperimentError(f"{field} is not valid JSON") from exc


@dataclass(frozen=True)
class DatasetSpec:
    attempt_id: str
    role: str
    shard_prefix: str
    schema_key: str
    high8_variables: tuple[int, ...]
    low4_variables: tuple[int, ...]
    maximum_raw_shard_bytes: int
    expected_field_sha256: str

    @classmethod
    def from_config(
        cls,
        value: object,
        *,
        expected_attempt_id: str,
    ) -> "DatasetSpec":
        row = _mapping(value, expected_attempt_id)
        attempt_id = row.get("attempt_id")
        if attempt_id != expected_attempt_id:
            raise UpstreamExperimentError("dataset attempt identity differs")
        role = row.get("role")
        if role != "measurements_unlabeled":
            raise UpstreamExperimentError("upstream shards must be unlabeled measurements")
        prefix = _safe_member(row.get("shard_prefix"), "shard_prefix")
        if not prefix.startswith("research/results/v1/"):
            raise UpstreamExperimentError("shard prefix is outside results/v1")
        schema_key = row.get("schema_key")
        expected_schema_key = f"{expected_attempt_id}_MEASUREMENT"
        if schema_key != expected_schema_key:
            raise UpstreamExperimentError("dataset schema key differs")
        high8 = tuple(
            _integer(item, "high8_variables")
            for item in _sequence(row.get("high8_variables"), "high8_variables")
        )
        low4 = tuple(
            _integer(item, "low4_variables")
            for item in _sequence(row.get("low4_variables"), "low4_variables")
        )
        if (
            len(high8) != 8
            or len(low4) != 4
            or any(item <= 0 for item in (*high8, *low4))
            or len(set((*high8, *low4))) != 12
        ):
            raise UpstreamExperimentError("dataset codec variables differ")
        maximum = _integer(
            row.get("maximum_raw_shard_bytes"), "maximum_raw_shard_bytes"
        )
        if not 1_500_000 <= maximum <= 4_000_000:
            raise UpstreamExperimentError("raw shard cap is outside the frozen budget")
        return cls(
            attempt_id=expected_attempt_id,
            role=str(role),
            shard_prefix=prefix,
            schema_key=str(schema_key),
            high8_variables=high8,
            low4_variables=low4,
            maximum_raw_shard_bytes=maximum,
            expected_field_sha256=_sha256(
                row.get("expected_field_sha256"), "expected_field_sha256"
            ),
        )

    def member(self, low4: int) -> str:
        if not 0 <= low4 < 16:
            raise UpstreamExperimentError("low4 is outside 0..15")
        return (
            f"artifacts/source_snapshot/{self.role}/{self.shard_prefix}/"
            f"slice_{low4:02x}.json.zst"
        )

    def source_ledger_path(self, low4: int) -> str:
        return f"{self.shard_prefix}/slice_{low4:02x}.json.zst"

    def fixed_units(self, low4: int) -> tuple[int, ...]:
        return tuple(
            variable if (low4 >> (3 - offset)) & 1 else -variable
            for offset, variable in enumerate(self.low4_variables)
        )


@dataclass(frozen=True)
class LoadedUpstreamField:
    spec: DatasetSpec
    field: UpstreamRawField
    measurement_ledger: tuple[Mapping[str, object], ...]
    cnf_sha256_by_low4: tuple[str, ...]
    compressed_bytes: int
    raw_bytes: int

    def describe(self) -> dict[str, object]:
        return {
            "schema": "o1-crypto-loaded-upstream-field-v1",
            "attempt_id": self.spec.attempt_id,
            "input_field_sha256": self.field.field_sha256,
            "shards": len(self.measurement_ledger),
            "cells": DOMAIN_SIZE,
            "solver_stages": DOMAIN_SIZE * len(HORIZONS),
            "raw_channels": list(RAW_CHANNEL_NAMES),
            "compressed_bytes": self.compressed_bytes,
            "raw_bytes": self.raw_bytes,
            "cnf_sha256_by_low4": list(self.cnf_sha256_by_low4),
            "cnf_set_sha256": _canonical_sha256(
                list(self.cnf_sha256_by_low4)
            ),
            "target_labels_used": 0,
        }


class PinnedO1C6Source:
    """Exact allowlist reader for the immutable O1C-0006 capsule."""

    def __init__(
        self,
        *,
        lab_root: Path,
        capsule_relative: str,
        expected_manifest_sha256: str,
        allowed_members: Sequence[str],
        writer: ArtifactWriter | None,
    ) -> None:
        relative = PurePosixPath(capsule_relative)
        if relative.is_absolute() or ".." in relative.parts:
            raise UpstreamExperimentError("source capsule path must be lab-relative")
        requested = lab_root / capsule_relative
        if requested.is_symlink():
            raise UpstreamExperimentError("source capsule cannot be a symbolic link")
        capsule = requested.resolve()
        if capsule.parent != (lab_root.resolve() / "runs").resolve():
            raise UpstreamExperimentError("source capsule must be directly under runs/")
        manifest = capsule / "artifacts.sha256"
        raw_manifest = manifest.read_bytes()
        expected = _sha256(expected_manifest_sha256, "expected_manifest_sha256")
        if hashlib.sha256(raw_manifest).hexdigest() != expected:
            raise UpstreamExperimentError("O1C-0006 manifest commitment differs")
        for path in (capsule, *capsule.rglob("*")):
            if path.is_symlink():
                raise UpstreamExperimentError("source capsule contains a symbolic link")
            if path.stat().st_mode & 0o222:
                raise UpstreamExperimentError("source capsule is not immutable")
        allowed = tuple(_safe_member(item, "allowed_member") for item in allowed_members)
        if not allowed or len(allowed) != len(set(allowed)):
            raise UpstreamExperimentError("source allowlist is empty or duplicated")
        self.capsule = capsule
        self.manifest_path = manifest
        self.manifest_sha256 = expected
        self.source = ReadOnlyArtifactSource(capsule, manifest)
        if self.source.manifest_sha256 != expected:
            raise UpstreamExperimentError("source manifest changed during construction")
        if any(member not in self.source.entries for member in allowed):
            raise UpstreamExperimentError("allowlisted source member is absent")
        self.allowed = frozenset(allowed)
        self.writer = writer
        self.receipts: list[dict[str, object]] = []
        self._opened: set[str] = set()
        if writer is not None:
            writer("source_snapshot/o1c_0006/artifacts.sha256", raw_manifest)

    def read(self, member: str, *, phase: str) -> bytes:
        safe = _safe_member(member, "source member")
        if safe not in self.allowed:
            raise UpstreamExperimentError(f"source member is outside allowlist: {safe}")
        if safe in self._opened:
            raise UpstreamExperimentError(f"source member repeated: {safe}")
        raw = self.source.read_bytes(safe)
        digest = hashlib.sha256(raw).hexdigest()
        if self.writer is not None:
            self.writer(f"source_snapshot/o1c_0006/{safe}", raw)
        self._opened.add(safe)
        self.receipts.append(
            {
                "member": safe,
                "sha256": digest,
                "bytes": len(raw),
                "phase": phase,
            }
        )
        return raw

    def descriptor(self) -> dict[str, object]:
        rows = sorted(self.receipts, key=lambda row: str(row["member"]))
        value: dict[str, object] = {
            "schema": SOURCE_SCHEMA,
            "source_capsule": str(self.capsule),
            "source_manifest_sha256": self.manifest_sha256,
            "allowed_members": len(self.allowed),
            "opened_members": len(rows),
            "all_opened_members_copied": self.writer is not None,
            "members": rows,
            "total_bytes": sum(int(row["bytes"]) for row in rows),
            "sibling_repository_reads": 0,
            "sibling_repository_writes": 0,
            "active_progress_or_outcome_reads": 0,
        }
        value["receipt_set_sha256"] = _canonical_sha256(value)
        return value


def _load_field(
    source: PinnedO1C6Source,
    spec: DatasetSpec,
    *,
    phase: str,
) -> LoadedUpstreamField:
    arrays = {
        horizon: [[0.0] * len(RAW_CHANNEL_NAMES) for _ in range(DOMAIN_SIZE)]
        for horizon in HORIZONS
    }
    decoder = BoundedZstdDecoder()
    ledger: list[Mapping[str, object]] = []
    cnf_hashes: list[str] = []
    compressed_total = 0
    raw_total = 0
    for low4 in range(16):
        member = spec.member(low4)
        compressed = source.read(member, phase=phase)
        try:
            raw = decoder.decode(
                compressed,
                max_output_bytes=spec.maximum_raw_shard_bytes,
            )
        except Stage3Error as exc:
            raise UpstreamExperimentError(str(exc)) from exc
        measurement = _load_json(raw, member)
        if _canonical_bytes(measurement) != raw:
            raise UpstreamExperimentError("measurement shard is not canonical JSON")
        if spec.attempt_id == "A356" and measurement.get(
            "selected_A355_view_available_to_measurement"
        ) is not False:
            raise UpstreamExperimentError(
                "A356 measurement had access to the selected A355 view"
            )
        try:
            cells, shard_cnf = Direct12Adapter._validate_run_and_extract(
                measurement,
                attempt_id=spec.attempt_id,
                schema_key=spec.schema_key,
                slice_id=f"slice_{low4:02x}",
                low4=low4,
                expected_assumption_variables=spec.high8_variables,
                expected_fixed_unit_literals=spec.fixed_units(low4),
            )
        except Direct12Error as exc:
            raise UpstreamExperimentError(str(exc)) from exc
        cnf_hashes.append(shard_cnf)
        for high8, cell in enumerate(cells):
            address = (high8 << 4) | low4
            for horizon_index, horizon in enumerate(HORIZONS):
                by_name = {
                    name: cell.values[channel_index][horizon_index]
                    for channel_index, name in enumerate(CHANNEL_NAMES)
                }
                arrays[horizon][address] = [
                    by_name[name] for name in RAW_CHANNEL_NAMES
                ]
        row: dict[str, object] = {
            "compressed_bytes": len(compressed),
            "compressed_sha256": hashlib.sha256(compressed).hexdigest(),
            "low4": low4,
            "path": spec.source_ledger_path(low4),
            "raw_bytes": len(raw),
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "resumed": False,
        }
        if spec.attempt_id == "A355":
            row["low4_binary"] = f"{low4:04b}"
        ledger.append(row)
        compressed_total += len(compressed)
        raw_total += len(raw)
    field = UpstreamRawField.from_horizon_arrays(arrays)
    if field.field_sha256 != spec.expected_field_sha256:
        raise UpstreamExperimentError(
            f"{spec.attempt_id} upstream raw field commitment differs"
        )
    if len(cnf_hashes) != 16:  # pragma: no cover - exact sixteen-shard loop
        raise AssertionError("dataset loader produced an incomplete CNF ledger")
    return LoadedUpstreamField(
        spec=spec,
        field=field,
        measurement_ledger=tuple(ledger),
        cnf_sha256_by_low4=tuple(cnf_hashes),
        compressed_bytes=compressed_total,
        raw_bytes=raw_total,
    )


def _validate_calibration_truth(
    value: Mapping[str, object],
    loaded: LoadedUpstreamField,
) -> int:
    if (
        value.get("schema")
        != "chacha20-round20-w46-corrected-group-direct12-reader-a355-v1"
        or value.get("attempt_id") != "A355"
        or value.get("confirmed_prefix_revealed_only_after_complete_measurement")
        is not True
    ):
        raise UpstreamExperimentError("A355 calibration truth contract differs")
    if value.get("measurement_ledger") != list(loaded.measurement_ledger):
        raise UpstreamExperimentError("A355 truth ledger differs from frozen shards")
    summary = _mapping(value.get("measurement_summary"), "A355 measurement_summary")
    if (
        summary.get("target_labels_used_during_measurement") != 0
        or summary.get("complete_direct12_cells") != DOMAIN_SIZE
        or summary.get("solver_stages") != DOMAIN_SIZE * len(HORIZONS)
    ):
        raise UpstreamExperimentError("A355 target-blind measurement gate differs")
    target = _integer(value.get("confirmed_prefix12"), "confirmed_prefix12")
    if not 0 <= target < DOMAIN_SIZE:
        raise UpstreamExperimentError("A355 target is outside Direct12")
    return target


def _validate_deployment_metadata(
    value: Mapping[str, object],
    loaded: LoadedUpstreamField,
) -> None:
    if (
        value.get("schema")
        != "chacha20-round20-w46-corrected-group-a345-transfer-a356-measurement-v1"
        or value.get("attempt_id") != "A356"
        or value.get("measurement_ledger") != list(loaded.measurement_ledger)
    ):
        raise UpstreamExperimentError("A356 measurement metadata differs")
    summary = _mapping(value.get("measurement_summary"), "A356 measurement_summary")
    if (
        summary.get("A355_selected_view_read") is not False
        or summary.get("target_labels_used") != 0
        or summary.get("reader_refits") != 0
        or summary.get("complete_direct12_cells") != DOMAIN_SIZE
        or summary.get("solver_stages") != DOMAIN_SIZE * len(HORIZONS)
    ):
        raise UpstreamExperimentError("A356 target-blind deployment gate differs")


def build_panel_inventory(
    panel: UpstreamPanelResult,
) -> tuple[dict[str, object], bytes]:
    """Pack every target-blind order into one offset-indexed immutable blob."""

    if panel.target_address is not None or panel.selected_primary is not None:
        raise UpstreamExperimentError("panel inventory requires target-blind orders")
    if len(panel.views) != PANEL_VIEW_COUNT:
        raise UpstreamExperimentError("panel inventory is incomplete")
    payload = bytearray()
    rows: list[dict[str, object]] = []
    for view in panel.views:
        if view.target_rank is not None or len(view.order_uint16be) != DOMAIN_SIZE * 2:
            raise UpstreamExperimentError("panel view leaked a target or incomplete order")
        offset = len(payload)
        payload.extend(view.order_uint16be)
        rows.append(
            {
                "view_id": view.spec.view_id,
                "spec_sha256": view.spec.spec_sha256,
                "selection_eligible": view.effective_selection_eligible,
                "streamable": view.spec.streamable,
                "tie_collision_excess": view.tie_collision_excess,
                "register_count": view.spec.register_count,
                "offset_bytes": offset,
                "length_bytes": len(view.order_uint16be),
                "order_sha256": view.order_sha256,
                "projected_field_sha256": view.projected_field_sha256,
            }
        )
    blob = bytes(payload)
    value: dict[str, object] = {
        "schema": PANEL_INVENTORY_SCHEMA,
        "input_field_sha256": panel.input_field_sha256,
        "orders": len(rows),
        "streamable_orders_before_tie_gate": sum(
            bool(row["streamable"]) for row in rows
        ),
        "selection_eligible_orders": sum(
            bool(row["selection_eligible"]) for row in rows
        ),
        "order_encoding": "concatenated-raw-uint16be",
        "bytes_per_order": DOMAIN_SIZE * 2,
        "order_blob_bytes": len(blob),
        "order_blob_sha256": hashlib.sha256(blob).hexdigest(),
        "target_address_present": False,
        "target_ranks_present": False,
        "views": rows,
    }
    value["inventory_sha256"] = _canonical_sha256(value)
    return value, blob


def _require_receipt(
    value: Mapping[str, object],
    *,
    schema: str,
    expected: Mapping[str, object],
) -> Mapping[str, object]:
    if value.get("schema") != schema or value.get("persisted") is not True:
        raise UpstreamExperimentError("persistence receipt identity differs")
    for field, wanted in expected.items():
        if value.get(field) != wanted:
            raise UpstreamExperimentError(
                f"persistence receipt field differs: {field}"
            )
    return value


def execution_evidence(
    field: UpstreamRawField,
    spec: PanelViewSpec,
) -> tuple[float, ...]:
    """Materialize the evidence field consumed once by the compact accumulator.

    Every eligible support excludes the constant Walsh mode.  Subtracting a
    population mean therefore vanishes exactly, and division by one positive
    population scale changes no order.  The executable mechanism can elide the
    panel's z-score pass and stream raw or signed-log1p evidence directly.
    """

    return tuple(_iter_execution_evidence(field, spec))


def _iter_execution_evidence(
    field: UpstreamRawField,
    spec: PanelViewSpec,
) -> Iterator[float]:
    """Yield the frozen pointwise decoder output in canonical address order."""

    if not isinstance(field, UpstreamRawField) or not isinstance(spec, PanelViewSpec):
        raise TypeError("field and PanelViewSpec are required")
    if not spec.selection_eligible or spec.transform_id == "rank":
        raise UpstreamExperimentError("selected execution must be streamable")
    sign = -1.0 if spec.orientation == "negative" else 1.0
    for raw in iter_base_channel_values(field, spec.channel_name, spec.horizon):
        value = (
            math.copysign(math.log1p(abs(raw)), raw)
            if spec.transform_id == "signed-log1p"
            else raw
        )
        value *= sign
        yield 0.0 if value == 0.0 else value


def freeze_selected_memory(
    field: UpstreamRawField,
    spec: PanelViewSpec,
) -> FrozenIsingMemory:
    # Stream first under the already frozen decoder contract, then bind the
    # digest produced by that same pass into the persistent query state.  This
    # avoids a hidden pre-hash pass while retaining conservative hash storage.
    plan = IsingMemoryPlan(
        name=spec.view_id,
        support_id=spec.support_id,
    )
    memory = IsingEvidenceMemory(plan)
    memory.observe_many(enumerate(_iter_execution_evidence(field, spec)))
    streamed = memory.finalize()
    bound_plan = IsingMemoryPlan(
        expected_evidence_sha256=streamed.evidence_field_sha256,
        name=spec.view_id,
        support_id=spec.support_id,
    )
    return FrozenIsingMemory(
        plan=bound_plan,
        coefficients=streamed.coefficients,
        evidence_field_sha256=streamed.evidence_field_sha256,
        observations=streamed.observations,
    )


def _order_bytes(order: Sequence[int]) -> bytes:
    values = tuple(order)
    if len(values) != DOMAIN_SIZE or set(values) != set(range(DOMAIN_SIZE)):
        raise UpstreamExperimentError("order must be a complete Direct12 permutation")
    return b"".join(value.to_bytes(2, "big") for value in values)


def _view_by_id(panel: UpstreamPanelResult, view_id: str) -> PanelViewResult:
    try:
        return next(view for view in panel.views if view.spec.view_id == view_id)
    except StopIteration as exc:
        raise UpstreamExperimentError(f"panel view is absent: {view_id}") from exc


@dataclass(frozen=True)
class UpstreamExperimentResult:
    report: Mapping[str, object]
    source_snapshot: Mapping[str, object]
    calibration_panel: UpstreamPanelResult
    exact_null: ExactLabelEnumeration
    selected_template: Mapping[str, object]
    a355_memory: FrozenIsingMemory
    a356_memory: FrozenIsingMemory
    success_gate_passed: bool

    def metrics(self) -> dict[str, object]:
        selected = self.calibration_panel.selected_primary
        assert selected is not None
        return {
            "schema": "o1-crypto-o1c0007-metrics-v1",
            "success_gate_passed": self.success_gate_passed,
            "success_gate_semantics": "protocol-integrity-not-scientific-efficacy",
            "protocol_success_gate_passed": self.success_gate_passed,
            "scientific_efficacy_gate_passed": False,
            "selected_view_id": selected.spec.view_id,
            "A355_rank": selected.target_rank,
            "A355_gain_bits": selected.target_gain_bits,
            "A355_order_sha256": self.a355_memory.order_uint16be_sha256,
            "A356_order_sha256": self.a356_memory.order_uint16be_sha256,
            "state_registers": self.a355_memory.plan.state_scalars,
            "maximum_serialized_logical_mechanism_state_bytes": (
                self.a355_memory.plan.maximum_serialized_logical_mechanism_state_bytes
            ),
            "exact_familywise_p": self.exact_null.exact_familywise_p,
            "favorable_labels": self.exact_null.favorable_label_count,
            "fresh_challenge_generated": False,
            "A356_target_labels_read": 0,
            "statistical_sota_claimed": False,
            "source_receipt_set_sha256": self.source_snapshot[
                "receipt_set_sha256"
            ],
        }


def run_upstream_ising_retrospective(
    config_path: Path,
    *,
    lab_root: Path,
    artifact_writer: ArtifactWriter | None,
    on_panel_frozen: PanelPersistence,
    on_selection_frozen: SelectionPersistence,
    on_deployment_frozen: DeploymentPersistence,
) -> UpstreamExperimentResult:
    """Execute O1C-0007 under the strict target/source chronology."""

    requested = config_path
    try:
        resolved = config_path.resolve(strict=True)
        expected_path = (
            lab_root.resolve(strict=True)
            / "configs/upstream_ising_retrospective_v1.json"
        ).resolve(strict=True)
    except OSError as exc:
        raise UpstreamExperimentError("O1C-0007 config path is missing") from exc
    if requested.is_symlink() or resolved != expected_path or not resolved.is_file():
        raise UpstreamExperimentError("O1C-0007 requires its canonical lab config")
    config = _load_json(resolved.read_bytes(), "config")
    if config.get("schema") != CONFIG_SCHEMA or config.get("attempt_id") != "O1C-0007":
        raise UpstreamExperimentError("O1C-0007 config identity differs")

    source_config = _mapping(config.get("source"), "source")
    a355_spec = DatasetSpec.from_config(
        source_config.get("A355"), expected_attempt_id="A355"
    )
    a356_spec = DatasetSpec.from_config(
        source_config.get("A356"), expected_attempt_id="A356"
    )
    truth_member = _safe_member(
        source_config.get("A355_truth_member"), "A355_truth_member"
    )
    metadata_member = _safe_member(
        source_config.get("A356_metadata_member"), "A356_metadata_member"
    )
    if "calibration_labeled" not in truth_member:
        raise UpstreamExperimentError("A355 truth member role differs")
    if "measurements_unlabeled" not in metadata_member:
        raise UpstreamExperimentError("A356 metadata member role differs")
    shard_members = tuple(
        spec.member(low4)
        for spec in (a355_spec, a356_spec)
        for low4 in range(16)
    )
    source = PinnedO1C6Source(
        lab_root=lab_root,
        capsule_relative=str(source_config.get("capsule")),
        expected_manifest_sha256=_sha256(
            source_config.get("manifest_sha256"), "source.manifest_sha256"
        ),
        allowed_members=(*shard_members, truth_member, metadata_member),
        writer=artifact_writer,
    )

    a355 = _load_field(source, a355_spec, phase="A355_TARGET_BLIND_PANEL_INPUT")
    blind_panel = run_upstream_panel(a355.field)
    inventory, order_blob = build_panel_inventory(blind_panel)
    panel_receipt = _require_receipt(
        on_panel_frozen(inventory, order_blob),
        schema="o1-crypto-o1c0007-panel-persistence-receipt-v1",
        expected={
            "inventory_sha256": inventory["inventory_sha256"],
            "order_blob_sha256": inventory["order_blob_sha256"],
            "orders": PANEL_VIEW_COUNT,
            "target_labels_read": 0,
        },
    )

    truth = _load_json(
        source.read(truth_member, phase="A355_POST_PANEL_CALIBRATION_TRUTH"),
        "A355 truth",
    )
    target = _validate_calibration_truth(truth, a355)
    bound_panel = bind_target(blind_panel, target)
    exact_null = exact_label_enumeration_fwer(bound_panel)
    selected = bound_panel.selected_primary
    if selected is None:  # pragma: no cover - target-bound invariant
        raise AssertionError("target-bound panel has no selected view")
    expected = _mapping(config.get("expected"), "expected")
    if (
        selected.spec.view_id != expected.get("selected_view_id")
        or selected.spec.spec_sha256 != expected.get("selected_spec_sha256")
        or selected.target_rank != expected.get("A355_selected_rank")
        or selected.order_sha256 != expected.get("A355_selected_order_sha256")
    ):
        raise UpstreamExperimentError("A355 selected calibration result differs")
    if (
        exact_null.favorable_label_count != expected.get("favorable_label_count")
        or exact_null.exact_familywise_p
        != _finite(expected.get("exact_familywise_p"), "exact_familywise_p")
    ):
        raise UpstreamExperimentError("exact A355 selection null differs")

    nonstreamable = min(
        (view for view in bound_panel.views if not view.spec.selection_eligible),
        key=lambda view: (
            int(view.target_rank),
            view.spec.register_count,
            view.spec.view_id,
        ),
    )
    tied_streamable = min(
        (
            view
            for view in bound_panel.views
            if view.spec.selection_eligible and view.tie_collision_excess > 0
        ),
        key=lambda view: (
            int(view.target_rank),
            view.spec.register_count,
            view.spec.view_id,
        ),
    )
    historical_candidate = _view_by_id(
        bound_panel, str(expected.get("historical_candidate_view_id"))
    )
    if (
        nonstreamable.spec.view_id != expected.get("best_nonstreamable_view_id")
        or nonstreamable.target_rank != expected.get("best_nonstreamable_rank")
        or tied_streamable.spec.view_id
        != expected.get("best_tied_streamable_view_id")
        or tied_streamable.target_rank
        != expected.get("best_tied_streamable_rank")
        or tied_streamable.tie_collision_excess
        != expected.get("best_tied_streamable_tie_collision_excess")
        or historical_candidate.target_rank
        != expected.get("historical_candidate_rank")
        or historical_candidate.order_sha256
        != expected.get("historical_candidate_order_sha256")
    ):
        raise UpstreamExperimentError("panel breadcrumb commitments differ")

    a355_memory = freeze_selected_memory(a355.field, selected.spec)
    if a355_memory.order_uint16be_sha256 != selected.order_sha256:
        raise UpstreamExperimentError(
            "single-pass accumulator A355 order differs from the panel"
        )
    maximum_state = (
        a355_memory.plan.maximum_serialized_logical_mechanism_state_bytes
    )
    budgets = _mapping(config.get("budgets"), "budgets")
    if (
        maximum_state
        > _integer(
            budgets.get("maximum_serialized_logical_mechanism_state_bytes"),
            "maximum state budget",
        )
        or maximum_state != expected.get("selected_maximum_state_bytes")
        or a355_memory.plan.state_scalars != expected.get("selected_registers")
    ):
        raise UpstreamExperimentError("selected memory state gate differs")

    future_template: dict[str, object] = {
        "schema": FUTURE_TEMPLATE_SCHEMA,
        "freeze_state": "FROZEN_AFTER_A355_EXACT_NULL_BEFORE_A356_SOURCE_OPEN",
        "selected_view": selected.spec.describe(),
        "execution_evidence_decoder": {
            "source_channel": selected.spec.channel_name,
            "horizon": selected.spec.horizon,
            "pointwise_transform": (
                "signed-log1p" if selected.spec.transform_id == "signed-log1p" else "identity"
            ),
            "orientation": selected.spec.orientation,
            "population_zscore_elided": True,
            "elision_proof": (
                "all retained Walsh masks are nonconstant, so mean subtraction "
                "vanishes and division by one positive scale preserves order"
            ),
            "accumulator_evidence_passes": 1,
            "current_harness_materializes_canonical_input_field": True,
            "end_to_end_source_streaming_executed": False,
            "eventwise_decoder_implementation_status": (
                "executed-over-materialized-canonical-field"
            ),
            "external_reference_replay_passes": 1,
            "external_reference_replay_counted_as_mechanism_pass": False,
        },
        "unbound_memory_plan": IsingMemoryPlan(
            name=selected.spec.view_id,
            support_id=selected.spec.support_id,
        ).describe(),
        "calibration": {
            "target_rank": selected.target_rank,
            "gain_bits": selected.target_gain_bits,
            "order_sha256": selected.order_sha256,
            "exact_familywise_p": exact_null.exact_familywise_p,
            "favorable_labels": exact_null.favorable_label_count,
            "panel_views": PANEL_VIEW_COUNT,
            "streamable_views_before_tie_gate": SELECTION_ELIGIBLE_VIEW_COUNT,
            "eligible_views_after_tie_gate": len(exact_null.eligible_view_ids),
        },
        "state_gate": {
            "registers": a355_memory.plan.state_scalars,
            "maximum_serialized_logical_mechanism_state_bytes": maximum_state,
            "prior_o1c0006_direct_table_budget_reference_bytes": _integer(
                budgets.get("direct_quantized_table_ceiling_bytes"),
                "direct table ceiling",
            ),
            "matched_fidelity_or_equal_information_comparison": False,
            "retained_candidate_rows": 0,
            "retained_evidence_values": 0,
            "retained_key_value_entries": 0,
        },
        "claim_boundary": {
            "retrospective_calibration_only": True,
            "selection_adjusted_significant": exact_null.exact_familywise_p < 0.05,
            "A356_target_label_available": False,
            "fresh_challenge_generated": False,
            "recovery_claimed": False,
            "statistical_sota_claimed": False,
            "table_budget_comparison_is_not_compression_dominance": True,
            "A356_is_transductive_target_outcome_blind_freeze": True,
            "A356_source_unseen_or_fresh_holdout": False,
        },
    }
    future_template["future_template_sha256"] = _canonical_sha256(future_template)
    a355_state_bytes = a355_memory.to_bytes()
    a355_order_bytes = _order_bytes(a355_memory.order)
    selection_receipt = _require_receipt(
        on_selection_frozen(future_template, a355_state_bytes, a355_order_bytes),
        schema="o1-crypto-o1c0007-selection-persistence-receipt-v1",
        expected={
            "future_template_sha256": future_template["future_template_sha256"],
            "A355_state_sha256": hashlib.sha256(a355_state_bytes).hexdigest(),
            "A355_order_sha256": a355_memory.order_uint16be_sha256,
            "A356_source_members_opened": 0,
        },
    )

    # The A356 metadata and shards become addressable only after the exact
    # selected template and calibration state have been persisted.
    deployment_metadata = _load_json(
        source.read(metadata_member, phase="A356_POST_SELECTION_METADATA"),
        "A356 metadata",
    )
    a356 = _load_field(source, a356_spec, phase="A356_POST_SELECTION_INPUT")
    _validate_deployment_metadata(deployment_metadata, a356)
    a356_memory = freeze_selected_memory(a356.field, selected.spec)
    projected_a356 = project_view(a356.field, selected.spec)
    projected_a356_order = direct12_order(projected_a356)
    if a356_memory.order != projected_a356_order:
        raise UpstreamExperimentError(
            "single-pass accumulator A356 order differs from the frozen view"
        )
    if a356_memory.order_uint16be_sha256 != expected.get("A356_order_sha256"):
        raise UpstreamExperimentError("A356 target-blind order commitment differs")
    deployment_document: dict[str, object] = {
        "schema": "o1-crypto-o1c0007-a356-target-blind-execution-v1",
        "selected_view": selected.spec.describe(),
        "input_field": a356.describe(),
        "memory": a356_memory.describe(),
        "order_sha256": a356_memory.order_uint16be_sha256,
        "order_cells": DOMAIN_SIZE,
        "target_labels_read": 0,
        "reader_refits": 0,
        "fresh_architecture_test": False,
        "transductive_target_outcome_blind_freeze": True,
        "source_unseen_or_fresh_holdout": False,
        "prospective_only_relative_to_target_outcome_reveal": True,
    }
    deployment_document["execution_sha256"] = _canonical_sha256(
        deployment_document
    )
    deployment_receipt = _require_receipt(
        on_deployment_frozen(
            deployment_document,
            a356_memory.to_bytes(),
            _order_bytes(a356_memory.order),
        ),
        schema="o1-crypto-o1c0007-deployment-persistence-receipt-v1",
        expected={
            "execution_sha256": deployment_document["execution_sha256"],
            "A356_state_sha256": hashlib.sha256(a356_memory.to_bytes()).hexdigest(),
            "A356_order_sha256": a356_memory.order_uint16be_sha256,
            "A356_target_labels_read": 0,
        },
    )

    source_snapshot = source.descriptor()
    if source_snapshot["opened_members"] != len(source.allowed):
        raise UpstreamExperimentError("not every allowlisted source member was consumed")
    success_gates = {
        "all_672_A355_orders_persisted_before_truth": True,
        "exact_4096_label_selection_null_computed": True,
        "selected_state_below_prior_table_budget_reference": maximum_state
        < _integer(
            budgets.get("direct_quantized_table_ceiling_bytes"),
            "direct table ceiling",
        ),
        "selected_memory_has_zero_candidate_rows": (
            a355_memory.retained_candidate_rows == 0
            and a356_memory.retained_candidate_rows == 0
        ),
        "A356_source_opened_only_after_selection_persistence": True,
        "A356_complete_order_persisted_target_blind": True,
        "A356_target_labels_read_zero": True,
        "fresh_challenge_generated_zero": True,
        "statistical_sota_claimed_false": True,
    }
    success = all(success_gates.values())
    report: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": "O1C-0007",
        "success_gate_passed": success,
        "success_gate_semantics": "protocol-integrity-not-scientific-efficacy",
        "protocol_success_gate_passed": success,
        "scientific_efficacy_gate_passed": False,
        "calibration_field": a355.describe(),
        "deployment_field": a356.describe(),
        "panel": {
            "views": PANEL_VIEW_COUNT,
            "streamable_views_before_tie_gate": SELECTION_ELIGIBLE_VIEW_COUNT,
            "eligible_views_after_tie_gate": len(exact_null.eligible_view_ids),
            "inventory_sha256": inventory["inventory_sha256"],
            "order_blob_sha256": inventory["order_blob_sha256"],
            "selected_view": selected.describe(),
            "best_nonstreamable": nonstreamable.describe(),
            "best_tied_streamable_control": tied_streamable.describe(),
            "historical_candidate": historical_candidate.describe(),
        },
        "exact_selection_null": exact_null.describe(include_label_vectors=False),
        "selected_memory": {
            "A355": a355_memory.describe(),
            "A356": a356_memory.describe(),
            "future_template": future_template,
        },
        "chronology_receipts": {
            "panel": panel_receipt,
            "selection": selection_receipt,
            "deployment": deployment_receipt,
        },
        "source_snapshot": source_snapshot,
        "success_gates": success_gates,
        "claim_boundary": {
            "result_class": (
                "RETROSPECTIVE_CALIBRATION_AND_TRANSDUCTIVE_"
                "TARGET_BLIND_ORDER_FREEZE"
            ),
            "A355_selection_adjusted_p": exact_null.exact_familywise_p,
            "A355_selection_adjusted_significant": exact_null.exact_familywise_p
            < 0.05,
            "A356_order_is_target_blind_but_not_outcome_evaluated": True,
            "A356_source_unseen_or_fresh_holdout": False,
            "prospective_only_relative_to_target_outcome_reveal": True,
            "fresh_challenges": 0,
            "recovered_key_bits": 0,
            "recovery_claimed": False,
            "statistical_sota_claimed": False,
            "exact_null_adjusts_declared_672_view_family": True,
            "exact_null_adjusts_pre_panel_exploration_or_family_design": False,
            "exact_null_inferential_scope": (
                "conditional-uniform-random-label-tail; label-exchangeability-"
                "not-established-by-this-experiment"
            ),
            "prior_table_budget_comparison_is_matched_fidelity": False,
            "bounded_state_complexity_scope": (
                "O(1)-in-stream-length-at-fixed-Direct12-width"
            ),
            "width_scaling": {
                "degree1_registers": "O(n)",
                "degree1_plus_2_registers": "O(n^2)",
            },
            "sota_target": (
                "smallest genuine O(1) solver-event memory with reproducible "
                "fresh unseen-key search-space reduction"
            ),
        },
        "next_action": config.get("next_action"),
    }
    report["report_sha256"] = _canonical_sha256(report)
    return UpstreamExperimentResult(
        report=report,
        source_snapshot=source_snapshot,
        calibration_panel=bound_panel,
        exact_null=exact_null,
        selected_template=future_template,
        a355_memory=a355_memory,
        a356_memory=a356_memory,
        success_gate_passed=success,
    )
