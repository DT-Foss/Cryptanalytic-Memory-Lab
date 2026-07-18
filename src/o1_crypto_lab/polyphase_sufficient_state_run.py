"""Capsule-backed full-256 hot-readout mechanism validation (O1C-0027)."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import resource
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence, cast

import numpy as np

from .polyphase_sufficient_state import (
    BASIS_SHA256,
    KEY_BITS,
    STATE_BYTES,
    TIMESCALES,
    WAVELENGTHS,
    PolyphaseReadoutSpec,
    PolyphaseSufficientState,
    ReplayRequiredError,
    basis_descriptor,
    basis_sha256_from_descriptor,
    direct_polyphase_state,
    read_polyphase_reference,
    read_polyphase_state,
    reference_readout_roundoff_bound,
)
from .run_capsule import ClaimLevel, RunCapsuleManager


RUN_CONFIG_SCHEMA = "o1-256-polyphase-sufficient-state-run-config-v1"
RUN_METRICS_SCHEMA = "o1-256-polyphase-sufficient-state-cli-result-v1"
RESULT_SCHEMA = "o1-256-polyphase-sufficient-state-result-v1"
WORK_SCHEMA = "o1-256-polyphase-sufficient-state-work-v1"
ARTIFACT_INDEX_SCHEMA = "o1-256-polyphase-sufficient-state-artifact-index-v1"
ATTEMPT_ID = "O1C-0027"
SLUG = "polyphase-sufficient-state-full256-v1"
SOURCE_GENERATOR = "dyadic-regime-switch-q31-parity-v1"
REFERENCE_STATE_BYTES = (
    len(WAVELENGTHS) * len(TIMESCALES) * KEY_BITS * (16 + 8)
    + KEY_BITS * 2
    + 8
)
CONTROL_INPUT_CHUNK_BYTES = len(WAVELENGTHS) * KEY_BITS * 4


class PolyphaseSufficientStateRunError(ValueError):
    """The O1C-0027 config, lifecycle, work, or resource contract differs."""


def _mapping(value: object, field: str, expected: set[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise PolyphaseSufficientStateRunError(f"{field} fields differ")
    return value


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise PolyphaseSufficientStateRunError(
            f"{field} must be an integer in [{minimum},{maximum}]"
        )
    return value


def _positive(value: object, field: str, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0.0 < float(value) <= maximum
    ):
        raise PolyphaseSufficientStateRunError(
            f"{field} must be finite in (0,{maximum}]"
        )
    return float(value)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            indent=2,
            sort_keys=True,
            allow_nan=False,
            ensure_ascii=True,
        )
    except (TypeError, ValueError) as exc:
        raise PolyphaseSufficientStateRunError("artifact is not finite JSON") from exc
    return (rendered + "\n").encode("ascii")


def _process_peak_rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    # macOS reports bytes; Linux reports KiB.
    return value if value > 16 * 1024 * 1024 else value * 1024


@dataclass(frozen=True)
class PolyphaseExperimentConfig:
    n_bits: int
    stream_groups: int
    regime_switch: int
    chunk_partition: tuple[int, ...]
    wavelengths: tuple[int, ...]
    timescales: tuple[int, ...]
    basis_sha256: str
    minimum_pairwise_normalized_readout_rms: float
    source_generator: str
    readouts: tuple[PolyphaseReadoutSpec, ...]

    @classmethod
    def from_mapping(cls, value: object) -> "PolyphaseExperimentConfig":
        row = _mapping(
            value,
            "experiment",
            {
                "n_bits",
                "stream_groups",
                "regime_switch",
                "chunk_partition",
                "wavelengths",
                "timescales",
                "basis_sha256",
                "minimum_pairwise_normalized_readout_rms",
                "source_generator",
                "readouts",
            },
        )
        n_bits = _integer(row["n_bits"], "experiment.n_bits", 1, 1 << 20)
        groups = _integer(
            row["stream_groups"], "experiment.stream_groups", 1, 1 << 31
        )
        regime_switch = _integer(
            row["regime_switch"], "experiment.regime_switch", 1, groups
        )
        partition_raw = row["chunk_partition"]
        if not isinstance(partition_raw, list) or not partition_raw:
            raise PolyphaseSufficientStateRunError(
                "experiment.chunk_partition differs"
            )
        partition = tuple(
            _integer(item, f"experiment.chunk_partition[{index}]", 1, groups)
            for index, item in enumerate(partition_raw)
        )
        if sum(partition) != groups:
            raise PolyphaseSufficientStateRunError(
                "experiment.chunk_partition must sum to stream_groups"
            )
        wavelengths_raw = row["wavelengths"]
        timescales_raw = row["timescales"]
        if not isinstance(wavelengths_raw, list) or not isinstance(timescales_raw, list):
            raise PolyphaseSufficientStateRunError("polyphase basis axes differ")
        wavelengths = tuple(
            _integer(item, f"experiment.wavelengths[{index}]", 1, 1 << 20)
            for index, item in enumerate(wavelengths_raw)
        )
        timescales = tuple(
            _integer(item, f"experiment.timescales[{index}]", 1, 1 << 20)
            for index, item in enumerate(timescales_raw)
        )
        basis = row["basis_sha256"]
        if not isinstance(basis, str) or len(basis) != 64:
            raise PolyphaseSufficientStateRunError(
                "experiment.basis_sha256 differs"
            )
        readouts_raw = row["readouts"]
        if not isinstance(readouts_raw, list) or len(readouts_raw) != 4:
            raise PolyphaseSufficientStateRunError(
                "experiment.readouts must contain exactly four specs"
            )
        readouts: list[PolyphaseReadoutSpec] = []
        for index, item in enumerate(readouts_raw):
            spec_row = _mapping(
                item,
                f"experiment.readouts[{index}]",
                {"name", "slot_weights", "temperature"},
            )
            name = spec_row["name"]
            weights = spec_row["slot_weights"]
            if not isinstance(name, str) or not isinstance(weights, list):
                raise PolyphaseSufficientStateRunError(
                    f"experiment.readouts[{index}] differs"
                )
            try:
                readouts.append(
                    PolyphaseReadoutSpec(
                        name=name,
                        basis_sha256=basis,
                        slot_weights=np.asarray(weights, dtype=np.float32),
                        temperature=_positive(
                            spec_row["temperature"],
                            f"experiment.readouts[{index}].temperature",
                            1_000_000.0,
                        ),
                    )
                )
            except ValueError as exc:
                raise PolyphaseSufficientStateRunError(
                    f"experiment.readouts[{index}] differs"
                ) from exc
        if len({spec.name for spec in readouts}) != len(readouts):
            raise PolyphaseSufficientStateRunError("readout names must be unique")
        source_generator = row["source_generator"]
        if not isinstance(source_generator, str):
            raise PolyphaseSufficientStateRunError(
                "experiment.source_generator differs"
            )
        result = cls(
            n_bits=n_bits,
            stream_groups=groups,
            regime_switch=regime_switch,
            chunk_partition=partition,
            wavelengths=wavelengths,
            timescales=timescales,
            basis_sha256=basis,
            minimum_pairwise_normalized_readout_rms=_positive(
                row["minimum_pairwise_normalized_readout_rms"],
                "experiment.minimum_pairwise_normalized_readout_rms",
                1_000_000.0,
            ),
            source_generator=source_generator,
            readouts=tuple(readouts),
        )
        if result.n_bits != KEY_BITS:
            raise PolyphaseSufficientStateRunError("O1C-0027 requires 256 bits")
        if result.stream_groups != 384 or result.regime_switch != 193:
            raise PolyphaseSufficientStateRunError(
                "O1C-0027 stream geometry differs"
            )
        if result.chunk_partition != (17, 64, 5, 96, 65, 32, 105):
            raise PolyphaseSufficientStateRunError(
                "O1C-0027 rechunk partition differs"
            )
        if result.wavelengths != WAVELENGTHS or result.timescales != TIMESCALES:
            raise PolyphaseSufficientStateRunError("O1C-0027 basis axes differ")
        if result.basis_sha256 != BASIS_SHA256:
            raise PolyphaseSufficientStateRunError(
                "O1C-0027 basis commitment differs"
            )
        if result.source_generator != SOURCE_GENERATOR:
            raise PolyphaseSufficientStateRunError(
                "O1C-0027 execution contract differs"
            )
        return result


@dataclass(frozen=True)
class PolyphaseRunBudgets:
    maximum_cpu_seconds: float
    maximum_wall_seconds: float
    maximum_resident_memory_mib: int
    maximum_persistent_artifact_bytes: int
    maximum_state_bytes_per_arm: int
    maximum_deployment_live_state_bytes: int
    maximum_reference_state_bytes: int
    maximum_aggregate_algorithmic_state_bytes: int
    maximum_state_snapshot_bytes: int
    maximum_source_buffer_bytes: int
    maximum_control_input_chunk_bytes: int
    maximum_source_plus_control_input_bytes: int
    maximum_readout_artifact_bytes: int
    maximum_source_generation_calls: int
    maximum_primary_consume_calls: int
    maximum_primary_reingested_groups: int
    maximum_state_group_updates: int
    maximum_input_scalar_deliveries: int
    maximum_resonator_cell_updates: int
    maximum_direct_reference_group_updates: int
    maximum_direct_reference_resonator_cell_updates: int
    maximum_direct_reference_readout_calls: int
    maximum_direct_reference_readout_slot_contributions: int
    maximum_successful_state_readout_calls: int
    maximum_replay_required_probes: int
    maximum_scientific_entropy_calls: int
    maximum_target_reads: int
    maximum_label_reads: int
    maximum_outcome_or_progress_reads: int
    maximum_solver_calls: int
    maximum_sibling_reads: int
    maximum_sibling_writes: int
    maximum_network_calls: int
    maximum_gpu_calls: int
    maximum_mps_calls: int

    @classmethod
    def from_mapping(cls, value: object) -> "PolyphaseRunBudgets":
        fields = set(cls.__dataclass_fields__)
        row = _mapping(value, "budgets", fields)
        cpu = _positive(row["maximum_cpu_seconds"], "budgets.maximum_cpu_seconds", 86_400)
        wall = _positive(
            row["maximum_wall_seconds"], "budgets.maximum_wall_seconds", 86_400
        )
        integers: dict[str, int] = {}
        for field in fields - {"maximum_cpu_seconds", "maximum_wall_seconds"}:
            integers[field] = _integer(row[field], f"budgets.{field}", 0, 1 << 40)
        result = cls(maximum_cpu_seconds=cpu, maximum_wall_seconds=wall, **integers)
        for field in (
            "maximum_primary_reingested_groups",
            "maximum_scientific_entropy_calls",
            "maximum_target_reads",
            "maximum_label_reads",
            "maximum_outcome_or_progress_reads",
            "maximum_solver_calls",
            "maximum_sibling_reads",
            "maximum_sibling_writes",
            "maximum_network_calls",
            "maximum_gpu_calls",
            "maximum_mps_calls",
        ):
            if getattr(result, field) != 0:
                raise PolyphaseSufficientStateRunError(f"O1C-0027 requires zero {field}")
        return result


def _read_document(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolyphaseSufficientStateRunError("run config is unreadable") from exc
    if not isinstance(value, dict):
        raise PolyphaseSufficientStateRunError("run config must be a mapping")
    return value


def load_polyphase_run_config(
    path: str | Path,
) -> tuple[dict[str, object], PolyphaseExperimentConfig, PolyphaseRunBudgets]:
    top = dict(
        _mapping(
            _read_document(Path(path)),
            "config",
            {
                "schema",
                "attempt_id",
                "slug",
                "claim_level",
                "hypothesis",
                "prediction",
                "controls",
                "budgets",
                "next_action",
                "experiment",
            },
        )
    )
    if top["schema"] != RUN_CONFIG_SCHEMA:
        raise PolyphaseSufficientStateRunError("run config schema differs")
    for field in (
        "attempt_id",
        "slug",
        "claim_level",
        "hypothesis",
        "prediction",
        "next_action",
    ):
        if not isinstance(top[field], str) or not str(top[field]).strip():
            raise PolyphaseSufficientStateRunError(f"config.{field} is required")
    if top["attempt_id"] != ATTEMPT_ID or top["slug"] != SLUG:
        raise PolyphaseSufficientStateRunError("O1C-0027 identity differs")
    if top["claim_level"] != ClaimLevel.VALIDATION.value:
        raise PolyphaseSufficientStateRunError("O1C-0027 claim level differs")
    controls = top["controls"]
    if (
        not isinstance(controls, list)
        or not controls
        or any(not isinstance(item, str) or not item.strip() for item in controls)
    ):
        raise PolyphaseSufficientStateRunError("config.controls differ")
    experiment = PolyphaseExperimentConfig.from_mapping(top["experiment"])
    budgets = PolyphaseRunBudgets.from_mapping(top["budgets"])
    planned = _planned_work(experiment)
    exact_budget_pairs = {
        "maximum_state_bytes_per_arm": STATE_BYTES,
        "maximum_deployment_live_state_bytes": 4 * STATE_BYTES,
        "maximum_reference_state_bytes": REFERENCE_STATE_BYTES,
        "maximum_aggregate_algorithmic_state_bytes": 4 * STATE_BYTES
        + REFERENCE_STATE_BYTES,
        "maximum_state_snapshot_bytes": 5 * STATE_BYTES,
        "maximum_source_buffer_bytes": planned["source_buffer_bytes"],
        "maximum_control_input_chunk_bytes": CONTROL_INPUT_CHUNK_BYTES,
        "maximum_source_plus_control_input_bytes": planned[
            "source_plus_control_input_bytes"
        ],
        "maximum_readout_artifact_bytes": planned["readout_artifact_bytes"],
        "maximum_source_generation_calls": 1,
        "maximum_primary_consume_calls": 1,
        "maximum_state_group_updates": planned["state_group_updates"],
        "maximum_input_scalar_deliveries": planned["input_scalar_deliveries"],
        "maximum_resonator_cell_updates": planned[
            "resonator_cell_updates"
        ],
        "maximum_direct_reference_group_updates": experiment.stream_groups,
        "maximum_direct_reference_resonator_cell_updates": planned[
            "direct_reference_resonator_cell_updates"
        ],
        "maximum_direct_reference_readout_calls": len(experiment.readouts),
        "maximum_direct_reference_readout_slot_contributions": planned[
            "direct_reference_readout_slot_contributions"
        ],
        "maximum_successful_state_readout_calls": 12,
        "maximum_replay_required_probes": 3,
    }
    for field, expected in exact_budget_pairs.items():
        if getattr(budgets, field) != expected:
            raise PolyphaseSufficientStateRunError(f"budgets.{field} differs")
    if budgets.maximum_resident_memory_mib != 128:
        raise PolyphaseSufficientStateRunError(
            "O1C-0027 resident-memory budget differs"
        )
    return top, experiment, budgets


def _planned_work(experiment: PolyphaseExperimentConfig) -> dict[str, int]:
    state_groups = 3 * experiment.stream_groups + experiment.regime_switch
    group_width = len(WAVELENGTHS) * KEY_BITS
    specs = len(experiment.readouts)
    return {
        "source_buffer_bytes": experiment.stream_groups * group_width * 4,
        "source_plus_control_input_bytes": experiment.stream_groups
        * group_width
        * 4
        + CONTROL_INPUT_CHUNK_BYTES,
        "readout_artifact_bytes": 4 * specs * KEY_BITS * 4,
        "state_group_updates": state_groups,
        "input_scalar_deliveries": state_groups * group_width,
        "resonator_cell_updates": state_groups * group_width * len(TIMESCALES),
        "direct_reference_resonator_cell_updates": experiment.stream_groups
        * group_width
        * len(TIMESCALES),
        "direct_reference_readout_slot_contributions": specs
        * group_width
        * len(TIMESCALES),
    }


def _deterministic_stream(experiment: PolyphaseExperimentConfig) -> np.ndarray:
    """Generate the single target-free dyadic source buffer."""

    result = np.empty(
        (experiment.stream_groups, len(WAVELENGTHS), KEY_BITS), dtype=np.float32
    )
    coordinates = np.arange(KEY_BITS, dtype=np.int64)
    signs = ((1, -1, 1), (-1, 1, 1))
    carrier_scale = (4, -8)
    for t in range(experiment.stream_groups):
        regime = int(t >= experiment.regime_switch)
        for horizon in range(len(WAVELENGTHS)):
            q = 2 * ((17 * coordinates + 29 * t + 7 * horizon) & 31) - 31
            parity = np.fromiter(
                (
                    1
                    if (int(i) ^ (13 * t + 5 * horizon)).bit_count() % 2 == 0
                    else -1
                    for i in coordinates
                ),
                dtype=np.int64,
                count=KEY_BITS,
            )
            numerator = signs[regime][horizon] * q + carrier_scale[regime] * parity
            result[t, horizon] = np.asarray(numerator / 64.0, dtype=np.float32)
    if (
        result.nbytes != experiment.stream_groups * len(WAVELENGTHS) * KEY_BITS * 4
        or not np.all(np.isfinite(result))
        or bool(np.any(result == 0.0))
    ):
        raise PolyphaseSufficientStateRunError("deterministic source differs")
    return result


def _partition(source: np.ndarray, widths: Sequence[int]) -> tuple[np.ndarray, ...]:
    offset = 0
    chunks: list[np.ndarray] = []
    for width in widths:
        chunks.append(source[offset : offset + width])
        offset += width
    if offset != source.shape[0]:
        raise PolyphaseSufficientStateRunError("rechunk partition differs")
    return tuple(chunks)


def _array_sha256(value: np.ndarray, dtype: str) -> str:
    return hashlib.sha256(value.astype(dtype, copy=False).tobytes(order="C")).hexdigest()


def _max_ulp_distance(left: np.ndarray, right: np.ndarray) -> int:
    left_u = np.asarray(left, dtype=np.float32).view(np.uint32)
    right_u = np.asarray(right, dtype=np.float32).view(np.uint32)

    def ordered(value: np.ndarray) -> np.ndarray:
        sign = (value & np.uint32(0x80000000)) != 0
        return np.where(sign, ~value, value | np.uint32(0x80000000)).astype(np.uint64)

    left_o = ordered(left_u)
    right_o = ordered(right_u)
    return int(np.max(np.maximum(left_o, right_o) - np.minimum(left_o, right_o)))


def _rms_normalized(value: np.ndarray) -> tuple[np.ndarray, float]:
    vector = np.asarray(value, dtype=np.float64)
    rms = float(np.sqrt(np.mean(vector * vector)))
    if not math.isfinite(rms) or rms <= np.finfo(np.float64).tiny:
        return np.zeros_like(vector), rms
    return vector / rms, rms


def _pairwise_rms(
    names: Sequence[str],
    values: Mapping[str, np.ndarray],
) -> dict[str, float]:
    return {
        f"{left}__vs__{right}": float(
            np.sqrt(
                np.mean(
                    (
                        np.asarray(values[left], dtype=np.float64)
                        - np.asarray(values[right], dtype=np.float64)
                    )
                    ** 2
                )
            )
        )
        for index, left in enumerate(names)
        for right in names[index + 1 :]
    }


def _foreign_basis_hashes() -> dict[str, str]:
    descriptor = basis_descriptor()
    encoder = copy.deepcopy(descriptor)
    cast(dict[str, object], encoder["encoder"])[
        "coordinate_order"
    ] = "reverse-key-bit-255-through-0"
    kernel = copy.deepcopy(descriptor)
    cast(dict[str, object], kernel["kernel"])["timescales"] = [1, 2, 4, 9]
    phase = copy.deepcopy(descriptor)
    cast(dict[str, object], phase["phase"])["wavelengths"] = [63, 96, 65]
    return {
        "encoder": basis_sha256_from_descriptor(encoder),
        "kernel": basis_sha256_from_descriptor(kernel),
        "phase": basis_sha256_from_descriptor(phase),
    }


@dataclass(frozen=True)
class PolyphaseEvaluation:
    report: dict[str, Any]
    artifacts: dict[str, bytes]
    passed: bool


def evaluate_polyphase_sufficient_state(
    experiment: PolyphaseExperimentConfig,
) -> PolyphaseEvaluation:
    """Run the deterministic mechanism test without touching the capsule layer."""

    if not isinstance(experiment, PolyphaseExperimentConfig):
        raise TypeError("experiment must be PolyphaseExperimentConfig")
    source_generation_calls = 1
    source = _deterministic_stream(experiment)
    source_sha256 = _array_sha256(source, "<f4")

    state_t000 = PolyphaseSufficientState.initial()
    initial_bytes = state_t000.to_bytes()
    initial_description = state_t000.describe()
    del state_t000
    primary = PolyphaseSufficientState.initial()
    rechunk = PolyphaseSufficientState.initial()
    swap = PolyphaseSufficientState.initial()
    prefix = PolyphaseSufficientState.initial()
    primary_groups = primary.consume(source)
    rechunk_groups = rechunk.consume(_partition(source, experiment.chunk_partition))
    swap_groups = swap.consume(
        (np.negative(group, dtype=np.float32) for group in source)
    )
    prefix_groups = prefix.consume(source[: experiment.regime_switch])
    reference = direct_polyphase_state(source)

    arms = {"primary": primary, "rechunk": rechunk, "swap": swap}
    outputs: dict[str, dict[str, np.ndarray]] = {name: {} for name in arms}
    query_receipts: list[dict[str, Any]] = []
    successful_state_readout_calls = 0
    for arm_name, state in arms.items():
        for spec in experiment.readouts:
            before = state.sha256()
            output = read_polyphase_state(state, spec)
            after = state.sha256()
            successful_state_readout_calls += 1
            outputs[arm_name][spec.name] = output
            query_receipts.append(
                {
                    "arm": arm_name,
                    "readout": spec.name,
                    "outcome": "success",
                    "state_sha256_before": before,
                    "state_sha256_after": after,
                    "state_unchanged": before == after,
                    "output_sha256": _array_sha256(output, "<f4"),
                    "reingested_groups": 0,
                }
            )

    reference_outputs: dict[str, np.ndarray] = {}
    parity_rows: dict[str, dict[str, Any]] = {}
    for spec in experiment.readouts:
        expected = read_polyphase_reference(reference, spec)
        actual = outputs["primary"][spec.name]
        bound = reference_readout_roundoff_bound(reference, spec)
        residual = np.abs(actual.astype(np.float64) - expected)
        reference_outputs[spec.name] = expected
        parity_rows[spec.name] = {
            "actual_f32_sha256": _array_sha256(actual, "<f4"),
            "reference_f64_sha256": _array_sha256(expected, "<f8"),
            "reference_rounded_f32_sha256": _array_sha256(expected, "<f4"),
            "max_abs_error": float(residual.max()),
            "max_derived_bound": float(bound.max()),
            "max_error_to_bound_ratio": float(
                np.max(residual / np.maximum(bound, np.finfo(np.float64).tiny))
            ),
            "max_float32_ulp_distance": _max_ulp_distance(
                actual, expected.astype(np.float32)
            ),
            "within_derived_bound": bool(np.all(residual <= bound)),
        }
    reference_clock = reference.clock
    reference_coverage = reference.coverage.copy()
    del reference

    foreign_hashes = _foreign_basis_hashes()
    replay_required_probes = 0
    for name, foreign_hash in foreign_hashes.items():
        spec = PolyphaseReadoutSpec(
            name=f"foreign-{name}",
            basis_sha256=foreign_hash,
            slot_weights=experiment.readouts[0].slot_weights,
            temperature=experiment.readouts[0].temperature,
        )
        before = primary.sha256()
        outcome = "unexpected-success"
        try:
            read_polyphase_state(primary, spec)
        except ReplayRequiredError:
            outcome = "replay-required"
            replay_required_probes += 1
        after = primary.sha256()
        query_receipts.append(
            {
                "arm": "primary",
                "readout": spec.name,
                "foreign_basis_sha256": foreign_hash,
                "outcome": outcome,
                "state_sha256_before": before,
                "state_sha256_after": after,
                "state_unchanged": before == after,
                "reingested_groups": 0,
            }
        )

    names = tuple(spec.name for spec in experiment.readouts)
    pairwise_rms = _pairwise_rms(names, outputs["primary"])
    normalized_primary: dict[str, np.ndarray] = {}
    primary_rms: dict[str, float] = {}
    for name in names:
        normalized_primary[name], primary_rms[name] = _rms_normalized(
            outputs["primary"][name]
        )
    normalized_pairwise_rms = _pairwise_rms(names, normalized_primary)
    common_slot = primary.slots.real.astype(np.float64).mean(axis=(0, 1))
    collapsed_outputs = {
        spec.name: common_slot
        * (float(np.sum(spec.slot_weights, dtype=np.float64)) / spec.temperature)
        for spec in experiment.readouts
    }
    normalized_collapsed = {
        name: _rms_normalized(value)[0] for name, value in collapsed_outputs.items()
    }
    collapsed_pairwise_rms = _pairwise_rms(names, normalized_collapsed)
    primary_bytes = primary.to_bytes()
    rechunk_bytes = rechunk.to_bytes()
    swap_bytes = swap.to_bytes()
    prefix_bytes = prefix.to_bytes()
    state_snapshots = (
        initial_bytes,
        prefix_bytes,
        primary_bytes,
        rechunk_bytes,
        swap_bytes,
    )
    state_sizes = tuple(len(value) for value in state_snapshots)
    expected_full_coverage = np.full(KEY_BITS, experiment.stream_groups, np.uint16)
    expected_prefix_coverage = np.full(KEY_BITS, experiment.regime_switch, np.uint16)

    gates = {
        "one_pass_primary": source_generation_calls == 1
        and primary_groups == experiment.stream_groups,
        "query_zero_reingest_and_state_immutable": all(
            row["reingested_groups"] == 0 and row["state_unchanged"]
            for row in query_receipts
        ),
        "hot_readouts_distinct_after_rms_normalization": all(
            math.isfinite(value) and value > np.finfo(np.float64).tiny
            for value in primary_rms.values()
        )
        and min(normalized_pairwise_rms.values())
        >= experiment.minimum_pairwise_normalized_readout_rms,
        "collapsed_bank_negative_control_rejected": max(
            collapsed_pairwise_rms.values()
        )
        < experiment.minimum_pairwise_normalized_readout_rms,
        "basis_changes_require_replay": replay_required_probes == 3,
        "direct_reference_within_derived_bound": all(
            bool(row["within_derived_bound"]) for row in parity_rows.values()
        ),
        "chunk_partition_byte_exact": primary_bytes == rechunk_bytes,
        "state_size_invariant": state_sizes == (STATE_BYTES,) * 5,
        "branch_swap_slots_exactly_odd": bool(
            np.array_equal(swap.slots, -primary.slots)
        ),
        "branch_swap_readouts_exactly_odd": all(
            np.array_equal(outputs["swap"][name], -outputs["primary"][name])
            for name in names
        ),
        "coverage_and_clock_exact": primary.clock == experiment.stream_groups
        and rechunk.clock == experiment.stream_groups
        and swap.clock == experiment.stream_groups
        and reference_clock == experiment.stream_groups
        and prefix.clock == experiment.regime_switch
        and bool(np.array_equal(primary.coverage, expected_full_coverage))
        and bool(np.array_equal(rechunk.coverage, expected_full_coverage))
        and bool(np.array_equal(swap.coverage, expected_full_coverage))
        and bool(np.array_equal(reference_coverage, expected_full_coverage))
        and bool(np.array_equal(prefix.coverage, expected_prefix_coverage)),
        "serialization_roundtrip_exact": PolyphaseSufficientState.from_bytes(
            primary_bytes
        ).to_bytes()
        == primary_bytes,
    }
    passed = all(gates.values())
    if not gates["one_pass_primary"] or not gates[
        "query_zero_reingest_and_state_immutable"
    ]:
        classification = "ONE_PASS_OR_MUTATION_FAILURE"
    elif not gates["basis_changes_require_replay"]:
        classification = "REPLAY_BOUNDARY_FAILURE"
    elif not gates["hot_readouts_distinct_after_rms_normalization"] or not gates[
        "collapsed_bank_negative_control_rejected"
    ]:
        classification = "HOT_READOUT_COLLAPSE"
    elif not gates["direct_reference_within_derived_bound"]:
        classification = "DIRECT_REFERENCE_PARITY_FAILURE"
    elif not gates["chunk_partition_byte_exact"]:
        classification = "CHUNK_INVARIANCE_FAILURE"
    elif not gates["state_size_invariant"]:
        classification = "T_SIZE_INVARIANCE_FAILURE"
    elif not gates["branch_swap_slots_exactly_odd"] or not gates[
        "branch_swap_readouts_exactly_odd"
    ]:
        classification = "BRANCH_SWAP_ODDNESS_FAILURE"
    elif not gates["coverage_and_clock_exact"]:
        classification = "COUNTER_INTEGRITY_FAILURE"
    elif not gates["serialization_roundtrip_exact"]:
        classification = "SERIALIZATION_FAILURE"
    else:
        classification = "POLYPHASE_SUFFICIENT_STATE_PASS"

    planned = _planned_work(experiment)
    work: dict[str, Any] = {
        "schema": WORK_SCHEMA,
        "source_generation_calls": source_generation_calls,
        "generated_groups": experiment.stream_groups,
        "generated_float32_evidence_values": experiment.stream_groups
        * len(WAVELENGTHS)
        * KEY_BITS,
        "source_buffer_bytes": source.nbytes,
        "maximum_control_input_chunk_bytes": CONTROL_INPUT_CHUNK_BYTES,
        "source_plus_control_input_bytes": source.nbytes
        + CONTROL_INPUT_CHUNK_BYTES,
        "consume_calls": 4,
        "primary_consume_calls": 1,
        "primary_reingested_groups": 0,
        "state_group_updates": primary_groups
        + rechunk_groups
        + swap_groups
        + prefix_groups,
        "input_scalar_deliveries": planned["input_scalar_deliveries"],
        "resonator_cell_updates": planned["resonator_cell_updates"],
        "direct_reference_group_updates": experiment.stream_groups,
        "direct_reference_resonator_cell_updates": planned[
            "direct_reference_resonator_cell_updates"
        ],
        "direct_reference_readout_calls": len(experiment.readouts),
        "direct_reference_readout_slot_contributions": planned[
            "direct_reference_readout_slot_contributions"
        ],
        "successful_state_readout_calls": successful_state_readout_calls,
        "state_readout_scalar_slot_contributions": successful_state_readout_calls
        * len(WAVELENGTHS)
        * len(TIMESCALES)
        * KEY_BITS,
        "replay_required_probes": replay_required_probes,
        "total_query_attempts": len(query_receipts),
        "trainable_parameters": 0,
        "gradient_steps": 0,
        "optimizer_steps": 0,
        "scientific_entropy_calls": 0,
        "target_reads": 0,
        "label_reads": 0,
        "outcome_or_progress_reads": 0,
        "solver_calls": 0,
        "sibling_reads": 0,
        "sibling_writes": 0,
        "network_calls": 0,
        "gpu_calls": 0,
        "mps_calls": 0,
    }
    readout_tensor = np.stack(
        [
            np.stack(
                [
                    (
                        reference_outputs[name].astype(np.float32)
                        if arm == "reference"
                        else outputs[arm][name]
                    )
                    for name in names
                ]
            )
            for arm in ("primary", "rechunk", "swap", "reference")
        ]
    ).astype("<f4", copy=False)
    if readout_tensor.shape != (4, 4, KEY_BITS):
        raise PolyphaseSufficientStateRunError("readout artifact shape differs")

    parity_report = {
        "schema": "o1-256-polyphase-sufficient-state-parity-v1",
        "basis_sha256": BASIS_SHA256,
        "readouts": parity_rows,
        "chunk_state_byte_exact": primary_bytes == rechunk_bytes,
        "branch_swap_slot_max_abs_residual": float(
            np.max(np.abs(swap.slots + primary.slots))
        ),
        "branch_swap_readout_max_abs_residual": float(
            max(
                np.max(np.abs(outputs["swap"][name] + outputs["primary"][name]))
                for name in names
            )
        ),
        "pairwise_primary_readout_rms": pairwise_rms,
        "primary_readout_rms": primary_rms,
        "pairwise_rms_normalized_primary_readouts": normalized_pairwise_rms,
        "pairwise_rms_normalized_collapsed_bank_control": collapsed_pairwise_rms,
    }
    state_rows = {
        "t000": initial_description,
        "prefix_t193": prefix.describe(),
        "primary_t384": primary.describe(),
        "rechunk_t384": rechunk.describe(),
        "swap_t384": swap.describe(),
    }
    report: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "classification": classification,
        "mechanism_validation_passed": passed,
        "cryptanalytic_signal_claimed": False,
        "full_round_key_recovery_claimed": False,
        "basis_sha256": BASIS_SHA256,
        "state": {
            "persistent_bytes_per_arm": STATE_BYTES,
            "deployment_live_state_bytes": 4 * STATE_BYTES,
            "reference_audit_state_bytes": REFERENCE_STATE_BYTES,
            "aggregate_algorithmic_state_bytes": 4 * STATE_BYTES
            + REFERENCE_STATE_BYTES,
            "snapshot_bytes": sum(state_sizes),
            "stream_length_dependent": False,
            "states": state_rows,
        },
        "stream": {
            "generator": SOURCE_GENERATOR,
            "sha256_f32le": source_sha256,
            "shape": list(source.shape),
            "dtype": "float32",
            "groups": experiment.stream_groups,
            "regime_switch": experiment.regime_switch,
            "minimum": float(source.min()),
            "maximum": float(source.max()),
            "zero_values": int(np.count_nonzero(source == 0.0)),
        },
        "readout": {
            "names": list(names),
            "primary_state_sha256": primary.sha256(),
            "minimum_pairwise_raw_rms": min(pairwise_rms.values()),
            "minimum_pairwise_rms_after_normalization": min(
                normalized_pairwise_rms.values()
            ),
            "collapsed_bank_maximum_pairwise_rms_after_normalization": max(
                collapsed_pairwise_rms.values()
            ),
            "work_per_switch": {
                "scalar_slot_contributions": len(WAVELENGTHS)
                * len(TIMESCALES)
                * KEY_BITS,
                "temperature_scalings": KEY_BITS,
                "state_writes": 0,
                "stream_groups_reingested": 0,
            },
            "event_reingestion_per_switch": 0,
        },
        "gates": gates,
        "work": work,
    }
    report["result_sha256"] = hashlib.sha256(_json_bytes(report)).hexdigest()

    stream_spec = {
        "schema": "o1-256-polyphase-source-spec-v1",
        "generator": SOURCE_GENERATOR,
        "formula": {
            "q": "2*((17*i+29*t+7*h)&31)-31",
            "carrier": "+1 iff popcount(i xor (13*t+5*h)) is even else -1",
            "regime_signs": [[1, -1, 1], [-1, 1, 1]],
            "carrier_scale": [4, -8],
            "division": 64,
        },
        "shape": list(source.shape),
        "dtype": "float32",
        "sha256_f32le": source_sha256,
        "generated_once": True,
        "contains_target_label_or_outcome": False,
    }
    readout_specs = {
        "schema": "o1-256-polyphase-readout-set-v1",
        "basis_sha256": BASIS_SHA256,
        "specs": [spec.describe() for spec in experiment.readouts],
        "foreign_basis_probes": foreign_hashes,
    }
    artifacts = {
        "stream_spec.json": _json_bytes(stream_spec),
        "readout_specs.json": _json_bytes(readout_specs),
        "state_t000.bin": initial_bytes,
        "state_t193.bin": prefix_bytes,
        "state_primary_t384.bin": primary_bytes,
        "state_rechunk_t384.bin": rechunk_bytes,
        "state_swap_t384.bin": swap_bytes,
        "readouts.f32le": readout_tensor.tobytes(order="C"),
        "query_receipts.json": _json_bytes(
            {
                "schema": "o1-256-polyphase-query-receipts-v1",
                "receipts": query_receipts,
            }
        ),
        "parity_report.json": _json_bytes(parity_report),
        "structural_work_ledger.json": _json_bytes(work),
        "result.json": _json_bytes(report),
    }
    if len(artifacts) != 12:
        raise PolyphaseSufficientStateRunError("artifact inventory differs")
    return PolyphaseEvaluation(report=report, artifacts=artifacts, passed=passed)


def _git_commit(root: Path) -> str:
    status = subprocess.run(
        ("git", "status", "--porcelain"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    if status.stdout:
        raise PolyphaseSufficientStateRunError("lab worktree must be clean")
    commit = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not commit:
        raise PolyphaseSufficientStateRunError("lab commit is unavailable")
    return commit


def _source_hashes(root: Path, config_path: Path) -> dict[str, str]:
    names = (
        "isolation.py",
        "polyphase_sufficient_state.py",
        "polyphase_sufficient_state_run.py",
        "run_capsule.py",
    )
    return {
        "config": _sha256_file(config_path),
        "pyproject": _sha256_file(root / "pyproject.toml"),
        **{
            f"module_{Path(name).stem}": _sha256_file(
                root / "src/o1_crypto_lab" / name
            )
            for name in names
        },
    }


def _already_finalized(manager: RunCapsuleManager, attempt_id: str) -> int | None:
    published = manager.finalized_attempt(attempt_id)
    if published is None:
        return None
    metrics_document = json.loads(
        (published.path / "metrics.json").read_text(encoding="utf-8")
    )
    capsule_status = metrics_document.get("status")
    print(
        json.dumps(
            {
                "attempt_id": attempt_id,
                "path": str(published.path),
                "manifest_sha256": published.manifest_sha256,
                "verified": published.verification.ok,
                "status": "already-finalized-no-replay",
                "capsule_status": capsule_status,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if capsule_status == "completed" else 2


def run_capsule_from_config(path: str | Path) -> int:
    root = Path(__file__).resolve().parents[2]
    config_path = Path(path).resolve(strict=True)
    canonical_config = (root / "configs/polyphase_sufficient_state_v1.json").resolve(
        strict=True
    )
    if config_path != canonical_config:
        raise PolyphaseSufficientStateRunError(
            "O1C-0027 requires the canonical tracked config path"
        )
    top, experiment, budgets = load_polyphase_run_config(config_path)
    manager = RunCapsuleManager(root)
    finalized_status = _already_finalized(manager, ATTEMPT_ID)
    if finalized_status is not None:
        return finalized_status
    if ATTEMPT_ID in manager.recoverable_attempt_ids():
        interrupted = manager.recover(ATTEMPT_ID)
        if interrupted.publication_prepared:
            finalized = interrupted.finalize(metrics={})
            metrics_document = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            return 0 if metrics_document.get("status") == "completed" else 2
        finalized = interrupted.finalize(
            metrics={
                "schema": RUN_METRICS_SCHEMA,
                "hard_interruption_recovered": True,
                "scientific_result_claimed": False,
            },
            status="stopped",
            next_action=(
                "Preserve the interrupted mechanism attempt and advance under a "
                "new O1C ID; never republish O1C-0027 by replay."
            ),
        )
        print(f"stopped capsule: {finalized.path}", file=sys.stderr)
        return 2

    commit = _git_commit(root)
    hashes = _source_hashes(root, config_path)
    run = manager.start(
        attempt_id=ATTEMPT_ID,
        slug=SLUG,
        commit=commit,
        hypothesis=str(top["hypothesis"]),
        prediction=str(top["prediction"]),
        controls=tuple(str(item) for item in cast(list[object], top["controls"])),
        budgets=dict(cast(Mapping[str, object], top["budgets"])),
        source_hashes=hashes,
        claim_level=ClaimLevel.VALIDATION,
        next_action=str(top["next_action"]),
        config=top,
        command=(
            sys.executable,
            "-m",
            "o1_crypto_lab.polyphase_sufficient_state_run",
            "--config",
            str(config_path),
        ),
        environment={
            "experiment_boundary": "synthetic-full256-polyphase-mechanism",
            "accelerator": "none",
            "numpy_version": np.__version__,
            "scientific_python_worker_processes": 1,
            "explicit_parallel_scientific_workers": 0,
            "state_bytes": STATE_BYTES,
            "source_generated_once": True,
            "scientific_entropy_calls": 0,
            "target_reads": 0,
            "label_reads": 0,
            "outcome_or_progress_reads": 0,
            "solver_calls": 0,
            "sibling_repository_reads": 0,
            "sibling_repository_writes": 0,
            "network_calls": 0,
            "mps_calls": 0,
            "gpu_calls": 0,
            "hard_interruption_policy": "FINALIZE_STOPPED_AND_NEVER_REPLAY",
        },
    )
    persisted: dict[str, dict[str, object]] = {}
    persistent_bytes = 0
    cpu_started = time.process_time()
    wall_started = time.monotonic()
    try:
        run.checkpoint(
            {
                "phase": "O1C0027_RESERVED",
                "basis_sha256": BASIS_SHA256,
                "stream_groups": experiment.stream_groups,
                "state_bytes": STATE_BYTES,
                "source_generation_calls": 0,
                "primary_consume_calls": 0,
                "query_attempts": 0,
            }
        )
        run.append_stdout(
            "O1C-0027 full-256 polyphase sufficient-state validation started.\n"
        )
        evaluation = evaluate_polyphase_sufficient_state(experiment)
        for relative, payload in sorted(evaluation.artifacts.items()):
            if persistent_bytes + len(payload) > budgets.maximum_persistent_artifact_bytes:
                raise PolyphaseSufficientStateRunError(
                    "persistent artifacts exceed budget before index"
                )
            output = run.write_artifact(relative, payload)
            digest = hashlib.sha256(payload).hexdigest()
            if _sha256_file(output) != digest:
                raise PolyphaseSufficientStateRunError(
                    f"persisted artifact differs: {relative}"
                )
            persisted[relative] = {"sha256": digest, "bytes": len(payload)}
            persistent_bytes += len(payload)
        artifact_index = {
            "schema": ARTIFACT_INDEX_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "artifacts": dict(sorted(persisted.items())),
            "indexed_artifact_count": len(persisted),
            "indexed_artifact_bytes": persistent_bytes,
            "self_excluded_from_index": True,
        }
        index_payload = _json_bytes(artifact_index)
        if persistent_bytes + len(index_payload) > budgets.maximum_persistent_artifact_bytes:
            raise PolyphaseSufficientStateRunError("artifact index exceeds budget")
        index_path = run.write_artifact("artifact_index.json", index_payload)
        if _sha256_file(index_path) != hashlib.sha256(index_payload).hexdigest():
            raise PolyphaseSufficientStateRunError("persisted artifact index differs")
        persistent_bytes += len(index_payload)
        run.checkpoint(
            {
                "phase": "MECHANISM_RESULT_AND_ARTIFACTS_FROZEN",
                "classification": evaluation.report["classification"],
                "result_sha256": evaluation.report["result_sha256"],
                "source_generation_calls": evaluation.report["work"][
                    "source_generation_calls"
                ],
                "primary_consume_calls": evaluation.report["work"][
                    "primary_consume_calls"
                ],
                "query_attempts": evaluation.report["work"]["total_query_attempts"],
                "persistent_artifact_bytes": persistent_bytes,
            }
        )
        if _git_commit(root) != commit or _source_hashes(root, config_path) != hashes:
            raise PolyphaseSufficientStateRunError("source changed during execution")

        cpu_seconds = time.process_time() - cpu_started
        wall_seconds = time.monotonic() - wall_started
        peak_rss_bytes = _process_peak_rss_bytes()
        work = evaluation.report["work"]
        state = evaluation.report["state"]
        budget_checks = {
            "cpu": cpu_seconds <= budgets.maximum_cpu_seconds,
            "wall": wall_seconds <= budgets.maximum_wall_seconds,
            "resident_memory": peak_rss_bytes
            <= budgets.maximum_resident_memory_mib * 1024 * 1024,
            "persistent_artifacts": persistent_bytes
            <= budgets.maximum_persistent_artifact_bytes,
            "state_bytes_per_arm": state["persistent_bytes_per_arm"]
            == budgets.maximum_state_bytes_per_arm,
            "deployment_live_state": state["deployment_live_state_bytes"]
            == budgets.maximum_deployment_live_state_bytes,
            "reference_state": state["reference_audit_state_bytes"]
            == budgets.maximum_reference_state_bytes,
            "aggregate_algorithmic_state": state[
                "aggregate_algorithmic_state_bytes"
            ]
            == budgets.maximum_aggregate_algorithmic_state_bytes,
            "state_snapshots": state["snapshot_bytes"]
            == budgets.maximum_state_snapshot_bytes,
            "source_buffer": work["source_buffer_bytes"]
            == budgets.maximum_source_buffer_bytes,
            "control_input_chunk": work["maximum_control_input_chunk_bytes"]
            == budgets.maximum_control_input_chunk_bytes,
            "source_plus_control_input": work["source_plus_control_input_bytes"]
            == budgets.maximum_source_plus_control_input_bytes,
            "readout_artifact": len(evaluation.artifacts["readouts.f32le"])
            == budgets.maximum_readout_artifact_bytes,
            "source_generation_calls": work["source_generation_calls"]
            == budgets.maximum_source_generation_calls,
            "primary_consume_calls": work["primary_consume_calls"]
            == budgets.maximum_primary_consume_calls,
            "primary_reingested_groups": work["primary_reingested_groups"]
            == budgets.maximum_primary_reingested_groups,
            "state_group_updates": work["state_group_updates"]
            == budgets.maximum_state_group_updates,
            "input_scalar_deliveries": work["input_scalar_deliveries"]
            == budgets.maximum_input_scalar_deliveries,
            "resonator_cell_updates": work["resonator_cell_updates"]
            == budgets.maximum_resonator_cell_updates,
            "direct_reference_group_updates": work[
                "direct_reference_group_updates"
            ]
            == budgets.maximum_direct_reference_group_updates,
            "direct_reference_resonator_cell_updates": work[
                "direct_reference_resonator_cell_updates"
            ]
            == budgets.maximum_direct_reference_resonator_cell_updates,
            "direct_reference_readout_calls": work[
                "direct_reference_readout_calls"
            ]
            == budgets.maximum_direct_reference_readout_calls,
            "direct_reference_readout_slot_contributions": work[
                "direct_reference_readout_slot_contributions"
            ]
            == budgets.maximum_direct_reference_readout_slot_contributions,
            "successful_state_readout_calls": work[
                "successful_state_readout_calls"
            ]
            == budgets.maximum_successful_state_readout_calls,
            "replay_required_probes": work["replay_required_probes"]
            == budgets.maximum_replay_required_probes,
            "scientific_entropy": work["scientific_entropy_calls"] == 0,
            "target_reads": work["target_reads"] == 0,
            "label_reads": work["label_reads"] == 0,
            "outcome_or_progress_reads": work["outcome_or_progress_reads"] == 0,
            "solver": work["solver_calls"] == 0,
            "sibling_reads": work["sibling_reads"] == 0,
            "sibling_writes": work["sibling_writes"] == 0,
            "network": work["network_calls"] == 0,
            "gpu": work["gpu_calls"] == 0,
            "mps": work["mps_calls"] == 0,
        }
        failed_budgets = sorted(
            name for name, passed in budget_checks.items() if not passed
        )
        operationally_complete = not failed_budgets
        completed = operationally_complete and evaluation.passed
        metrics = {
            "schema": RUN_METRICS_SCHEMA,
            "classification": evaluation.report["classification"],
            "mechanism_validation_passed": evaluation.passed,
            "cryptanalytic_signal_claimed": False,
            "full_round_key_recovery_claimed": False,
            "result_sha256": evaluation.report["result_sha256"],
            "gates": evaluation.report["gates"],
            "state": state,
            "work": work,
            "cpu_seconds": cpu_seconds,
            "wall_seconds": wall_seconds,
            "peak_rss_bytes": peak_rss_bytes,
            "peak_rss_mib": peak_rss_bytes / (1024 * 1024),
            "persistent_artifact_bytes": persistent_bytes,
            "budget_checks": budget_checks,
            "failed_budgets": failed_budgets,
            "operationally_complete": operationally_complete,
        }
        run.append_stdout(json.dumps(metrics, sort_keys=True) + "\n")
        finalized = run.finalize(
            metrics=metrics,
            status="completed" if completed else "failed",
        )
    except Exception as exc:
        if run.publication_prepared:
            finalized = run.finalize(metrics={})
            metrics_document = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            return 0 if metrics_document.get("status") == "completed" else 2
        run.append_stderr(f"{type(exc).__name__}: {exc}\n")
        finalized = run.finalize(
            metrics={
                "schema": RUN_METRICS_SCHEMA,
                "classification": "OPERATIONAL_FAILURE",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "persistent_artifact_bytes": persistent_bytes,
                "scientific_result_claimed": False,
            },
            status="failed",
            next_action=(
                "Preserve this operational failure and repair it under a new O1C "
                "identity without replaying O1C-0027."
            ),
        )
        print(f"failed capsule: {finalized.path}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "attempt_id": finalized.attempt_id,
                "path": str(finalized.path),
                "manifest_sha256": finalized.manifest_sha256,
                "verified": finalized.verification.ok,
                "classification": evaluation.report["classification"],
                "mechanism_validation_passed": evaluation.passed,
                "failed_budgets": failed_budgets,
                "state_bytes": STATE_BYTES,
                "stream_groups": experiment.stream_groups,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if completed else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run capsule-backed full-256 polyphase sufficient-state validation"
    )
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    return run_capsule_from_config(args.config)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ARTIFACT_INDEX_SCHEMA",
    "ATTEMPT_ID",
    "PolyphaseEvaluation",
    "PolyphaseExperimentConfig",
    "PolyphaseRunBudgets",
    "PolyphaseSufficientStateRunError",
    "RESULT_SCHEMA",
    "RUN_CONFIG_SCHEMA",
    "RUN_METRICS_SCHEMA",
    "SLUG",
    "WORK_SCHEMA",
    "evaluate_polyphase_sufficient_state",
    "load_polyphase_run_config",
    "main",
    "run_capsule_from_config",
]
