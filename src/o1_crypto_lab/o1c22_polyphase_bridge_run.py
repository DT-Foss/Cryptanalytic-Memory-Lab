"""Capsule-backed O1C-0022 packet to polyphase V2 validation (O1C-0028).

This is a synthetic mechanism run.  It validates transport geometry, state
semantics and a synthetic O1-O-shaped hot/cold contract without ChaCha20 output, an
unknown key, a solver artifact or any sibling repository.  Real efficacy is a
separate successor attempt over authoritative O1C-0022 packet extractions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import resource
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence, cast

import numpy as np

from .o1c22_packet_codec import (
    FrozenMedianAbsQuantizer,
    PacketDeltaExtraction,
    PacketDeltaGroup,
    active_coordinate_sequence_sha256,
    complement_packet_polarity,
)
from .o1c22_polyphase_bridge import (
    COLD_OPERATOR_IDS,
    ENCODING_NORMALIZED_FLOAT32,
    ENCODING_QUANTIZED_INT8_FLOAT32,
    GROUP_BYTES,
    GROUP_SHAPE,
    HOT_OPERATOR_IDS,
    O1C22_HORIZONS,
    bind_o1o_hot_readout,
    build_dense_horizon_major_stream,
    consume_dense_horizon_major_stream,
    decode_packet_delta_extraction,
    fit_nonnegative_horizon_readout,
    freeze_hot_readout_lineage,
    permute_dense_coordinates,
    read_bound_hot_state,
    read_fitted_horizon_state,
)
from .polyphase_sufficient_state_v2 import (
    BASIS_SHA256,
    KEY_BITS,
    POLE_COUNT,
    STATE_BYTES,
    STATE_SCHEMA,
    TIMESCALES,
    WAVELENGTHS,
    PolyphaseReadoutSpec,
    PolyphaseSufficientState,
    ReplayRequiredError,
    direct_polyphase_state,
    read_polyphase_reference,
    read_polyphase_state,
    reference_readout_roundoff_bound,
)
from .run_capsule import ClaimLevel, RunCapsuleManager


RUN_CONFIG_SCHEMA = "o1-256-o1c22-polyphase-bridge-run-config-v1"
RUN_METRICS_SCHEMA = "o1-256-o1c22-polyphase-bridge-cli-result-v1"
RESULT_SCHEMA = "o1-256-o1c22-polyphase-bridge-result-v1"
WORK_SCHEMA = "o1-256-o1c22-polyphase-bridge-work-v1"
ARTIFACT_INDEX_SCHEMA = "o1-256-o1c22-polyphase-bridge-artifact-index-v1"
ATTEMPT_ID = "O1C-0028"
SLUG = "horizon-major-hot-routing-full256-v1"
SYNTHETIC_GENERATOR = "full256-three-horizon-dyadic-packet-fixture-v1"
EXPECTED_COLD_PROBES = 13
ALLOCATION_REPEAT_TRIALS = 64


class O1C22PolyphaseBridgeRunError(ValueError):
    """The O1C-0028 config, mechanism, lifecycle or budget differs."""


def _mapping(value: object, field: str, expected: set[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise O1C22PolyphaseBridgeRunError(f"{field} fields differ")
    return value


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise O1C22PolyphaseBridgeRunError(
            f"{field} must be an integer in [{minimum},{maximum}]"
        )
    return value


def _number(value: object, field: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise O1C22PolyphaseBridgeRunError(f"{field} must be numeric")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise O1C22PolyphaseBridgeRunError(f"{field} differs")
    return result


def _json_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise O1C22PolyphaseBridgeRunError("artifact is not finite JSON") from exc
    return (rendered + "\n").encode("ascii")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _process_peak_rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return value if value > 16 * 1024 * 1024 else value * 1024


@dataclass(frozen=True)
class BridgeExperimentConfig:
    n_bits: int
    state_abi_revision: int
    state_schema: str
    state_basis_sha256: str
    packet_horizons: tuple[int, ...]
    polyphase_wavelengths: tuple[int, ...]
    quantizer_scales: tuple[float, ...]
    coordinate_permutation_offset: int
    ridge_alpha: float
    normalized_encoding: str
    quantized_encoding: str

    @classmethod
    def from_mapping(cls, value: object) -> "BridgeExperimentConfig":
        row = _mapping(
            value,
            "experiment",
            {
                "n_bits",
                "state_abi_revision",
                "state_schema",
                "state_basis_sha256",
                "packet_horizons",
                "polyphase_wavelengths",
                "quantizer_scales",
                "coordinate_permutation_offset",
                "ridge_alpha",
                "normalized_encoding",
                "quantized_encoding",
            },
        )
        horizons_raw = row["packet_horizons"]
        wavelengths_raw = row["polyphase_wavelengths"]
        scales_raw = row["quantizer_scales"]
        if not all(isinstance(value, list) for value in (horizons_raw, wavelengths_raw, scales_raw)):
            raise O1C22PolyphaseBridgeRunError("experiment vector fields differ")
        horizons = tuple(
            _integer(item, f"experiment.packet_horizons[{index}]", 1, 1 << 20)
            for index, item in enumerate(cast(list[object], horizons_raw))
        )
        wavelengths = tuple(
            _integer(item, f"experiment.polyphase_wavelengths[{index}]", 1, 1 << 20)
            for index, item in enumerate(cast(list[object], wavelengths_raw))
        )
        scales = tuple(
            _number(item, f"experiment.quantizer_scales[{index}]", 1e-12, 1e12)
            for index, item in enumerate(cast(list[object], scales_raw))
        )
        result = cls(
            n_bits=_integer(row["n_bits"], "experiment.n_bits", 1, 1 << 20),
            state_abi_revision=_integer(
                row["state_abi_revision"], "experiment.state_abi_revision", 1, 1024
            ),
            state_schema=str(row["state_schema"]),
            state_basis_sha256=str(row["state_basis_sha256"]),
            packet_horizons=horizons,
            polyphase_wavelengths=wavelengths,
            quantizer_scales=scales,
            coordinate_permutation_offset=_integer(
                row["coordinate_permutation_offset"],
                "experiment.coordinate_permutation_offset",
                1,
                KEY_BITS - 1,
            ),
            ridge_alpha=_number(
                row["ridge_alpha"], "experiment.ridge_alpha", 1e-12, 1e12
            ),
            normalized_encoding=str(row["normalized_encoding"]),
            quantized_encoding=str(row["quantized_encoding"]),
        )
        if (
            result.n_bits != KEY_BITS
            or result.state_abi_revision != 2
            or result.state_schema != STATE_SCHEMA
            or result.state_basis_sha256 != BASIS_SHA256
            or result.packet_horizons != O1C22_HORIZONS
            or result.polyphase_wavelengths != WAVELENGTHS
            or result.quantizer_scales != (2.0, 4.0, 8.0)
            or result.coordinate_permutation_offset != 17
            or result.ridge_alpha != 1.0
            or result.normalized_encoding != ENCODING_NORMALIZED_FLOAT32
            or result.quantized_encoding != ENCODING_QUANTIZED_INT8_FLOAT32
        ):
            raise O1C22PolyphaseBridgeRunError("O1C-0028 experiment differs")
        return result


@dataclass(frozen=True)
class BridgeRunBudgets:
    maximum_cpu_seconds: float
    maximum_wall_seconds: float
    maximum_resident_memory_mib: int
    maximum_persistent_artifact_bytes: int
    maximum_state_bytes_per_arm: int
    maximum_dense_stream_bytes_per_encoding: int
    maximum_dense_stream_aggregate_bytes: int
    maximum_sparse_control_chunk_bytes: int
    maximum_reference_state_bytes: int
    maximum_simultaneous_live_states: int
    maximum_aggregate_validation_state_bytes: int
    maximum_state_snapshot_bytes: int
    maximum_readout_artifact_bytes: int
    expected_packet_groups_per_extraction: int
    expected_packet_slots_per_extraction: int
    expected_canonical_packet_extraction_generations: int
    expected_derived_packet_extractions: int
    expected_packet_extractions_rehydrated: int
    expected_packet_codec_roundtrips: int
    expected_canonical_packet_groups_constructed: int
    expected_derived_packet_groups_materialized: int
    expected_packet_groups_rehydrated: int
    expected_total_packet_group_objects_materialized: int
    expected_total_packet_slot_objects_materialized: int
    expected_dense_groups_per_encoding: int
    expected_dense_stream_build_calls: int
    expected_consume_calls: int
    expected_primary_consume_calls: int
    expected_primary_reingested_groups: int
    expected_lineage_verification_consume_calls: int
    expected_lineage_verification_consume_groups: int
    expected_allocation_repeat_trials: int
    expected_state_group_updates: int
    expected_input_scalar_deliveries: int
    expected_resonator_cell_updates: int
    expected_direct_reference_group_updates: int
    expected_direct_reference_resonator_cell_updates: int
    expected_production_readout_api_calls: int
    expected_successful_state_readout_calls: int
    expected_exact_abstention_prior_calls: int
    expected_direct_reference_readout_calls: int
    expected_direct_reference_readout_slot_contributions: int
    expected_hot_operator_bindings: int
    expected_cold_replay_probes: int
    expected_fit_calls: int
    expected_active_set_evaluations: int
    expected_synthetic_mechanism_label_values: int
    expected_trainable_parameters: int
    expected_gradient_steps: int
    expected_optimizer_steps: int
    maximum_scientific_entropy_calls: int
    maximum_cipher_target_reads: int
    maximum_unknown_key_reads: int
    maximum_solver_calls: int
    maximum_sibling_reads: int
    maximum_sibling_writes: int
    maximum_network_calls: int
    maximum_gpu_calls: int
    maximum_mps_calls: int

    @classmethod
    def from_mapping(cls, value: object) -> "BridgeRunBudgets":
        row = _mapping(value, "budgets", set(cls.__dataclass_fields__))
        values: dict[str, object] = {
            "maximum_cpu_seconds": _number(
                row["maximum_cpu_seconds"], "budgets.maximum_cpu_seconds", 0.001, 86400
            ),
            "maximum_wall_seconds": _number(
                row["maximum_wall_seconds"], "budgets.maximum_wall_seconds", 0.001, 86400
            ),
        }
        for field in set(cls.__dataclass_fields__) - {
            "maximum_cpu_seconds",
            "maximum_wall_seconds",
        }:
            values[field] = _integer(row[field], f"budgets.{field}", 0, 1 << 40)
        result = cls(**values)  # type: ignore[arg-type]
        exact = {
            "maximum_resident_memory_mib": 128,
            "maximum_persistent_artifact_bytes": 1 << 20,
            "maximum_state_bytes_per_arm": STATE_BYTES,
            "maximum_dense_stream_bytes_per_encoding": GROUP_BYTES,
            "maximum_dense_stream_aggregate_bytes": 4 * GROUP_BYTES,
            "maximum_sparse_control_chunk_bytes": KEY_BITS
            * len(WAVELENGTHS)
            * KEY_BITS
            * np.dtype("<f4").itemsize,
            "maximum_reference_state_bytes": 74_248,
            "maximum_simultaneous_live_states": 13,
            "maximum_aggregate_validation_state_bytes": 13 * STATE_BYTES + 74_248,
            "maximum_state_snapshot_bytes": 5 * STATE_BYTES,
            "maximum_readout_artifact_bytes": 7 * KEY_BITS * np.dtype("<f4").itemsize,
            "expected_packet_groups_per_extraction": KEY_BITS,
            "expected_packet_slots_per_extraction": KEY_BITS * len(O1C22_HORIZONS),
            "expected_canonical_packet_extraction_generations": 1,
            "expected_derived_packet_extractions": 2,
            "expected_packet_extractions_rehydrated": 1,
            "expected_packet_codec_roundtrips": 1,
            "expected_canonical_packet_groups_constructed": KEY_BITS,
            "expected_derived_packet_groups_materialized": 2 * KEY_BITS,
            "expected_packet_groups_rehydrated": KEY_BITS,
            "expected_total_packet_group_objects_materialized": 4 * KEY_BITS,
            "expected_total_packet_slot_objects_materialized": 4
            * KEY_BITS
            * len(O1C22_HORIZONS),
            "expected_dense_groups_per_encoding": len(O1C22_HORIZONS),
            "expected_dense_stream_build_calls": 4,
            "expected_consume_calls": 75,
            "expected_primary_consume_calls": 1,
            "expected_primary_reingested_groups": 0,
            "expected_lineage_verification_consume_calls": 1,
            "expected_lineage_verification_consume_groups": len(O1C22_HORIZONS),
            "expected_allocation_repeat_trials": ALLOCATION_REPEAT_TRIALS,
            "expected_state_group_updates": 731,
            "expected_input_scalar_deliveries": 731 * len(WAVELENGTHS) * KEY_BITS,
            "expected_resonator_cell_updates": 731
            * len(WAVELENGTHS)
            * KEY_BITS
            * len(TIMESCALES),
            "expected_direct_reference_group_updates": len(O1C22_HORIZONS),
            "expected_direct_reference_resonator_cell_updates": len(O1C22_HORIZONS)
            * len(WAVELENGTHS)
            * KEY_BITS
            * len(TIMESCALES),
            "expected_production_readout_api_calls": 7,
            "expected_successful_state_readout_calls": 6,
            "expected_exact_abstention_prior_calls": 1,
            "expected_direct_reference_readout_calls": 1,
            "expected_direct_reference_readout_slot_contributions": len(WAVELENGTHS)
            * POLE_COUNT
            * KEY_BITS,
            "expected_hot_operator_bindings": len(HOT_OPERATOR_IDS),
            "expected_cold_replay_probes": EXPECTED_COLD_PROBES,
            "expected_fit_calls": 2,
            "expected_active_set_evaluations": 2 * (1 << len(WAVELENGTHS)),
            "expected_synthetic_mechanism_label_values": 5 * KEY_BITS,
            "expected_trainable_parameters": len(WAVELENGTHS),
            "expected_gradient_steps": 0,
            "expected_optimizer_steps": 0,
        }
        for field, expected in exact.items():
            if getattr(result, field) != expected:
                raise O1C22PolyphaseBridgeRunError(f"budgets.{field} differs")
        for field in (
            "maximum_scientific_entropy_calls",
            "maximum_cipher_target_reads",
            "maximum_unknown_key_reads",
            "maximum_solver_calls",
            "maximum_sibling_reads",
            "maximum_sibling_writes",
            "maximum_network_calls",
            "maximum_gpu_calls",
            "maximum_mps_calls",
        ):
            if getattr(result, field) != 0:
                raise O1C22PolyphaseBridgeRunError(f"O1C-0028 requires zero {field}")
        if len(COLD_OPERATOR_IDS) != EXPECTED_COLD_PROBES:
            raise O1C22PolyphaseBridgeRunError("registered cold operator set drifted")
        return result


def load_bridge_run_config(
    path: str | Path,
) -> tuple[dict[str, object], BridgeExperimentConfig, BridgeRunBudgets]:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise O1C22PolyphaseBridgeRunError("run config is unreadable") from exc
    top = dict(
        _mapping(
            document,
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
    if (
        top["schema"] != RUN_CONFIG_SCHEMA
        or top["attempt_id"] != ATTEMPT_ID
        or top["slug"] != SLUG
        or top["claim_level"] != ClaimLevel.VALIDATION.value
    ):
        raise O1C22PolyphaseBridgeRunError("O1C-0028 identity differs")
    for field in ("hypothesis", "prediction", "next_action"):
        if not isinstance(top[field], str) or not str(top[field]).strip():
            raise O1C22PolyphaseBridgeRunError(f"config.{field} is required")
    controls = top["controls"]
    if (
        not isinstance(controls, list)
        or not controls
        or any(not isinstance(item, str) or not item.strip() for item in controls)
    ):
        raise O1C22PolyphaseBridgeRunError("config.controls differ")
    return (
        top,
        BridgeExperimentConfig.from_mapping(top["experiment"]),
        BridgeRunBudgets.from_mapping(top["budgets"]),
    )


def _fixture_delta(coordinate: int, horizon_index: int) -> float:
    numerator = ((coordinate * 11 + horizon_index * 7) % 29) - 14
    return float(numerator * (horizon_index + 1)) / 8.0


def _fixture_extraction(order: Iterable[int]) -> PacketDeltaExtraction:
    coordinates = tuple(order)
    active_sha256 = active_coordinate_sequence_sha256(coordinates)
    source_sha256 = _sha256_bytes(b"O1C-0028 synthetic source")
    pool_sha256 = _sha256_bytes(b"O1C-0028 synthetic public pool")
    reader_sha256 = _sha256_bytes(b"O1C-0028 frozen fixture reader")
    groups = tuple(
        PacketDeltaGroup(
            source_stream_sha256=source_sha256,
            action_pool_sha256=pool_sha256,
            reader_state_sha256=reader_sha256,
            active_coordinates_sha256=active_sha256,
            pair_sha256=f"{coordinate:064x}",
            coordinate=coordinate,
            horizons=O1C22_HORIZONS,
            incremental_deltas=tuple(
                _fixture_delta(coordinate, index)
                for index in range(len(O1C22_HORIZONS))
            ),
            incremental_work_units=(128, 2, 62),
            group_salt=28,
        )
        for coordinate in coordinates
    )
    return PacketDeltaExtraction(
        source_stream_sha256=source_sha256,
        action_pool_sha256=pool_sha256,
        active_coordinates=coordinates,
        ordered_horizons=O1C22_HORIZONS,
        groups=groups,
        reader_state_sha256=reader_sha256,
        reader_state_bytes=96,
        slow_state_sha256=_sha256_bytes(b"O1C-0028 slow state"),
        slow_state_bytes=32,
        final_fast_state_sha256=_sha256_bytes(b"O1C-0028 final fast state"),
        final_fast_state_bytes=512,
        physical_work_units=sum(group.physical_work_units for group in groups),
        observed_slots=len(groups) * len(O1C22_HORIZONS),
    )


def _complemented(extraction: PacketDeltaExtraction) -> PacketDeltaExtraction:
    groups = tuple(complement_packet_polarity(group) for group in extraction.groups)
    return PacketDeltaExtraction(
        source_stream_sha256=extraction.source_stream_sha256,
        action_pool_sha256=extraction.action_pool_sha256,
        active_coordinates=extraction.active_coordinates,
        ordered_horizons=extraction.ordered_horizons,
        groups=groups,
        reader_state_sha256=extraction.reader_state_sha256,
        reader_state_bytes=extraction.reader_state_bytes,
        slow_state_sha256=extraction.slow_state_sha256,
        slow_state_bytes=extraction.slow_state_bytes,
        final_fast_state_sha256=extraction.final_fast_state_sha256,
        final_fast_state_bytes=extraction.final_fast_state_bytes,
        physical_work_units=extraction.physical_work_units,
        observed_slots=extraction.observed_slots,
    )


def _reordered(
    extraction: PacketDeltaExtraction,
    order: Sequence[int],
) -> PacketDeltaExtraction:
    coordinates = tuple(order)
    if set(coordinates) != set(extraction.active_coordinates):
        raise O1C22PolyphaseBridgeRunError("derived packet order differs")
    active_sha256 = active_coordinate_sequence_sha256(coordinates)
    source = {group.coordinate: group for group in extraction.groups}
    groups = tuple(
        PacketDeltaGroup(
            source_stream_sha256=source[coordinate].source_stream_sha256,
            action_pool_sha256=source[coordinate].action_pool_sha256,
            reader_state_sha256=source[coordinate].reader_state_sha256,
            active_coordinates_sha256=active_sha256,
            pair_sha256=source[coordinate].pair_sha256,
            coordinate=coordinate,
            horizons=source[coordinate].horizons,
            incremental_deltas=source[coordinate].incremental_deltas,
            incremental_work_units=source[coordinate].incremental_work_units,
            group_salt=source[coordinate].group_salt,
        )
        for coordinate in coordinates
    )
    return PacketDeltaExtraction(
        source_stream_sha256=extraction.source_stream_sha256,
        action_pool_sha256=extraction.action_pool_sha256,
        active_coordinates=coordinates,
        ordered_horizons=extraction.ordered_horizons,
        groups=groups,
        reader_state_sha256=extraction.reader_state_sha256,
        reader_state_bytes=extraction.reader_state_bytes,
        slow_state_sha256=extraction.slow_state_sha256,
        slow_state_bytes=extraction.slow_state_bytes,
        final_fast_state_sha256=extraction.final_fast_state_sha256,
        final_fast_state_bytes=extraction.final_fast_state_bytes,
        physical_work_units=extraction.physical_work_units,
        observed_slots=extraction.observed_slots,
    )


def _fixture_quantizer(experiment: BridgeExperimentConfig) -> FrozenMedianAbsQuantizer:
    return FrozenMedianAbsQuantizer(
        horizons=O1C22_HORIZONS,
        scales=experiment.quantizer_scales,
        total_counts=(768, 768, 768),
        nonzero_counts=(700, 700, 700),
        public_replay_ledger_sha256=_sha256_bytes(b"O1C-0028 public scale ledger"),
    )


def _sparse_coordinate_major_groups(
    extraction: PacketDeltaExtraction,
    quantizer: FrozenMedianAbsQuantizer,
) -> np.ndarray:
    groups = np.zeros((KEY_BITS, len(WAVELENGTHS), KEY_BITS), dtype=np.float32)
    for time_index, packet in enumerate(extraction.groups):
        for horizon, delta in zip(packet.horizons, packet.incremental_deltas):
            groups[time_index, WAVELENGTHS.index(horizon), packet.coordinate] = np.float32(
                quantizer.normalized(horizon, delta)
            )
    return groups


def _label_row(seed: int) -> np.ndarray:
    return np.asarray(
        [
            (
                coordinate
                ^ (coordinate >> (seed + 1))
                ^ (seed * 0x9E3779B1)
            ).bit_count()
            & 1
            for coordinate in range(KEY_BITS)
        ],
        dtype=np.uint8,
    )


def _fit_state(labels: np.ndarray) -> PolyphaseSufficientState:
    groups = np.zeros(GROUP_SHAPE, dtype=np.float32)
    groups[2, WAVELENGTHS.index(96)] = 2.0 * labels.astype(np.float32) - 1.0
    state = PolyphaseSufficientState.initial()
    state.consume(groups)
    return state


def _operator(
    operator_id: str,
    replaced_component: str,
    salt: bytes,
    **extra: object,
) -> dict[str, object]:
    return {
        "operator_id": operator_id,
        "operator_fingerprint": _sha256_bytes(b"operator:" + salt),
        "source_result_sha256": _sha256_bytes(b"source-result:" + salt),
        "verified_decision_sha256": _sha256_bytes(b"decision:" + salt),
        "policy_sha256": _sha256_bytes(b"policy:" + salt),
        "replaced_components": [replaced_component],
        **extra,
    }


@dataclass(frozen=True)
class BridgeEvaluation:
    report: dict[str, Any]
    artifacts: dict[str, bytes]
    passed: bool


def evaluate_bridge(experiment: BridgeExperimentConfig) -> BridgeEvaluation:
    """Evaluate the deterministic mechanism without touching capsule storage."""

    primary_extraction = _fixture_extraction(range(KEY_BITS))
    reverse_extraction = _reordered(primary_extraction, tuple(reversed(range(KEY_BITS))))
    complement_extraction = _complemented(primary_extraction)
    extraction_bytes = primary_extraction.to_bytes()
    codec_roundtrip = decode_packet_delta_extraction(extraction_bytes).to_bytes()
    quantizer = _fixture_quantizer(experiment)

    normalized = build_dense_horizon_major_stream(
        primary_extraction, quantizer, encoding=experiment.normalized_encoding
    )
    quantized = build_dense_horizon_major_stream(
        primary_extraction, quantizer, encoding=experiment.quantized_encoding
    )
    reversed_dense = build_dense_horizon_major_stream(
        reverse_extraction, quantizer, encoding=experiment.normalized_encoding
    )
    complemented_dense = build_dense_horizon_major_stream(
        complement_extraction, quantizer, encoding=experiment.normalized_encoding
    )

    primary = consume_dense_horizon_major_stream(normalized)
    quantized_state = consume_dense_horizon_major_stream(quantized)
    reversed_state = consume_dense_horizon_major_stream(reversed_dense)
    complement_state = consume_dense_horizon_major_stream(complemented_dense)
    allocation_repeat_hashes = tuple(
        consume_dense_horizon_major_stream(normalized).sha256()
        for _ in range(ALLOCATION_REPEAT_TRIALS)
    )

    sparse_ascending = PolyphaseSufficientState.initial()
    sparse_descending = PolyphaseSufficientState.initial()
    sparse_ascending.consume(_sparse_coordinate_major_groups(primary_extraction, quantizer))
    sparse_descending.consume(_sparse_coordinate_major_groups(reverse_extraction, quantizer))

    permutation = tuple(
        (coordinate + experiment.coordinate_permutation_offset) % KEY_BITS
        for coordinate in range(KEY_BITS)
    )
    permuted_groups = permute_dense_coordinates(normalized, permutation)
    permuted_state = PolyphaseSufficientState.initial()
    permuted_state.consume(permuted_groups)

    reference_spec = PolyphaseReadoutSpec(
        name="balanced-reference",
        basis_sha256=BASIS_SHA256,
        slot_weights=np.full(
            (len(WAVELENGTHS), POLE_COUNT),
            np.float32(1.0 / (len(WAVELENGTHS) * POLE_COUNT)),
            dtype=np.float32,
        ),
        temperature=1.0,
    )
    production_reference_logits = read_polyphase_state(primary, reference_spec)
    complement_logits = read_polyphase_state(complement_state, reference_spec)
    permuted_logits = read_polyphase_state(permuted_state, reference_spec)
    reference_state = direct_polyphase_state(normalized.groups)
    independent_logits = read_polyphase_reference(reference_state, reference_spec)
    reference_bound = reference_readout_roundoff_bound(reference_state, reference_spec)
    reference_residual = np.abs(
        production_reference_logits.astype(np.float64) - independent_logits
    )

    labels = np.stack([_label_row(seed) for seed in (0, 1, 2)])
    fit_states = tuple(_fit_state(row) for row in labels)
    fit = fit_nonnegative_horizon_readout(
        fit_states[:2], labels[:2], alpha=experiment.ridge_alpha
    )
    fit_logits = read_fitted_horizon_state(fit_states[2], fit)
    fit_prediction = (fit_logits > 0.0).astype(np.uint8)
    zero_states = (PolyphaseSufficientState.initial(), PolyphaseSufficientState.initial())
    zero_labels = np.stack([_label_row(0), _label_row(1)])
    zero_fit = fit_nonnegative_horizon_readout(
        zero_states, zero_labels, alpha=experiment.ridge_alpha
    )
    zero_logits = read_fitted_horizon_state(zero_states[0], zero_fit)

    lineage = freeze_hot_readout_lineage(normalized, quantizer, primary, fit)
    simplex_weights = fit.slot_weights
    confidence_weights = fit.slot_weights
    confidence_weights_sha256 = _sha256_bytes(
        confidence_weights.astype("<f4", copy=False).tobytes(order="C")
    )
    hot_inputs = (
        (
            _operator(
                "horizon_nonnegative_simplex_v1",
                "horizon_scale_weighting",
                b"horizon",
                weight_contract="nonnegative_horizon_simplex_equal_poles",
            ),
            simplex_weights,
            fit.temperature,
        ),
        (
            _operator(
                "magnitude_confidence_calibration_v1",
                "magnitude_confidence",
                b"confidence",
                calibration_scope="global_temperature_only",
                frozen_slot_weights_sha256=confidence_weights_sha256,
            ),
            confidence_weights,
            fit.temperature * 2.0,
        ),
    )
    state_before_hot = primary.to_bytes()
    bindings = tuple(
        bind_o1o_hot_readout(
            operator,
            slot_weights=weights,
            temperature=temperature,
            lineage=lineage,
        )
        for operator, weights, temperature in hot_inputs
    )
    hot_outputs = tuple(read_bound_hot_state(primary, binding) for binding in bindings)
    state_after_hot = primary.to_bytes()

    cold_receipts: list[dict[str, object]] = []
    for index, operator_id in enumerate(sorted(COLD_OPERATOR_IDS)):
        before = primary.sha256()
        outcome = "unexpected-success"
        try:
            bind_o1o_hot_readout(
                _operator(operator_id, "cold-state-component", f"cold-{index}".encode()),
                slot_weights=np.ones((len(WAVELENGTHS), POLE_COUNT), dtype=np.float32),
                temperature=1.0,
                lineage=lineage,
            )
        except ReplayRequiredError:
            outcome = "replay-required"
        after = primary.sha256()
        cold_receipts.append(
            {
                "operator_id": operator_id,
                "outcome": outcome,
                "state_sha256_before": before,
                "state_sha256_after": after,
                "state_unchanged": before == after,
            }
        )

    gates = {
        "complete_k256_packet_geometry": len(primary_extraction.groups) == KEY_BITS
        and primary_extraction.observed_slots == KEY_BITS * len(O1C22_HORIZONS)
        and set(primary_extraction.active_coordinates) == set(range(KEY_BITS)),
        "packet_extraction_codec_byte_exact": codec_roundtrip == extraction_bytes,
        "dense_geometry_and_separate_encodings": normalized.groups.shape == GROUP_SHAPE
        and quantized.groups.shape == GROUP_SHAPE
        and len(normalized.evidence_bytes) == GROUP_BYTES
        and len(quantized.evidence_bytes) == GROUP_BYTES
        and normalized.evidence_sha256 != quantized.evidence_sha256,
        "packet_order_canonicalized": primary_extraction.public_packet_ledger_sha256
        != reverse_extraction.public_packet_ledger_sha256
        and normalized.evidence_bytes == reversed_dense.evidence_bytes
        and primary.to_bytes() == reversed_state.to_bytes(),
        "allocation_alignment_state_hash_invariant": len(
            set(allocation_repeat_hashes)
        )
        == 1
        and allocation_repeat_hashes[0] == primary.sha256(),
        "coordinate_major_sparse_negative_control_rejects": sparse_ascending.to_bytes()
        != sparse_descending.to_bytes()
        and sparse_ascending.clock == KEY_BITS
        and sparse_descending.clock == KEY_BITS,
        "complement_state_and_readout_exactly_odd": bool(
            np.array_equal(complemented_dense.groups, -normalized.groups)
        )
        and bool(np.array_equal(complement_state.slots, -primary.slots))
        and bool(np.array_equal(complement_logits, -production_reference_logits)),
        "direct_reference_within_derived_bound": bool(
            np.all(reference_residual <= reference_bound)
        ),
        "coordinate_permutation_commutes": bool(
            np.array_equal(
                permuted_logits[np.asarray(permutation, dtype=np.int64)],
                production_reference_logits,
            )
        ),
        "hot_o1o_bindings_are_distinct_and_state_immutable": len(bindings)
        == len(HOT_OPERATOR_IDS)
        and len({binding.binding_sha256 for binding in bindings}) == len(bindings)
        and state_before_hot == state_after_hot
        and not bool(np.array_equal(hot_outputs[0], hot_outputs[1])),
        "cold_o1o_operators_require_replay_without_mutation": len(cold_receipts)
        == EXPECTED_COLD_PROBES
        and all(
            row["outcome"] == "replay-required" and row["state_unchanged"]
            for row in cold_receipts
        ),
        "build_only_horizon_fit_generalizes_synthetic_holdout": not fit.abstained
        and len({_sha256_bytes(row.tobytes(order="C")) for row in labels}) == 3
        and len({state.sha256() for state in fit_states}) == 3
        and bool(np.array_equal(fit_prediction, labels[2])),
        "zero_design_abstains_exactly": zero_fit.abstained
        and bool(np.array_equal(zero_logits, np.zeros(KEY_BITS, dtype=np.float32))),
        "state_serialization_and_size_exact": len(primary.to_bytes()) == STATE_BYTES
        and PolyphaseSufficientState.from_bytes(primary.to_bytes()).to_bytes()
        == primary.to_bytes()
        and primary.clock == len(O1C22_HORIZONS)
        and bool(
            np.array_equal(
                primary.coverage,
                np.full(KEY_BITS, len(O1C22_HORIZONS), dtype=np.uint16),
            )
        ),
    }
    passed = all(gates.values())
    classification = (
        "HORIZON_MAJOR_HOT_ROUTING_PASS"
        if passed
        else "HORIZON_MAJOR_HOT_ROUTING_GATE_FAILURE"
    )

    state_group_updates = (
        4 * len(O1C22_HORIZONS)
        + 2 * KEY_BITS
        + len(O1C22_HORIZONS)
        + len(fit_states) * len(O1C22_HORIZONS)
        + len(O1C22_HORIZONS)
        + ALLOCATION_REPEAT_TRIALS * len(O1C22_HORIZONS)
    )
    work: dict[str, Any] = {
        "schema": WORK_SCHEMA,
        "canonical_packet_extraction_generations": 1,
        "derived_packet_extractions": 2,
        "packet_extractions_rehydrated": 1,
        "canonical_packet_groups_constructed": KEY_BITS,
        "derived_packet_groups_materialized": 2 * KEY_BITS,
        "packet_groups_rehydrated": KEY_BITS,
        "total_packet_group_objects_materialized": 4 * KEY_BITS,
        "total_packet_slot_objects_materialized": 4
        * KEY_BITS
        * len(O1C22_HORIZONS),
        "packet_codec_roundtrips": 1,
        "dense_stream_build_calls": 4,
        "dense_groups_per_encoding": len(O1C22_HORIZONS),
        "dense_stream_aggregate_bytes": 4 * GROUP_BYTES,
        "maximum_sparse_control_chunk_bytes": KEY_BITS
        * len(WAVELENGTHS)
        * KEY_BITS
        * np.dtype("<f4").itemsize,
        "consume_calls": 75,
        "primary_consume_calls": 1,
        "primary_reingested_groups": 0,
        "lineage_verification_consume_calls": 1,
        "lineage_verification_consume_groups": len(O1C22_HORIZONS),
        "allocation_repeat_trials": ALLOCATION_REPEAT_TRIALS,
        "state_group_updates": state_group_updates,
        "input_scalar_deliveries": state_group_updates * len(WAVELENGTHS) * KEY_BITS,
        "resonator_cell_updates": state_group_updates
        * len(WAVELENGTHS)
        * KEY_BITS
        * len(TIMESCALES),
        "direct_reference_group_updates": len(O1C22_HORIZONS),
        "direct_reference_resonator_cell_updates": len(O1C22_HORIZONS)
        * len(WAVELENGTHS)
        * KEY_BITS
        * len(TIMESCALES),
        "hot_operator_bindings": len(bindings),
        "cold_replay_probes": len(cold_receipts),
        "production_readout_api_calls": 7,
        "successful_state_readout_calls": 6,
        "exact_abstention_prior_calls": 1,
        "direct_reference_readout_calls": 1,
        "direct_reference_readout_slot_contributions": len(WAVELENGTHS)
        * POLE_COUNT
        * KEY_BITS,
        "synthetic_mechanism_label_values_generated": int(labels.size + zero_labels.size),
        "fit_calls": 2,
        "active_set_evaluations": 2 * (1 << len(WAVELENGTHS)),
        "trainable_parameters": 3,
        "gradient_steps": 0,
        "optimizer_steps": 0,
        "scientific_entropy_calls": 0,
        "cipher_target_reads": 0,
        "unknown_key_reads": 0,
        "solver_calls": 0,
        "sibling_reads": 0,
        "sibling_writes": 0,
        "network_calls": 0,
        "gpu_calls": 0,
        "mps_calls": 0,
    }

    readout_tensor = np.stack(
        (
            production_reference_logits,
            complement_logits,
            permuted_logits,
            hot_outputs[0],
            hot_outputs[1],
            fit_logits,
            zero_logits,
        )
    ).astype("<f4", copy=False)
    controls_report = {
        "schema": "o1-256-o1c22-polyphase-controls-v1",
        "reference": {
            "maximum_absolute_error": float(reference_residual.max()),
            "maximum_derived_bound": float(reference_bound.max()),
            "within_bound": gates["direct_reference_within_derived_bound"],
        },
        "packet_order": {
            "ascending_ledger_sha256": primary_extraction.public_packet_ledger_sha256,
            "reverse_ledger_sha256": reverse_extraction.public_packet_ledger_sha256,
            "canonical_evidence_byte_exact": normalized.evidence_bytes
            == reversed_dense.evidence_bytes,
            "canonical_state_byte_exact": primary.to_bytes() == reversed_state.to_bytes(),
            "ascending_state_sha256": primary.sha256(),
            "reverse_state_sha256": reversed_state.sha256(),
            "sparse_state_byte_exact": sparse_ascending.to_bytes()
            == sparse_descending.to_bytes(),
            "sparse_ascending_state_sha256": sparse_ascending.sha256(),
            "sparse_descending_state_sha256": sparse_descending.sha256(),
            "allocation_repeat_trials": ALLOCATION_REPEAT_TRIALS,
            "allocation_unique_state_hashes": sorted(set(allocation_repeat_hashes)),
        },
        "coordinate_permutation": {
            "offset": experiment.coordinate_permutation_offset,
            "state_sha256": permuted_state.sha256(),
            "logits_sha256": _sha256_bytes(
                permuted_logits.astype("<f4", copy=False).tobytes(order="C")
            ),
        },
        "complement_maximum_slot_residual": float(
            np.max(np.abs(complement_state.slots + primary.slots))
        ),
        "hot_bindings": [binding.describe() for binding in bindings],
        "cold_receipts": cold_receipts,
        "fit": fit.describe(),
        "zero_fit": zero_fit.describe(),
        "fit_training_state_sha256": [state.sha256() for state in fit_states],
        "fit_label_sha256": [
            _sha256_bytes(row.tobytes(order="C")) for row in labels
        ],
        "fit_holdout_prediction_sha256": _sha256_bytes(
            fit_prediction.tobytes(order="C")
        ),
        "lineage": lineage.describe(),
    }
    report: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "classification": classification,
        "mechanism_validation_passed": passed,
        "cryptanalytic_signal_claimed": False,
        "full_round_key_recovery_claimed": False,
        "contains_chacha20_evidence": False,
        "contains_unknown_key": False,
        "basis_sha256": BASIS_SHA256,
        "packet_transport": {
            "generator": SYNTHETIC_GENERATOR,
            "packet_groups": len(primary_extraction.groups),
            "packet_slots": primary_extraction.observed_slots,
            "packet_ledger_sha256": primary_extraction.public_packet_ledger_sha256,
            "normalized": normalized.describe(),
            "quantized": quantized.describe(),
        },
        "state": {
            "schema": STATE_SCHEMA,
            "abi_revision": experiment.state_abi_revision,
            "basis_sha256": BASIS_SHA256,
            "persistent_bytes_per_arm": STATE_BYTES,
            "maximum_simultaneous_live_states": 13,
            "reference_audit_state_bytes": 74_248,
            "aggregate_validation_state_bytes": 13 * STATE_BYTES + 74_248,
            "maximum_live_snapshot_bytes": 5 * STATE_BYTES,
            "stream_groups_per_encoding": len(O1C22_HORIZONS),
            "stream_length_dependent": False,
            "primary_sha256": primary.sha256(),
            "quantized_sha256": quantized_state.sha256(),
            "complement_sha256": complement_state.sha256(),
        },
        "hot_cold_boundary": {
            "descriptor_authority": "synthetic-o1o-shaped-contract-only",
            "authoritative_o1c23_decision_verified": False,
            "hot_operator_ids": sorted(HOT_OPERATOR_IDS),
            "cold_operator_ids": sorted(COLD_OPERATOR_IDS),
            "hot_bindings": len(bindings),
            "cold_replay_probes": len(cold_receipts),
            "state_replays_per_hot_switch": 0,
            "state_writes_per_hot_switch": 0,
        },
        "gates": gates,
        "work": work,
    }
    report["result_sha256"] = _sha256_bytes(_json_bytes(report))
    artifacts = {
        "packet_extraction.json": extraction_bytes,
        "quantizer.json": quantizer.to_bytes(),
        "normalized_stream.json": _json_bytes(normalized.describe()),
        "quantized_stream.json": _json_bytes(quantized.describe()),
        "normalized_evidence.f32le": normalized.evidence_bytes,
        "quantized_evidence.f32le": quantized.evidence_bytes,
        "state_primary.bin": primary.to_bytes(),
        "state_quantized.bin": quantized_state.to_bytes(),
        "state_complement.bin": complement_state.to_bytes(),
        "readouts.f32le": readout_tensor.tobytes(order="C"),
        "controls.json": _json_bytes(controls_report),
        "structural_work_ledger.json": _json_bytes(work),
        "result.json": _json_bytes(report),
    }
    if len(artifacts) != 13:
        raise O1C22PolyphaseBridgeRunError("artifact inventory differs")
    return BridgeEvaluation(report=report, artifacts=artifacts, passed=passed)


def _git_commit(root: Path) -> str:
    status = subprocess.run(
        ("git", "status", "--porcelain"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    if status.stdout:
        raise O1C22PolyphaseBridgeRunError("lab worktree must be clean")
    commit = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not commit:
        raise O1C22PolyphaseBridgeRunError("lab commit is unavailable")
    return commit


def _source_hashes(root: Path, config_path: Path) -> dict[str, str]:
    modules = (
        "isolation.py",
        "o1c19_causal_vault_bridge.py",
        "o1c22_packet_codec.py",
        "o1c22_polyphase_bridge.py",
        "o1c22_polyphase_bridge_run.py",
        "polyphase_sufficient_state.py",
        "polyphase_sufficient_state_v2.py",
        "run_capsule.py",
    )
    return {
        "config": _sha256_file(config_path),
        "pyproject": _sha256_file(root / "pyproject.toml"),
        **{
            f"module_{Path(name).stem}": _sha256_file(root / "src/o1_crypto_lab" / name)
            for name in modules
        },
    }


def _already_finalized(manager: RunCapsuleManager) -> int | None:
    published = manager.finalized_attempt(ATTEMPT_ID)
    if published is None:
        return None
    metrics = json.loads((published.path / "metrics.json").read_text(encoding="utf-8"))
    status = metrics.get("status")
    print(
        json.dumps(
            {
                "attempt_id": ATTEMPT_ID,
                "path": str(published.path),
                "manifest_sha256": published.manifest_sha256,
                "verified": published.verification.ok,
                "status": "already-finalized-no-replay",
                "capsule_status": status,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if status == "completed" else 2


def run_capsule_from_config(path: str | Path) -> int:
    root = Path(__file__).resolve().parents[2]
    config_path = Path(path).resolve(strict=True)
    canonical = (root / "configs/o1c22_polyphase_bridge_v1.json").resolve(strict=True)
    if config_path != canonical:
        raise O1C22PolyphaseBridgeRunError(
            "O1C-0028 requires the canonical tracked config path"
        )
    manager = RunCapsuleManager(root)
    finalized_status = _already_finalized(manager)
    if finalized_status is not None:
        return finalized_status
    if ATTEMPT_ID in manager.recoverable_attempt_ids():
        interrupted = manager.recover(ATTEMPT_ID)
        if interrupted.publication_prepared:
            finalized = interrupted.finalize(metrics={})
            metrics = json.loads((finalized.path / "metrics.json").read_text(encoding="utf-8"))
            return 0 if metrics.get("status") == "completed" else 2
        finalized = interrupted.finalize(
            metrics={
                "schema": RUN_METRICS_SCHEMA,
                "hard_interruption_recovered": True,
                "scientific_result_claimed": False,
            },
            status="stopped",
            next_action=(
                "Preserve the interrupted mechanism attempt and advance under a new "
                "O1C identity; never replay O1C-0028."
            ),
        )
        print(f"stopped capsule: {finalized.path}", file=sys.stderr)
        return 2

    top, experiment, budgets = load_bridge_run_config(config_path)
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
            "/usr/bin/env",
            f"PYTHONPATH={root / 'src'}",
            sys.executable,
            "-m",
            "o1_crypto_lab.o1c22_polyphase_bridge_run",
            "--config",
            str(config_path),
        ),
        environment={
            "experiment_boundary": "synthetic-full256-packet-to-polyphase-mechanism",
            "accelerator": "none",
            "numpy_version": np.__version__,
            "state_bytes": STATE_BYTES,
            "dense_stream_bytes": GROUP_BYTES,
            "packet_codec": "pure-stdlib-byte-exact-o1c22-v1",
            "legacy_controller_stack_imported": False,
            "torch_imported": False,
            "canonical_packet_extraction_generations": 1,
            "derived_packet_extractions": 2,
            "packet_extractions_rehydrated": 1,
            "scientific_entropy_calls": 0,
            "cipher_target_reads": 0,
            "unknown_key_reads": 0,
            "solver_calls": 0,
            "sibling_repository_reads": 0,
            "sibling_repository_writes": 0,
            "network_calls": 0,
            "gpu_calls": 0,
            "mps_calls": 0,
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
                "phase": "O1C0028_RESERVED",
                "packet_groups": KEY_BITS,
                "dense_groups": len(O1C22_HORIZONS),
                "state_bytes": STATE_BYTES,
                "primary_consume_calls": 0,
            }
        )
        run.append_stdout("O1C-0028 full-256 horizon-major bridge validation started.\n")
        evaluation = evaluate_bridge(experiment)
        for relative, payload in sorted(evaluation.artifacts.items()):
            if persistent_bytes + len(payload) > budgets.maximum_persistent_artifact_bytes:
                raise O1C22PolyphaseBridgeRunError(
                    "persistent artifacts exceed budget before index"
                )
            output = run.write_artifact(relative, payload)
            digest = _sha256_bytes(payload)
            if _sha256_file(output) != digest:
                raise O1C22PolyphaseBridgeRunError(
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
            raise O1C22PolyphaseBridgeRunError("artifact index exceeds budget")
        index_path = run.write_artifact("artifact_index.json", index_payload)
        if _sha256_file(index_path) != _sha256_bytes(index_payload):
            raise O1C22PolyphaseBridgeRunError("persisted artifact index differs")
        persistent_bytes += len(index_payload)
        run.checkpoint(
            {
                "phase": "MECHANISM_RESULT_AND_ARTIFACTS_FROZEN",
                "classification": evaluation.report["classification"],
                "result_sha256": evaluation.report["result_sha256"],
                "primary_consume_calls": evaluation.report["work"][
                    "primary_consume_calls"
                ],
                "persistent_artifact_bytes": persistent_bytes,
            }
        )
        if _git_commit(root) != commit or _source_hashes(root, config_path) != hashes:
            raise O1C22PolyphaseBridgeRunError("source changed during execution")

        cpu_seconds = time.process_time() - cpu_started
        wall_seconds = time.monotonic() - wall_started
        peak_rss_bytes = _process_peak_rss_bytes()
        work = evaluation.report["work"]
        state = evaluation.report["state"]
        transport = evaluation.report["packet_transport"]
        budget_checks = {
            "cpu": cpu_seconds <= budgets.maximum_cpu_seconds,
            "wall": wall_seconds <= budgets.maximum_wall_seconds,
            "resident_memory": peak_rss_bytes
            <= budgets.maximum_resident_memory_mib * 1024 * 1024,
            "persistent_artifacts": persistent_bytes
            <= budgets.maximum_persistent_artifact_bytes,
            "state_bytes": state["persistent_bytes_per_arm"]
            == budgets.maximum_state_bytes_per_arm,
            "simultaneous_live_states": state["maximum_simultaneous_live_states"]
            == budgets.maximum_simultaneous_live_states,
            "reference_state_bytes": state["reference_audit_state_bytes"]
            == budgets.maximum_reference_state_bytes,
            "aggregate_validation_state": state["aggregate_validation_state_bytes"]
            == budgets.maximum_aggregate_validation_state_bytes,
            "state_snapshots": state["maximum_live_snapshot_bytes"]
            == budgets.maximum_state_snapshot_bytes,
            "normalized_stream_bytes": transport["normalized"]["bytes"]
            == budgets.maximum_dense_stream_bytes_per_encoding,
            "quantized_stream_bytes": transport["quantized"]["bytes"]
            == budgets.maximum_dense_stream_bytes_per_encoding,
            "dense_stream_aggregate": work["dense_stream_aggregate_bytes"]
            == budgets.maximum_dense_stream_aggregate_bytes,
            "sparse_control_chunk": work["maximum_sparse_control_chunk_bytes"]
            == budgets.maximum_sparse_control_chunk_bytes,
            "readout_artifact": len(evaluation.artifacts["readouts.f32le"])
            == budgets.maximum_readout_artifact_bytes,
            "packet_groups": transport["packet_groups"]
            == budgets.expected_packet_groups_per_extraction,
            "packet_slots": transport["packet_slots"]
            == budgets.expected_packet_slots_per_extraction,
            "canonical_packet_generation": work[
                "canonical_packet_extraction_generations"
            ]
            == budgets.expected_canonical_packet_extraction_generations,
            "derived_packet_extractions": work["derived_packet_extractions"]
            == budgets.expected_derived_packet_extractions,
            "packet_extractions_rehydrated": work["packet_extractions_rehydrated"]
            == budgets.expected_packet_extractions_rehydrated,
            "packet_codec_roundtrips": work["packet_codec_roundtrips"]
            == budgets.expected_packet_codec_roundtrips,
            "canonical_packet_groups": work["canonical_packet_groups_constructed"]
            == budgets.expected_canonical_packet_groups_constructed,
            "derived_packet_groups": work["derived_packet_groups_materialized"]
            == budgets.expected_derived_packet_groups_materialized,
            "packet_groups_rehydrated": work["packet_groups_rehydrated"]
            == budgets.expected_packet_groups_rehydrated,
            "total_packet_group_objects": work[
                "total_packet_group_objects_materialized"
            ]
            == budgets.expected_total_packet_group_objects_materialized,
            "total_packet_slot_objects": work[
                "total_packet_slot_objects_materialized"
            ]
            == budgets.expected_total_packet_slot_objects_materialized,
            "dense_groups": work["dense_groups_per_encoding"]
            == budgets.expected_dense_groups_per_encoding,
            "dense_stream_build_calls": work["dense_stream_build_calls"]
            == budgets.expected_dense_stream_build_calls,
            "consume_calls": work["consume_calls"] == budgets.expected_consume_calls,
            "primary_consume_calls": work["primary_consume_calls"]
            == budgets.expected_primary_consume_calls,
            "primary_reingested_groups": work["primary_reingested_groups"]
            == budgets.expected_primary_reingested_groups,
            "lineage_verification_calls": work[
                "lineage_verification_consume_calls"
            ]
            == budgets.expected_lineage_verification_consume_calls,
            "lineage_verification_groups": work[
                "lineage_verification_consume_groups"
            ]
            == budgets.expected_lineage_verification_consume_groups,
            "allocation_repeat_trials": work["allocation_repeat_trials"]
            == budgets.expected_allocation_repeat_trials,
            "state_group_updates": work["state_group_updates"]
            == budgets.expected_state_group_updates,
            "input_scalar_deliveries": work["input_scalar_deliveries"]
            == budgets.expected_input_scalar_deliveries,
            "resonator_cell_updates": work["resonator_cell_updates"]
            == budgets.expected_resonator_cell_updates,
            "direct_reference_groups": work["direct_reference_group_updates"]
            == budgets.expected_direct_reference_group_updates,
            "direct_reference_cells": work[
                "direct_reference_resonator_cell_updates"
            ]
            == budgets.expected_direct_reference_resonator_cell_updates,
            "production_readout_calls": work["production_readout_api_calls"]
            == budgets.expected_production_readout_api_calls,
            "successful_state_readouts": work["successful_state_readout_calls"]
            == budgets.expected_successful_state_readout_calls,
            "abstention_prior_calls": work["exact_abstention_prior_calls"]
            == budgets.expected_exact_abstention_prior_calls,
            "reference_readout_calls": work["direct_reference_readout_calls"]
            == budgets.expected_direct_reference_readout_calls,
            "reference_readout_contributions": work[
                "direct_reference_readout_slot_contributions"
            ]
            == budgets.expected_direct_reference_readout_slot_contributions,
            "hot_bindings": work["hot_operator_bindings"]
            == budgets.expected_hot_operator_bindings,
            "cold_replay_probes": work["cold_replay_probes"]
            == budgets.expected_cold_replay_probes,
            "fit_calls": work["fit_calls"] == budgets.expected_fit_calls,
            "active_set_evaluations": work["active_set_evaluations"]
            == budgets.expected_active_set_evaluations,
            "synthetic_label_values": work[
                "synthetic_mechanism_label_values_generated"
            ]
            == budgets.expected_synthetic_mechanism_label_values,
            "trainable_parameters": work["trainable_parameters"]
            == budgets.expected_trainable_parameters,
            "gradient_steps": work["gradient_steps"]
            == budgets.expected_gradient_steps,
            "optimizer_steps": work["optimizer_steps"]
            == budgets.expected_optimizer_steps,
            "scientific_entropy": work["scientific_entropy_calls"] == 0,
            "cipher_targets": work["cipher_target_reads"] == 0,
            "unknown_keys": work["unknown_key_reads"] == 0,
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
            metrics = json.loads((finalized.path / "metrics.json").read_text(encoding="utf-8"))
            return 0 if metrics.get("status") == "completed" else 2
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
                "Preserve this failure and repair it under a new O1C identity "
                "without replaying O1C-0028."
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
                "dense_stream_bytes": GROUP_BYTES,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if completed else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run capsule-backed full-256 O1C-0022 polyphase bridge validation"
    )
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    return run_capsule_from_config(args.config)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ARTIFACT_INDEX_SCHEMA",
    "ATTEMPT_ID",
    "BridgeEvaluation",
    "BridgeExperimentConfig",
    "BridgeRunBudgets",
    "O1C22PolyphaseBridgeRunError",
    "RESULT_SCHEMA",
    "RUN_CONFIG_SCHEMA",
    "RUN_METRICS_SCHEMA",
    "SLUG",
    "WORK_SCHEMA",
    "evaluate_bridge",
    "load_bridge_run_config",
    "main",
    "run_capsule_from_config",
]
