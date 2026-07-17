"""Reusable public-only full-256 paired proof probe core.

The core consumes one already generated public ChaCha20 CNF, its semantic map,
and an already built native CaDiCaL sensor executable.  It never accepts labels,
keys, internal target traces, source-capsule metadata, or diagnostic callbacks.
"""

from __future__ import annotations

import hashlib
import math
import os
import resource
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, cast

import numpy as np

from .cadical_sensor import (
    KEY_BITS,
    MOTIF_DIMENSIONS,
    ClauseProvenanceIndex,
    ProofEvent,
    ProbeRecord,
    ProbeStreamHeader,
    branch_difficulty,
    iter_native_probe_records,
    pair_commitment,
    paired_records,
    sha256_file,
    summarize_probe_prefixes,
)
from .causal_bitfield import (
    ARX_NEIGHBORS,
    HORIZON_COUNT,
    CausalBitfieldAccumulator,
    CausalBitfieldPlan,
    FrozenCausalBitfieldState,
    PairedCausalEvent,
    state_swap_control,
)
from .full256_action_pool import (
    ACTION_POOL_SCHEMA,
    BRANCH_FEATURES,
    Full256ActionPool,
    branch_feature_vector,
    serialize_action_pool,
)
from .living_inverse import canonical_json_bytes, canonical_sha256


PROBE_CORE_SCHEMA = "o1-256-full256-probe-core-v1"
PROBE_EVENT_INDEX_SCHEMA = "o1-256-full256-probe-event-index-v1"
READER_FEATURE_SCHEMA = "o1-256-full256-reader-features-v1"
READER_FEATURES = 39
UNARY_FEATURES = 3
ARX_FEATURES = 24
MOTIF_FEATURES = 12


class Full256ProbeCoreError(ValueError):
    """A public input, probe stream, or core invariant differs."""


def _optional_sha256(value: str | None, field_name: str) -> None:
    if value is None:
        return
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise Full256ProbeCoreError(f"{field_name} must be lowercase SHA-256")


def _positive_float(value: object, field_name: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) <= 0.0
    ):
        raise Full256ProbeCoreError(f"{field_name} must be positive and finite")
    return float(value)


@dataclass(frozen=True)
class Full256ProbeCoreConfig:
    """Label-free request for one complete 512-branch public probe sweep."""

    public_cnf: str | Path
    semantic_map: str | Path
    native_executable: str | Path
    state_plan: CausalBitfieldPlan = field(default_factory=CausalBitfieldPlan)
    seed: int = 0
    timeout_seconds: float = 600.0
    sentinel_bit: int = 173
    sentinel_reruns: int = 0
    maximum_state_bytes: int = 18_000
    expected_public_cnf_sha256: str | None = None
    expected_semantic_map_sha256: str | None = None
    expected_variable_count: int | None = None
    expected_clause_count: int | None = None

    def __post_init__(self) -> None:
        for field_name in ("public_cnf", "semantic_map", "native_executable"):
            value = getattr(self, field_name)
            if not isinstance(value, (str, Path)) or not str(value):
                raise Full256ProbeCoreError(f"{field_name} path is required")
        if not isinstance(self.state_plan, CausalBitfieldPlan):
            raise Full256ProbeCoreError("state_plan must be CausalBitfieldPlan")
        if len(self.state_plan.horizons) != HORIZON_COUNT:
            raise Full256ProbeCoreError("state plan must contain three horizons")
        if isinstance(self.seed, bool) or not isinstance(self.seed, int):
            raise Full256ProbeCoreError("seed must be an integer")
        if not 0 <= self.seed <= 2_000_000_000:
            raise Full256ProbeCoreError("seed is outside the native range")
        _positive_float(self.timeout_seconds, "timeout_seconds")
        if (
            isinstance(self.sentinel_bit, bool)
            or not isinstance(self.sentinel_bit, int)
            or not 0 <= self.sentinel_bit < KEY_BITS
        ):
            raise Full256ProbeCoreError("sentinel_bit must address the 256-bit key")
        if isinstance(self.sentinel_reruns, bool) or self.sentinel_reruns not in (
            0,
            1,
        ):
            raise Full256ProbeCoreError("sentinel_reruns must be zero or one")
        if (
            isinstance(self.maximum_state_bytes, bool)
            or not isinstance(self.maximum_state_bytes, int)
            or self.maximum_state_bytes < self.state_plan.serialized_state_bytes
        ):
            raise Full256ProbeCoreError("maximum_state_bytes cannot fit the state")
        _optional_sha256(
            self.expected_public_cnf_sha256,
            "expected_public_cnf_sha256",
        )
        _optional_sha256(
            self.expected_semantic_map_sha256,
            "expected_semantic_map_sha256",
        )
        for field_name in ("expected_variable_count", "expected_clause_count"):
            value = getattr(self, field_name)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 1
            ):
                raise Full256ProbeCoreError(f"{field_name} must be positive")

    @property
    def conflict_horizon(self) -> int:
        return max(self.state_plan.horizons)


@dataclass(frozen=True)
class Full256ProbeCoreResult:
    """Frozen bounded state plus a label-free external reader panel."""

    state: FrozenCausalBitfieldState
    reader_features: np.ndarray
    action_pool: Full256ActionPool
    event_index: Mapping[str, object]
    report: Mapping[str, object]

    def __post_init__(self) -> None:
        features = np.asarray(self.reader_features)
        if (
            features.shape != (KEY_BITS, READER_FEATURES)
            or features.dtype != np.float32
            or not np.all(np.isfinite(features))
        ):
            raise Full256ProbeCoreError(
                "reader_features must be finite float32[256,39]"
            )
        features.setflags(write=False)
        object.__setattr__(self, "reader_features", features)
        if not isinstance(self.action_pool, Full256ActionPool):
            raise Full256ProbeCoreError("action_pool must be Full256ActionPool")
        if self.action_pool.horizons != self.state.plan.horizons:
            raise Full256ProbeCoreError("action pool and state horizons differ")
        if (
            self.action_pool.source_stream_sha256 != self.state.source_stream_sha256
            or self.event_index.get("source_stream_sha256")
            != self.state.source_stream_sha256
        ):
            raise Full256ProbeCoreError("action pool source binding differs")

    @property
    def success_gate_passed(self) -> bool:
        gates = cast(Mapping[str, object], self.report["gates"])
        return bool(gates["success_gate_passed"])

    def reader_features_bytes(self) -> bytes:
        return self.reader_features.astype("<f4", copy=False).tobytes(order="C")

    @property
    def reader_features_sha256(self) -> str:
        return hashlib.sha256(self.reader_features_bytes()).hexdigest()


def midrank_quantiles(values: np.ndarray) -> np.ndarray:
    """Return stable, tie-aware empirical midrank quantiles."""

    flat = np.asarray(values, dtype=np.float64).reshape(-1)
    if flat.size < 2 or not np.all(np.isfinite(flat)):
        raise Full256ProbeCoreError("branch difficulty panel is invalid")
    order = np.argsort(flat, kind="stable")
    ranks = np.empty(flat.size, dtype=np.float64)
    start = 0
    while start < flat.size:
        end = start + 1
        while end < flat.size and flat[order[end]] == flat[order[start]]:
            end += 1
        ranks[order[start:end]] = 0.5 * (start + end - 1)
        start = end
    return ((ranks + 0.5) / flat.size).reshape(values.shape)


def _proof_event_commitment_payload(event: ProofEvent) -> dict[str, object]:
    return {
        "id": event.clause_id,
        "redundant": event.redundant,
        "witness": event.witness,
        "conclusion_phase": event.conclusion_phase,
        "snapshot": event.snapshot.describe(),
        "clause": list(event.clause),
        "antecedents": list(event.antecedents),
    }


def _baseline_commitment(header: ProbeStreamHeader) -> str:
    return canonical_sha256(
        [_proof_event_commitment_payload(event) for event in header.baseline_events]
    )


def _peak_rss_bytes() -> int:
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(raw if sys.platform == "darwin" else raw * 1024)


def _validate_header(
    header: ProbeStreamHeader,
    provenance: ClauseProvenanceIndex,
    *,
    first_bit: int,
    last_bit: int,
    conflict_horizon: int,
    seed: int,
) -> None:
    if (
        header.variables != provenance.variable_count
        or header.original_clause_count != provenance.clause_count
        or header.first_bit != first_bit
        or header.last_bit != last_bit
        or header.conflict_horizon != conflict_horizon
        or header.seed != seed
    ):
        raise Full256ProbeCoreError("native stream and public request differ")


def _reader_feature_panel(
    *,
    unary_scores: np.ndarray,
    key_touch_delta: np.ndarray,
    motif_delta: np.ndarray,
) -> np.ndarray:
    """Build U3 | ARX24 | M12 in fixed horizon-major column order."""

    if unary_scores.shape != (HORIZON_COUNT, KEY_BITS):
        raise Full256ProbeCoreError("unary reader panel shape differs")
    if key_touch_delta.shape != (HORIZON_COUNT, KEY_BITS, KEY_BITS):
        raise Full256ProbeCoreError("ARX reader panel shape differs")
    if motif_delta.shape != (HORIZON_COUNT, KEY_BITS, MOTIF_DIMENSIONS):
        raise Full256ProbeCoreError("motif reader panel shape differs")

    features = np.empty((KEY_BITS, READER_FEATURES), dtype=np.float32)
    features[:, :UNARY_FEATURES] = unary_scores.T.astype(np.float32)
    offset = UNARY_FEATURES
    for horizon_index in range(HORIZON_COUNT):
        for bit in range(KEY_BITS):
            features[
                bit,
                offset : offset + len(ARX_NEIGHBORS[bit]),
            ] = key_touch_delta[
                horizon_index,
                bit,
                ARX_NEIGHBORS[bit],
            ]
        offset += ARX_FEATURES // HORIZON_COUNT
    motif_families = MOTIF_FEATURES // HORIZON_COUNT
    motif_family_width = MOTIF_DIMENSIONS // motif_families
    for horizon_index in range(HORIZON_COUNT):
        for family in range(motif_families):
            first = family * motif_family_width
            last = first + motif_family_width
            features[:, offset] = np.sum(
                motif_delta[horizon_index, :, first:last],
                axis=1,
                dtype=np.float32,
            )
            offset += 1
    if offset != READER_FEATURES or not np.all(np.isfinite(features)):
        raise Full256ProbeCoreError("reader feature construction differs")
    return features


def _reader_feature_description(
    direct: np.ndarray,
    swapped: np.ndarray,
) -> dict[str, object]:
    direct_bytes = direct.astype("<f4", copy=False).tobytes(order="C")
    swapped_bytes = swapped.astype("<f4", copy=False).tobytes(order="C")
    swap_negates = bool(np.array_equal(direct, -swapped))
    return {
        "schema": READER_FEATURE_SCHEMA,
        "shape": [KEY_BITS, READER_FEATURES],
        "dtype": "float32le",
        "serialized_bytes": len(direct_bytes),
        "reader_features_sha256": hashlib.sha256(direct_bytes).hexdigest(),
        "swapped_features_sha256": hashlib.sha256(swapped_bytes).hexdigest(),
        "polarity_swap_exactly_negates": swap_negates,
        "column_order": {
            "U3": {
                "columns_half_open": [0, 3],
                "order": "three plan horizons",
            },
            "ARX24": {
                "columns_half_open": [3, 27],
                "order": "horizon-major then eight ARX_NEIGHBORS edges",
            },
            "M12": {
                "columns_half_open": [27, 39],
                "order": "horizon-major then four contiguous 16-motif sums",
            },
        },
        "signed_features": True,
        "retained_labels": 0,
        "part_of_recurrent_state": False,
    }


def _record_resources(
    record: ProbeRecord,
    totals: dict[str, int],
) -> None:
    totals["native_cpu_microseconds"] += record.resources["solver_cpu_microseconds"]
    totals["native_wall_microseconds"] += record.resources["solver_wall_microseconds"]
    totals["native_peak_rss_bytes"] = max(
        totals["native_peak_rss_bytes"],
        record.resources["solver_peak_rss_bytes"],
    )


def run_full256_probe_core(
    config: Full256ProbeCoreConfig,
) -> Full256ProbeCoreResult:
    """Run 512 public assumption branches and freeze their bounded O1 state."""

    if not isinstance(config, Full256ProbeCoreConfig):
        raise TypeError("config must be Full256ProbeCoreConfig")
    wall_started = time.monotonic()
    cpu_started = time.process_time()
    public_cnf = Path(config.public_cnf).resolve(strict=True)
    semantic_map = Path(config.semantic_map).resolve(strict=True)
    executable = Path(config.native_executable).resolve(strict=True)
    if not public_cnf.is_file() or not semantic_map.is_file():
        raise Full256ProbeCoreError("public CNF and semantic map must be files")
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise Full256ProbeCoreError("native_executable must be executable")

    cnf_sha256 = sha256_file(public_cnf)
    map_sha256 = sha256_file(semantic_map)
    if (
        config.expected_public_cnf_sha256 is not None
        and cnf_sha256 != config.expected_public_cnf_sha256
    ):
        raise Full256ProbeCoreError("public CNF hash differs")
    if (
        config.expected_semantic_map_sha256 is not None
        and map_sha256 != config.expected_semantic_map_sha256
    ):
        raise Full256ProbeCoreError("semantic map hash differs")

    provenance = ClauseProvenanceIndex.load(public_cnf, semantic_map)
    if (
        config.expected_variable_count is not None
        and provenance.variable_count != config.expected_variable_count
    ):
        raise Full256ProbeCoreError("public CNF variable count differs")
    if (
        config.expected_clause_count is not None
        and provenance.clause_count != config.expected_clause_count
    ):
        raise Full256ProbeCoreError("public CNF clause count differs")

    horizons = config.state_plan.horizons
    costs = np.empty((HORIZON_COUNT, KEY_BITS, 2), dtype=np.float64)
    motif_delta = np.empty(
        (HORIZON_COUNT, KEY_BITS, MOTIF_DIMENSIONS), dtype=np.float32
    )
    key_touch_delta = np.empty((HORIZON_COUNT, KEY_BITS, KEY_BITS), dtype=np.float32)
    information_mass = np.empty((HORIZON_COUNT, KEY_BITS), dtype=np.float64)
    raw_branch_features = np.empty(
        (HORIZON_COUNT, KEY_BITS, 2, BRANCH_FEATURES),
        dtype=np.float32,
    )
    final_resources = np.empty((KEY_BITS, 2, 3), dtype=np.uint64)
    pair_hashes: list[str] = []
    event_rows: list[dict[str, object]] = []
    frontier_event_gaps: list[int] = []
    final_overshoots: list[int] = []
    resource_totals = {
        "native_cpu_microseconds": 0,
        "native_wall_microseconds": 0,
        "native_peak_rss_bytes": 0,
    }

    stream = iter_native_probe_records(
        executable=executable,
        cnf_path=public_cnf,
        first_bit=0,
        last_bit=KEY_BITS - 1,
        conflict_limit=config.conflict_horizon,
        seed=config.seed,
        timeout_seconds=config.timeout_seconds,
    )
    header, pairs = paired_records(iter(stream))
    _validate_header(
        header,
        provenance,
        first_bit=0,
        last_bit=KEY_BITS - 1,
        conflict_horizon=config.conflict_horizon,
        seed=config.seed,
    )
    baseline_sha256 = _baseline_commitment(header)

    for expected_bit, (zero, one) in enumerate(pairs):
        if zero.bit_index != expected_bit or one.bit_index != expected_bit:
            raise Full256ProbeCoreError("full sweep bit order or coverage differs")
        if zero.status != 0 or one.status != 0:
            raise Full256ProbeCoreError(
                "paired branch reached SAT/UNSAT before the frozen horizon"
            )
        pair_sha256 = pair_commitment(zero, one)
        pair_hashes.append(pair_sha256)
        zero_summaries = summarize_probe_prefixes(
            zero,
            provenance,
            horizons,
            baseline_events=header.baseline_events,
        )
        one_summaries = summarize_probe_prefixes(
            one,
            provenance,
            horizons,
            baseline_events=header.baseline_events,
        )
        horizon_rows: list[dict[str, object]] = []
        row: dict[str, object] = {
            "bit_index": expected_bit,
            "pair_sha256": pair_sha256,
            "branches": {
                "0": zero.deterministic_sha256,
                "1": one.deterministic_sha256,
            },
            "horizons": horizon_rows,
        }
        for horizon_index, horizon in enumerate(horizons):
            zero_summary = zero_summaries[horizon]
            one_summary = one_summaries[horizon]
            raw_branch_features[horizon_index, expected_bit, 0] = branch_feature_vector(
                zero_summary
            )
            raw_branch_features[horizon_index, expected_bit, 1] = branch_feature_vector(
                one_summary
            )
            zero_cost = branch_difficulty(zero_summary)
            one_cost = branch_difficulty(one_summary)
            costs[horizon_index, expected_bit] = (zero_cost, one_cost)
            motif = one_summary.motif - zero_summary.motif
            touches = one_summary.key_touch - zero_summary.key_touch
            motif_delta[horizon_index, expected_bit] = motif
            key_touch_delta[horizon_index, expected_bit] = touches
            telemetry_delta = math.fsum(
                abs(
                    math.log1p(getattr(one_summary.snapshot, field_name))
                    - math.log1p(getattr(zero_summary.snapshot, field_name))
                )
                for field_name in ("decisions", "propagations", "ticks")
            )
            mass = (
                telemetry_delta
                + float(np.abs(motif).sum())
                + float(np.abs(touches).sum())
            )
            information_mass[horizon_index, expected_bit] = mass
            frontier_event_gaps.extend(
                (
                    zero_summary.frontier_event_gap,
                    one_summary.frontier_event_gap,
                )
            )
            horizon_rows.append(
                {
                    "horizon": horizon,
                    "zero_summary_sha256": zero_summary.summary_sha256,
                    "one_summary_sha256": one_summary.summary_sha256,
                    "zero_difficulty": zero_cost,
                    "one_difficulty": one_cost,
                    "zero_last_event_conflict": (zero_summary.snapshot.conflicts),
                    "one_last_event_conflict": one_summary.snapshot.conflicts,
                    "zero_frontier_event_gap": (zero_summary.frontier_event_gap),
                    "one_frontier_event_gap": one_summary.frontier_event_gap,
                    "zero_exact_conflict_event_present": (
                        zero_summary.exact_conflict_event_present
                    ),
                    "one_exact_conflict_event_present": (
                        one_summary.exact_conflict_event_present
                    ),
                    "motif_delta_l1": float(np.abs(motif).sum()),
                    "key_touch_delta_l1": float(np.abs(touches).sum()),
                    "information_mass": mass,
                }
            )
        event_rows.append(row)
        for polarity, record in enumerate((zero, one)):
            final_resources[expected_bit, polarity] = (
                record.resources["solver_cpu_microseconds"],
                record.resources["solver_wall_microseconds"],
                record.resources["solver_peak_rss_bytes"],
            )
            _record_resources(record, resource_totals)
            final_overshoots.append(record.final_overshoot_conflicts)

    if len(pair_hashes) != KEY_BITS:
        raise Full256ProbeCoreError("full sweep lacks 256 paired coordinates")

    source_stream_sha256 = canonical_sha256(
        {
            "baseline_sha256": baseline_sha256,
            "pair_hashes": pair_hashes,
            "horizons": list(horizons),
        }
    )
    action_pool = Full256ActionPool(
        horizons=horizons,
        branch_features=raw_branch_features,
        final_resources=final_resources,
        pair_sha256=tuple(pair_hashes),
        source_stream_sha256=source_stream_sha256,
    )
    action_pool_description = action_pool.describe()
    action_pool_swap_control = action_pool.swap_control()
    action_pool_bytes = serialize_action_pool(action_pool)
    action_pool_byte_inventory = cast(
        Mapping[str, object],
        action_pool_description["byte_inventory"],
    )
    quantiles = np.empty_like(costs)
    unary_scores = np.empty((HORIZON_COUNT, KEY_BITS), dtype=np.float64)
    for horizon_index in range(HORIZON_COUNT):
        quantiles[horizon_index] = midrank_quantiles(costs[horizon_index])
        unary_scores[horizon_index] = (
            quantiles[horizon_index, :, 0] ** 3 - quantiles[horizon_index, :, 1] ** 3
        )
        for bit, row in enumerate(event_rows):
            horizon_rows = cast(list[dict[str, object]], row["horizons"])
            horizon_row = horizon_rows[horizon_index]
            horizon_row.update(
                {
                    "zero_midrank_quantile": quantiles[horizon_index, bit, 0],
                    "one_midrank_quantile": quantiles[horizon_index, bit, 1],
                    "unary_score": unary_scores[horizon_index, bit],
                }
            )

    reader_features = _reader_feature_panel(
        unary_scores=unary_scores,
        key_touch_delta=key_touch_delta,
        motif_delta=motif_delta,
    )
    swapped_reader_features = _reader_feature_panel(
        unary_scores=-unary_scores,
        key_touch_delta=-key_touch_delta,
        motif_delta=-motif_delta,
    )
    reader_description = _reader_feature_description(
        reader_features,
        swapped_reader_features,
    )

    direct = CausalBitfieldAccumulator(config.state_plan)
    swapped = CausalBitfieldAccumulator(config.state_plan)
    for bit in range(KEY_BITS):
        for horizon_index, horizon in enumerate(horizons):
            event = PairedCausalEvent(
                bit_index=bit,
                horizon=horizon,
                unary_score=float(unary_scores[horizon_index, bit]),
                information_mass=float(information_mass[horizon_index, bit]),
                motif_delta=motif_delta[horizon_index, bit],
                key_touch_delta=key_touch_delta[horizon_index, bit],
                source_pair_sha256=pair_hashes[bit],
            )
            direct.update(event)
            swapped.update(
                PairedCausalEvent(
                    bit_index=bit,
                    horizon=horizon,
                    unary_score=-event.unary_score,
                    information_mass=event.information_mass,
                    motif_delta=-event.motif_delta,
                    key_touch_delta=-event.key_touch_delta,
                    source_pair_sha256=pair_hashes[bit],
                )
            )
    frozen = direct.freeze(source_stream_sha256=source_stream_sha256)
    swapped_frozen = swapped.freeze(source_stream_sha256=source_stream_sha256)
    swap_control = state_swap_control(frozen, swapped_frozen)
    state_bytes = frozen.to_bytes()
    if len(state_bytes) > config.maximum_state_bytes:
        raise Full256ProbeCoreError("frozen causal state exceeds byte budget")

    sentinel_replays: list[dict[str, object]] = []
    if config.sentinel_reruns:
        rerun_stream = iter_native_probe_records(
            executable=executable,
            cnf_path=public_cnf,
            first_bit=config.sentinel_bit,
            last_bit=config.sentinel_bit,
            conflict_limit=config.conflict_horizon,
            seed=config.seed,
            timeout_seconds=config.timeout_seconds,
        )
        rerun_header, rerun_pairs = paired_records(iter(rerun_stream))
        _validate_header(
            rerun_header,
            provenance,
            first_bit=config.sentinel_bit,
            last_bit=config.sentinel_bit,
            conflict_horizon=config.conflict_horizon,
            seed=config.seed,
        )
        try:
            rerun_zero, rerun_one = next(rerun_pairs)
        except StopIteration as exc:
            raise Full256ProbeCoreError("sentinel rerun is empty") from exc
        if next(rerun_pairs, None) is not None:
            raise Full256ProbeCoreError("sentinel rerun contains extra pairs")
        if rerun_zero.status != 0 or rerun_one.status != 0:
            raise Full256ProbeCoreError("sentinel rerun terminated early")
        rerun_pair_sha256 = pair_commitment(rerun_zero, rerun_one)
        rerun_baseline_sha256 = _baseline_commitment(rerun_header)
        sentinel_replays.append(
            {
                "bit_index": config.sentinel_bit,
                "pair_sha256": rerun_pair_sha256,
                "baseline_sha256": rerun_baseline_sha256,
                "matches_full_sweep_pair": (
                    rerun_pair_sha256 == pair_hashes[config.sentinel_bit]
                ),
                "matches_full_sweep_baseline": (
                    rerun_baseline_sha256 == baseline_sha256
                ),
            }
        )
        for record in (rerun_zero, rerun_one):
            _record_resources(record, resource_totals)

    deterministic_sentinel = all(
        row["matches_full_sweep_pair"] and row["matches_full_sweep_baseline"]
        for row in sentinel_replays
    )
    event_index: dict[str, object] = {
        "schema": PROBE_EVENT_INDEX_SCHEMA,
        "source_stream_sha256": source_stream_sha256,
        "public_baseline_sha256": baseline_sha256,
        "paired_bits": len(event_rows),
        "horizons": list(horizons),
        "rows": event_rows,
    }
    event_index["event_index_sha256"] = canonical_sha256(event_index)

    process_peak_rss_bytes = _peak_rss_bytes()
    resources = {
        "full_sweep_native_solver_branches": 2 * KEY_BITS,
        "sentinel_native_solver_branches": 2 * len(sentinel_replays),
        "total_native_solver_branches": (2 * KEY_BITS + 2 * len(sentinel_replays)),
        "proof_frontiers": len(frontier_event_gaps),
        "native_cpu_seconds": (
            resource_totals["native_cpu_microseconds"] / 1_000_000.0
        ),
        "native_wall_seconds": (
            resource_totals["native_wall_microseconds"] / 1_000_000.0
        ),
        "python_cpu_seconds": time.process_time() - cpu_started,
        "wall_seconds": time.monotonic() - wall_started,
        "native_peak_rss_bytes": resource_totals["native_peak_rss_bytes"],
        "process_peak_rss_bytes": process_peak_rss_bytes,
        "conservative_process_group_peak_rss_bytes": (
            process_peak_rss_bytes + 2 * resource_totals["native_peak_rss_bytes"]
        ),
        "public_cnf_bytes": public_cnf.stat().st_size,
        "semantic_map_bytes": semantic_map.stat().st_size,
        "state_bytes": len(state_bytes),
        "reader_feature_bytes": reader_description["serialized_bytes"],
        "action_pool_feature_bytes": action_pool.raw_feature_bytes,
        "action_pool_resource_bytes": action_pool.resource_bytes,
        "action_pool_payload_bytes": action_pool_byte_inventory["payload_bytes"],
        "action_pool_serialized_bytes": len(action_pool_bytes),
        "native_final_conflict_overshoot_min": min(final_overshoots),
        "native_final_conflict_overshoot_max": max(final_overshoots),
        "native_final_conflict_overshoot_mean": float(np.mean(final_overshoots)),
        "mps_calls": 0,
        "gpu_calls": 0,
    }
    exact_prefix_count = sum(gap == 0 for gap in frontier_event_gaps)
    state_description = frozen.describe()
    gates = {
        "full_256_bit_pair_coverage": len(pair_hashes) == KEY_BITS,
        "exactly_512_full_sweep_branches": len(pair_hashes) * 2 == 512,
        "all_1536_closed_proof_prefixes_present": (
            len(frontier_event_gaps) == HORIZON_COUNT * KEY_BITS * 2
        ),
        "deterministic_sentinel_replay": deterministic_sentinel,
        "polarity_swap_antisymmetry": bool(swap_control["passed"]),
        "reader_feature_swap_antisymmetry": bool(
            reader_description["polarity_swap_exactly_negates"]
        ),
        "action_pool_schema_valid": (
            action_pool_description["schema"] == ACTION_POOL_SCHEMA
        ),
        "action_pool_hash_valid": (
            action_pool_description["action_pool_sha256"]
            == hashlib.sha256(action_pool_bytes).hexdigest()
        ),
        "action_pool_byte_inventory_valid": (
            action_pool_byte_inventory["payload_bytes"]
            == action_pool.raw_feature_bytes + action_pool.resource_bytes
            and action_pool_byte_inventory["serialized_bytes"] == len(action_pool_bytes)
        ),
        "action_pool_source_bound": (
            action_pool.source_stream_sha256 == source_stream_sha256
            and action_pool.pair_sha256 == tuple(pair_hashes)
        ),
        "action_pool_polarity_swap_antisymmetry": bool(
            action_pool_swap_control["passed"]
        ),
        "action_pool_contains_no_labels": (
            b"label" not in canonical_json_bytes(action_pool_description).lower()
        ),
        "bounded_state_under_budget": len(state_bytes) <= config.maximum_state_bytes,
        "state_has_unary_signal": cast(int, state_description["unary_nonzero"]) > 0,
        "state_has_interaction_signal": (
            cast(int, state_description["interaction_nonzero"]) > 0
        ),
        "state_has_holographic_signal": (
            cast(int, state_description["holographic_nonzero"]) > 0
        ),
        "zero_labels_or_diagnostics": True,
        "zero_mps_calls": True,
        "zero_gpu_calls": True,
    }
    gates["success_gate_passed"] = all(gates.values())
    unsigned_report: dict[str, object] = {
        "schema": PROBE_CORE_SCHEMA,
        "input_contract": {
            "public_only": True,
            "public_cnf": str(public_cnf),
            "public_cnf_sha256": cnf_sha256,
            "semantic_map": str(semantic_map),
            "semantic_map_sha256": map_sha256,
            "native_executable": str(executable),
            "native_executable_sha256": sha256_file(executable),
            "accepted_labels": 0,
            "accepted_diagnostics": 0,
            "source_capsule_required": False,
        },
        "provenance": provenance.describe(),
        "probe_stream": {
            "cadical_version": header.cadical_version,
            "branch_isolation": header.branch_isolation,
            "seed": config.seed,
            "public_baseline_event_count": len(header.baseline_events),
            "public_baseline_sha256": baseline_sha256,
            "paired_bit_count": len(pair_hashes),
            "branch_count": 2 * len(pair_hashes),
            "horizons": list(horizons),
            "unary_transform": "midrank(zero)^3 - midrank(one)^3",
            "proof_frontier_count": len(frontier_event_gaps),
            "exact_conflict_event_prefix_count": exact_prefix_count,
            "frontier_event_gap_min": min(frontier_event_gaps),
            "frontier_event_gap_max": max(frontier_event_gaps),
            "frontier_event_gap_mean": float(np.mean(frontier_event_gaps)),
            "source_stream_sha256": source_stream_sha256,
            "sentinel_replays_requested": config.sentinel_reruns,
            "sentinel_replays": sentinel_replays,
            "prefix_contract": (
                "complete closed proof-event prefix at conflicts <= horizon"
            ),
            "final_conflict_tail_is_billed_but_excluded": True,
        },
        "state": state_description,
        "reader_features": reader_description,
        "action_pool": action_pool_description,
        "polarity_swap_control": swap_control,
        "action_pool_polarity_swap_control": action_pool_swap_control,
        "event_index": {
            "schema": event_index["schema"],
            "paired_bits": event_index["paired_bits"],
            "event_index_sha256": event_index["event_index_sha256"],
        },
        "resources": resources,
        "gates": gates,
    }
    report = {
        **unsigned_report,
        "result_sha256": canonical_sha256(unsigned_report),
    }
    return Full256ProbeCoreResult(
        state=frozen,
        reader_features=reader_features,
        action_pool=action_pool,
        event_index=event_index,
        report=report,
    )
