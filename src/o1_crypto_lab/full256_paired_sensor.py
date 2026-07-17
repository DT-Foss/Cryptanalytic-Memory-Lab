"""O1C-0012 full-width paired proof sensor and bounded-state experiment."""

from __future__ import annotations

import hashlib
import json
import math
import resource
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

import numpy as np

from .cadical_sensor import (
    KEY_BITS,
    MOTIF_DIMENSIONS,
    ClauseProvenanceIndex,
    ProofEvent,
    branch_difficulty,
    build_native_sensor,
    iter_native_probe_records,
    pair_commitment,
    paired_records,
    sha256_file,
    summarize_probe_prefixes,
)
from .causal_bitfield import (
    CausalBitfieldAccumulator,
    CausalBitfieldPlan,
    PairedCausalEvent,
    plan_from_mapping,
    state_swap_control,
)
from .chacha_trace import chacha20_block
from .living_inverse import canonical_json_bytes, canonical_sha256


CONFIG_SCHEMA = "o1-256-paired-causal-sensor-config-v1"
RESULT_SCHEMA = "o1-256-paired-causal-sensor-result-v1"
EVENT_INDEX_SCHEMA = "o1-256-paired-causal-event-index-v1"
DIAGNOSTIC_SCHEMA = "o1-256-known-key-sensor-diagnostic-v1"


class Full256PairedSensorError(ValueError):
    """The frozen O1C-0012 protocol or a mandatory gate differs."""


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise Full256PairedSensorError(
            f"{field} must be an integer in [{minimum}, {maximum}]"
        )
    return value


def _positive(value: object, field: str, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not 0 < float(value) <= maximum
    ):
        raise Full256PairedSensorError(f"{field} must be in (0, {maximum}]")
    return float(value)


def _sha(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise Full256PairedSensorError(f"{field} must be lowercase SHA-256")
    return value


def _hex_bytes(value: object, field: str, length: int) -> bytes:
    if not isinstance(value, str) or len(value) != length * 2:
        raise Full256PairedSensorError(
            f"{field} must encode exactly {length} bytes"
        )
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise Full256PairedSensorError(f"{field} must be hexadecimal") from exc
    if result.hex() != value:
        raise Full256PairedSensorError(f"{field} must be canonical lowercase hex")
    return result


def _strict_mapping(
    value: object, field: str, expected: set[str]
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise Full256PairedSensorError(f"{field} fields differ")
    return value


@dataclass(frozen=True)
class PairedSensorSource:
    capsule: str
    manifest_sha256: str
    public_instance: str
    public_instance_sha256: str
    semantic_map: str
    semantic_map_sha256: str
    expected_variable_count: int
    expected_clause_count: int

    @classmethod
    def from_mapping(cls, value: object) -> "PairedSensorSource":
        row = _strict_mapping(
            value,
            "source",
            {
                "capsule",
                "manifest_sha256",
                "public_instance",
                "public_instance_sha256",
                "semantic_map",
                "semantic_map_sha256",
                "expected_variable_count",
                "expected_clause_count",
            },
        )
        for field in ("capsule", "public_instance", "semantic_map"):
            if not isinstance(row[field], str) or not row[field]:
                raise Full256PairedSensorError(f"source.{field} is required")
        return cls(
            capsule=str(row["capsule"]),
            manifest_sha256=_sha(
                row["manifest_sha256"], "source.manifest_sha256"
            ),
            public_instance=str(row["public_instance"]),
            public_instance_sha256=_sha(
                row["public_instance_sha256"],
                "source.public_instance_sha256",
            ),
            semantic_map=str(row["semantic_map"]),
            semantic_map_sha256=_sha(
                row["semantic_map_sha256"], "source.semantic_map_sha256"
            ),
            expected_variable_count=_integer(
                row["expected_variable_count"],
                "source.expected_variable_count",
                897,
                1_000_000,
            ),
            expected_clause_count=_integer(
                row["expected_clause_count"],
                "source.expected_clause_count",
                1,
                10_000_000,
            ),
        )


@dataclass(frozen=True)
class NativeDependencyConfig:
    compiler: str
    include_directory: str
    static_library: str
    cadical_header_sha256: str
    cadical_library_sha256: str

    @classmethod
    def from_mapping(cls, value: object) -> "NativeDependencyConfig":
        row = _strict_mapping(
            value,
            "native",
            {
                "compiler",
                "include_directory",
                "static_library",
                "cadical_header_sha256",
                "cadical_library_sha256",
            },
        )
        for field in ("compiler", "include_directory", "static_library"):
            if not isinstance(row[field], str) or not row[field]:
                raise Full256PairedSensorError(f"native.{field} is required")
        return cls(
            compiler=str(row["compiler"]),
            include_directory=str(row["include_directory"]),
            static_library=str(row["static_library"]),
            cadical_header_sha256=_sha(
                row["cadical_header_sha256"],
                "native.cadical_header_sha256",
            ),
            cadical_library_sha256=_sha(
                row["cadical_library_sha256"],
                "native.cadical_library_sha256",
            ),
        )


@dataclass(frozen=True)
class ProbeConfig:
    first_bit: int
    last_bit: int
    conflict_horizon: int
    seed: int
    sentinel_bit: int
    deterministic_sentinel_reruns: int
    timeout_seconds: float

    @classmethod
    def from_mapping(cls, value: object) -> "ProbeConfig":
        row = _strict_mapping(
            value,
            "probe",
            {
                "first_bit",
                "last_bit",
                "conflict_horizon",
                "seed",
                "sentinel_bit",
                "deterministic_sentinel_reruns",
                "timeout_seconds",
            },
        )
        result = cls(
            first_bit=_integer(row["first_bit"], "probe.first_bit", 0, 255),
            last_bit=_integer(row["last_bit"], "probe.last_bit", 0, 255),
            conflict_horizon=_integer(
                row["conflict_horizon"],
                "probe.conflict_horizon",
                1,
                1_000_000,
            ),
            seed=_integer(row["seed"], "probe.seed", 0, 2_000_000_000),
            sentinel_bit=_integer(
                row["sentinel_bit"], "probe.sentinel_bit", 0, 255
            ),
            deterministic_sentinel_reruns=_integer(
                row["deterministic_sentinel_reruns"],
                "probe.deterministic_sentinel_reruns",
                1,
                8,
            ),
            timeout_seconds=_positive(
                row["timeout_seconds"], "probe.timeout_seconds", 3600.0
            ),
        )
        if (
            result.first_bit != 0
            or result.last_bit != 255
            or not result.first_bit <= result.sentinel_bit <= result.last_bit
        ):
            raise Full256PairedSensorError(
                "O1C-0012 must cover all 256 bits and include its sentinel"
            )
        return result


@dataclass(frozen=True)
class DiagnosticConfig:
    key: bytes
    counter: int
    nonce: bytes
    output: bytes
    decoy_count: int
    decoy_seed: int

    @classmethod
    def from_mapping(cls, value: object) -> "DiagnosticConfig":
        row = _strict_mapping(
            value,
            "known_key_diagnostic",
            {
                "key_hex",
                "counter",
                "nonce_hex",
                "output_hex",
                "decoy_count",
                "decoy_seed",
            },
        )
        return cls(
            key=_hex_bytes(row["key_hex"], "known_key_diagnostic.key_hex", 32),
            counter=_integer(
                row["counter"],
                "known_key_diagnostic.counter",
                0,
                (1 << 32) - 1,
            ),
            nonce=_hex_bytes(
                row["nonce_hex"], "known_key_diagnostic.nonce_hex", 12
            ),
            output=_hex_bytes(
                row["output_hex"], "known_key_diagnostic.output_hex", 64
            ),
            decoy_count=_integer(
                row["decoy_count"],
                "known_key_diagnostic.decoy_count",
                1,
                10_000_000,
            ),
            decoy_seed=_integer(
                row["decoy_seed"],
                "known_key_diagnostic.decoy_seed",
                0,
                (1 << 63) - 1,
            ),
        )


@dataclass(frozen=True)
class SensorBudgetConfig:
    maximum_cpu_seconds: float
    maximum_wall_seconds: float
    maximum_resident_memory_mib: float
    maximum_persistent_artifact_bytes: int
    maximum_native_solver_branches: int
    maximum_mps_calls: int
    maximum_gpu_calls: int
    maximum_sibling_reads: int
    maximum_sibling_writes: int
    maximum_fresh_random_targets: int

    @classmethod
    def from_mapping(cls, value: object) -> "SensorBudgetConfig":
        row = _strict_mapping(
            value,
            "budgets",
            {
                "maximum_cpu_seconds",
                "maximum_wall_seconds",
                "maximum_resident_memory_mib",
                "maximum_persistent_artifact_bytes",
                "maximum_native_solver_branches",
                "maximum_mps_calls",
                "maximum_gpu_calls",
                "maximum_sibling_reads",
                "maximum_sibling_writes",
                "maximum_fresh_random_targets",
            },
        )
        return cls(
            maximum_cpu_seconds=_positive(
                row["maximum_cpu_seconds"], "budgets.maximum_cpu_seconds", 86400.0
            ),
            maximum_wall_seconds=_positive(
                row["maximum_wall_seconds"],
                "budgets.maximum_wall_seconds",
                86400.0,
            ),
            maximum_resident_memory_mib=_positive(
                row["maximum_resident_memory_mib"],
                "budgets.maximum_resident_memory_mib",
                1_048_576.0,
            ),
            maximum_persistent_artifact_bytes=_integer(
                row["maximum_persistent_artifact_bytes"],
                "budgets.maximum_persistent_artifact_bytes",
                1,
                1_000_000_000,
            ),
            maximum_native_solver_branches=_integer(
                row["maximum_native_solver_branches"],
                "budgets.maximum_native_solver_branches",
                1,
                1_000_000,
            ),
            maximum_mps_calls=_integer(
                row["maximum_mps_calls"], "budgets.maximum_mps_calls", 0, 1_000_000
            ),
            maximum_gpu_calls=_integer(
                row["maximum_gpu_calls"], "budgets.maximum_gpu_calls", 0, 1_000_000
            ),
            maximum_sibling_reads=_integer(
                row["maximum_sibling_reads"],
                "budgets.maximum_sibling_reads",
                0,
                1_000_000,
            ),
            maximum_sibling_writes=_integer(
                row["maximum_sibling_writes"],
                "budgets.maximum_sibling_writes",
                0,
                1_000_000,
            ),
            maximum_fresh_random_targets=_integer(
                row["maximum_fresh_random_targets"],
                "budgets.maximum_fresh_random_targets",
                0,
                1_000_000,
            ),
        )


@dataclass(frozen=True)
class Full256PairedSensorConfig:
    source: PairedSensorSource
    native: NativeDependencyConfig
    probe: ProbeConfig
    state_plan: CausalBitfieldPlan
    diagnostic: DiagnosticConfig
    budgets: SensorBudgetConfig
    maximum_state_bytes: int


def load_full256_paired_sensor_config(
    path: str | Path,
) -> tuple[dict[str, object], Full256PairedSensorConfig]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Full256PairedSensorError("could not load paired sensor config") from exc
    row = _strict_mapping(
        value,
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
            "source",
            "native",
            "probe",
            "state_plan",
            "known_key_diagnostic",
            "maximum_state_bytes",
        },
    )
    if row.get("schema") != CONFIG_SCHEMA:
        raise Full256PairedSensorError("paired sensor config schema differs")
    for field in (
        "attempt_id",
        "slug",
        "claim_level",
        "hypothesis",
        "prediction",
        "next_action",
    ):
        if not isinstance(row[field], str) or not row[field]:
            raise Full256PairedSensorError(f"config.{field} is required")
    if (
        not isinstance(row["controls"], list)
        or not row["controls"]
        or any(not isinstance(item, str) or not item for item in row["controls"])
        or not isinstance(row["budgets"], dict)
        or not isinstance(row["state_plan"], Mapping)
    ):
        raise Full256PairedSensorError("controls, budgets, or state plan differ")
    config = Full256PairedSensorConfig(
        source=PairedSensorSource.from_mapping(row["source"]),
        native=NativeDependencyConfig.from_mapping(row["native"]),
        probe=ProbeConfig.from_mapping(row["probe"]),
        state_plan=plan_from_mapping(row["state_plan"]),
        diagnostic=DiagnosticConfig.from_mapping(row["known_key_diagnostic"]),
        budgets=SensorBudgetConfig.from_mapping(row["budgets"]),
        maximum_state_bytes=_integer(
            row["maximum_state_bytes"], "maximum_state_bytes", 1, 1_000_000
        ),
    )
    if max(config.state_plan.horizons) != config.probe.conflict_horizon:
        raise Full256PairedSensorError(
            "native conflict limit must equal the largest state horizon"
        )
    if config.state_plan.serialized_state_bytes > config.maximum_state_bytes:
        raise Full256PairedSensorError("declared state exceeds maximum_state_bytes")
    native_branches = 2 * KEY_BITS + 2 * config.probe.deterministic_sentinel_reruns
    if native_branches > config.budgets.maximum_native_solver_branches:
        raise Full256PairedSensorError("declared native branch count exceeds budget")
    return dict(row), config


def _midrank_quantiles(values: np.ndarray) -> np.ndarray:
    flat = np.asarray(values, dtype=np.float64).reshape(-1)
    if flat.size < 2 or not np.all(np.isfinite(flat)):
        raise Full256PairedSensorError("branch difficulty panel is invalid")
    order = np.argsort(flat, kind="stable")
    ranks = np.empty(flat.size, dtype=np.float64)
    start = 0
    while start < flat.size:
        end = start + 1
        while end < flat.size and flat[order[end]] == flat[order[start]]:
            end += 1
        midpoint = 0.5 * (start + end - 1)
        ranks[order[start:end]] = midpoint
        start = end
    return ((ranks + 0.5) / flat.size).reshape(values.shape)


def _labels_from_key(key: bytes) -> np.ndarray:
    return np.unpackbits(
        np.frombuffer(key, dtype=np.uint8), bitorder="little"
    ).astype(np.uint8)


def _bits_to_key(bits: np.ndarray) -> bytes:
    values = np.asarray(bits, dtype=np.uint8)
    if values.shape != (KEY_BITS,) or np.any((values != 0) & (values != 1)):
        raise Full256PairedSensorError("predicted key bits differ")
    return np.packbits(values, bitorder="little").tobytes()


def _nll_bits(probabilities: np.ndarray, labels: np.ndarray) -> float:
    selected = np.where(labels == 1, probabilities, 1.0 - probabilities)
    selected = np.clip(selected, 2.0**-64, 1.0)
    return float(-np.log2(selected).sum())


def _proof_event_commitment_payload(event: ProofEvent) -> dict[str, object]:
    """Commit every proof-event field that can affect reduction or validation."""

    return {
        "id": event.clause_id,
        "redundant": event.redundant,
        "witness": event.witness,
        "conclusion_phase": event.conclusion_phase,
        "snapshot": event.snapshot.describe(),
        "clause": list(event.clause),
        "antecedents": list(event.antecedents),
    }


def _stream_decoy_rank(
    probabilities: np.ndarray,
    labels: np.ndarray,
    *,
    decoy_count: int,
    seed: int,
) -> dict[str, object]:
    log_zero = np.log2(np.clip(1.0 - probabilities, 2.0**-64, 1.0))
    log_one = np.log2(np.clip(probabilities, 2.0**-64, 1.0))
    delta = log_one - log_zero
    base = float(log_zero.sum())
    true_score = base + float(labels @ delta)
    rng = np.random.Generator(np.random.PCG64(seed))
    better = equal = 0
    digest = hashlib.sha256(b"o1c0012-decoy-score-stream-v1\0")
    remaining = decoy_count
    while remaining:
        count = min(4096, remaining)
        bits = rng.integers(0, 2, size=(count, KEY_BITS), dtype=np.uint8)
        scores = base + np.einsum(
            "ij,j->i", bits, delta, dtype=np.float64, optimize=False
        )
        better += int(np.count_nonzero(scores > true_score))
        equal += int(np.count_nonzero(scores == true_score))
        digest.update(scores.astype("<f8", copy=False).tobytes(order="C"))
        remaining -= count
    return {
        "decoy_count": decoy_count,
        "true_log2_probability": true_score,
        "strictly_better_decoys": better,
        "equal_score_decoys": equal,
        "rank_one_based": better + 1,
        "score_stream_float64le_sha256": digest.hexdigest(),
    }


def _known_key_diagnostic(
    *,
    state,
    diagnostic: DiagnosticConfig,
) -> dict[str, object]:
    labels = _labels_from_key(diagnostic.key)
    base_probabilities = state.probabilities(corrected=False)
    corrected_probabilities = state.probabilities(corrected=True)
    base_prediction = (base_probabilities >= 0.5).astype(np.uint8)
    corrected_prediction = (corrected_probabilities >= 0.5).astype(np.uint8)
    predicted_key = _bits_to_key(corrected_prediction)
    base_nll = _nll_bits(base_probabilities, labels)
    corrected_nll = _nll_bits(corrected_probabilities, labels)
    byte_truth = np.frombuffer(diagnostic.key, dtype=np.uint8)
    byte_prediction = np.frombuffer(predicted_key, dtype=np.uint8)
    word_truth = np.frombuffer(diagnostic.key, dtype="<u2")
    word_prediction = np.frombuffer(predicted_key, dtype="<u2")
    horizon_rows: list[dict[str, object]] = []
    for index, horizon in enumerate(state.plan.horizons):
        prediction = (state.unary[index] >= 0.0).astype(np.uint8)
        correct = int(np.count_nonzero(prediction == labels))
        horizon_rows.append(
            {
                "horizon": horizon,
                "correct_bits": correct,
                "bit_accuracy": correct / KEY_BITS,
            }
        )
    decoy_rank = _stream_decoy_rank(
        corrected_probabilities,
        labels,
        decoy_count=diagnostic.decoy_count,
        seed=diagnostic.decoy_seed,
    )
    output_matches_config = (
        chacha20_block(diagnostic.key, diagnostic.counter, diagnostic.nonce)
        == diagnostic.output
    )
    predicted_output = chacha20_block(
        predicted_key, diagnostic.counter, diagnostic.nonce
    )
    result = {
        "schema": DIAGNOSTIC_SCHEMA,
        "label_access_phase": "POST_STATE_FREEZE_KNOWN_KEY_DIAGNOSTIC_ONLY",
        "uniform_random_baseline_nll_bits": 256.0,
        "base_key_nll_bits": base_nll,
        "corrected_key_nll_bits": corrected_nll,
        "base_effective_compression_bits": 256.0 - base_nll,
        "corrected_effective_compression_bits": 256.0 - corrected_nll,
        "base_correct_bits": int(np.count_nonzero(base_prediction == labels)),
        "corrected_correct_bits": int(
            np.count_nonzero(corrected_prediction == labels)
        ),
        "correct_bytes": int(np.count_nonzero(byte_prediction == byte_truth)),
        "correct_16bit_blocks": int(
            np.count_nonzero(word_prediction == word_truth)
        ),
        "hamming_distance": int(
            np.count_nonzero(corrected_prediction != labels)
        ),
        "horizon_diagnostics": horizon_rows,
        "predicted_key_sha256": hashlib.sha256(predicted_key).hexdigest(),
        "exact_key_recovered": predicted_key == diagnostic.key,
        "configured_known_key_recomputes_public_output": output_matches_config,
        "predicted_key_passes_exact_chacha20_verification": (
            predicted_output == diagnostic.output
        ),
        "million_decoy_rank": decoy_rank,
        "claim_boundary": (
            "single-known-key post-freeze mechanism diagnostic; no cross-key "
            "inverse-signal claim"
        ),
    }
    result["diagnostic_sha256"] = canonical_sha256(result)
    return result


def _peak_rss_bytes() -> int:
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(raw if __import__("sys").platform == "darwin" else raw * 1024)


@dataclass(frozen=True)
class Full256PairedSensorResult:
    report: Mapping[str, object]
    artifacts: Mapping[str, bytes]

    @property
    def success_gate_passed(self) -> bool:
        return bool(self.report["gates"]["success_gate_passed"])

    def metrics(self) -> dict[str, object]:
        diagnostic = self.report["known_key_diagnostic"]
        resources = self.report["resources"]
        state = self.report["state"]
        return {
            "schema": "o1-256-paired-causal-sensor-metrics-v1",
            "success_gate_passed": self.success_gate_passed,
            "unknown_target_key_bits": 256,
            "paired_bit_count": self.report["probe_stream"]["paired_bit_count"],
            "proof_frontier_count": self.report["probe_stream"][
                "proof_frontier_count"
            ],
            "state_bytes": state["serialized_state_bytes"],
            "state_sha256": state["state_sha256"],
            "corrected_key_nll_bits": diagnostic["corrected_key_nll_bits"],
            "corrected_effective_compression_bits": diagnostic[
                "corrected_effective_compression_bits"
            ],
            "corrected_correct_bits": diagnostic["corrected_correct_bits"],
            "hamming_distance": diagnostic["hamming_distance"],
            "million_decoy_rank": diagnostic["million_decoy_rank"][
                "rank_one_based"
            ],
            "exact_key_recovered": diagnostic["exact_key_recovered"],
            "native_cpu_seconds": resources["native_child_cpu_seconds"],
            "wall_seconds": resources["wall_seconds"],
            "peak_rss_bytes": resources["peak_rss_bytes"],
            "fresh_random_targets": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "mps_calls": 0,
            "gpu_calls": 0,
        }


def run_full256_paired_sensor(
    config: Full256PairedSensorConfig,
    *,
    lab_root: str | Path,
    working_directory: str | Path,
) -> Full256PairedSensorResult:
    """Execute one direct full-256 paired sweep and freeze its bounded state."""

    wall_started = time.monotonic()
    parent_cpu_started = time.process_time()
    children_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    rss_milestones = {"entry": _peak_rss_bytes()}
    root = Path(lab_root).resolve(strict=True)
    workspace = Path(working_directory)
    workspace.mkdir(parents=True, exist_ok=True)
    source_capsule = (root / config.source.capsule).resolve(strict=True)
    public_cnf = (source_capsule / config.source.public_instance).resolve(strict=True)
    semantic_map = (source_capsule / config.source.semantic_map).resolve(strict=True)
    if source_capsule.parent != (root / "runs").resolve(strict=True):
        raise Full256PairedSensorError("source capsule is outside finalized runs")
    if sha256_file(public_cnf) != config.source.public_instance_sha256:
        raise Full256PairedSensorError("public attacker CNF hash differs")
    if sha256_file(semantic_map) != config.source.semantic_map_sha256:
        raise Full256PairedSensorError("semantic map hash differs")
    manifest_path = source_capsule / "artifacts.sha256"
    if sha256_file(manifest_path) != config.source.manifest_sha256:
        raise Full256PairedSensorError("source capsule manifest hash differs")

    native_source = root / "native/cadical_pair_sensor.cpp"
    tracer_header = root / "native/cadical_tracer_3_0_0.hpp"
    executable = workspace / "cadical_pair_sensor"
    build = build_native_sensor(
        source=native_source,
        tracer_header=tracer_header,
        cadical_include=config.native.include_directory,
        cadical_library=config.native.static_library,
        output=executable,
        expected_cadical_header_sha256=(
            config.native.cadical_header_sha256
        ),
        expected_cadical_library_sha256=(
            config.native.cadical_library_sha256
        ),
        compiler=config.native.compiler,
    )
    provenance = ClauseProvenanceIndex.load(public_cnf, semantic_map)
    if (
        provenance.variable_count != config.source.expected_variable_count
        or provenance.clause_count != config.source.expected_clause_count
    ):
        raise Full256PairedSensorError("public CNF dimensions differ")
    rss_milestones["native_build_and_provenance_loaded"] = _peak_rss_bytes()

    horizons = config.state_plan.horizons
    costs = np.empty((len(horizons), KEY_BITS, 2), dtype=np.float64)
    motif_delta = np.empty(
        (len(horizons), KEY_BITS, MOTIF_DIMENSIONS), dtype=np.float32
    )
    key_touch_delta = np.empty(
        (len(horizons), KEY_BITS, KEY_BITS), dtype=np.float32
    )
    information_mass = np.empty((len(horizons), KEY_BITS), dtype=np.float64)
    pair_hashes: list[str] = []
    event_index: list[dict[str, object]] = []
    sentinel_report: dict[str, object] | None = None
    sentinel_pair_hash: str | None = None
    native_cpu_microseconds = 0
    native_peak_rss_bytes = 0
    final_overshoots: list[int] = []
    frontier_event_gaps: list[int] = []
    stream = iter_native_probe_records(
        executable=build.executable,
        cnf_path=public_cnf,
        first_bit=config.probe.first_bit,
        last_bit=config.probe.last_bit,
        conflict_limit=config.probe.conflict_horizon,
        seed=config.probe.seed,
        timeout_seconds=config.probe.timeout_seconds,
    )
    header, pairs = paired_records(iter(stream))
    if (
        header.variables != provenance.variable_count
        or header.original_clause_count != provenance.clause_count
    ):
        raise Full256PairedSensorError("native stream and provenance differ")
    baseline_sha256 = canonical_sha256(
        [_proof_event_commitment_payload(event) for event in header.baseline_events]
    )

    for zero, one in pairs:
        if zero.status != 0 or one.status != 0:
            raise Full256PairedSensorError(
                "paired sensor reached SAT/UNSAT before the frozen horizon"
            )
        pair_sha = pair_commitment(zero, one)
        pair_hashes.append(pair_sha)
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
        bit = zero.bit_index
        row: dict[str, object] = {
            "bit_index": bit,
            "pair_sha256": pair_sha,
            "branches": {
                "0": zero.deterministic_sha256,
                "1": one.deterministic_sha256,
            },
            "horizons": [],
        }
        for horizon_index, horizon in enumerate(horizons):
            zero_summary = zero_summaries[horizon]
            one_summary = one_summaries[horizon]
            costs[horizon_index, bit, 0] = branch_difficulty(zero_summary)
            costs[horizon_index, bit, 1] = branch_difficulty(one_summary)
            motif = one_summary.motif - zero_summary.motif
            touches = one_summary.key_touch - zero_summary.key_touch
            motif_delta[horizon_index, bit] = motif
            key_touch_delta[horizon_index, bit] = touches
            telemetry_delta = math.fsum(
                abs(
                    math.log1p(getattr(one_summary.snapshot, field))
                    - math.log1p(getattr(zero_summary.snapshot, field))
                )
                for field in ("decisions", "propagations", "ticks")
            )
            information_mass[horizon_index, bit] = (
                telemetry_delta
                + float(np.abs(motif).sum())
                + float(np.abs(touches).sum())
            )
            frontier_event_gaps.extend(
                (
                    zero_summary.frontier_event_gap,
                    one_summary.frontier_event_gap,
                )
            )
            row["horizons"].append(
                {
                    "horizon": horizon,
                    "zero_summary_sha256": zero_summary.summary_sha256,
                    "one_summary_sha256": one_summary.summary_sha256,
                    "zero_difficulty": costs[horizon_index, bit, 0],
                    "one_difficulty": costs[horizon_index, bit, 1],
                    "zero_last_event_conflict": zero_summary.snapshot.conflicts,
                    "one_last_event_conflict": one_summary.snapshot.conflicts,
                    "zero_frontier_event_gap": zero_summary.frontier_event_gap,
                    "one_frontier_event_gap": one_summary.frontier_event_gap,
                    "zero_exact_conflict_event_present": (
                        zero_summary.exact_conflict_event_present
                    ),
                    "one_exact_conflict_event_present": (
                        one_summary.exact_conflict_event_present
                    ),
                    "motif_delta_l1": float(np.abs(motif).sum()),
                    "key_touch_delta_l1": float(np.abs(touches).sum()),
                    "information_mass": information_mass[horizon_index, bit],
                }
            )
        event_index.append(row)
        for record in (zero, one):
            native_cpu_microseconds += record.resources[
                "solver_cpu_microseconds"
            ]
            native_peak_rss_bytes = max(
                native_peak_rss_bytes,
                record.resources["solver_peak_rss_bytes"],
            )
            final_overshoots.append(record.final_overshoot_conflicts)
        if bit == config.probe.sentinel_bit:
            sentinel_pair_hash = pair_sha
            sentinel_report = {
                "bit_index": bit,
                "pair_sha256": pair_sha,
                "zero": {
                    "record_sha256": zero.deterministic_sha256,
                    "final_stats": dict(zero.stats),
                    "prefixes": {
                        str(horizon): zero_summaries[horizon].describe()
                        for horizon in horizons
                    },
                },
                "one": {
                    "record_sha256": one.deterministic_sha256,
                    "final_stats": dict(one.stats),
                    "prefixes": {
                        str(horizon): one_summaries[horizon].describe()
                        for horizon in horizons
                    },
                },
            }

    if len(pair_hashes) != KEY_BITS or sentinel_report is None:
        raise Full256PairedSensorError("full 256-bit pair coverage is incomplete")
    rss_milestones["all_probe_prefixes_reduced"] = _peak_rss_bytes()
    stream_sha256 = canonical_sha256(
        {
            "baseline_sha256": baseline_sha256,
            "pair_hashes": pair_hashes,
            "horizons": list(horizons),
        }
    )
    quantiles = np.empty_like(costs)
    unary_scores = np.empty((len(horizons), KEY_BITS), dtype=np.float64)
    for horizon_index in range(len(horizons)):
        quantiles[horizon_index] = _midrank_quantiles(costs[horizon_index])
        unary_scores[horizon_index] = (
            quantiles[horizon_index, :, 0] ** 3
            - quantiles[horizon_index, :, 1] ** 3
        )

    direct = CausalBitfieldAccumulator(config.state_plan)
    swapped = CausalBitfieldAccumulator(config.state_plan)
    for bit in range(KEY_BITS):
        pair_sha = pair_hashes[bit]
        for horizon_index, horizon in enumerate(horizons):
            event = PairedCausalEvent(
                bit_index=bit,
                horizon=horizon,
                unary_score=float(unary_scores[horizon_index, bit]),
                information_mass=float(information_mass[horizon_index, bit]),
                motif_delta=motif_delta[horizon_index, bit],
                key_touch_delta=key_touch_delta[horizon_index, bit],
                source_pair_sha256=pair_sha,
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
                    source_pair_sha256=pair_sha,
                )
            )
    frozen = direct.freeze(source_stream_sha256=stream_sha256)
    swapped_frozen = swapped.freeze(source_stream_sha256=stream_sha256)
    swap_control = state_swap_control(frozen, swapped_frozen)
    if len(frozen.to_bytes()) > config.maximum_state_bytes:
        raise Full256PairedSensorError("frozen O1 state exceeds byte budget")
    rss_milestones["bounded_states_frozen"] = _peak_rss_bytes()

    # The known RFC key is first accessed here, after state serialization and
    # polarity-swap controls are frozen.  It never enters a solver probe.
    known_diagnostic = _known_key_diagnostic(
        state=frozen, diagnostic=config.diagnostic
    )
    rss_milestones["known_key_diagnostic_complete"] = _peak_rss_bytes()

    sentinel_reruns: list[dict[str, object]] = []
    for rerun in range(config.probe.deterministic_sentinel_reruns):
        rerun_stream = iter_native_probe_records(
            executable=build.executable,
            cnf_path=public_cnf,
            first_bit=config.probe.sentinel_bit,
            last_bit=config.probe.sentinel_bit,
            conflict_limit=config.probe.conflict_horizon,
            seed=config.probe.seed,
            timeout_seconds=config.probe.timeout_seconds,
        )
        rerun_header, rerun_pairs = paired_records(iter(rerun_stream))
        try:
            rerun_zero, rerun_one = next(rerun_pairs)
        except StopIteration as exc:  # pragma: no cover
            raise Full256PairedSensorError("sentinel rerun is empty") from exc
        if next(rerun_pairs, None) is not None:
            raise Full256PairedSensorError("sentinel rerun contains extra pairs")
        rerun_pair_sha = pair_commitment(rerun_zero, rerun_one)
        rerun_baseline_sha = canonical_sha256(
            [
                _proof_event_commitment_payload(event)
                for event in rerun_header.baseline_events
            ]
        )
        sentinel_reruns.append(
            {
                "rerun": rerun,
                "pair_sha256": rerun_pair_sha,
                "baseline_sha256": rerun_baseline_sha,
                "matches_full_sweep_pair": rerun_pair_sha == sentinel_pair_hash,
                "matches_full_sweep_baseline": rerun_baseline_sha
                == baseline_sha256,
            }
        )
        for record in (rerun_zero, rerun_one):
            native_cpu_microseconds += record.resources[
                "solver_cpu_microseconds"
            ]
            native_peak_rss_bytes = max(
                native_peak_rss_bytes,
                record.resources["solver_peak_rss_bytes"],
            )
    rss_milestones["sentinel_replay_complete"] = _peak_rss_bytes()

    source_unchanged = (
        sha256_file(public_cnf) == config.source.public_instance_sha256
        and sha256_file(semantic_map) == config.source.semantic_map_sha256
        and sha256_file(manifest_path) == config.source.manifest_sha256
    )
    deterministic_gate = all(
        row["matches_full_sweep_pair"] and row["matches_full_sweep_baseline"]
        for row in sentinel_reruns
    )
    closed_prefixes = all(
        row["horizons"][index]["horizon"] == horizon
        for row in event_index
        for index, horizon in enumerate(horizons)
    )
    state_description = frozen.describe()
    wall_seconds = time.monotonic() - wall_started
    parent_cpu_seconds = time.process_time() - parent_cpu_started
    children_finished = resource.getrusage(resource.RUSAGE_CHILDREN)
    process_child_cpu_seconds = max(
        0.0,
        (children_finished.ru_utime + children_finished.ru_stime)
        - (children_started.ru_utime + children_started.ru_stime),
    )
    native_child_cpu_seconds = native_cpu_microseconds / 1_000_000.0
    budgeted_cpu_seconds = parent_cpu_seconds + max(
        native_child_cpu_seconds, process_child_cpu_seconds
    )
    process_peak_rss_bytes = _peak_rss_bytes()
    max_single_process_peak_rss_bytes = max(
        process_peak_rss_bytes, native_peak_rss_bytes
    )
    conservative_process_group_peak_rss_bytes = (
        process_peak_rss_bytes + 2 * native_peak_rss_bytes
    )
    total_native_branches = 2 * len(pair_hashes) + 2 * len(sentinel_reruns)
    resource_budget_gates = {
        "cpu_under_budget": budgeted_cpu_seconds
        <= config.budgets.maximum_cpu_seconds,
        "wall_under_budget": wall_seconds
        <= config.budgets.maximum_wall_seconds,
        "resident_memory_under_budget": conservative_process_group_peak_rss_bytes
        <= config.budgets.maximum_resident_memory_mib * 1024 * 1024,
        "native_branch_count_under_budget": total_native_branches
        <= config.budgets.maximum_native_solver_branches,
        "zero_mps_calls_under_budget": 0 <= config.budgets.maximum_mps_calls,
        "zero_gpu_calls_under_budget": 0 <= config.budgets.maximum_gpu_calls,
        "zero_sibling_reads_under_budget": 0
        <= config.budgets.maximum_sibling_reads,
        "zero_sibling_writes_under_budget": 0
        <= config.budgets.maximum_sibling_writes,
        "zero_fresh_targets_under_budget": 0
        <= config.budgets.maximum_fresh_random_targets,
    }
    gates = {
        "source_capsule_unchanged": source_unchanged,
        "full_256_bit_pair_coverage": len(pair_hashes) == KEY_BITS,
        "all_768_closed_proof_prefixes_present": closed_prefixes,
        "deterministic_sentinel_replay": deterministic_gate,
        "polarity_swap_antisymmetry": swap_control["passed"],
        "bounded_state_under_budget": len(frozen.to_bytes())
        <= config.maximum_state_bytes,
        "state_has_unary_signal": state_description["unary_nonzero"] > 0,
        "state_has_interaction_signal": state_description[
            "interaction_nonzero"
        ]
        > 0,
        "state_has_holographic_signal": state_description[
            "holographic_nonzero"
        ]
        > 0,
        "known_key_recomputes_public_output": known_diagnostic[
            "configured_known_key_recomputes_public_output"
        ],
        **resource_budget_gates,
    }
    gates["success_gate_passed"] = all(gates.values())
    resources = {
        "native_child_cpu_seconds": native_child_cpu_seconds,
        "process_child_cpu_seconds": process_child_cpu_seconds,
        "parent_cpu_seconds": parent_cpu_seconds,
        "budgeted_cpu_seconds": budgeted_cpu_seconds,
        "core_wall_seconds": wall_seconds,
        "wall_seconds": wall_seconds,
        "native_child_peak_rss_bytes": native_peak_rss_bytes,
        "native_parent_peak_rss_estimate_bytes": native_peak_rss_bytes,
        "process_peak_rss_bytes": process_peak_rss_bytes,
        "max_single_process_peak_rss_bytes": max_single_process_peak_rss_bytes,
        "conservative_process_group_peak_rss_bytes": (
            conservative_process_group_peak_rss_bytes
        ),
        "peak_rss_bytes": conservative_process_group_peak_rss_bytes,
        "rss_accounting": (
            "conservative sum of Python peak plus one native-parent and one "
            "fork-child peak; shared COW pages may be double-counted"
        ),
        "process_rss_milestones_bytes": rss_milestones,
        "native_solver_branches": total_native_branches,
        "native_final_conflict_overshoot_min": min(final_overshoots),
        "native_final_conflict_overshoot_max": max(final_overshoots),
        "native_final_conflict_overshoot_mean": float(
            np.mean(final_overshoots)
        ),
        "evidence_frontier_uses_overshoot_tail": False,
        "sibling_reads": 0,
        "sibling_writes": 0,
        "mps_calls": 0,
        "gpu_calls": 0,
        "fresh_random_targets": 0,
    }
    event_document = {
        "schema": EVENT_INDEX_SCHEMA,
        "source_stream_sha256": stream_sha256,
        "baseline_sha256": baseline_sha256,
        "paired_bits": len(event_index),
        "horizons": list(horizons),
        "rows": event_index,
    }
    event_document["event_index_sha256"] = canonical_sha256(event_document)
    unsigned_report = {
        "schema": RESULT_SCHEMA,
        "attacker_contract": {
            "cipher": "ChaCha20",
            "rounds": 20,
            "unknown_key_bits": 256,
            "public_inputs": ["counter", "nonce", "512-bit block output"],
            "target_internal_trace_inputs": 0,
            "key_unit_clauses": 0,
            "solver_assumptions_per_branch": 1,
            "known_key_access_phase": (
                "POST_STATE_FREEZE_KNOWN_KEY_DIAGNOSTIC_ONLY"
            ),
        },
        "source": {
            "capsule": config.source.capsule,
            "manifest_sha256": config.source.manifest_sha256,
            "public_instance_sha256": provenance.cnf_sha256,
            "semantic_map_file_sha256": provenance.map_sha256,
            "provenance": provenance.describe(),
        },
        "native_build": build.describe(),
        "probe_stream": {
            "cadical_version": header.cadical_version,
            "branch_isolation": header.branch_isolation,
            "public_baseline_event_count": len(header.baseline_events),
            "public_baseline_sha256": baseline_sha256,
            "paired_bit_count": len(pair_hashes),
            "branch_count": 2 * len(pair_hashes),
            "horizons": list(horizons),
            "proof_frontier_count": len(horizons) * 2 * len(pair_hashes),
            "exact_conflict_event_prefix_count": sum(
                gap == 0 for gap in frontier_event_gaps
            ),
            "frontier_event_gap_min": min(frontier_event_gaps),
            "frontier_event_gap_max": max(frontier_event_gaps),
            "frontier_event_gap_mean": float(np.mean(frontier_event_gaps)),
            "prefix_contract": (
                "complete closed proof-event prefix at conflicts <= horizon; "
                "last-event gap is explicit and no solver counters are fabricated"
            ),
            "source_stream_sha256": stream_sha256,
            "sentinel_replays": sentinel_reruns,
            "final_conflict_tail_is_billed_but_excluded": True,
        },
        "state": state_description,
        "polarity_swap_control": swap_control,
        "known_key_diagnostic": known_diagnostic,
        "resources": resources,
        "gates": gates,
        "claim_boundary": {
            "inverse_signal_claimed": False,
            "cross_key_transfer_claimed": False,
            "full_width_causal_sensor_validated": gates[
                "success_gate_passed"
            ],
            "negative_or_positive_known_key_diagnostic_is_a_breadcrumb": True,
        },
    }
    report = {**unsigned_report, "result_sha256": ""}
    state_binary = frozen.to_bytes()
    artifacts = {
        "causal_bitfield.bin": state_binary,
        "causal_bitfield.json": canonical_json_bytes(state_description),
        "paired_event_index.json": canonical_json_bytes(event_document),
        "sentinel_bit.json": canonical_json_bytes(sentinel_report),
        "known_key_diagnostic.json": canonical_json_bytes(known_diagnostic),
        "native_build.json": canonical_json_bytes(build.describe()),
    }
    for _ in range(2):
        end_to_end_wall_seconds = time.monotonic() - wall_started
        wall_gate = (
            end_to_end_wall_seconds <= config.budgets.maximum_wall_seconds
        )
        resources["wall_seconds"] = end_to_end_wall_seconds
        resource_budget_gates["wall_under_budget"] = wall_gate
        gates["wall_under_budget"] = wall_gate
        gates["success_gate_passed"] = all(
            passed
            for name, passed in gates.items()
            if name != "success_gate_passed"
        )
        report["result_sha256"] = canonical_sha256(unsigned_report)
        artifacts["full256_paired_sensor.json"] = canonical_json_bytes(report)
    persistent_artifact_bytes = sum(len(payload) for payload in artifacts.values())
    if persistent_artifact_bytes > (
        config.budgets.maximum_persistent_artifact_bytes
    ):
        raise Full256PairedSensorError(
            "paired sensor artifacts exceed persistent-byte budget"
        )
    if not all(resource_budget_gates.values()):
        failed = sorted(
            name for name, passed in resource_budget_gates.items() if not passed
        )
        raise Full256PairedSensorError(
            "paired sensor resource budget exceeded: "
            + ", ".join(failed)
            + f"; cpu={budgeted_cpu_seconds:.6f}s"
            + f" wall={resources['wall_seconds']:.6f}s"
            + f" conservative_rss={conservative_process_group_peak_rss_bytes}B"
        )
    return Full256PairedSensorResult(report=report, artifacts=artifacts)
