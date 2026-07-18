#!/usr/bin/env python3
"""Bounded full-256 tests of a feed-forward fixed-point view of ChaCha20.

The search functions receive only a public counter, nonce and one output block.
The deterministic build harness retains the generated secret solely to score
distance and directional information after each public-only search decision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import resource
import statistics
import struct
import sys
import time
import tracemalloc
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence


MASK32 = (1 << 32) - 1
MASK256 = (1 << 256) - 1
CONSTANT_WORDS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
DEFAULT_SEED = "apple-view-full256-v1-20260719"
RFC_KEY = bytes(range(32))
RFC_NONCE = bytes.fromhex("000000090000004a00000000")
RFC_BLOCK = bytes.fromhex(
    "10f1e7e4d13b5915500fdd1fa32071c4"
    "c7d1f4c733c068030422aa9ac3d46c4e"
    "d2826446079faa0914c2d705d98b02a2"
    "b5129cd1de164eb9cbd083e8a2503c4e"
)
APPLE_VIEW_DIR = Path(__file__).resolve().parent


def _rotl32(value: int, distance: int) -> int:
    return ((value << distance) & MASK32) | (value >> (32 - distance))


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl32(state[b] ^ state[c], 7)


def _initial_words(key: bytes, counter: int, nonce: bytes) -> tuple[int, ...]:
    if len(key) != 32:
        raise ValueError("key must be exactly 32 bytes")
    if not 0 <= counter <= MASK32:
        raise ValueError("counter must be uint32")
    if len(nonce) != 12:
        raise ValueError("nonce must be exactly 12 bytes")
    return (
        *CONSTANT_WORDS,
        *struct.unpack("<8I", key),
        counter,
        *struct.unpack("<3I", nonce),
    )


def chacha20_permutation_words(
    key: bytes, counter: int, nonce: bytes
) -> tuple[int, ...]:
    """Return the 20-round state before ChaCha's final feed-forward addition."""

    state = list(_initial_words(key, counter, nonce))
    for _ in range(10):
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)
    return tuple(state)


def chacha20_block_raw(key: bytes, counter: int, nonce: bytes) -> bytes:
    initial = _initial_words(key, counter, nonce)
    final = chacha20_permutation_words(key, counter, nonce)
    return struct.pack(
        "<16I", *((left + right) & MASK32 for left, right in zip(final, initial))
    )


@dataclass
class EvaluationMeter:
    permutation_evaluations: int = 0
    lean_block_evaluations: int = 0
    project_helper_block_evaluations: int = 0

    @property
    def lean_permutation_only_evaluations(self) -> int:
        return self.permutation_evaluations - self.lean_block_evaluations

    @property
    def total_chacha20_core_permutation_evaluations(self) -> int:
        return self.permutation_evaluations + self.project_helper_block_evaluations

    def permutation(self, key: bytes, counter: int, nonce: bytes) -> tuple[int, ...]:
        self.permutation_evaluations += 1
        return chacha20_permutation_words(key, counter, nonce)

    def block(self, key: bytes, counter: int, nonce: bytes) -> bytes:
        self.lean_block_evaluations += 1
        initial = _initial_words(key, counter, nonce)
        final = self.permutation(key, counter, nonce)
        return struct.pack(
            "<16I",
            *((left + right) & MASK32 for left, right in zip(final, initial)),
        )


@dataclass(frozen=True)
class PublicTarget:
    counter: int
    nonce: bytes
    block: bytes


@dataclass(frozen=True)
class GeneratedCase:
    case_id: int
    target: PublicTarget
    secret_key: bytes


@dataclass(frozen=True)
class ExperimentConfig:
    seed: str = DEFAULT_SEED
    targets: int = 32
    projection_starts: int = 4
    projection_steps: int = 24
    coordinate_targets: int = 6
    coordinate_steps: int = 6

    def validate(self) -> None:
        if self.targets < 4:
            raise ValueError("targets must be at least 4 for a holdout split")
        if self.projection_starts < 1:
            raise ValueError("projection_starts must be positive")
        if self.projection_steps < 1:
            raise ValueError("projection_steps must be positive")
        if not 0 <= self.coordinate_targets <= self.targets:
            raise ValueError("coordinate_targets must be in [0, targets]")
        if self.coordinate_steps < 0:
            raise ValueError("coordinate_steps must be non-negative")


def _derive(seed: str, label: str, indices: Sequence[int], length: int) -> bytes:
    shake = hashlib.shake_256()
    shake.update(seed.encode("utf-8"))
    shake.update(b"\x00")
    shake.update(label.encode("ascii"))
    for index in indices:
        shake.update(index.to_bytes(8, "little", signed=False))
    return shake.digest(length)


def generate_cases(
    config: ExperimentConfig, meter: EvaluationMeter
) -> list[GeneratedCase]:
    cases: list[GeneratedCase] = []
    for case_id in range(config.targets):
        key = _derive(config.seed, "target-key", (case_id,), 32)
        nonce = _derive(config.seed, "target-nonce", (case_id,), 12)
        counter = int.from_bytes(
            _derive(config.seed, "target-counter", (case_id,), 4), "little"
        )
        block = meter.block(key, counter, nonce)
        cases.append(
            GeneratedCase(case_id, PublicTarget(counter, nonce, block), key)
        )
    return cases


def generated_start(config: ExperimentConfig, case_id: int, start_id: int) -> bytes:
    return _derive(config.seed, "search-start", (case_id, start_id), 32)


def key_hamming(left: bytes, right: bytes) -> int:
    return (int.from_bytes(left, "little") ^ int.from_bytes(right, "little")).bit_count()


def block_hamming(left: bytes, right: bytes) -> int:
    return (int.from_bytes(left, "little") ^ int.from_bytes(right, "little")).bit_count()


def project_key(
    target: PublicTarget, candidate: bytes, meter: EvaluationMeter
) -> bytes:
    """Apply F_y(k); this function has no access to a generated secret key."""

    target_words = struct.unpack("<16I", target.block)
    final_words = meter.permutation(candidate, target.counter, target.nonce)
    projected = tuple(
        (target_words[index] - final_words[index]) & MASK32
        for index in range(4, 12)
    )
    return struct.pack("<8I", *projected)


def public_fitness(
    target: PublicTarget, candidate: bytes, meter: EvaluationMeter
) -> int:
    return block_hamming(
        meter.block(candidate, target.counter, target.nonce), target.block
    )


UPDATE_MASKS: dict[str, int] = {
    "full": MASK256,
    "even_bits": int.from_bytes(bytes([0x55]) * 32, "little"),
    "odd_bits": int.from_bytes(bytes([0xAA]) * 32, "little"),
    "low16_each_word": int.from_bytes(bytes([0xFF, 0xFF, 0x00, 0x00]) * 8, "little"),
    "high16_each_word": int.from_bytes(bytes([0x00, 0x00, 0xFF, 0xFF]) * 8, "little"),
}


def apply_update_mask(candidate: bytes, projected: bytes, mask: int) -> bytes:
    current_int = int.from_bytes(candidate, "little")
    projected_int = int.from_bytes(projected, "little")
    updated = current_int ^ ((current_int ^ projected_int) & mask)
    return updated.to_bytes(32, "little")


def _mean_ci(
    values: Sequence[float], null: float | None = None
) -> dict[str, float | None]:
    if not values:
        result: dict[str, float | None] = {
            "mean": None,
            "ci95_low": None,
            "ci95_high": None,
        }
        if null is not None:
            result["null"] = null
            result["mean_minus_null"] = None
        return result
    mean = statistics.fmean(values)
    if len(values) == 1:
        ci_low = None
        ci_high = None
    else:
        half_width = 1.96 * statistics.stdev(values) / math.sqrt(len(values))
        ci_low = mean - half_width
        ci_high = mean + half_width
    result = {
        "mean": mean,
        "ci95_low": ci_low,
        "ci95_high": ci_high,
    }
    if null is not None:
        result["null"] = null
        result["mean_minus_null"] = mean - null
    return result


def _target_clustered_ci(
    rows: Sequence[dict[str, object]],
    value,
    null: float | None = None,
) -> dict[str, float | int | None]:
    grouped: dict[int, list[float]] = {}
    for row in rows:
        grouped.setdefault(int(row["case_id"]), []).append(float(value(row)))
    result: dict[str, float | int | None] = _mean_ci(
        [statistics.fmean(group) for group in grouped.values()], null
    )
    result["target_clusters"] = len(grouped)
    result["observations"] = len(rows)
    return result


def _auc(scores: Sequence[int], labels: Sequence[int]) -> float:
    positive = sum(labels)
    negative = len(labels) - positive
    if positive == 0 or negative == 0:
        return math.nan
    ordered = sorted(zip(scores, labels, strict=True), key=lambda pair: pair[0])
    positive_rank_sum = 0.0
    position = 0
    while position < len(ordered):
        end = position + 1
        while end < len(ordered) and ordered[end][0] == ordered[position][0]:
            end += 1
        average_rank = ((position + 1) + end) / 2.0
        positive_rank_sum += average_rank * sum(
            label for _, label in ordered[position:end]
        )
        position = end
    return (
        positive_rank_sum - positive * (positive + 1) / 2.0
    ) / (positive * negative)


def _mutual_information(contingency: dict[tuple[int, int], int]) -> float:
    total = sum(contingency.values())
    if total == 0:
        return math.nan
    label_totals = {
        label: sum(count for (row_label, _), count in contingency.items() if row_label == label)
        for label in (0, 1)
    }
    sign_totals = {
        sign: sum(count for (_, row_sign), count in contingency.items() if row_sign == sign)
        for sign in (-1, 0, 1)
    }
    information = 0.0
    for (label, sign), count in contingency.items():
        if count == 0:
            continue
        joint = count / total
        independent = (label_totals[label] / total) * (sign_totals[sign] / total)
        information += joint * math.log2(joint / independent)
    return information


def _summarize_projection(rows: Sequence[dict[str, object]]) -> dict[str, object]:
    variants: dict[str, object] = {}
    for name in UPDATE_MASKS:
        variants[name] = {
            "key_distance_bits": _target_clustered_ci(
                rows,
                lambda row: row["variant_distances"][name],  # type: ignore[index]
                128.0,
            ),
            "distance_improvement_bits": _target_clustered_ci(
                rows,
                lambda row: float(row["start_distance"])
                - float(row["variant_distances"][name]),  # type: ignore[index]
                0.0,
            ),
            "exact_secret_keys": sum(
                int(row["variant_distances"][name]) == 0 for row in rows  # type: ignore[index]
            ),
        }
    return {
        "observations": len(rows),
        "target_clusters": len({int(row["case_id"]) for row in rows}),
        "start_key_distance_bits": _target_clustered_ci(
            rows, lambda row: row["start_distance"], 128.0
        ),
        "variants": variants,
        "public_selector_advantage_over_uniform_choice_bits": _target_clustered_ci(
            rows, lambda row: row["selector_advantage_bits"], 0.0
        ),
        "public_selector_exact_secret_keys": sum(
            int(row["selected_distance"]) == 0 for row in rows
        ),
    }


def projection_diagnostics(
    cases: Sequence[GeneratedCase],
    config: ExperimentConfig,
    meter: EvaluationMeter,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    rows: list[dict[str, object]] = []
    for case in cases:
        for start_id in range(config.projection_starts):
            start = generated_start(config, case.case_id, start_id)
            projected = project_key(case.target, start, meter)
            candidates = {
                name: apply_update_mask(start, projected, mask)
                for name, mask in UPDATE_MASKS.items()
            }
            start_fitness = public_fitness(case.target, start, meter)
            variant_fitness = {
                name: public_fitness(case.target, candidate, meter)
                for name, candidate in candidates.items()
            }
            variant_distances = {
                name: key_hamming(candidate, case.secret_key)
                for name, candidate in candidates.items()
            }
            all_distances = [key_hamming(start, case.secret_key), *variant_distances.values()]
            choices = [("start", start_fitness), *variant_fitness.items()]
            selected_name, _ = min(choices, key=lambda pair: (pair[1], pair[0]))
            selected_distance = (
                all_distances[0]
                if selected_name == "start"
                else variant_distances[selected_name]
            )
            rows.append(
                {
                    "case_id": case.case_id,
                    "start_id": start_id,
                    "split": "train" if case.case_id < config.targets // 2 else "holdout",
                    "start_distance": all_distances[0],
                    "variant_distances": variant_distances,
                    "start_fitness": start_fitness,
                    "variant_fitness": variant_fitness,
                    "selected_name": selected_name,
                    "selected_distance": selected_distance,
                    "selector_advantage_bits": statistics.fmean(all_distances)
                    - selected_distance,
                }
            )
    train = [row for row in rows if row["split"] == "train"]
    holdout = [row for row in rows if row["split"] == "holdout"]
    return {
        "all": _summarize_projection(rows),
        "train": _summarize_projection(train),
        "holdout": _summarize_projection(holdout),
    }, rows


def _landscape_row(
    case: GeneratedCase,
    candidate: bytes,
    meter: EvaluationMeter,
) -> dict[str, object]:
    base_fitness = public_fitness(case.target, candidate, meter)
    candidate_int = int.from_bytes(candidate, "little")
    secret_int = int.from_bytes(case.secret_key, "little")
    scores: list[int] = []
    labels: list[int] = []
    flip_fitness: list[int] = []
    for bit in range(256):
        flipped = (candidate_int ^ (1 << bit)).to_bytes(32, "little")
        fitness = public_fitness(case.target, flipped, meter)
        flip_fitness.append(fitness)
        scores.append(base_fitness - fitness)
        labels.append((candidate_int ^ secret_int) >> bit & 1)
    correct = 0.0
    contingency = {(label, sign): 0 for label in (0, 1) for sign in (-1, 0, 1)}
    for score, label in zip(scores, labels, strict=True):
        sign = (score > 0) - (score < 0)
        contingency[(label, sign)] += 1
        if score == 0:
            correct += 0.5
        elif (score > 0) == bool(label):
            correct += 1.0
    ranked_bits = sorted(range(256), key=lambda bit: (-scores[bit], bit))
    best_bit = ranked_bits[0]
    return {
        "case_id": case.case_id,
        "base_fitness": base_fitness,
        "base_key_distance": sum(labels),
        "auc": _auc(scores, labels),
        "direction_accuracy_ties_half": correct / 256.0,
        "tie_fraction": sum(score == 0 for score in scores) / 256.0,
        "top1_is_wrong_bit": labels[best_bit],
        "top8_wrong_fraction": statistics.fmean(labels[bit] for bit in ranked_bits[:8]),
        "top32_wrong_fraction": statistics.fmean(labels[bit] for bit in ranked_bits[:32]),
        "best_flip_fitness_delta": base_fitness - flip_fitness[best_bit],
        "contingency": {f"{label}:{sign}": count for (label, sign), count in contingency.items()},
    }


def _summarize_landscape(rows: Sequence[dict[str, object]]) -> dict[str, object]:
    pooled = {(label, sign): 0 for label in (0, 1) for sign in (-1, 0, 1)}
    for row in rows:
        for label in (0, 1):
            for sign in (-1, 0, 1):
                pooled[(label, sign)] += int(row["contingency"][f"{label}:{sign}"])  # type: ignore[index]
    return {
        "observations": len(rows),
        "bits_scored": 256 * len(rows),
        "base_wrong_bit_fraction": _mean_ci(
            [float(row["base_key_distance"]) / 256.0 for row in rows], 0.5
        ),
        "direction_accuracy_ties_half": _mean_ci(
            [float(row["direction_accuracy_ties_half"]) for row in rows], 0.5
        ),
        "auc_for_wrong_bit": _mean_ci([float(row["auc"]) for row in rows], 0.5),
        "fitness_tie_fraction": _mean_ci(
            [float(row["tie_fraction"]) for row in rows]
        ),
        "top1_wrong_bit_fraction": _mean_ci(
            [float(row["top1_is_wrong_bit"]) for row in rows], 0.5
        ),
        "top8_wrong_bit_fraction": _mean_ci(
            [float(row["top8_wrong_fraction"]) for row in rows], 0.5
        ),
        "top32_wrong_bit_fraction": _mean_ci(
            [float(row["top32_wrong_fraction"]) for row in rows], 0.5
        ),
        "empirical_mutual_information_label_vs_fitness_sign_bits": _mutual_information(
            pooled
        ),
        "pooled_contingency": {
            f"label_{label}_sign_{sign}": count
            for (label, sign), count in pooled.items()
        },
    }


def landscape_diagnostics(
    cases: Sequence[GeneratedCase], config: ExperimentConfig, meter: EvaluationMeter
) -> tuple[dict[str, object], list[dict[str, object]]]:
    rows = [
        _landscape_row(
            case, generated_start(config, case.case_id, config.projection_starts), meter
        )
        for case in cases
    ]
    train = [row for row in rows if int(row["case_id"]) < config.targets // 2]
    holdout = [row for row in rows if int(row["case_id"]) >= config.targets // 2]
    return {
        "all": _summarize_landscape(rows),
        "train": _summarize_landscape(train),
        "holdout": _summarize_landscape(holdout),
    }, rows


def projection_chain_search(
    target: PublicTarget,
    start: bytes,
    steps: int,
    meter: EvaluationMeter,
) -> tuple[bytes, int, int]:
    """Public-only fixed-point chain, returning its best photographed match."""

    current = start
    best = current
    best_fitness = public_fitness(target, current, meter)
    visited = {current}
    executed = 0
    for _ in range(steps):
        current = project_key(target, current, meter)
        executed += 1
        fitness = public_fitness(target, current, meter)
        if (fitness, current) < (best_fitness, best):
            best, best_fitness = current, fitness
        if fitness == 0 or current in visited:
            break
        visited.add(current)
    return best, best_fitness, executed


def coordinate_greedy_search(
    target: PublicTarget,
    start: bytes,
    steps: int,
    meter: EvaluationMeter,
) -> tuple[bytes, int, int]:
    """Public-only best one-bit descent over all 256 unknown key bits."""

    current = start
    current_int = int.from_bytes(current, "little")
    current_fitness = public_fitness(target, current, meter)
    executed = 0
    for _ in range(steps):
        best_int = current_int
        best_fitness = current_fitness
        for bit in range(256):
            trial_int = current_int ^ (1 << bit)
            trial = trial_int.to_bytes(32, "little")
            fitness = public_fitness(target, trial, meter)
            if (fitness, trial_int) < (best_fitness, best_int):
                best_int, best_fitness = trial_int, fitness
        if best_fitness >= current_fitness:
            break
        current_int, current_fitness = best_int, best_fitness
        executed += 1
        if current_fitness == 0:
            break
    return current_int.to_bytes(32, "little"), current_fitness, executed


def _project_helper_block(
    key: bytes, counter: int, nonce: bytes, meter: EvaluationMeter
) -> bytes:
    repo_root = Path(__file__).resolve().parents[2]
    source = str(repo_root / "src")
    if source not in sys.path:
        sys.path.insert(0, source)
    from o1_crypto_lab.chacha_trace import chacha20_block as project_chacha20_block

    meter.project_helper_block_evaluations += 1
    return project_chacha20_block(key, counter, nonce)


def _cross_check_project_helper(
    cases: Sequence[GeneratedCase], meter: EvaluationMeter
) -> int:
    if _project_helper_block(RFC_KEY, 1, RFC_NONCE, meter) != RFC_BLOCK:
        raise AssertionError("project helper does not reproduce the RFC vector")
    for case in cases:
        expected = _project_helper_block(
            case.secret_key, case.target.counter, case.target.nonce, meter
        )
        if expected != case.target.block:
            raise AssertionError(f"project helper mismatch for case {case.case_id}")
    return len(cases) + 1


def _verify_candidate(
    case: GeneratedCase,
    candidate: bytes,
    claimed_fitness: int,
    meter: EvaluationMeter,
) -> tuple[bool, bool]:
    raw_match = (
        meter.block(candidate, case.target.counter, case.target.nonce)
        == case.target.block
    )
    if raw_match != (claimed_fitness == 0):
        raise AssertionError("cached fitness and raw ChaCha verification differ")
    independent_match = False
    if raw_match:
        independent_match = (
            _project_helper_block(
                candidate, case.target.counter, case.target.nonce, meter
            )
            == case.target.block
        )
        if not independent_match:
            raise AssertionError("lean and project-helper exact verification differ")
    return raw_match and independent_match, candidate == case.secret_key


def _max_rss_bytes(raw_value: int) -> int:
    return raw_value if sys.platform == "darwin" else raw_value * 1024


def run_experiment(config: ExperimentConfig) -> dict[str, object]:
    config.validate()
    meter = EvaluationMeter()
    usage_before = resource.getrusage(resource.RUSAGE_SELF)
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    tracemalloc.start()

    if meter.block(RFC_KEY, 1, RFC_NONCE) != RFC_BLOCK:
        raise AssertionError("local lean implementation does not reproduce RFC 8439")
    cases = generate_cases(config, meter)
    helper_checks = _cross_check_project_helper(cases, meter)
    projection_summary, _ = projection_diagnostics(cases, config, meter)
    landscape_summary, _ = landscape_diagnostics(cases, config, meter)

    projection_search_rows: list[dict[str, object]] = []
    for case in cases:
        for start_id in range(config.projection_starts):
            start = generated_start(config, case.case_id, 1000 + start_id)
            start_fitness = public_fitness(case.target, start, meter)
            candidate, fitness, steps = projection_chain_search(
                case.target, start, config.projection_steps, meter
            )
            block_match, key_match = _verify_candidate(
                case, candidate, fitness, meter
            )
            projection_search_rows.append(
                {
                    "case_id": case.case_id,
                    "steps": steps,
                    "start_output_mismatch_bits": start_fitness,
                    "output_mismatch_bits": fitness,
                    "key_distance_bits": key_hamming(candidate, case.secret_key),
                    "exact_block_verified": block_match,
                    "exact_key_verified": key_match and block_match,
                }
            )

    coordinate_rows: list[dict[str, object]] = []
    for case in cases[: config.coordinate_targets]:
        start = generated_start(config, case.case_id, 2000)
        start_distance = key_hamming(start, case.secret_key)
        start_fitness = public_fitness(case.target, start, meter)
        candidate, fitness, steps = coordinate_greedy_search(
            case.target, start, config.coordinate_steps, meter
        )
        block_match, key_match = _verify_candidate(case, candidate, fitness, meter)
        coordinate_rows.append(
            {
                "case_id": case.case_id,
                "steps": steps,
                "start_key_distance_bits": start_distance,
                "start_output_mismatch_bits": start_fitness,
                "final_key_distance_bits": key_hamming(candidate, case.secret_key),
                "output_mismatch_bits": fitness,
                "exact_block_verified": block_match,
                "exact_key_verified": key_match and block_match,
            }
        )

    python_current, python_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    wall_seconds = time.perf_counter() - wall_start
    cpu_seconds = time.process_time() - cpu_start
    usage_after = resource.getrusage(resource.RUSAGE_SELF)

    holdout_projection = projection_summary["holdout"]["variants"]["full"][  # type: ignore[index]
        "distance_improvement_bits"
    ]
    holdout_auc = landscape_summary["holdout"]["auc_for_wrong_bit"]  # type: ignore[index]
    projection_signal = (
        float(holdout_projection["mean"]) >= 2.0
        and float(holdout_projection["ci95_low"]) > 0.0
    )
    landscape_signal = (
        float(holdout_auc["mean"]) >= 0.53
        and float(holdout_auc["ci95_low"]) > 0.5
    )
    exact_keys = sum(
        bool(row["exact_key_verified"])
        for row in projection_search_rows + coordinate_rows
    )
    if exact_keys:
        decision = "exact key recovery observed and independently block-verified; replicate"
    elif projection_signal or landscape_signal:
        decision = (
            "holdout directional signal passed the predeclared practical gate; "
            "replicate with new deterministic seed before scaling"
        )
    else:
        decision = (
            "stop the fixed-point/local-fitness direction at 20 rounds: no gated "
            "holdout signal or exact recovery; this bounded negative result does "
            "not establish impossibility"
        )

    return {
        "schema": "apple-view-full256-projection-result-v1",
        "hypothesis": "H-Apple-1 feed-forward fixed-point attraction",
        "config": asdict(config),
        "constraints": {
            "standard": "RFC 8439 ChaCha20 block",
            "rounds": 20,
            "unknown_key_bits_seen_by_search": 256,
            "public_target": "counter + 96-bit nonce + one 512-bit output block",
            "target_source": "deterministically generated build data",
            "sealed_targets_used": False,
            "sibling_repositories_written": False,
            "gpu_or_mps_used": False,
            "secret_key_access": "measurement harness only; absent from search interfaces",
        },
        "validation": {
            "lean_rfc8439_vector": True,
            "project_helper_cross_checks": helper_checks,
            "exact_recovery_definition": "candidate equals generated 256-bit secret and both standard block implementations reproduce all 512 output bits",
        },
        "projection_diagnostic": projection_summary,
        "local_one_bit_landscape": landscape_summary,
        "public_only_searches": {
            "projection_chain": {
                "trials": len(projection_search_rows),
                "budgeted_steps_per_trial": config.projection_steps,
                "executed_steps": sum(int(row["steps"]) for row in projection_search_rows),
                "best_output_mismatch_bits": _target_clustered_ci(
                    projection_search_rows,
                    lambda row: row["output_mismatch_bits"],
                ),
                "output_mismatch_reduction_bits": _target_clustered_ci(
                    projection_search_rows,
                    lambda row: float(row["start_output_mismatch_bits"])
                    - float(row["output_mismatch_bits"]),
                    0.0,
                ),
                "best_key_distance_bits": _target_clustered_ci(
                    projection_search_rows,
                    lambda row: row["key_distance_bits"],
                    128.0,
                ),
                "exact_block_matches": sum(
                    bool(row["exact_block_verified"]) for row in projection_search_rows
                ),
                "exact_keys_verified": sum(
                    bool(row["exact_key_verified"]) for row in projection_search_rows
                ),
            },
            "coordinate_greedy": {
                "trials": len(coordinate_rows),
                "budgeted_steps_per_trial": config.coordinate_steps,
                "executed_steps": sum(int(row["steps"]) for row in coordinate_rows),
                "output_mismatch_bits": _mean_ci(
                    [float(row["output_mismatch_bits"]) for row in coordinate_rows]
                ),
                "output_mismatch_reduction_bits": _mean_ci(
                    [
                        float(row["start_output_mismatch_bits"])
                        - float(row["output_mismatch_bits"])
                        for row in coordinate_rows
                    ],
                    0.0,
                ),
                "key_distance_change_bits": _mean_ci(
                    [
                        float(row["start_key_distance_bits"])
                        - float(row["final_key_distance_bits"])
                        for row in coordinate_rows
                    ],
                    0.0,
                ),
                "exact_block_matches": sum(
                    bool(row["exact_block_verified"]) for row in coordinate_rows
                ),
                "exact_keys_verified": sum(
                    bool(row["exact_key_verified"]) for row in coordinate_rows
                ),
            },
        },
        "predeclared_continuation_gates": {
            "projection": "holdout mean improvement >= 2 key bits and 95% CI excludes 0",
            "landscape": "holdout mean AUC >= 0.53 and 95% CI excludes 0.5",
            "projection_passed": projection_signal,
            "landscape_passed": landscape_signal,
        },
        "resources": {
            "wall_seconds": wall_seconds,
            "cpu_seconds": cpu_seconds,
            "lean_permutation_evaluations": meter.permutation_evaluations,
            "lean_block_evaluations": meter.lean_block_evaluations,
            "lean_permutation_only_evaluations": (
                meter.lean_permutation_only_evaluations
            ),
            "project_helper_block_evaluations": meter.project_helper_block_evaluations,
            "total_chacha20_core_permutation_evaluations": (
                meter.total_chacha20_core_permutation_evaluations
            ),
            "core_permutation_evaluations_per_wall_second": (
                meter.total_chacha20_core_permutation_evaluations / wall_seconds
            ),
            "python_tracemalloc_current_bytes": python_current,
            "python_tracemalloc_peak_bytes": python_peak,
            "process_max_rss_bytes": _max_rss_bytes(usage_after.ru_maxrss),
            "minor_page_faults_delta": usage_after.ru_minflt - usage_before.ru_minflt,
            "major_page_faults_delta": usage_after.ru_majflt - usage_before.ru_majflt,
            "platform": platform.platform(),
            "python": platform.python_version(),
            "pid": os.getpid(),
        },
        "decision": decision,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run bounded full-256 ChaCha20 fixed-point and local-fitness tests."
    )
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument("--targets", type=int, default=32)
    parser.add_argument("--projection-starts", type=int, default=4)
    parser.add_argument("--projection-steps", type=int, default=24)
    parser.add_argument("--coordinate-targets", type=int, default=6)
    parser.add_argument("--coordinate-steps", type=int, default=6)
    parser.add_argument("--output", type=Path)
    return parser


def validated_output_path(path: Path) -> Path:
    candidate = path if path.is_absolute() else Path.cwd() / path
    resolved = candidate.resolve()
    if resolved.parent != APPLE_VIEW_DIR:
        raise ValueError("output must remain directly inside research/apple_view")
    if not resolved.name.startswith("apple_view_") or resolved.suffix != ".json":
        raise ValueError("output filename must match apple_view_*.json")
    return resolved


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    output: Path | None = None
    if args.output is not None:
        try:
            output = validated_output_path(args.output)
        except ValueError as error:
            parser.error(str(error))
    config = ExperimentConfig(
        seed=args.seed,
        targets=args.targets,
        projection_starts=args.projection_starts,
        projection_steps=args.projection_steps,
        coordinate_targets=args.coordinate_targets,
        coordinate_steps=args.coordinate_steps,
    )
    result = run_experiment(config)
    rendered = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if output is not None:
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
