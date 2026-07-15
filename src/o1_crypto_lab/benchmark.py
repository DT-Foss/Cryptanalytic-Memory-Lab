"""Deterministic memory, weak-evidence and information-flow benchmark ladder."""

from __future__ import annotations

import hashlib
import json
import math
import random
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import fmean
from typing import Iterable

from .composer import ChainComposer, FlowViolation, default_registry
from .memory import (
    CountSketchBitMemory,
    DirectBitVault,
    FullContextAttentionCeiling,
    HolographicBitMemory,
    StreamingEvidenceAccumulator,
)
from .types import DataKind, FlowState, InformationLabel


@dataclass(frozen=True)
class BenchmarkConfig:
    schema: str = "o1-crypto-benchmark-config-v1"
    n_bits: int = 256
    seeds: tuple[int, ...] = (1, 7, 42, 123, 2024)
    haystack_lengths: tuple[int, ...] = (0, 1024, 65536)
    holographic_channels: int = 128
    undersized_slots: int = 64
    evidence_relations: tuple[int, ...] = (1, 8, 32, 128, 512, 1024)
    weak_accuracy: float = 0.55

    def validate(self) -> None:
        if self.schema != "o1-crypto-benchmark-config-v1":
            raise ValueError(f"unsupported config schema: {self.schema}")
        if not isinstance(self.n_bits, int) or isinstance(self.n_bits, bool):
            raise TypeError("n_bits must be an integer")
        if self.n_bits < 2:
            raise ValueError("n_bits must be at least 2")
        for name, values in (
            ("seeds", self.seeds),
            ("haystack_lengths", self.haystack_lengths),
            ("evidence_relations", self.evidence_relations),
        ):
            if not isinstance(values, tuple) or any(
                not isinstance(value, int) or isinstance(value, bool)
                for value in values
            ):
                raise TypeError(f"{name} must be a tuple of integers")
        if not self.seeds or len(set(self.seeds)) != len(self.seeds):
            raise ValueError("seeds must be a non-empty unique list")
        if not self.haystack_lengths or min(self.haystack_lengths) < 0:
            raise ValueError("haystack lengths must be non-negative")
        if tuple(sorted(set(self.haystack_lengths))) != self.haystack_lengths:
            raise ValueError("haystack lengths must be unique and sorted")
        if any(
            not isinstance(value, int) or isinstance(value, bool)
            for value in (self.holographic_channels, self.undersized_slots)
        ):
            raise TypeError("memory dimensions must be integers")
        if self.holographic_channels < 1 or self.undersized_slots < 1:
            raise ValueError("memory dimensions must be positive")
        if 2 * self.holographic_channels != self.n_bits:
            raise ValueError(
                "holographic_equal_budget requires two real scalars per complex "
                "channel and therefore 2 * holographic_channels == n_bits"
            )
        if self.undersized_slots >= self.n_bits:
            raise ValueError(
                "countsketch_under_capacity requires undersized_slots < n_bits"
            )
        if not self.evidence_relations or min(self.evidence_relations) < 1:
            raise ValueError("evidence relation counts must be positive")
        if tuple(sorted(set(self.evidence_relations))) != self.evidence_relations:
            raise ValueError("evidence relation counts must be unique and sorted")
        if (
            isinstance(self.weak_accuracy, bool)
            or not isinstance(self.weak_accuracy, (int, float))
            or not math.isfinite(self.weak_accuracy)
        ):
            raise TypeError("weak_accuracy must be a finite number")
        if not 0.5 < self.weak_accuracy < 1.0:
            raise ValueError("weak_accuracy must be in (0.5, 1.0)")

    @classmethod
    def load(cls, path: str | Path) -> "BenchmarkConfig":
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("benchmark config must be a JSON object")
        allowed = set(cls.__dataclass_fields__)
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise ValueError(f"unknown config fields: {', '.join(unknown)}")
        for field_name in (
            "seeds",
            "haystack_lengths",
            "evidence_relations",
        ):
            if field_name in value:
                value[field_name] = tuple(value[field_name])
        config = cls(**value)
        config.validate()
        return config

    def describe(self) -> dict[str, object]:
        value = asdict(self)
        for key in ("seeds", "haystack_lengths", "evidence_relations"):
            value[key] = list(value[key])
        return value


def _accuracy(expected: list[int], actual: list[int]) -> float:
    return sum(
        left == right for left, right in zip(expected, actual, strict=True)
    ) / len(expected)


def _brier(expected: list[int], probabilities: list[float]) -> float:
    return fmean(
        (probability - bit) ** 2
        for bit, probability in zip(expected, probabilities, strict=True)
    )


def _memory_rows(config: BenchmarkConfig) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for seed in config.seeds:
        # Every length replays the same bindings and query order.  Otherwise a
        # length sweep would quietly compare different memory problems.
        rng = random.Random((seed << 32) ^ 0x4D514152)
        secret = [rng.getrandbits(1) for _ in range(config.n_bits)]
        addresses = list(range(config.n_bits))
        write_order = addresses.copy()
        query_order = addresses.copy()
        rng.shuffle(write_order)
        rng.shuffle(query_order)
        for haystack_length in config.haystack_lengths:
            models = {
                "full_context_attention_ceiling": FullContextAttentionCeiling(),
                "direct_bit_vault": DirectBitVault(config.n_bits),
                "holographic_equal_budget": HolographicBitMemory(
                    config.holographic_channels, seed=seed
                ),
                "countsketch_under_capacity": CountSketchBitMemory(
                    config.undersized_slots, seed=seed
                ),
            }
            for address in write_order:
                for model in models.values():
                    model.write(address, secret[address])

            before = {name: model.state_digest() for name, model in models.items()}
            for token in range(haystack_length):
                for model in models.values():
                    model.observe_haystack(token)
            after = {name: model.state_digest() for name, model in models.items()}

            for name, model in models.items():
                expected = [secret[address] for address in query_order]
                actual = [model.read(address) for address in query_order]
                accuracy = _accuracy(expected, actual)
                rows.append(
                    {
                        "seed": seed,
                        "haystack_length": haystack_length,
                        "model": name,
                        "state_scalars": model.state_scalars,
                        "state_precision_bits": model.state_precision_bits,
                        "state_dtype": model.state_dtype,
                        "serialized_state_bytes": model.serialized_state_bytes,
                        "bit_accuracy": accuracy,
                        "exact_all_bits": accuracy == 1.0,
                        "state_frozen_through_haystack": before[name] == after[name],
                    }
                )
    return rows


def _memory_summary(rows: Iterable[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, int], list[dict[str, object]]] = {}
    for row in rows:
        grouped.setdefault((str(row["model"]), int(row["haystack_length"])), []).append(
            row
        )
    result = []
    for (model, length), group in sorted(grouped.items()):
        result.append(
            {
                "model": model,
                "haystack_length": length,
                "state_scalars": int(group[0]["state_scalars"]),
                "state_precision_bits": int(group[0]["state_precision_bits"]),
                "state_dtype": str(group[0]["state_dtype"]),
                "serialized_state_bytes": int(group[0]["serialized_state_bytes"]),
                "mean_bit_accuracy": fmean(float(row["bit_accuracy"]) for row in group),
                "exact_key_rate": fmean(bool(row["exact_all_bits"]) for row in group),
                "frozen_state_rate": fmean(
                    bool(row["state_frozen_through_haystack"]) for row in group
                ),
                "seeds": len(group),
            }
        )
    return result


def _evidence_vector(
    secret: list[int],
    *,
    rng: random.Random,
    correct_probability: float,
    magnitude: float,
) -> list[float]:
    result = []
    for bit in secret:
        observed = bit if rng.random() < correct_probability else 1 - bit
        result.append(magnitude if observed else -magnitude)
    return result


def _correlated_orientation(
    secret: list[int],
    *,
    rng: random.Random,
    correct_probability: float,
    magnitude: float,
) -> list[float]:
    return _evidence_vector(
        secret,
        rng=rng,
        correct_probability=correct_probability,
        magnitude=magnitude,
    )


def _run_evidence_mode(
    secret: list[int],
    *,
    seed: int,
    relations: int,
    mode: str,
    weak_accuracy: float,
) -> dict[str, object]:
    rng = random.Random(
        (seed << 32) ^ relations ^ int.from_bytes(mode.encode(), "little")
    )
    accumulator = StreamingEvidenceAccumulator(len(secret))
    magnitude = math.log(weak_accuracy / (1.0 - weak_accuracy))

    if mode == "independent_weak_signal":
        for _ in range(relations):
            accumulator.update(
                _evidence_vector(
                    secret,
                    rng=rng,
                    correct_probability=weak_accuracy,
                    magnitude=magnitude,
                )
            )
    elif mode == "no_signal_control":
        for _ in range(relations):
            accumulator.update(
                _evidence_vector(
                    secret,
                    rng=rng,
                    correct_probability=0.5,
                    magnitude=magnitude,
                )
            )
    elif mode == "perfectly_correlated_error_control":
        orientation = _correlated_orientation(
            secret,
            rng=rng,
            correct_probability=weak_accuracy,
            magnitude=magnitude,
        )
        for _ in range(relations):
            accumulator.update(orientation)
    else:
        raise ValueError(f"unknown evidence mode: {mode}")

    prediction = accumulator.predict()
    accuracy = _accuracy(secret, prediction)
    return {
        "seed": seed,
        "relations": relations,
        "mode": mode,
        "state_scalars": accumulator.state_scalars,
        "state_precision_bits": accumulator.state_precision_bits,
        "state_dtype": accumulator.state_dtype,
        "serialized_state_bytes": accumulator.serialized_state_bytes,
        "relation_vectors_consumed": relations,
        "evidence_scalars_consumed": relations * len(secret),
        "bit_accuracy": accuracy,
        "exact_all_bits": accuracy == 1.0,
        "brier": _brier(secret, accumulator.probabilities()),
    }


def _run_evidence_curve(
    secret: list[int],
    *,
    seed: int,
    relation_counts: tuple[int, ...],
    mode: str,
    weak_accuracy: float,
) -> list[dict[str, object]]:
    """Run one nested stream and report fixed prefixes of that same stream."""

    if not relation_counts:
        return []
    rng = random.Random((seed << 32) ^ int.from_bytes(mode.encode(), "little"))
    accumulator = StreamingEvidenceAccumulator(len(secret))
    magnitude = math.log(weak_accuracy / (1.0 - weak_accuracy))
    correlated = None
    if mode == "perfectly_correlated_error_control":
        correlated = _correlated_orientation(
            secret,
            rng=rng,
            correct_probability=weak_accuracy,
            magnitude=magnitude,
        )
    elif mode not in {"independent_weak_signal", "no_signal_control"}:
        raise ValueError(f"unknown evidence mode: {mode}")

    requested = set(relation_counts)
    rows: list[dict[str, object]] = []
    for relation in range(1, max(relation_counts) + 1):
        if mode == "independent_weak_signal":
            evidence = _evidence_vector(
                secret,
                rng=rng,
                correct_probability=weak_accuracy,
                magnitude=magnitude,
            )
        elif mode == "no_signal_control":
            evidence = _evidence_vector(
                secret,
                rng=rng,
                correct_probability=0.5,
                magnitude=magnitude,
            )
        else:
            assert correlated is not None
            evidence = correlated
        accumulator.update(evidence)
        if relation not in requested:
            continue
        prediction = accumulator.predict()
        accuracy = _accuracy(secret, prediction)
        rows.append(
            {
                "seed": seed,
                "relations": relation,
                "mode": mode,
                "state_scalars": accumulator.state_scalars,
                "state_precision_bits": accumulator.state_precision_bits,
                "state_dtype": accumulator.state_dtype,
                "serialized_state_bytes": accumulator.serialized_state_bytes,
                "relation_vectors_consumed": relation,
                "evidence_scalars_consumed": relation * len(secret),
                "bit_accuracy": accuracy,
                "exact_all_bits": accuracy == 1.0,
                "brier": _brier(secret, accumulator.probabilities()),
            }
        )
    return rows


def _evidence_rows(config: BenchmarkConfig) -> list[dict[str, object]]:
    rows = []
    modes = (
        "independent_weak_signal",
        "no_signal_control",
        "perfectly_correlated_error_control",
    )
    for seed in config.seeds:
        secret_rng = random.Random(seed ^ 0x4F314B4559)
        secret = [secret_rng.getrandbits(1) for _ in range(config.n_bits)]
        for mode in modes:
            rows.extend(
                _run_evidence_curve(
                    secret,
                    seed=seed,
                    relation_counts=config.evidence_relations,
                    mode=mode,
                    weak_accuracy=config.weak_accuracy,
                )
            )
    return rows


def _evidence_summary(rows: Iterable[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, int], list[dict[str, object]]] = {}
    for row in rows:
        grouped.setdefault((str(row["mode"]), int(row["relations"])), []).append(row)
    result = []
    for (mode, relations), group in sorted(grouped.items()):
        result.append(
            {
                "mode": mode,
                "relations": relations,
                "state_scalars": int(group[0]["state_scalars"]),
                "state_precision_bits": int(group[0]["state_precision_bits"]),
                "state_dtype": str(group[0]["state_dtype"]),
                "serialized_state_bytes": int(group[0]["serialized_state_bytes"]),
                "relation_vectors_consumed": int(group[0]["relation_vectors_consumed"]),
                "evidence_scalars_consumed": int(group[0]["evidence_scalars_consumed"]),
                "mean_bit_accuracy": fmean(float(row["bit_accuracy"]) for row in group),
                "exact_key_rate": fmean(bool(row["exact_all_bits"]) for row in group),
                "mean_brier": fmean(float(row["brier"]) for row in group),
                "seeds": len(group),
            }
        )
    return result


def composition_report() -> dict[str, object]:
    registry = default_registry()
    composer = ChainComposer(registry)
    public = FlowState(DataKind.PUBLIC_RELATIONS, frozenset({InformationLabel.PUBLIC}))
    public_to_order = composer.find_chains(
        public, DataKind.TARGET_BLIND_ORDER, max_depth=8
    )
    public_to_confirmed = composer.find_chains(
        public, DataKind.CONFIRMED, max_depth=10, require_target_blind=False
    )
    revealed = FlowState(
        DataKind.CONFIRMED,
        frozenset(
            {
                InformationLabel.PUBLIC,
                InformationLabel.POST_REVEAL,
                InformationLabel.TARGET_SECRET,
            }
        ),
    )
    leaked = composer.find_chains(
        revealed, DataKind.TARGET_BLIND_ORDER, max_depth=2, require_target_blind=True
    )
    leak_rejection = ""
    post_reveal_operator = next(op for op in registry if op.name == "post_reveal_rank")
    try:
        post_reveal_operator.apply(revealed)
    except FlowViolation as exc:
        leak_rejection = str(exc)

    return {
        "public_to_target_blind_order": [chain.describe() for chain in public_to_order],
        "public_to_confirmed_model": [
            chain.describe() for chain in public_to_confirmed
        ],
        "post_reveal_to_target_blind_order_count": len(leaked),
        "post_reveal_rejection": leak_rejection,
        "gate_passed": bool(public_to_order) and not leaked and bool(leak_rejection),
    }


def run_benchmark(config: BenchmarkConfig) -> dict[str, object]:
    config.validate()
    memory_rows = _memory_rows(config)
    evidence_rows = _evidence_rows(config)
    result: dict[str, object] = {
        "schema": "o1-crypto-benchmark-result-v1",
        "claim_scope": {
            "memory": "synthetic retention only; direct vault is position-indexed",
            "evidence": "synthetic oracle signal only; not evidence of cipher leakage",
            "composition": "type and provenance safety only; no operator quality claim",
        },
        "config": config.describe(),
        "memory": {
            "rows": memory_rows,
            "summary": _memory_summary(memory_rows),
        },
        "evidence": {
            "rows": evidence_rows,
            "summary": _evidence_summary(evidence_rows),
        },
        "composition": composition_report(),
    }
    canonical = json.dumps(result, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    result["result_sha256"] = hashlib.sha256(canonical).hexdigest()
    return result
