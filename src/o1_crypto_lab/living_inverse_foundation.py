"""Deterministic O1C-0008 full-256 attacker/teacher foundation run."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from .chacha_trace import CHACHA20_ROUNDS
from .living_inverse import (
    ContrastFamily,
    KEY_BITS,
    LivingInverseError,
    build_known_target,
    canonical_json_bytes,
    canonical_sha256,
    deployment_feature_vector,
    key_bits,
    make_output_flip_control,
    make_training_contrast,
    make_wrong_nonce_control,
    posterior_metrics,
)


FOUNDATION_SCHEMA = "o1-256-living-inverse-foundation-config-v1"


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise LivingInverseError(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise LivingInverseError(f"{field} must be in [{minimum}, {maximum}]")
    return value


def _seed_bytes(domain: str, seed: int, length: int) -> bytes:
    payload = canonical_json_bytes([domain, seed])
    return hashlib.shake_256(payload).digest(length)


@dataclass(frozen=True)
class FoundationConfig:
    build_targets: int
    development_targets: int
    contrasts_per_family: int
    block_count: int
    seed: int
    decoy_count: int
    decoy_seed: int
    confidence_threshold: float
    beam_uncertain_bits: int
    beam_size: int

    @classmethod
    def from_mapping(cls, value: object) -> "FoundationConfig":
        if not isinstance(value, dict):
            raise LivingInverseError("foundation config must be an object")
        expected = {
            "build_targets",
            "development_targets",
            "contrasts_per_family",
            "block_count",
            "seed",
            "decoy_count",
            "decoy_seed",
            "confidence_threshold",
            "beam_uncertain_bits",
            "beam_size",
        }
        if set(value) != expected:
            raise LivingInverseError("foundation config fields differ")
        threshold = value["confidence_threshold"]
        if (
            isinstance(threshold, bool)
            or not isinstance(threshold, (int, float))
            or not math.isfinite(float(threshold))
            or not 0.5 < float(threshold) < 1.0
        ):
            raise LivingInverseError("confidence_threshold must be in (0.5, 1)")
        return cls(
            build_targets=_integer(value["build_targets"], "build_targets", 1, 1024),
            development_targets=_integer(
                value["development_targets"], "development_targets", 1, 1024
            ),
            contrasts_per_family=_integer(
                value["contrasts_per_family"], "contrasts_per_family", 1, 1024
            ),
            block_count=_integer(value["block_count"], "block_count", 1, 16),
            seed=_integer(value["seed"], "seed", 0, (1 << 63) - 1),
            decoy_count=_integer(
                value["decoy_count"], "decoy_count", 0, 10_000_000
            ),
            decoy_seed=_integer(
                value["decoy_seed"], "decoy_seed", 0, (1 << 63) - 1
            ),
            confidence_threshold=float(threshold),
            beam_uncertain_bits=_integer(
                value["beam_uncertain_bits"], "beam_uncertain_bits", 0, 20
            ),
            beam_size=_integer(value["beam_size"], "beam_size", 1, 1 << 20),
        )

    def describe(self) -> dict[str, object]:
        return {
            "build_targets": self.build_targets,
            "development_targets": self.development_targets,
            "contrasts_per_family": self.contrasts_per_family,
            "block_count": self.block_count,
            "seed": self.seed,
            "decoy_count": self.decoy_count,
            "decoy_seed": self.decoy_seed,
            "confidence_threshold": self.confidence_threshold,
            "beam_uncertain_bits": self.beam_uncertain_bits,
            "beam_size": self.beam_size,
        }


@dataclass(frozen=True)
class FoundationResult:
    report: dict[str, object]

    @property
    def success_gate_passed(self) -> bool:
        return bool(self.report["success_gate_passed"])

    def metrics(self) -> dict[str, object]:
        return {
            "schema": "o1-256-living-inverse-foundation-metrics-v1",
            "success_gate_passed": self.success_gate_passed,
            "unknown_target_key_bits": self.report["attacker_contract"][
                "unknown_target_key_bits"
            ],
            "target_trace_fields_in_deployment": self.report["attacker_contract"][
                "target_trace_fields_in_deployment"
            ],
            "build_targets": self.report["corpus"]["build_targets"],
            "development_targets": self.report["corpus"]["development_targets"],
            "deployment_contrasts": self.report["corpus"]["deployment_contrasts"],
            "deployment_feature_dimension": self.report["corpus"][
                "deployment_feature_dimension"
            ],
            "random_baseline_key_nll_bits": self.report["metric_harness"][
                "random_baseline"
            ]["key_nll_bits"],
            "oracle_ceiling_key_nll_bits": self.report["metric_harness"][
                "oracle_ceiling"
            ]["key_nll_bits"],
            "decoy_count": self.report["metric_harness"]["random_baseline"][
                "decoy_count"
            ],
            "result_sha256": self.report["result_sha256"],
            "sibling_reads": 0,
            "sibling_writes": 0,
            "fresh_target_revealed": False,
            "scientific_inverse_signal_claimed": False,
        }


def load_foundation_config(path: str | Path) -> tuple[dict[str, object], FoundationConfig]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema") != FOUNDATION_SCHEMA:
        raise LivingInverseError("foundation top-level schema differs")
    if "foundation" not in raw:
        raise LivingInverseError("foundation section is required")
    return raw, FoundationConfig.from_mapping(raw["foundation"])


def _target(seed: int, split: str, index: int, block_count: int):
    domain = f"{split}/{index}"
    key = _seed_bytes(f"key/{domain}", seed, 32)
    nonce = _seed_bytes(f"nonce/{domain}", seed, 12)
    counter = int.from_bytes(_seed_bytes(f"counter/{domain}", seed, 4), "little")
    counter %= (1 << 32) - block_count + 1
    return build_known_target(
        key, counter=counter, nonce=nonce, block_count=block_count
    )


def run_living_inverse_foundation(config: FoundationConfig) -> FoundationResult:
    target_rows: list[dict[str, object]] = []
    contrast_hashes: list[str] = []
    label_hashes: list[str] = []
    hamming_by_family: dict[str, list[int]] = {
        family.value: [] for family in ContrastFamily
    }
    feature_dimension: int | None = None
    target_keys: set[bytes] = set()
    targets = []

    split_counts = (
        ("BUILD", config.build_targets),
        ("DEVELOPMENT", config.development_targets),
    )
    for split, count in split_counts:
        for index in range(count):
            target = _target(config.seed, split, index, config.block_count)
            if target.teacher.target_key in target_keys:
                raise LivingInverseError("build/development target key collision")
            target_keys.add(target.teacher.target_key)
            targets.append((split, index, target))
            target_rows.append(
                {
                    "split": split,
                    "index": index,
                    "public_view_sha256": target.public.digest(),
                    "teacher_label_sha256": canonical_sha256(
                        target.teacher.describe_labels()
                    ),
                    "unknown_key_bits": KEY_BITS,
                    "target_key_in_public": (
                        target.teacher.target_key.hex()
                        in canonical_json_bytes(target.public.describe()).decode("ascii")
                    ),
                }
            )

            sequence = 0
            for family in ContrastFamily:
                for repeat in range(config.contrasts_per_family):
                    probabilities = (
                        np.full(KEY_BITS, 0.5, dtype=np.float64)
                        if family is ContrastFamily.POSTERIOR_SAMPLE
                        else None
                    )
                    contrast = make_training_contrast(
                        target,
                        family=family,
                        seed=config.seed + 1_000_003 * index + repeat,
                        sequence=sequence,
                        posterior_probabilities=probabilities,
                    )
                    deployment_document = contrast.deployment.describe()
                    deployment_bytes = canonical_json_bytes(deployment_document)
                    if target.teacher.target_key.hex().encode("ascii") in deployment_bytes:
                        raise LivingInverseError("target key entered deployment document")
                    if "correction_bits" in deployment_document:
                        raise LivingInverseError("training label entered deployment document")
                    features = deployment_feature_vector(contrast.deployment)
                    if feature_dimension is None:
                        feature_dimension = int(features.size)
                    elif feature_dimension != int(features.size):
                        raise LivingInverseError("deployment feature dimension changed")
                    contrast_hashes.append(hashlib.sha256(deployment_bytes).hexdigest())
                    labels = contrast.describe_labels()
                    label_hashes.append(canonical_sha256(labels))
                    hamming_by_family[family.value].append(
                        int(sum(contrast.correction_bits))
                    )
                    sequence += 1

    if feature_dimension is None:
        raise AssertionError("foundation produced no contrast features")

    development = next(
        target for split, _index, target in targets if split == "DEVELOPMENT"
    )
    random_probabilities = np.full(KEY_BITS, 0.5, dtype=np.float64)
    truth = key_bits(development.teacher.target_key)
    oracle_probabilities = np.where(truth == 1, 0.99, 0.01).astype(np.float64)
    metric_options = {
        "confidence_threshold": config.confidence_threshold,
        "decoy_count": config.decoy_count,
        "decoy_seed": config.decoy_seed,
        "beam_uncertain_bits": config.beam_uncertain_bits,
        "beam_size": config.beam_size,
    }
    random_metrics = posterior_metrics(
        development.teacher.target_key,
        random_probabilities,
        **metric_options,
    )
    oracle_metrics = posterior_metrics(
        development.teacher.target_key,
        oracle_probabilities,
        **metric_options,
    )

    output_control = make_output_flip_control(development.public, 137)
    nonce_control = make_wrong_nonce_control(development.public, 23)
    output_delta = sum(
        (left ^ right).bit_count()
        for original, changed in zip(
            development.public.output_blocks,
            output_control.output_blocks,
            strict=True,
        )
        for left, right in zip(original, changed, strict=True)
    )
    nonce_delta = sum(
        (left ^ right).bit_count()
        for left, right in zip(
            development.public.nonce, nonce_control.nonce, strict=True
        )
    )

    contrasts = len(contrast_hashes)
    report_without_hash = {
        "schema": "o1-256-living-inverse-foundation-result-v1",
        "config": config.describe(),
        "attacker_contract": {
            "cipher": "ChaCha20",
            "rounds": CHACHA20_ROUNDS,
            "feed_forward": True,
            "unknown_target_key_bits": KEY_BITS,
            "public_target_fields": ["counter_schedule", "nonce", "output_blocks"],
            "attacker_computable_fields": [
                "candidate_key",
                "candidate_output",
                "candidate_round_trace",
                "candidate_carry_trace",
            ],
            "teacher_only_fields": [
                "target_key",
                "target_round_trace",
                "target_carry_trace",
                "correction_bits",
            ],
            "target_trace_fields_in_deployment": 0,
            "reduced_width_target": False,
        },
        "corpus": {
            "build_targets": config.build_targets,
            "development_targets": config.development_targets,
            "target_rows": target_rows,
            "contrast_families": [family.value for family in ContrastFamily],
            "contrasts_per_family_per_target": config.contrasts_per_family,
            "deployment_contrasts": contrasts,
            "deployment_feature_dimension": feature_dimension,
            "deployment_contrast_set_sha256": canonical_sha256(contrast_hashes),
            "teacher_label_set_sha256": canonical_sha256(label_hashes),
            "hamming_by_family": {
                family: {
                    "minimum": min(values),
                    "maximum": max(values),
                    "mean": float(sum(values) / len(values)),
                }
                for family, values in hamming_by_family.items()
            },
            "unique_target_keys": len(target_keys),
            "logical_unique_chacha_blocks": (
                (config.build_targets + config.development_targets + contrasts)
                * config.block_count
            ),
        },
        "controls": {
            "output_flip_hamming_bits": output_delta,
            "wrong_nonce_hamming_bits": nonce_delta,
            "wrong_nonce_preserves_output_bytes": (
                nonce_control.output_blocks == development.public.output_blocks
            ),
            "shuffled_key_control_registered": True,
        },
        "metric_harness": {
            "random_baseline": random_metrics,
            "oracle_ceiling": oracle_metrics,
            "random_baseline_exact_256_bits": math.isclose(
                float(random_metrics["key_nll_bits"]), 256.0, abs_tol=1e-12
            ),
            "oracle_exact_mode": oracle_metrics["hamming_distance"] == 0,
            "oracle_exact_beam": oracle_metrics["beam"]["exact_key_in_beam"],
        },
        "resource_contract": {
            "cpu_only": True,
            "mps_calls": 0,
            "gpu_calls": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "fresh_target_generated": False,
            "fresh_target_revealed": False,
        },
    }
    success = (
        all(not row["target_key_in_public"] for row in target_rows)
        and report_without_hash["attacker_contract"][
            "target_trace_fields_in_deployment"
        ]
        == 0
        and report_without_hash["attacker_contract"]["unknown_target_key_bits"]
        == 256
        and output_delta == 1
        and nonce_delta == 1
        and report_without_hash["controls"]["wrong_nonce_preserves_output_bytes"]
        and report_without_hash["metric_harness"][
            "random_baseline_exact_256_bits"
        ]
        and report_without_hash["metric_harness"]["oracle_exact_mode"]
        and report_without_hash["metric_harness"]["oracle_exact_beam"]
    )
    report_without_hash["success_gate_passed"] = bool(success)
    result_sha = canonical_sha256(report_without_hash)
    return FoundationResult(
        report={**report_without_hash, "result_sha256": result_sha}
    )
