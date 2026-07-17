"""One-shot full-256 output-only Living Inverse reader experiment."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from .living_inverse import (
    KEY_BITS,
    PublicTargetView,
    build_known_target,
    canonical_json_bytes,
    canonical_sha256,
    key_bits,
    make_output_flip_control,
    make_wrong_nonce_control,
    posterior_metrics,
    public_target_feature_vector,
)
from .full256_broker import public_view_from_publication, verify_publication
from .living_inverse_corpus import (
    CANDIDATE_FEATURE_DIMENSION,
    PUBLIC_FEATURE_DIMENSION,
    ReaderTarget,
    attacker_candidate_keys,
    candidate_feature_vector,
    make_reader_target,
)
from .living_inverse_ridge import (
    FeatureSegment,
    FrozenHolographicRidge,
    HolographicFeatureMap,
    HolographicFeaturePlan,
    fit_holographic_ridge,
    serialize_ridge,
)

READER_EXPERIMENT_SCHEMA = "o1-256-living-inverse-reader-config-v1"
FACTUAL_ARMS = ("direct", "relative", "distilled")
POSTERIOR_ARMS = (*FACTUAL_ARMS, "shuffled_key_control")


class LivingInverseReaderError(ValueError):
    """Raised when the frozen reader protocol or an outcome differs."""


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise LivingInverseReaderError(
            f"{field} must be an integer in [{minimum}, {maximum}]"
        )
    return value


def _finite_number(value: object, field: str, minimum: float, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not minimum <= float(value) <= maximum
    ):
        raise LivingInverseReaderError(
            f"{field} must be finite in [{minimum}, {maximum}]"
        )
    return float(value)


@dataclass(frozen=True)
class LivingInverseReaderConfig:
    train_structured_targets: int
    train_uniform_targets: int
    calibration_targets: int
    development_targets: int
    candidates_per_target: int
    corpus_seed: int
    relation_seed: int
    candidate_seed: int
    feature_seed: int
    feature_slots: int
    ridge_lambda: float
    rank: int
    auxiliary_weight: float
    shrinkage_grid: tuple[float, ...]
    confidence_threshold: float
    stable_accuracy: float
    stable_nll_gain: float
    familywise_alpha: float
    maximum_selected_bits: int
    signal_compression_bits: float
    signal_control_margin_bits: float
    decoy_count: int
    decoy_seed: int
    beam_uncertain_bits: int
    beam_size: int

    @classmethod
    def from_mapping(cls, value: object) -> "LivingInverseReaderConfig":
        if not isinstance(value, dict):
            raise LivingInverseReaderError("reader config must be an object")
        expected = {
            "train_structured_targets",
            "train_uniform_targets",
            "calibration_targets",
            "development_targets",
            "candidates_per_target",
            "corpus_seed",
            "relation_seed",
            "candidate_seed",
            "feature_seed",
            "feature_slots",
            "ridge_lambda",
            "rank",
            "auxiliary_weight",
            "shrinkage_grid",
            "confidence_threshold",
            "stable_accuracy",
            "stable_nll_gain",
            "familywise_alpha",
            "maximum_selected_bits",
            "signal_compression_bits",
            "signal_control_margin_bits",
            "decoy_count",
            "decoy_seed",
            "beam_uncertain_bits",
            "beam_size",
        }
        if set(value) != expected:
            raise LivingInverseReaderError("reader config fields differ")
        raw_grid = value["shrinkage_grid"]
        if not isinstance(raw_grid, list) or not raw_grid:
            raise LivingInverseReaderError("shrinkage_grid must be a non-empty list")
        grid = tuple(
            _finite_number(item, "shrinkage_grid item", 0.0, 1.0) for item in raw_grid
        )
        if tuple(sorted(set(grid))) != grid or grid[0] != 0.0:
            raise LivingInverseReaderError(
                "shrinkage_grid must be sorted, unique and start at zero"
            )
        config = cls(
            train_structured_targets=_integer(
                value["train_structured_targets"],
                "train_structured_targets",
                1,
                4096,
            ),
            train_uniform_targets=_integer(
                value["train_uniform_targets"], "train_uniform_targets", 1, 4096
            ),
            calibration_targets=_integer(
                value["calibration_targets"], "calibration_targets", 2, 4096
            ),
            development_targets=_integer(
                value["development_targets"], "development_targets", 2, 4096
            ),
            candidates_per_target=_integer(
                value["candidates_per_target"], "candidates_per_target", 1, 64
            ),
            corpus_seed=_integer(value["corpus_seed"], "corpus_seed", 0, (1 << 63) - 1),
            relation_seed=_integer(
                value["relation_seed"], "relation_seed", 0, (1 << 63) - 1
            ),
            candidate_seed=_integer(
                value["candidate_seed"], "candidate_seed", 0, (1 << 63) - 1
            ),
            feature_seed=_integer(
                value["feature_seed"], "feature_seed", 0, (1 << 63) - 1
            ),
            feature_slots=_integer(value["feature_slots"], "feature_slots", 4, 1024),
            ridge_lambda=_finite_number(
                value["ridge_lambda"], "ridge_lambda", 1e-12, 1e12
            ),
            rank=_integer(value["rank"], "rank", 1, 1024),
            auxiliary_weight=_finite_number(
                value["auxiliary_weight"], "auxiliary_weight", 0.0, 100.0
            ),
            shrinkage_grid=grid,
            confidence_threshold=_finite_number(
                value["confidence_threshold"],
                "confidence_threshold",
                0.500001,
                0.999999,
            ),
            stable_accuracy=_finite_number(
                value["stable_accuracy"], "stable_accuracy", 0.5, 1.0
            ),
            stable_nll_gain=_finite_number(
                value["stable_nll_gain"], "stable_nll_gain", 0.0, 1.0
            ),
            familywise_alpha=_finite_number(
                value["familywise_alpha"], "familywise_alpha", 1e-9, 0.25
            ),
            maximum_selected_bits=_integer(
                value["maximum_selected_bits"],
                "maximum_selected_bits",
                1,
                KEY_BITS,
            ),
            signal_compression_bits=_finite_number(
                value["signal_compression_bits"],
                "signal_compression_bits",
                0.0,
                256.0,
            ),
            signal_control_margin_bits=_finite_number(
                value["signal_control_margin_bits"],
                "signal_control_margin_bits",
                0.0,
                256.0,
            ),
            decoy_count=_integer(value["decoy_count"], "decoy_count", 0, 10_000_000),
            decoy_seed=_integer(value["decoy_seed"], "decoy_seed", 0, (1 << 63) - 1),
            beam_uncertain_bits=_integer(
                value["beam_uncertain_bits"], "beam_uncertain_bits", 0, 20
            ),
            beam_size=_integer(value["beam_size"], "beam_size", 1, 1 << 20),
        )
        if config.rank > config.feature_slots * 9:
            raise LivingInverseReaderError("rank exceeds the candidate feature map")
        return config

    @property
    def train_targets(self) -> int:
        return self.train_structured_targets + self.train_uniform_targets

    def describe(self) -> dict[str, object]:
        return {
            "train_structured_targets": self.train_structured_targets,
            "train_uniform_targets": self.train_uniform_targets,
            "calibration_targets": self.calibration_targets,
            "development_targets": self.development_targets,
            "candidates_per_target": self.candidates_per_target,
            "corpus_seed": self.corpus_seed,
            "relation_seed": self.relation_seed,
            "candidate_seed": self.candidate_seed,
            "feature_seed": self.feature_seed,
            "feature_slots": self.feature_slots,
            "ridge_lambda": self.ridge_lambda,
            "rank": self.rank,
            "auxiliary_weight": self.auxiliary_weight,
            "shrinkage_grid": list(self.shrinkage_grid),
            "confidence_threshold": self.confidence_threshold,
            "stable_accuracy": self.stable_accuracy,
            "stable_nll_gain": self.stable_nll_gain,
            "familywise_alpha": self.familywise_alpha,
            "maximum_selected_bits": self.maximum_selected_bits,
            "signal_compression_bits": self.signal_compression_bits,
            "signal_control_margin_bits": self.signal_control_margin_bits,
            "decoy_count": self.decoy_count,
            "decoy_seed": self.decoy_seed,
            "beam_uncertain_bits": self.beam_uncertain_bits,
            "beam_size": self.beam_size,
        }


def load_living_inverse_reader_config(
    path: str | Path,
) -> tuple[dict[str, object], LivingInverseReaderConfig]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema") != READER_EXPERIMENT_SCHEMA:
        raise LivingInverseReaderError("reader top-level schema differs")
    if "reader" not in raw:
        raise LivingInverseReaderError("reader section is required")
    return raw, LivingInverseReaderConfig.from_mapping(raw["reader"])


def direct_feature_plan(config: LivingInverseReaderConfig) -> HolographicFeaturePlan:
    return HolographicFeaturePlan(
        input_dimension=PUBLIC_FEATURE_DIMENSION,
        slots=config.feature_slots,
        seed=config.feature_seed,
        segments=(
            FeatureSegment("target_output", 0, 512),
            FeatureSegment("public_relation", 512, PUBLIC_FEATURE_DIMENSION),
        ),
        interactions=(("target_output", "public_relation"),),
    )


def candidate_feature_plan(config: LivingInverseReaderConfig) -> HolographicFeaturePlan:
    return HolographicFeaturePlan(
        input_dimension=CANDIDATE_FEATURE_DIMENSION,
        slots=config.feature_slots,
        seed=config.feature_seed ^ 0xA465A469,
        segments=(
            FeatureSegment("target_output", 0, 512),
            FeatureSegment("candidate_output", 512, 1024),
            FeatureSegment("output_residual", 1024, 1536),
            FeatureSegment("candidate_key", 1536, 1792),
            FeatureSegment("public_relation", 1792, 1920),
            FeatureSegment("candidate_trace", 1920, CANDIDATE_FEATURE_DIMENSION),
        ),
        interactions=(
            ("target_output", "candidate_output"),
            ("target_output", "output_residual"),
            ("candidate_key", "candidate_trace"),
        ),
    )


def _relation(seed: int, split: str, index: int) -> tuple[int, bytes]:
    material = hashlib.shake_256(
        canonical_json_bytes(["o1-256-public-relation", seed, split, index])
    ).digest(16)
    return int.from_bytes(material[:4], "little"), material[4:]


def _make_targets(
    config: LivingInverseReaderConfig,
    split: str,
    count: int,
    *,
    structured_count: int = 0,
) -> tuple[ReaderTarget, ...]:
    targets = []
    for index in range(count):
        counter, nonce = _relation(config.relation_seed, split, index)
        targets.append(
            make_reader_target(
                seed=config.corpus_seed,
                split=split,
                index=index,
                counter=counter,
                nonce=nonce,
                structured=index < structured_count,
            )
        )
    return tuple(targets)


def _matrix_sha256(array: np.ndarray, dtype: str = "<f4") -> str:
    payload = np.ascontiguousarray(array, dtype=dtype).tobytes()
    return hashlib.sha256(payload).hexdigest()


def _target_inventory(targets: Sequence[ReaderTarget]) -> dict[str, object]:
    keys = [target.key for target in targets]
    public = [target.public_commitment() for target in targets]
    teachers = [target.teacher_commitment() for target in targets]
    if len(set(keys)) != len(keys) or len(set(public)) != len(public):
        raise LivingInverseReaderError("target split contains a collision")
    return {
        "targets": len(targets),
        "structured_targets": sum(
            target.distribution == "STRUCTURED" for target in targets
        ),
        "uniform_targets": sum(target.distribution == "UNIFORM" for target in targets),
        "public_commitment_root": canonical_sha256(public),
        "teacher_commitment_root": canonical_sha256(teachers),
        "target_ids_sha256": canonical_sha256([target.target_id for target in targets]),
    }


def _assert_disjoint(*splits: Sequence[ReaderTarget]) -> None:
    keys: set[bytes] = set()
    public: set[str] = set()
    for split in splits:
        for target in split:
            if target.key in keys or target.public.digest() in public:
                raise LivingInverseReaderError("TRAIN/CAL/DEV collision detected")
            keys.add(target.key)
            public.add(target.public.digest())


def _binary_nll_bits(logits: np.ndarray, labels: np.ndarray, scale: float) -> float:
    scores = np.asarray(logits, dtype=np.float64)
    truth = np.asarray(labels, dtype=np.float64)
    if (
        scores.ndim != 2
        or scores.shape != truth.shape
        or scores.shape[1] != KEY_BITS
        or not np.all(np.isfinite(scores))
        or np.any((truth != 0.0) & (truth != 1.0))
    ):
        raise LivingInverseReaderError("logits and labels must be finite matched Nx256")
    scaled = scores * float(scale)
    losses = np.logaddexp(0.0, scaled) - truth * scaled
    return float(np.mean(np.sum(losses, axis=1) / math.log(2.0)))


def _select_scale(
    logits: np.ndarray, labels: np.ndarray, grid: Sequence[float]
) -> tuple[float, tuple[dict[str, float], ...]]:
    rows = tuple(
        {
            "scale": float(scale),
            "mean_key_nll_bits": _binary_nll_bits(logits, labels, float(scale)),
        }
        for scale in grid
    )
    selected = min(rows, key=lambda row: (row["mean_key_nll_bits"], row["scale"]))
    return float(selected["scale"]), rows


def _posterior(logits: np.ndarray, scale: float) -> np.ndarray:
    scores = np.asarray(logits, dtype=np.float64)
    if (
        scores.ndim != 2
        or scores.shape[1] != KEY_BITS
        or not np.all(np.isfinite(scores))
    ):
        raise LivingInverseReaderError("reader scores must be finite Nx256")
    scaled = np.clip(scores * float(scale), -40.0, 40.0)
    return 1.0 / (1.0 + np.exp(-scaled))


def _evaluation(
    probabilities: np.ndarray,
    labels: np.ndarray,
    config: LivingInverseReaderConfig,
) -> dict[str, object]:
    values = np.asarray(probabilities, dtype=np.float64)
    truth = np.asarray(labels, dtype=np.float64)
    if (
        values.ndim != 2
        or values.shape != truth.shape
        or values.shape[1] != KEY_BITS
        or not np.all(np.isfinite(values))
        or np.any((values <= 0.0) | (values >= 1.0))
        or np.any((truth != 0.0) & (truth != 1.0))
    ):
        raise LivingInverseReaderError("posterior evaluation arrays differ")
    selected = np.where(truth == 1.0, values, 1.0 - values)
    per_target_nll = -np.log2(selected).sum(axis=1)
    per_bit_nll = -np.log2(selected).mean(axis=0)
    predictions = values >= 0.5
    per_bit_accuracy = np.mean(predictions == truth, axis=0)
    stable = (per_bit_accuracy >= config.stable_accuracy) & (
        per_bit_nll <= 1.0 - config.stable_nll_gain
    )
    order = np.lexsort((np.arange(KEY_BITS), per_bit_nll))
    return {
        "targets": int(values.shape[0]),
        "mean_key_nll_bits": float(np.mean(per_target_nll)),
        "median_key_nll_bits": float(np.median(per_target_nll)),
        "minimum_key_nll_bits": float(np.min(per_target_nll)),
        "maximum_key_nll_bits": float(np.max(per_target_nll)),
        "mean_effective_compression_bits": float(KEY_BITS - np.mean(per_target_nll)),
        "bit_accuracy": float(np.mean(predictions == truth)),
        "stable_bits": int(np.count_nonzero(stable)),
        "stable_bit_coordinates": [int(bit) for bit in np.flatnonzero(stable)],
        "top_bits": [
            {
                "bit": int(bit),
                "accuracy": float(per_bit_accuracy[bit]),
                "nll_bits": float(per_bit_nll[bit]),
                "nll_gain_bits": float(1.0 - per_bit_nll[bit]),
            }
            for bit in order[:16]
        ],
        "posterior_set_sha256": _matrix_sha256(values, "<f8"),
    }


def _per_bit_statistics(
    probabilities: np.ndarray, labels: np.ndarray
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    selected = np.where(labels == 1.0, probabilities, 1.0 - probabilities)
    nll = -np.log2(selected).mean(axis=0)
    correct = np.sum((probabilities >= 0.5) == labels, axis=0, dtype=np.int64)
    return nll, correct / labels.shape[0], correct


def _binomial_success_threshold(
    trials: int, hypotheses: int, familywise_alpha: float
) -> tuple[int, float]:
    if trials < 1 or hypotheses < 1:
        raise LivingInverseReaderError("binomial gate dimensions must be positive")
    target = familywise_alpha / hypotheses
    denominator = 1 << trials
    for successes in range((trials + 1) // 2, trials + 1):
        tail = sum(math.comb(trials, value) for value in range(successes, trials + 1))
        probability = float(tail / denominator)
        if probability <= target:
            return successes, probability
    return trials, float(1 / denominator)


def _freeze_bit_coordinates(
    probabilities: np.ndarray,
    labels: np.ndarray,
    shuffled_probabilities: np.ndarray,
    config: LivingInverseReaderConfig,
) -> dict[str, object]:
    nll, accuracy, correct = _per_bit_statistics(probabilities, labels)
    shuffled_nll, _shuffled_accuracy, _shuffled_correct = _per_bit_statistics(
        shuffled_probabilities, labels
    )
    threshold, null_tail = _binomial_success_threshold(
        labels.shape[0], KEY_BITS, config.familywise_alpha
    )
    eligible = np.flatnonzero(
        (correct >= threshold)
        & (nll <= 1.0 - config.stable_nll_gain)
        & (nll < shuffled_nll)
    )
    order = sorted(
        (int(bit) for bit in eligible),
        key=lambda bit: (nll[bit] - shuffled_nll[bit], nll[bit], bit),
    )[: config.maximum_selected_bits]
    return {
        "selection_split": "CALIBRATION",
        "familywise_alpha": config.familywise_alpha,
        "hypotheses": KEY_BITS,
        "minimum_correct": threshold,
        "null_tail_probability_per_bit": null_tail,
        "maximum_selected_bits": config.maximum_selected_bits,
        "coordinates": order,
        "selected_bits": len(order),
        "details": [
            {
                "bit": bit,
                "correct": int(correct[bit]),
                "accuracy": float(accuracy[bit]),
                "nll_bits": float(nll[bit]),
                "shuffled_control_nll_bits": float(shuffled_nll[bit]),
            }
            for bit in order
        ],
        "development_statistics_used_for_selection": False,
    }


def _preselected_bit_transfer(
    probabilities: np.ndarray,
    labels: np.ndarray,
    shuffled_probabilities: np.ndarray,
    frozen_selection: Mapping[str, object],
    config: LivingInverseReaderConfig,
) -> dict[str, object]:
    coordinates = tuple(int(bit) for bit in frozen_selection["coordinates"])
    nll, accuracy, correct = _per_bit_statistics(probabilities, labels)
    shuffled_nll, _shuffled_accuracy, _shuffled_correct = _per_bit_statistics(
        shuffled_probabilities, labels
    )
    hypotheses = max(1, len(coordinates))
    threshold, null_tail = _binomial_success_threshold(
        labels.shape[0], hypotheses, config.familywise_alpha
    )
    transferred = [
        bit
        for bit in coordinates
        if correct[bit] >= threshold
        and nll[bit] <= 1.0 - config.stable_nll_gain
        and nll[bit] < shuffled_nll[bit]
    ]
    return {
        "coordinates_frozen_on_calibration": list(coordinates),
        "coordinates_tested": len(coordinates),
        "familywise_alpha": config.familywise_alpha,
        "minimum_correct": threshold,
        "null_tail_probability_per_bit": null_tail,
        "transferable_bits": len(transferred),
        "coordinates": transferred,
        "details": [
            {
                "bit": bit,
                "correct": int(correct[bit]),
                "accuracy": float(accuracy[bit]),
                "nll_bits": float(nll[bit]),
                "shuffled_control_nll_bits": float(shuffled_nll[bit]),
                "transferred": bit in transferred,
            }
            for bit in coordinates
        ],
        "unselected_development_bits_used_for_claim": False,
    }


def _training_candidate_matrix(
    targets: Sequence[ReaderTarget],
    config: LivingInverseReaderConfig,
    feature_map: HolographicFeatureMap,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, dict[str, object]]:
    mapped_rows: list[np.ndarray] = []
    correction_rows: list[np.ndarray] = []
    auxiliary_rows: list[np.ndarray] = []
    deployment_hasher = hashlib.sha256()
    correction_hasher = hashlib.sha256()
    neutral = np.full(KEY_BITS, 0.5, dtype=np.float64)
    for target_index, target in enumerate(targets):
        candidates = attacker_candidate_keys(
            target.public,
            neutral,
            count=config.candidates_per_target,
            seed=config.candidate_seed + target_index,
        )
        raw = np.stack(
            [
                candidate_feature_vector(target.public, candidate)
                for candidate in candidates
            ]
        )
        mapped = feature_map.transform(raw)
        candidate_bits = np.stack(
            [key_bits(candidate).astype(np.float32) for candidate in candidates]
        )
        corrections = np.not_equal(candidate_bits, target.key_labels[None, :]).astype(
            np.float32
        )
        mapped_rows.append(mapped)
        correction_rows.append(corrections)
        auxiliary_rows.append(
            np.repeat(
                target.teacher_features[None, :],
                config.candidates_per_target,
                axis=0,
            )
        )
        deployment_hasher.update(target.public.digest().encode("ascii"))
        deployment_hasher.update(b"".join(candidates))
        deployment_hasher.update(raw.tobytes())
        correction_hasher.update(corrections.tobytes())
    mapped_matrix = np.concatenate(mapped_rows, axis=0)
    corrections = np.concatenate(correction_rows, axis=0)
    auxiliary = np.concatenate(auxiliary_rows, axis=0)
    return (
        mapped_matrix,
        corrections,
        auxiliary,
        {
            "examples": int(mapped_matrix.shape[0]),
            "mapped_dimension": int(mapped_matrix.shape[1]),
            "deployment_input_sha256": deployment_hasher.hexdigest(),
            "teacher_correction_sha256": correction_hasher.hexdigest(),
            "raw_candidate_features_retained": False,
            "target_key_used_for_candidate_generation": False,
        },
    )


def _orient_correction_scores(
    correction_scores: np.ndarray, candidate_bits: np.ndarray
) -> np.ndarray:
    scores = np.asarray(correction_scores, dtype=np.float64)
    bits = np.asarray(candidate_bits, dtype=np.float64)
    if (
        scores.ndim != 2
        or scores.shape != bits.shape
        or scores.shape[1] != KEY_BITS
        or not np.all(np.isfinite(scores))
        or np.any((bits != 0.0) & (bits != 1.0))
    ):
        raise LivingInverseReaderError("correction scores and candidate bits differ")
    # correction = target XOR candidate.  A candidate one therefore reverses
    # the signed correction polarity when it is rotated into target-bit space.
    return scores * (1.0 - 2.0 * bits)


def _candidate_logits(
    public_targets: Sequence[PublicTargetView],
    direct_probabilities: np.ndarray,
    models: Mapping[str, FrozenHolographicRidge],
    config: LivingInverseReaderConfig,
    feature_map: HolographicFeatureMap,
    *,
    ablate_key_and_trace: bool = False,
    additional_ablated_models: Mapping[str, FrozenHolographicRidge] | None = None,
) -> tuple[dict[str, np.ndarray], str]:
    probabilities = np.asarray(direct_probabilities, dtype=np.float64)
    if probabilities.shape != (len(public_targets), KEY_BITS):
        raise LivingInverseReaderError("direct posterior portfolio shape differs")
    result = {
        name: np.zeros((len(public_targets), KEY_BITS), dtype=np.float64)
        for name in models
    }
    if additional_ablated_models:
        result.update(
            {
                f"{name}_key_trace_ablation": np.zeros(
                    (len(public_targets), KEY_BITS), dtype=np.float64
                )
                for name in additional_ablated_models
            }
        )
    deployment_hasher = hashlib.sha256()
    for target_index, (target, direct_row) in enumerate(
        zip(public_targets, probabilities, strict=True)
    ):
        candidates = attacker_candidate_keys(
            target,
            direct_row,
            count=config.candidates_per_target,
            seed=config.candidate_seed + target_index,
        )
        raw = np.stack(
            [candidate_feature_vector(target, candidate) for candidate in candidates]
        )
        if ablate_key_and_trace:
            raw[:, 1536:1792] = 0.0
            raw[:, 1920:CANDIDATE_FEATURE_DIMENSION] = 0.0
        mapped = feature_map.transform(raw)
        candidate_bits = np.stack(
            [key_bits(candidate).astype(np.float64) for candidate in candidates]
        )
        for name, model in models.items():
            correction_scores = model.predict_mapped(mapped)
            oriented = _orient_correction_scores(correction_scores, candidate_bits)
            accumulator = np.zeros(KEY_BITS, dtype=np.float64)
            evidence_count = 0
            for score in oriented:
                accumulator += score
                evidence_count += 1
            result[name][target_index] = accumulator / evidence_count
        if additional_ablated_models:
            ablated = raw.copy()
            ablated[:, 1536:1792] = 0.0
            ablated[:, 1920:CANDIDATE_FEATURE_DIMENSION] = 0.0
            ablated_mapped = feature_map.transform(ablated)
            for name, model in additional_ablated_models.items():
                correction_scores = model.predict_mapped(ablated_mapped)
                oriented = _orient_correction_scores(correction_scores, candidate_bits)
                accumulator = np.zeros(KEY_BITS, dtype=np.float64)
                for score in oriented:
                    accumulator += score
                result[f"{name}_key_trace_ablation"][target_index] = accumulator / len(
                    candidates
                )
            deployment_hasher.update(b"key-trace-ablation")
            deployment_hasher.update(ablated.tobytes())
        deployment_hasher.update(target.digest().encode("ascii"))
        deployment_hasher.update(b"".join(candidates))
        deployment_hasher.update(raw.tobytes())
    return result, deployment_hasher.hexdigest()


def _public_controls(
    targets: Sequence[PublicTargetView],
) -> dict[str, tuple[PublicTargetView, ...]]:
    permuted = tuple(
        PublicTargetView(
            counter_schedule=target.counter_schedule,
            nonce=target.nonce,
            output_blocks=targets[(index - 1) % len(targets)].output_blocks,
        )
        for index, target in enumerate(targets)
    )
    return {
        "output_permutation": permuted,
        "wrong_nonce": tuple(
            make_wrong_nonce_control(target, index % 96)
            for index, target in enumerate(targets)
        ),
        "output_flip": tuple(
            make_output_flip_control(target, (137 * index + 17) % 512)
            for index, target in enumerate(targets)
        ),
    }


def _prediction_bundle(
    matrices: Mapping[str, np.ndarray], target_ids: Sequence[str]
) -> tuple[bytes, dict[str, object]]:
    rows = []
    payloads = []
    offset = 0
    expected_shape = (len(target_ids), KEY_BITS)
    for name in sorted(matrices):
        values = np.asarray(matrices[name], dtype=np.float64)
        if (
            values.shape != expected_shape
            or not np.all(np.isfinite(values))
            or np.any((values <= 0.0) | (values >= 1.0))
        ):
            raise LivingInverseReaderError("development prediction matrix differs")
        payload = np.ascontiguousarray(values, dtype="<f8").tobytes()
        rows.append(
            {
                "name": name,
                "shape": list(values.shape),
                "offset": offset,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        payloads.append(payload)
        offset += len(payload)
    blob = b"".join(payloads)
    index_without_hash = {
        "schema": "o1-256-frozen-development-predictions-v1",
        "dtype": "float64-le",
        "target_order_sha256": canonical_sha256(list(target_ids)),
        "matrices": rows,
        "bytes": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "labels_read_before_freeze": 0,
    }
    return blob, {
        **index_without_hash,
        "index_sha256": canonical_sha256(index_without_hash),
    }


@dataclass(frozen=True)
class SealedDevelopmentPanel:
    target_ids: tuple[str, ...]
    public_targets: tuple[PublicTargetView, ...]
    publications: tuple[dict[str, object], ...]

    def validate(self, expected_count: int) -> None:
        if (
            len(self.target_ids) != expected_count
            or len(self.public_targets) != expected_count
            or len(self.publications) != expected_count
            or len(set(self.target_ids)) != expected_count
        ):
            raise LivingInverseReaderError("sealed development panel size differs")
        digests: set[str] = set()
        for target_id, public, publication in zip(
            self.target_ids,
            self.public_targets,
            self.publications,
            strict=True,
        ):
            checked = verify_publication(publication)
            parsed = public_view_from_publication(checked)
            public.validate()
            if (
                checked["target_id"] != target_id
                or public.block_count != 1
                or parsed.digest() != public.digest()
                or public.digest() in digests
            ):
                raise LivingInverseReaderError("sealed development publication differs")
            digests.add(public.digest())

    def describe(self) -> dict[str, object]:
        self.validate(len(self.target_ids))
        return {
            "targets": len(self.target_ids),
            "target_ids_sha256": canonical_sha256(list(self.target_ids)),
            "public_view_root": canonical_sha256(
                [target.digest() for target in self.public_targets]
            ),
            "publication_root": canonical_sha256(list(self.publications)),
            "keys_in_publications": False,
            "target_traces_in_publications": False,
        }


@dataclass(frozen=True)
class DevelopmentReveal:
    keys: tuple[bytes, ...]
    receipt: dict[str, object]

    def validate(
        self,
        panel: SealedDevelopmentPanel,
        prediction_index: Mapping[str, object],
    ) -> None:
        if (
            len(self.keys) != len(panel.public_targets)
            or len(set(self.keys)) != len(self.keys)
            or any(not isinstance(key, bytes) or len(key) != 32 for key in self.keys)
        ):
            raise LivingInverseReaderError("development reveal key inventory differs")
        canonical_json_bytes(self.receipt)
        if (
            self.receipt.get("predictions_frozen_before_reveal") is not True
            or self.receipt.get("frozen_prediction_sha256")
            != prediction_index.get("sha256")
            or self.receipt.get("frozen_prediction_index_sha256")
            != prediction_index.get("index_sha256")
        ):
            raise LivingInverseReaderError("development reveal receipt is not frozen")
        for key, public in zip(self.keys, panel.public_targets, strict=True):
            recomputed = build_known_target(
                key,
                counter=public.counter_schedule[0],
                nonce=public.nonce,
                block_count=1,
            )
            if recomputed.public.digest() != public.digest():
                raise LivingInverseReaderError(
                    "development reveal does not reproduce public output"
                )


@dataclass(frozen=True)
class LivingInverseReaderResult:
    report: dict[str, object]
    model_blobs: Mapping[str, bytes]
    posterior_blob: bytes
    posterior_index: dict[str, object]

    @property
    def execution_success_gate_passed(self) -> bool:
        return bool(self.report["execution_success_gate_passed"])

    @property
    def scientific_signal_gate_passed(self) -> bool:
        return bool(self.report["scientific_signal_gate"]["passed"])

    def metrics(self) -> dict[str, object]:
        primary = str(self.report["calibration"]["primary_arm"])
        development = self.report["development"]
        primary_metrics = development["arms"][primary]
        return {
            "schema": "o1-256-living-inverse-reader-metrics-v1",
            "execution_success_gate_passed": self.execution_success_gate_passed,
            "scientific_signal_gate_passed": self.scientific_signal_gate_passed,
            "scientific_inverse_signal_claimed": self.scientific_signal_gate_passed,
            "primary_arm": primary,
            "primary_development_mean_key_nll_bits": primary_metrics[
                "mean_key_nll_bits"
            ],
            "primary_development_compression_bits": primary_metrics[
                "mean_effective_compression_bits"
            ],
            "primary_transferable_bits": development["cross_split_bits"][primary][
                "transferable_bits"
            ],
            "shuffled_control_development_compression_bits": development["arms"][
                "shuffled_key_control"
            ]["mean_effective_compression_bits"],
            "unknown_target_key_bits": KEY_BITS,
            "target_trace_fields_in_deployment": 0,
            "train_targets": self.report["corpus"]["TRAIN"]["targets"],
            "calibration_targets": self.report["corpus"]["CALIBRATION"]["targets"],
            "development_targets": self.report["corpus"]["DEVELOPMENT"]["targets"],
            "candidate_training_examples": self.report["corpus"]["candidate_training"][
                "examples"
            ],
            "maximum_persistent_live_state_bytes": self.report["bounded_live_state"][
                "maximum_persistent_bytes_per_target_arm"
            ],
            "result_sha256": self.report["result_sha256"],
            "fresh_target_generated": True,
            "fresh_target_revealed": True,
            "fresh_target_count": self.report["corpus"]["DEVELOPMENT"]["targets"],
            "sibling_reads": 0,
            "sibling_writes": 0,
            "mps_calls": 0,
            "gpu_calls": 0,
        }


CalibrationFreeze = Callable[
    [dict[str, object], Mapping[str, bytes]], dict[str, object]
]
DevelopmentOpen = Callable[[], SealedDevelopmentPanel]
DevelopmentFreezeAndReveal = Callable[[bytes, dict[str, object]], DevelopmentReveal]


def run_living_inverse_reader_experiment(
    config: LivingInverseReaderConfig,
    *,
    open_sealed_development: DevelopmentOpen,
    freeze_predictions_and_reveal: DevelopmentFreezeAndReveal,
    on_calibration_frozen: CalibrationFreeze | None = None,
    require_calibration_persistence: bool = False,
) -> LivingInverseReaderResult:
    direct_plan = direct_feature_plan(config)
    candidate_plan = candidate_feature_plan(config)
    direct_map = HolographicFeatureMap(direct_plan)
    candidate_map = HolographicFeatureMap(candidate_plan)

    train = _make_targets(
        config,
        "TRAIN",
        config.train_targets,
        structured_count=config.train_structured_targets,
    )
    calibration = _make_targets(config, "CALIBRATION", config.calibration_targets)
    _assert_disjoint(train, calibration)
    train_inventory = _target_inventory(train)
    calibration_inventory = _target_inventory(calibration)
    train_keys = tuple(target.key for target in train)
    calibration_keys = tuple(target.key for target in calibration)
    known_public_digests = {target.public.digest() for target in (*train, *calibration)}
    calibration_views = tuple(target.public for target in calibration)
    train_labels = np.stack([target.key_labels for target in train])
    calibration_labels = np.stack([target.key_labels for target in calibration])
    train_public = np.stack([target.public_features for target in train])
    train_feature_sha256 = _matrix_sha256(train_public)
    train_label_sha256 = _matrix_sha256(train_labels)
    calibration_public = np.stack([target.public_features for target in calibration])
    train_direct_mapped = direct_map.transform(train_public)
    calibration_direct_mapped = direct_map.transform(calibration_public)

    direct_model = fit_holographic_ridge(
        direct_plan,
        train_direct_mapped,
        train_labels,
        ridge_lambda=config.ridge_lambda,
        rank=config.rank,
    )
    shuffled_labels = np.roll(train_labels, 1, axis=0)
    shuffled_model = fit_holographic_ridge(
        direct_plan,
        train_direct_mapped,
        shuffled_labels,
        ridge_lambda=config.ridge_lambda,
        rank=config.rank,
    )
    candidate_mapped, corrections, auxiliary, candidate_inventory = (
        _training_candidate_matrix(train, config, candidate_map)
    )
    # Retain only compact labels/public views before the memory-heaviest fit.
    del train, calibration, train_public, train_labels, shuffled_labels
    del train_direct_mapped
    distilled_model = fit_holographic_ridge(
        candidate_plan,
        candidate_mapped,
        corrections,
        ridge_lambda=config.ridge_lambda,
        rank=config.rank,
        auxiliary_labels=auxiliary,
        auxiliary_weight=config.auxiliary_weight,
    )
    del auxiliary
    relative_model = fit_holographic_ridge(
        candidate_plan,
        candidate_mapped,
        corrections,
        ridge_lambda=config.ridge_lambda,
        rank=config.rank,
    )
    del candidate_mapped, corrections

    calibration_logits: dict[str, np.ndarray] = {
        "direct": direct_model.predict_mapped(calibration_direct_mapped),
        "shuffled_key_control": shuffled_model.predict_mapped(
            calibration_direct_mapped
        ),
    }
    direct_scale, direct_curve = _select_scale(
        calibration_logits["direct"], calibration_labels, config.shrinkage_grid
    )
    calibration_direct_probabilities = _posterior(
        calibration_logits["direct"], direct_scale
    )
    candidate_calibration_logits, calibration_candidate_commitment = _candidate_logits(
        calibration_views,
        calibration_direct_probabilities,
        {"relative": relative_model, "distilled": distilled_model},
        config,
        candidate_map,
    )
    calibration_logits.update(candidate_calibration_logits)
    scales: dict[str, float] = {"direct": direct_scale}
    curves: dict[str, tuple[dict[str, float], ...]] = {"direct": direct_curve}
    for arm in ("relative", "distilled", "shuffled_key_control"):
        scales[arm], curves[arm] = _select_scale(
            calibration_logits[arm], calibration_labels, config.shrinkage_grid
        )
    calibration_posteriors = {
        arm: _posterior(calibration_logits[arm], scales[arm]) for arm in POSTERIOR_ARMS
    }
    calibration_evaluations = {
        arm: _evaluation(calibration_posteriors[arm], calibration_labels, config)
        for arm in POSTERIOR_ARMS
    }
    frozen_bit_selections = {
        arm: _freeze_bit_coordinates(
            calibration_posteriors[arm],
            calibration_labels,
            calibration_posteriors["shuffled_key_control"],
            config,
        )
        for arm in FACTUAL_ARMS
    }
    primary_arm = min(
        FACTUAL_ARMS,
        key=lambda arm: (
            calibration_evaluations[arm]["mean_key_nll_bits"],
            FACTUAL_ARMS.index(arm),
        ),
    )
    model_blobs = {
        "direct": serialize_ridge(direct_model),
        "relative": serialize_ridge(relative_model),
        "distilled": serialize_ridge(distilled_model),
        "shuffled_key_control": serialize_ridge(shuffled_model),
    }
    calibration_document = {
        "schema": "o1-256-living-inverse-calibration-freeze-v1",
        "primary_arm": primary_arm,
        "arm_order": list(FACTUAL_ARMS),
        "scales": scales,
        "curves": {arm: list(curves[arm]) for arm in POSTERIOR_ARMS},
        "evaluations": calibration_evaluations,
        "frozen_bit_selections": frozen_bit_selections,
        "direct_plan": direct_plan.describe(),
        "candidate_plan": candidate_plan.describe(),
        "models": {
            arm: {
                "sha256": hashlib.sha256(blob).hexdigest(),
                "bytes": len(blob),
            }
            for arm, blob in model_blobs.items()
        },
        "calibration_candidate_deployment_sha256": calibration_candidate_commitment,
        "development_targets_created": 0,
        "development_publications_opened": 0,
        "development_labels_read": 0,
    }
    receipt: dict[str, object]
    if on_calibration_frozen is None:
        if require_calibration_persistence:
            raise LivingInverseReaderError(
                "production reader requires a persisted calibration callback"
            )
        receipt = {
            "schema": "o1-256-calibration-freeze-receipt-v1",
            "persisted": False,
            "unit_or_dry_mode": True,
        }
    else:
        receipt = on_calibration_frozen(calibration_document, model_blobs)
        if not isinstance(receipt, dict) or receipt.get("persisted") is not True:
            raise LivingInverseReaderError("calibration persistence receipt differs")

    # No Development key exists in config or in this function before the model,
    # scales, bit coordinates, proposal policy and primary arm are persisted.
    panel = open_sealed_development()
    if not isinstance(panel, SealedDevelopmentPanel):
        raise LivingInverseReaderError("sealed development callback differs")
    panel.validate(config.development_targets)
    if any(target.digest() in known_public_digests for target in panel.public_targets):
        raise LivingInverseReaderError("development public view overlaps TRAIN/CAL")
    development_public = np.stack(
        [public_target_feature_vector(target) for target in panel.public_targets]
    )
    development_direct_mapped = direct_map.transform(development_public)
    development_logits: dict[str, np.ndarray] = {
        "direct": direct_model.predict_mapped(development_direct_mapped),
        "shuffled_key_control": shuffled_model.predict_mapped(
            development_direct_mapped
        ),
    }
    development_direct_probabilities = _posterior(
        development_logits["direct"], scales["direct"]
    )
    factual_models = {"relative": relative_model, "distilled": distilled_model}
    ablated_models = (
        None if primary_arm == "direct" else {primary_arm: factual_models[primary_arm]}
    )
    factual_candidate_logits, development_candidate_commitment = _candidate_logits(
        panel.public_targets,
        development_direct_probabilities,
        factual_models,
        config,
        candidate_map,
        additional_ablated_models=ablated_models,
    )
    ablated_logits = None
    if primary_arm != "direct":
        ablated_logits = factual_candidate_logits.pop(
            f"{primary_arm}_key_trace_ablation"
        )
    development_logits.update(factual_candidate_logits)
    development_posteriors = {
        arm: _posterior(development_logits[arm], scales[arm]) for arm in POSTERIOR_ARMS
    }

    controls = _public_controls(panel.public_targets)
    direct_control_posteriors: dict[str, np.ndarray] = {}
    for name, public_views in controls.items():
        features = np.stack(
            [public_target_feature_vector(target) for target in public_views]
        )
        scores = direct_model.predict_mapped(direct_map.transform(features))
        probabilities = _posterior(scores, scales["direct"])
        direct_control_posteriors[name] = probabilities

    primary_control_posteriors: dict[str, np.ndarray] = {}
    primary_control_commitments: dict[str, str] = {}
    if primary_arm == "direct":
        primary_control_posteriors = dict(direct_control_posteriors)
    else:
        if ablated_logits is None:
            raise AssertionError("primary ablation logits are absent")
        primary_control_posteriors["candidate_key_trace_ablation"] = _posterior(
            ablated_logits, scales[primary_arm]
        )
        permuted_direct_features = np.stack(
            [
                public_target_feature_vector(target)
                for target in controls["output_permutation"]
            ]
        )
        permuted_direct_scores = direct_model.predict_mapped(
            direct_map.transform(permuted_direct_features)
        )
        permuted_direct_probabilities = _posterior(
            permuted_direct_scores, scales["direct"]
        )
        permuted_logits, permuted_commitment = _candidate_logits(
            controls["output_permutation"],
            permuted_direct_probabilities,
            {primary_arm: factual_models[primary_arm]},
            config,
            candidate_map,
        )
        primary_control_posteriors["output_permutation"] = _posterior(
            permuted_logits[primary_arm], scales[primary_arm]
        )
        primary_control_commitments["output_permutation_deployment_sha256"] = (
            permuted_commitment
        )

    prediction_matrices = {
        **{f"factual/{arm}": development_posteriors[arm] for arm in POSTERIOR_ARMS},
        **{
            f"direct_control/{name}": probabilities
            for name, probabilities in direct_control_posteriors.items()
        },
        **{
            f"primary_control/{name}": probabilities
            for name, probabilities in primary_control_posteriors.items()
        },
    }
    prediction_blob, prediction_index = _prediction_bundle(
        prediction_matrices, panel.target_ids
    )
    reveal = freeze_predictions_and_reveal(prediction_blob, prediction_index)
    if not isinstance(reveal, DevelopmentReveal):
        raise LivingInverseReaderError("development reveal callback differs")
    reveal.validate(panel, prediction_index)
    development_keys = reveal.keys
    if set(development_keys) & set((*train_keys, *calibration_keys)):
        raise LivingInverseReaderError("development key overlaps TRAIN/CAL")
    development_labels = np.stack(
        [key_bits(key).astype(np.float32) for key in development_keys]
    )

    development_evaluations = {
        arm: _evaluation(development_posteriors[arm], development_labels, config)
        for arm in POSTERIOR_ARMS
    }
    cross_split = {
        arm: _preselected_bit_transfer(
            development_posteriors[arm],
            development_labels,
            development_posteriors["shuffled_key_control"],
            frozen_bit_selections[arm],
            config,
        )
        for arm in FACTUAL_ARMS
    }
    direct_control_reports = {
        name: _evaluation(probabilities, development_labels, config)
        for name, probabilities in direct_control_posteriors.items()
    }
    primary_control = {
        "arm": primary_arm,
        **{
            name: _evaluation(probabilities, development_labels, config)
            for name, probabilities in primary_control_posteriors.items()
        },
        **primary_control_commitments,
    }

    sentinel = {}
    for arm_index, arm in enumerate(POSTERIOR_ARMS):
        sentinel[arm] = posterior_metrics(
            development_keys[0],
            development_posteriors[arm][0],
            confidence_threshold=config.confidence_threshold,
            decoy_count=config.decoy_count,
            decoy_seed=config.decoy_seed + arm_index,
            beam_uncertain_bits=config.beam_uncertain_bits,
            beam_size=config.beam_size,
        )

    primary_compression = float(
        development_evaluations[primary_arm]["mean_effective_compression_bits"]
    )
    shuffled_compression = float(
        development_evaluations["shuffled_key_control"][
            "mean_effective_compression_bits"
        ]
    )
    transferable_bits = int(cross_split[primary_arm]["transferable_bits"])
    scientific_criteria = {
        "primary_compression_at_least_threshold": (
            primary_compression >= config.signal_compression_bits
        ),
        "primary_beats_shuffled_control_by_margin": (
            primary_compression - shuffled_compression
            >= config.signal_control_margin_bits
        ),
        "at_least_one_cross_split_transferable_bit": transferable_bits >= 1,
    }
    scientific_gate = {
        "passed": all(scientific_criteria.values()),
        "criteria": scientific_criteria,
        "compression_threshold_bits": config.signal_compression_bits,
        "control_margin_threshold_bits": config.signal_control_margin_bits,
        "observed_primary_compression_bits": primary_compression,
        "observed_shuffled_compression_bits": shuffled_compression,
        "observed_transferable_bits": transferable_bits,
    }

    all_keys = [*train_keys, *calibration_keys, *development_keys]
    if len(set(all_keys)) != len(all_keys):
        raise LivingInverseReaderError("full corpus key collision detected")
    development_inventory = {
        **panel.describe(),
        "structured_targets": 0,
        "uniform_targets": len(development_keys),
        "reveal_key_commitment_root": canonical_sha256(
            [hashlib.sha256(key).hexdigest() for key in development_keys]
        ),
        "predictions_frozen_before_reveal": True,
        "reveal_receipt": reveal.receipt,
    }

    report_without_hash = {
        "schema": "o1-256-living-inverse-reader-result-v1",
        "config": config.describe(),
        "attacker_contract": {
            "cipher": "ChaCha20",
            "rounds": 20,
            "feed_forward": True,
            "unknown_target_key_bits": KEY_BITS,
            "public_target_fields": ["counter", "nonce", "full_round_output"],
            "deployment_target_object": "PublicTargetView",
            "target_key_fields_in_deployment": 0,
            "target_trace_fields_in_deployment": 0,
            "candidate_key_and_trace_attacker_computable": True,
            "reduced_width_target": False,
        },
        "protocol": {
            "train_then_calibration_then_development": True,
            "development_created_after_calibration_freeze": True,
            "development_entropy_present_before_calibration_freeze": False,
            "development_keys_absent_from_committed_config": True,
            "development_predictions_frozen_before_reveal": True,
            "primary_arm_selected_on": "CALIBRATION",
            "development_openings": 1,
            "candidate_policy_inputs": [
                "PublicTargetView",
                "frozen_direct_posterior",
                "frozen_seed",
            ],
            "training_candidate_anchor": "neutral-public-portfolio",
            "fresh_target_generated": True,
            "fresh_target_revealed": True,
            "fresh_target_count": len(development_keys),
        },
        "feature_plans": {
            "direct": direct_plan.describe(),
            "candidate": candidate_plan.describe(),
        },
        "corpus": {
            "TRAIN": train_inventory,
            "CALIBRATION": calibration_inventory,
            "DEVELOPMENT": development_inventory,
            "candidate_training": candidate_inventory,
            "direct_training_feature_sha256": train_feature_sha256,
            "direct_training_label_sha256": train_label_sha256,
            "all_keys_unique": True,
            "full_width_only": True,
        },
        "models": {
            "direct": direct_model.describe(),
            "relative": relative_model.describe(),
            "distilled": distilled_model.describe(),
            "shuffled_key_control": shuffled_model.describe(),
        },
        "calibration": {
            **calibration_document,
            "freeze_receipt": receipt,
        },
        "development": {
            "arms": development_evaluations,
            "cross_split_bits": cross_split,
            "candidate_deployment_sha256": development_candidate_commitment,
            "direct_controls": direct_control_reports,
            "primary_control": primary_control,
            "sentinel_index": 0,
            "sentinel": sentinel,
            "frozen_prediction_binary": prediction_index,
        },
        "bounded_live_state": {
            "evidence_accumulator_bytes": KEY_BITS * 8,
            "evidence_count_bytes": 8,
            "maximum_persistent_bytes_per_target_arm": KEY_BITS * 8 + 8,
            "holographic_event_bank_bytes": candidate_plan.output_dimension * 4,
            "state_independent_of_stream_length": True,
            "static_reader_parameters_excluded_from_live_state": True,
        },
        "scientific_signal_gate": scientific_gate,
        "execution_success_gate_passed": True,
        "sibling_reads": 0,
        "sibling_writes": 0,
        "mps_calls": 0,
        "gpu_calls": 0,
    }
    report = {
        **report_without_hash,
        "result_sha256": canonical_sha256(report_without_hash),
    }
    return LivingInverseReaderResult(
        report=report,
        model_blobs=model_blobs,
        posterior_blob=prediction_blob,
        posterior_index=prediction_index,
    )


__all__ = [
    "DevelopmentReveal",
    "FACTUAL_ARMS",
    "LivingInverseReaderConfig",
    "LivingInverseReaderError",
    "LivingInverseReaderResult",
    "SealedDevelopmentPanel",
    "candidate_feature_plan",
    "direct_feature_plan",
    "load_living_inverse_reader_config",
    "run_living_inverse_reader_experiment",
]
