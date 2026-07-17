"""Prospective no-refit replication of the O1C-0009 signed direct breadcrumb."""

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
    canonical_json_bytes,
    canonical_sha256,
    key_bits,
    public_target_feature_vector,
)
from .living_inverse_reader_experiment import (
    DevelopmentReveal,
    SealedDevelopmentPanel,
    _prediction_bundle,
    _public_controls,
)
from .living_inverse_ridge import FrozenHolographicRidge, deserialize_ridge


SIGNED_REPLICATION_SCHEMA = "o1-256-signed-direct-replication-config-v1"
PREDICTION_ARMS = (
    "control/output_flip",
    "control/output_permutation",
    "control/polarity_reverse",
    "control/shuffled_signed",
    "control/wrong_nonce",
    "factual/direct_signed",
)


class SignedDirectReplicationError(ValueError):
    """Raised when the no-refit replication contract differs."""


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise SignedDirectReplicationError(
            f"{field} must be an integer in [{minimum}, {maximum}]"
        )
    return value


def _finite(value: object, field: str, minimum: float, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not minimum <= float(value) <= maximum
    ):
        raise SignedDirectReplicationError(
            f"{field} must be finite in [{minimum}, {maximum}]"
        )
    return float(value)


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise SignedDirectReplicationError(f"{field} must be a lowercase SHA-256")
    return value


@dataclass(frozen=True)
class FrozenReaderSource:
    source_attempt_id: str
    source_capsule: str
    source_manifest_sha256: str
    source_result_sha256: str
    direct_model_artifact: str
    direct_model_sha256: str
    shuffled_model_artifact: str
    shuffled_model_sha256: str
    direct_scale: float
    shuffled_scale: float
    selection_origin: str

    @classmethod
    def from_mapping(cls, value: object) -> "FrozenReaderSource":
        if not isinstance(value, dict):
            raise SignedDirectReplicationError("source must be an object")
        expected = {
            "source_attempt_id",
            "source_capsule",
            "source_manifest_sha256",
            "source_result_sha256",
            "direct_model_artifact",
            "direct_model_sha256",
            "shuffled_model_artifact",
            "shuffled_model_sha256",
            "direct_scale",
            "shuffled_scale",
            "selection_origin",
        }
        if set(value) != expected:
            raise SignedDirectReplicationError("source fields differ")
        strings = {
            field: value[field]
            for field in (
                "source_attempt_id",
                "source_capsule",
                "direct_model_artifact",
                "shuffled_model_artifact",
                "selection_origin",
            )
        }
        if any(
            not isinstance(item, str) or not item or len(item) > 512
            for item in strings.values()
        ):
            raise SignedDirectReplicationError("source string field is invalid")
        source = cls(
            **strings,  # type: ignore[arg-type]
            source_manifest_sha256=_sha256(
                value["source_manifest_sha256"], "source_manifest_sha256"
            ),
            source_result_sha256=_sha256(
                value["source_result_sha256"], "source_result_sha256"
            ),
            direct_model_sha256=_sha256(
                value["direct_model_sha256"], "direct_model_sha256"
            ),
            shuffled_model_sha256=_sha256(
                value["shuffled_model_sha256"], "shuffled_model_sha256"
            ),
            direct_scale=_finite(value["direct_scale"], "direct_scale", -4.0, 4.0),
            shuffled_scale=_finite(
                value["shuffled_scale"], "shuffled_scale", -4.0, 4.0
            ),
        )
        if source.direct_scale >= 0.0 or source.shuffled_scale >= 0.0:
            raise SignedDirectReplicationError("replication scales must remain negative")
        return source

    def describe(self) -> dict[str, object]:
        return {
            "source_attempt_id": self.source_attempt_id,
            "source_capsule": self.source_capsule,
            "source_manifest_sha256": self.source_manifest_sha256,
            "source_result_sha256": self.source_result_sha256,
            "direct_model_artifact": self.direct_model_artifact,
            "direct_model_sha256": self.direct_model_sha256,
            "shuffled_model_artifact": self.shuffled_model_artifact,
            "shuffled_model_sha256": self.shuffled_model_sha256,
            "direct_scale": self.direct_scale,
            "shuffled_scale": self.shuffled_scale,
            "selection_origin": self.selection_origin,
        }


@dataclass(frozen=True)
class SignedDirectReplicationConfig:
    development_targets: int
    minimum_direct_compression_bits: float
    minimum_direct_conditional_z: float
    minimum_target_lcb_z: float
    minimum_shuffled_margin_bits: float
    minimum_output_permutation_margin_bits: float
    minimum_paired_conditional_z: float

    @classmethod
    def from_mapping(cls, value: object) -> "SignedDirectReplicationConfig":
        if not isinstance(value, dict):
            raise SignedDirectReplicationError("replication must be an object")
        expected = {
            "development_targets",
            "minimum_direct_compression_bits",
            "minimum_direct_conditional_z",
            "minimum_target_lcb_z",
            "minimum_shuffled_margin_bits",
            "minimum_output_permutation_margin_bits",
            "minimum_paired_conditional_z",
        }
        if set(value) != expected:
            raise SignedDirectReplicationError("replication fields differ")
        return cls(
            development_targets=_integer(
                value["development_targets"], "development_targets", 2, 8192
            ),
            minimum_direct_compression_bits=_finite(
                value["minimum_direct_compression_bits"],
                "minimum_direct_compression_bits",
                0.0,
                16.0,
            ),
            minimum_direct_conditional_z=_finite(
                value["minimum_direct_conditional_z"],
                "minimum_direct_conditional_z",
                0.0,
                16.0,
            ),
            minimum_target_lcb_z=_finite(
                value["minimum_target_lcb_z"], "minimum_target_lcb_z", 0.0, 8.0
            ),
            minimum_shuffled_margin_bits=_finite(
                value["minimum_shuffled_margin_bits"],
                "minimum_shuffled_margin_bits",
                0.0,
                16.0,
            ),
            minimum_output_permutation_margin_bits=_finite(
                value["minimum_output_permutation_margin_bits"],
                "minimum_output_permutation_margin_bits",
                0.0,
                16.0,
            ),
            minimum_paired_conditional_z=_finite(
                value["minimum_paired_conditional_z"],
                "minimum_paired_conditional_z",
                0.0,
                16.0,
            ),
        )

    def describe(self) -> dict[str, object]:
        return {
            "development_targets": self.development_targets,
            "minimum_direct_compression_bits": self.minimum_direct_compression_bits,
            "minimum_direct_conditional_z": self.minimum_direct_conditional_z,
            "minimum_target_lcb_z": self.minimum_target_lcb_z,
            "minimum_shuffled_margin_bits": self.minimum_shuffled_margin_bits,
            "minimum_output_permutation_margin_bits": (
                self.minimum_output_permutation_margin_bits
            ),
            "minimum_paired_conditional_z": self.minimum_paired_conditional_z,
        }


def load_signed_direct_replication_config(
    path: str | Path,
) -> tuple[dict[str, object], FrozenReaderSource, SignedDirectReplicationConfig]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema") != SIGNED_REPLICATION_SCHEMA:
        raise SignedDirectReplicationError("signed replication schema differs")
    expected = {
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
        "replication",
    }
    if set(raw) != expected:
        raise SignedDirectReplicationError("top-level replication fields differ")
    return (
        raw,
        FrozenReaderSource.from_mapping(raw["source"]),
        SignedDirectReplicationConfig.from_mapping(raw["replication"]),
    )


def _posterior(logits: np.ndarray, scale: float) -> np.ndarray:
    scores = np.asarray(logits, dtype=np.float64)
    if (
        scores.ndim != 2
        or scores.shape[1] != KEY_BITS
        or not np.all(np.isfinite(scores))
        or not math.isfinite(scale)
    ):
        raise SignedDirectReplicationError("reader scores must be finite Nx256")
    scaled = np.clip(scores * scale, -30.0, 30.0)
    return 1.0 / (1.0 + np.exp(-scaled))


def _conditional_null_from_outcomes(
    outcome_zero: np.ndarray,
    outcome_one: np.ndarray,
    observed_mean: float,
) -> dict[str, float | int | str]:
    zero = np.asarray(outcome_zero, dtype=np.float64)
    one = np.asarray(outcome_one, dtype=np.float64)
    if (
        zero.shape != one.shape
        or zero.ndim != 2
        or zero.shape[1] != KEY_BITS
        or not np.all(np.isfinite(zero))
        or not np.all(np.isfinite(one))
        or not math.isfinite(observed_mean)
    ):
        raise SignedDirectReplicationError("conditional-null outcomes differ")
    targets = zero.shape[0]
    null_mean = float(np.sum((zero + one) * 0.5) / targets)
    null_variance = float(np.sum(np.square((one - zero) * 0.5)) / targets**2)
    null_sd = math.sqrt(max(null_variance, 0.0))
    if null_sd == 0.0:
        if not math.isclose(observed_mean, null_mean, abs_tol=1e-12):
            raise SignedDirectReplicationError(
                "zero-variance conditional null differs from observation"
            )
        z_score = 0.0
        p_value = 0.5
    else:
        z_score = (observed_mean - null_mean) / null_sd
        p_value = 0.5 * math.erfc(z_score / math.sqrt(2.0))
    centered_half_difference = (one - zero) * 0.5
    weight_square = np.square(centered_half_difference)
    weight_square_sum = float(np.sum(weight_square))
    weight_fourth_sum = float(np.sum(np.square(weight_square)))
    effective_terms = (
        weight_square_sum**2 / weight_fourth_sum
        if weight_fourth_sum > 0.0
        else 0.0
    )
    maximum_variance_share = (
        float(np.max(weight_square)) / weight_square_sum
        if weight_square_sum > 0.0
        else 0.0
    )
    return {
        "method": "conditional-uniform-key-exact-moments-normal-tail-v1",
        "reference_assumption": (
            "fixed public-input scores with independent uniform Rademacher key labels"
        ),
        "distribution_free": False,
        "moments_exact_under_reference_assumption": True,
        "tail_is_normal_approximation": True,
        "independent_secret_bits": targets * KEY_BITS,
        "null_mean_bits": null_mean,
        "null_standard_deviation_bits": null_sd,
        "observed_minus_null_bits": observed_mean - null_mean,
        "z_score": z_score,
        "normal_approx_one_sided_p_value": p_value,
        "effective_weighted_terms": effective_terms,
        "maximum_single_bit_variance_share": maximum_variance_share,
    }


def conditional_uniform_compression_null(
    probabilities: np.ndarray,
    labels: np.ndarray,
) -> dict[str, float | int | str]:
    values = np.asarray(probabilities, dtype=np.float64)
    truth = np.asarray(labels, dtype=np.float64)
    if (
        values.shape != truth.shape
        or values.ndim != 2
        or values.shape[1] != KEY_BITS
        or not np.all(np.isfinite(values))
        or np.any((values <= 0.0) | (values >= 1.0))
        or np.any((truth != 0.0) & (truth != 1.0))
    ):
        raise SignedDirectReplicationError("posterior and labels must be matched Nx256")
    compression_zero = 1.0 + np.log1p(-values) / math.log(2.0)
    compression_one = 1.0 + np.log(values) / math.log(2.0)
    observed = np.where(truth == 1.0, compression_one, compression_zero)
    return _conditional_null_from_outcomes(
        compression_zero,
        compression_one,
        float(np.sum(observed) / values.shape[0]),
    )


def conditional_uniform_paired_null(
    factual: np.ndarray,
    control: np.ndarray,
    labels: np.ndarray,
) -> dict[str, float | int | str]:
    left = np.asarray(factual, dtype=np.float64)
    right = np.asarray(control, dtype=np.float64)
    truth = np.asarray(labels, dtype=np.float64)
    if (
        left.shape != right.shape
        or left.shape != truth.shape
        or left.ndim != 2
        or left.shape[1] != KEY_BITS
        or not np.all(np.isfinite(left))
        or not np.all(np.isfinite(right))
        or np.any((left <= 0.0) | (left >= 1.0))
        or np.any((right <= 0.0) | (right >= 1.0))
        or np.any((truth != 0.0) & (truth != 1.0))
    ):
        raise SignedDirectReplicationError("paired posterior arrays differ")
    # Direct-minus-control compression equals control NLL minus direct NLL.
    delta_zero = (np.log1p(-left) - np.log1p(-right)) / math.log(2.0)
    delta_one = (np.log(left) - np.log(right)) / math.log(2.0)
    observed = np.where(truth == 1.0, delta_one, delta_zero)
    return _conditional_null_from_outcomes(
        delta_zero,
        delta_one,
        float(np.sum(observed) / left.shape[0]),
    )


def _arm_evaluation(
    probabilities: np.ndarray, labels: np.ndarray
) -> dict[str, object]:
    values = np.asarray(probabilities, dtype=np.float64)
    truth = np.asarray(labels, dtype=np.float64)
    if (
        values.shape != truth.shape
        or values.ndim != 2
        or values.shape[1] != KEY_BITS
        or not np.all(np.isfinite(values))
        or np.any((values <= 0.0) | (values >= 1.0))
        or np.any((truth != 0.0) & (truth != 1.0))
    ):
        raise SignedDirectReplicationError("posterior evaluation arrays differ")
    selected = np.where(truth == 1.0, values, 1.0 - values)
    per_target_nll = -np.log2(selected).sum(axis=1)
    per_target_compression = KEY_BITS - per_target_nll
    predictions = values >= 0.5
    correct = predictions == truth
    per_bit_nll = -np.log2(selected).mean(axis=0)
    per_bit_accuracy = np.mean(correct, axis=0)
    per_bit_compression = 1.0 - per_bit_nll
    byte_correct = correct.reshape(values.shape[0], 32, 8).all(axis=2).sum(axis=1)
    word16_correct = correct.reshape(values.shape[0], 16, 16).all(axis=2).sum(axis=1)
    sample_sd = float(np.std(per_target_compression, ddof=1))
    order = np.lexsort((np.arange(KEY_BITS), -per_bit_compression))
    bit_rows = [
        {
            "bit": int(bit),
            "accuracy": float(per_bit_accuracy[bit]),
            "nll_bits": float(per_bit_nll[bit]),
            "compression_bits": float(per_bit_compression[bit]),
        }
        for bit in order
    ]
    return {
        "targets": values.shape[0],
        "mean_key_nll_bits": float(np.mean(per_target_nll)),
        "mean_effective_compression_bits": float(np.mean(per_target_compression)),
        "median_effective_compression_bits": float(np.median(per_target_compression)),
        "minimum_effective_compression_bits": float(np.min(per_target_compression)),
        "maximum_effective_compression_bits": float(np.max(per_target_compression)),
        "per_target_compression_sample_sd_bits": sample_sd,
        "per_target_compression_standard_error_bits": (
            sample_sd / math.sqrt(values.shape[0])
        ),
        "positive_compression_targets": int(np.sum(per_target_compression > 0.0)),
        "bit_accuracy": float(np.mean(correct)),
        "mean_correct_key_bits": float(np.mean(np.sum(correct, axis=1))),
        "mean_exact_bytes": float(np.mean(byte_correct)),
        "mean_exact_16bit_blocks": float(np.mean(word16_correct)),
        "exact_keys": int(np.sum(np.all(correct, axis=1))),
        "conditional_uniform_key_null": conditional_uniform_compression_null(
            values, truth
        ),
        "top_bits": bit_rows[:16],
        "all_bit_diagnostics": bit_rows,
        "posterior_set_sha256": hashlib.sha256(
            np.ascontiguousarray(values, dtype="<f8").tobytes()
        ).hexdigest(),
    }


def _paired_evaluation(
    factual: np.ndarray, control: np.ndarray, labels: np.ndarray
) -> dict[str, object]:
    truth = np.asarray(labels, dtype=np.float64)
    left_selected = np.where(truth == 1.0, factual, 1.0 - factual)
    right_selected = np.where(truth == 1.0, control, 1.0 - control)
    per_target_delta = (
        (np.log(left_selected) - np.log(right_selected)).sum(axis=1)
        / math.log(2.0)
    )
    sample_sd = float(np.std(per_target_delta, ddof=1))
    return {
        "targets": factual.shape[0],
        "mean_direct_minus_control_compression_bits": float(
            np.mean(per_target_delta)
        ),
        "median_direct_minus_control_compression_bits": float(
            np.median(per_target_delta)
        ),
        "sample_sd_bits": sample_sd,
        "standard_error_bits": sample_sd / math.sqrt(factual.shape[0]),
        "positive_delta_targets": int(np.sum(per_target_delta > 0.0)),
        "conditional_uniform_key_null": conditional_uniform_paired_null(
            factual, control, truth
        ),
    }


def _predict(
    model: FrozenHolographicRidge,
    targets: Sequence[PublicTargetView],
    scale: float,
) -> np.ndarray:
    features = np.stack([public_target_feature_vector(target) for target in targets])
    return _posterior(model.predict(features), scale)


@dataclass(frozen=True)
class SignedDirectReplicationResult:
    report: dict[str, object]
    prediction_blob: bytes
    prediction_index: dict[str, object]

    @property
    def execution_success_gate_passed(self) -> bool:
        return bool(self.report["execution_success_gate_passed"])

    @property
    def scientific_signal_gate_passed(self) -> bool:
        return bool(self.report["scientific_signal_gate"]["passed"])

    def metrics(self) -> dict[str, object]:
        direct = self.report["evaluation"]["arms"]["factual/direct_signed"]
        return {
            "schema": "o1-256-signed-direct-replication-metrics-v1",
            "execution_success_gate_passed": self.execution_success_gate_passed,
            "scientific_signal_gate_passed": self.scientific_signal_gate_passed,
            "scientific_subkey_signal_claimed": self.scientific_signal_gate_passed,
            "full_key_recovery_claimed": False,
            "mean_key_nll_bits": direct["mean_key_nll_bits"],
            "mean_effective_compression_bits": direct[
                "mean_effective_compression_bits"
            ],
            "conditional_null_z_score": direct["conditional_uniform_key_null"][
                "z_score"
            ],
            "direct_minus_shuffled_compression_bits": self.report["evaluation"][
                "paired_controls"
            ]["control/shuffled_signed"][
                "mean_direct_minus_control_compression_bits"
            ],
            "direct_minus_output_permutation_compression_bits": self.report[
                "evaluation"
            ]["paired_controls"]["control/output_permutation"][
                "mean_direct_minus_control_compression_bits"
            ],
            "fresh_target_count": self.report["protocol"]["fresh_target_count"],
            "unknown_target_key_bits": KEY_BITS,
            "target_trace_fields_in_deployment": 0,
            "source_models_refit": False,
            "result_sha256": self.report["result_sha256"],
            "sibling_reads": 0,
            "sibling_writes": 0,
            "mps_calls": 0,
            "gpu_calls": 0,
        }


ProtocolFreeze = Callable[
    [dict[str, object], Mapping[str, bytes]], dict[str, object]
]
DevelopmentOpen = Callable[[], SealedDevelopmentPanel]
DevelopmentFreezeAndReveal = Callable[[bytes, dict[str, object]], DevelopmentReveal]


def run_signed_direct_replication(
    config: SignedDirectReplicationConfig,
    source: FrozenReaderSource,
    *,
    direct_model_blob: bytes,
    shuffled_model_blob: bytes,
    source_provenance: Mapping[str, object],
    open_sealed_development: DevelopmentOpen,
    freeze_predictions_and_reveal: DevelopmentFreezeAndReveal,
    on_protocol_frozen: ProtocolFreeze | None = None,
    require_protocol_persistence: bool = False,
) -> SignedDirectReplicationResult:
    model_blobs = {
        "direct": direct_model_blob,
        "shuffled_key_control": shuffled_model_blob,
    }
    for name, blob in model_blobs.items():
        if not isinstance(blob, bytes):
            raise SignedDirectReplicationError("source model blob must be bytes")
        expected = (
            source.direct_model_sha256
            if name == "direct"
            else source.shuffled_model_sha256
        )
        if hashlib.sha256(blob).hexdigest() != expected:
            raise SignedDirectReplicationError(f"{name} source model SHA-256 differs")
    direct_model = deserialize_ridge(direct_model_blob)
    shuffled_model = deserialize_ridge(shuffled_model_blob)
    if (
        direct_model.plan.describe() != shuffled_model.plan.describe()
        or direct_model.plan.input_dimension != 640
        or direct_model.plan.output_dimension != 96
        or direct_model.auxiliary_dimension != 0
        or shuffled_model.auxiliary_dimension != 0
    ):
        raise SignedDirectReplicationError("frozen direct reader plans differ")
    provenance = dict(source_provenance)
    canonical_json_bytes(provenance)
    if (
        provenance.get("source_manifest_sha256")
        != source.source_manifest_sha256
        or provenance.get("source_result_sha256") != source.source_result_sha256
        or provenance.get("source_capsule_verified") is not True
    ):
        raise SignedDirectReplicationError("verified source provenance differs")

    protocol_document = {
        "schema": "o1-256-signed-direct-protocol-freeze-v1",
        "source": source.describe(),
        "source_provenance": provenance,
        "replication": config.describe(),
        "prediction_arms": list(PREDICTION_ARMS),
        "direct_plan": direct_model.plan.describe(),
        "models": {
            "direct": direct_model.describe(),
            "shuffled_key_control": shuffled_model.describe(),
        },
        "models_refit": False,
        "scales_refit": False,
        "hypothesis_selected_post_reveal_on_source_attempt": True,
        "replication_is_prospective": True,
        "development_targets_created": 0,
        "development_publications_opened": 0,
        "development_labels_read": 0,
    }
    if on_protocol_frozen is None:
        if require_protocol_persistence:
            raise SignedDirectReplicationError(
                "production replication requires a persisted protocol callback"
            )
        protocol_receipt = {
            "schema": "o1-256-signed-direct-protocol-freeze-receipt-v1",
            "persisted": False,
            "unit_or_dry_mode": True,
        }
    else:
        protocol_receipt = on_protocol_frozen(protocol_document, model_blobs)
        if (
            not isinstance(protocol_receipt, dict)
            or protocol_receipt.get("persisted") is not True
        ):
            raise SignedDirectReplicationError("protocol persistence receipt differs")

    panel = open_sealed_development()
    if not isinstance(panel, SealedDevelopmentPanel):
        raise SignedDirectReplicationError("sealed development callback differs")
    panel.validate(config.development_targets)
    public_features = np.stack(
        [public_target_feature_vector(target) for target in panel.public_targets]
    )
    direct_logits = direct_model.predict(public_features)
    prediction_matrices: dict[str, np.ndarray] = {
        "factual/direct_signed": _posterior(direct_logits, source.direct_scale),
        "control/polarity_reverse": _posterior(
            direct_logits, -source.direct_scale
        ),
        "control/shuffled_signed": _posterior(
            shuffled_model.predict(public_features), source.shuffled_scale
        ),
    }
    del public_features, direct_logits
    for name, targets in _public_controls(panel.public_targets).items():
        prediction_matrices[f"control/{name}"] = _predict(
            direct_model, targets, source.direct_scale
        )
    if tuple(sorted(prediction_matrices)) != PREDICTION_ARMS:
        raise SignedDirectReplicationError("prediction arm inventory differs")
    prediction_blob, prediction_index = _prediction_bundle(
        prediction_matrices, panel.target_ids
    )
    reveal = freeze_predictions_and_reveal(prediction_blob, prediction_index)
    if not isinstance(reveal, DevelopmentReveal):
        raise SignedDirectReplicationError("development reveal callback differs")
    reveal.validate(panel, prediction_index)
    labels = np.stack(
        [key_bits(key).astype(np.float64) for key in reveal.keys], axis=0
    )

    evaluations = {
        name: _arm_evaluation(probabilities, labels)
        for name, probabilities in sorted(prediction_matrices.items())
    }
    direct = prediction_matrices["factual/direct_signed"]
    paired = {
        name: _paired_evaluation(direct, prediction_matrices[name], labels)
        for name in PREDICTION_ARMS
        if name != "factual/direct_signed"
    }
    direct_report = evaluations["factual/direct_signed"]
    direct_compression = float(direct_report["mean_effective_compression_bits"])
    direct_z = float(direct_report["conditional_uniform_key_null"]["z_score"])
    direct_standard_error = float(
        direct_report["per_target_compression_standard_error_bits"]
    )
    shuffled_margin = float(
        paired["control/shuffled_signed"][
            "mean_direct_minus_control_compression_bits"
        ]
    )
    permutation_margin = float(
        paired["control/output_permutation"][
            "mean_direct_minus_control_compression_bits"
        ]
    )
    shuffled_pair_z = float(
        paired["control/shuffled_signed"]["conditional_uniform_key_null"][
            "z_score"
        ]
    )
    permutation_pair_z = float(
        paired["control/output_permutation"]["conditional_uniform_key_null"][
            "z_score"
        ]
    )
    shuffled_pair_standard_error = float(
        paired["control/shuffled_signed"]["standard_error_bits"]
    )
    permutation_pair_standard_error = float(
        paired["control/output_permutation"]["standard_error_bits"]
    )
    reverse_compression = float(
        evaluations["control/polarity_reverse"][
            "mean_effective_compression_bits"
        ]
    )
    criteria = {
        "direct_compression_at_least_threshold": (
            direct_compression >= config.minimum_direct_compression_bits
        ),
        "direct_conditional_z_at_least_threshold": (
            direct_z >= config.minimum_direct_conditional_z
        ),
        "direct_target_level_lower_bound_positive": (
            direct_compression
            - config.minimum_target_lcb_z * direct_standard_error
            > 0.0
        ),
        "direct_beats_shuffled_by_margin": (
            shuffled_margin >= config.minimum_shuffled_margin_bits
        ),
        "direct_beats_output_permutation_by_margin": (
            permutation_margin >= config.minimum_output_permutation_margin_bits
        ),
        "shuffled_pair_conditional_z_at_least_threshold": (
            shuffled_pair_z >= config.minimum_paired_conditional_z
        ),
        "output_permutation_pair_conditional_z_at_least_threshold": (
            permutation_pair_z >= config.minimum_paired_conditional_z
        ),
        "shuffled_pair_target_level_lower_bound_positive": (
            shuffled_margin
            - config.minimum_target_lcb_z * shuffled_pair_standard_error
            > 0.0
        ),
        "output_permutation_pair_target_level_lower_bound_positive": (
            permutation_margin
            - config.minimum_target_lcb_z * permutation_pair_standard_error
            > 0.0
        ),
        "polarity_reverse_not_positive": reverse_compression <= 0.0,
    }
    signal_gate = {
        "passed": all(criteria.values()),
        "criteria": criteria,
        "thresholds": {
            "minimum_direct_compression_bits": config.minimum_direct_compression_bits,
            "minimum_direct_conditional_z": config.minimum_direct_conditional_z,
            "minimum_target_lcb_z": config.minimum_target_lcb_z,
            "minimum_shuffled_margin_bits": config.minimum_shuffled_margin_bits,
            "minimum_output_permutation_margin_bits": (
                config.minimum_output_permutation_margin_bits
            ),
            "minimum_paired_conditional_z": config.minimum_paired_conditional_z,
            "maximum_polarity_reverse_compression_bits": 0.0,
        },
        "observed": {
            "direct_compression_bits": direct_compression,
            "direct_conditional_z": direct_z,
            "direct_target_level_lower_bound_bits": (
                direct_compression
                - config.minimum_target_lcb_z * direct_standard_error
            ),
            "direct_minus_shuffled_compression_bits": shuffled_margin,
            "direct_minus_output_permutation_compression_bits": permutation_margin,
            "shuffled_pair_conditional_z": shuffled_pair_z,
            "output_permutation_pair_conditional_z": permutation_pair_z,
            "shuffled_pair_target_level_lower_bound_bits": (
                shuffled_margin
                - config.minimum_target_lcb_z * shuffled_pair_standard_error
            ),
            "output_permutation_pair_target_level_lower_bound_bits": (
                permutation_margin
                - config.minimum_target_lcb_z * permutation_pair_standard_error
            ),
            "polarity_reverse_compression_bits": reverse_compression,
        },
    }
    report_without_hash = {
        "schema": "o1-256-signed-direct-replication-result-v1",
        "source": source.describe(),
        "source_provenance": provenance,
        "replication": config.describe(),
        "attacker_contract": {
            "cipher": "ChaCha20",
            "rounds": 20,
            "feed_forward": True,
            "unknown_target_key_bits": KEY_BITS,
            "public_target_fields": ["counter", "nonce", "full_round_output"],
            "target_key_fields_in_deployment": 0,
            "target_trace_fields_in_deployment": 0,
            "reduced_width_target": False,
        },
        "protocol": {
            "source_models_refit": False,
            "source_scales_refit": False,
            "source_hypothesis_was_post_reveal": True,
            "replication_hypothesis_frozen_before_new_target_entropy": True,
            "protocol_persisted_before_development_creation": True,
            "development_predictions_frozen_before_reveal": True,
            "development_openings": 1,
            "fresh_target_generated": True,
            "fresh_target_revealed": True,
            "fresh_target_count": len(reveal.keys),
            "uniform_secret_bits_assumed_for_conditional_null": True,
            "conditional_null_conditioned_on_public_inputs_and_fixed_logits": True,
            "protocol_freeze_receipt": protocol_receipt,
            "development_panel": panel.describe(),
            "development_reveal_receipt": reveal.receipt,
        },
        "models": {
            "direct": direct_model.describe(),
            "shuffled_key_control": shuffled_model.describe(),
        },
        "evaluation": {
            "arms": evaluations,
            "paired_controls": paired,
            "frozen_prediction_binary": prediction_index,
        },
        "bounded_live_state": {
            "reader_state_bytes_per_target": KEY_BITS * 8,
            "state_independent_of_stream_length": True,
            "static_reader_parameters_excluded_from_live_state": True,
        },
        "scientific_signal_gate": signal_gate,
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
    return SignedDirectReplicationResult(
        report=report,
        prediction_blob=prediction_blob,
        prediction_index=prediction_index,
    )


__all__ = [
    "FrozenReaderSource",
    "PREDICTION_ARMS",
    "SignedDirectReplicationConfig",
    "SignedDirectReplicationError",
    "SignedDirectReplicationResult",
    "conditional_uniform_compression_null",
    "conditional_uniform_paired_null",
    "load_signed_direct_replication_config",
    "run_signed_direct_replication",
]
