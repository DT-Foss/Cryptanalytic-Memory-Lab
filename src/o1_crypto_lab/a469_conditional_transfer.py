"""Exact frozen A469 bucket-local correction around an A465 rank field."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import numpy as np

from .a448_proof_byte_transfer import A448_CANDIDATES, _anchored, _json_object
from .a465_rank_poe_transfer import A465RankField, load_frozen_a465_model


A469_SELECTED_SPEC = {
    "active_head_buckets": 4,
    "alpha_denominator": 1,
    "alpha_numerator": 2,
    "base_bins": 8,
    "candidate_id": "BB008_IB04_A02of01_H01of02_positive_only_Tbase",
    "head_denominator": 2,
    "head_numerator": 1,
    "interaction_bins": 4,
    "kind": "conditional_interaction",
    "maximum_calibration_displacement": 31,
    "mode": "positive_only",
    "tie_policy": "base",
}
A469_COPULA_SPEC = {
    "alpha_denominator": 2,
    "alpha_numerator": 1,
    "bins": 16,
    "portfolio": ["P", "T"],
}
A469_RESULT_RELATIVE = Path(
    "research/results/v1/"
    "chacha20_round20_w52_a465_preserving_conditional_interaction_reader_a469_v1.json"
)
A467_SOURCE_RELATIVE = Path(
    "research/experiments/"
    "chacha20_round20_w52_no_refit_head_copula_reader_a467.py"
)
A469_SOURCE_RELATIVE = Path(
    "research/experiments/"
    "chacha20_round20_w52_a465_preserving_conditional_interaction_reader_a469.py"
)
A469_RESULT_SHA256 = "dc33384c0c4e65bf57a9e0bdb8297b16737df0494e2af1036a85f49e7ececc01"
A467_SOURCE_SHA256 = "d20560089cc5a7639b3b9f1e4f1ace5b65884d726f3c7df7e817bf4fb392929e"
A469_SOURCE_SHA256 = "5b0e12688ab526ff36841d9e4bdfa8b1bcb45b20c8a1e1653418f3d9c2f0194f"
A469_RESULT_COMMITMENT_SHA256 = (
    "c13d7fd7f330298504d50f3764ad14bc8daa98d1a120102e6b13b54602770e7d"
)
A469_MODEL_COMMITMENT_SHA256 = (
    "ca588f8f4fc3db37a3867d8eea36577172cd43ebb8735224d64eccf4d267c3ac"
)
A469_TABLE_SIZES = {
    "q0": 16,
    "q1": 16,
    "q2": 16,
    "pair01": 256,
    "pair02": 256,
    "pair12": 256,
    "triple": 4096,
    "order": 27,
    "spread": 16,
}


class A469TransferError(RuntimeError):
    """The frozen A469 model or its A465 input differs."""


@dataclass(frozen=True)
class FrozenA469Model:
    sibling_root: Path
    copula_tables: Mapping[str, np.ndarray]
    residual_table: np.ndarray
    selected_spec: Mapping[str, object]
    result_sha256: str
    result_commitment_sha256: str
    model_commitment_sha256: str

    def __post_init__(self) -> None:
        for name, size in A469_TABLE_SIZES.items():
            value = self.copula_tables.get(name)
            if value is None or value.shape != (size,) or value.dtype != np.int64:
                raise A469TransferError(f"A469 copula table differs: {name}")
            value.setflags(write=False)
        if self.residual_table.shape != (32,) or self.residual_table.dtype != np.int64:
            raise A469TransferError("A469 residual table differs")
        self.residual_table.setflags(write=False)


@dataclass(frozen=True)
class A469RankField:
    base_ranks: np.ndarray
    interaction_ranks: np.ndarray
    final_ranks: np.ndarray
    correction_gate: np.ndarray
    correction_score: np.ndarray

    def __post_init__(self) -> None:
        exact = set(range(1, A448_CANDIDATES + 1))
        for field in (self.base_ranks, self.interaction_ranks, self.final_ranks):
            if field.shape != (A448_CANDIDATES,) or set(field.tolist()) != exact:
                raise A469TransferError("A469 rank field is not an exact permutation")
            field.setflags(write=False)
        if self.correction_gate.shape != (A448_CANDIDATES,) or self.correction_gate.dtype != np.bool_:
            raise A469TransferError("A469 correction gate differs")
        if self.correction_score.shape != (A448_CANDIDATES,) or self.correction_score.dtype != np.int64:
            raise A469TransferError("A469 correction score differs")
        self.correction_gate.setflags(write=False)
        self.correction_score.setflags(write=False)

    def describe(self) -> dict[str, object]:
        order = np.argsort(self.final_ranks, kind="stable").astype(int).tolist()
        return {
            "schema": "o1-256-a469-conditional-byte-field-v1",
            "selected_spec": A469_SELECTED_SPEC,
            "copula_spec": A469_COPULA_SPEC,
            "base_ranks": self.base_ranks.astype(int).tolist(),
            "interaction_ranks": self.interaction_ranks.astype(int).tolist(),
            "final_ranks": self.final_ranks.astype(int).tolist(),
            "correction_gate": self.correction_gate.astype(int).tolist(),
            "correction_score": self.correction_score.astype(int).tolist(),
            "active_correction_cells": int(np.count_nonzero(self.correction_gate)),
            "changed_rank_cells": int(np.count_nonzero(self.final_ranks != self.base_ranks)),
            "candidate_order": order,
            "candidate_order_uint8_sha256": hashlib.sha256(bytes(order)).hexdigest(),
        }


def _exact_ranks(order: Sequence[int]) -> np.ndarray:
    values = np.asarray(order, dtype=np.int64)
    if values.shape != (A448_CANDIDATES,) or set(values.tolist()) != set(
        range(A448_CANDIDATES)
    ):
        raise A469TransferError("A469 candidate order is not exact")
    ranks = np.empty(A448_CANDIDATES, dtype=np.int16)
    ranks[values] = np.arange(1, A448_CANDIDATES + 1, dtype=np.int16)
    return ranks


def quantile_bins(ranks: np.ndarray, bins: int) -> np.ndarray:
    values = np.asarray(ranks, dtype=np.int64)
    if (
        values.shape != (A448_CANDIDATES,)
        or np.any(values < 1)
        or np.any(values > A448_CANDIDATES)
        or bins <= 0
    ):
        raise A469TransferError("A469 quantile input differs")
    return ((bins * (values - 1)) // A448_CANDIDATES).astype(np.int16)


def _comparison_code(left: np.ndarray, right: np.ndarray) -> np.ndarray:
    return np.where(left < right, 0, np.where(left == right, 1, 2)).astype(np.int16)


def _feature_codes(experts: Mapping[str, np.ndarray]) -> dict[str, np.ndarray]:
    bins = 16
    r0 = np.asarray(experts["A460"], dtype=np.int64)
    r1 = np.asarray(experts["A462"], dtype=np.int64)
    r2 = np.asarray(experts["A463"], dtype=np.int64)
    q0, q1, q2 = (quantile_bins(value, bins) for value in (r0, r1, r2))
    order = (
        9 * _comparison_code(r0, r1)
        + 3 * _comparison_code(r0, r2)
        + _comparison_code(r1, r2)
    ).astype(np.int16)
    stack = np.stack((q0, q1, q2))
    return {
        "q0": q0,
        "q1": q1,
        "q2": q2,
        "pair01": (q0 * bins + q1).astype(np.int16),
        "pair02": (q0 * bins + q2).astype(np.int16),
        "pair12": (q1 * bins + q2).astype(np.int16),
        "triple": ((q0 * bins + q1) * bins + q2).astype(np.int16),
        "order": order,
        "spread": (stack.max(axis=0) - stack.min(axis=0)).astype(np.int16),
    }


def interaction_ranks(
    experts: Mapping[str, np.ndarray],
    base_ranks: np.ndarray,
    model: FrozenA469Model,
) -> np.ndarray:
    codes = _feature_codes(experts)
    tables = model.copula_tables
    l0 = tables["q0"][codes["q0"]]
    l1 = tables["q1"][codes["q1"]]
    l2 = tables["q2"][codes["q2"]]
    l01 = tables["pair01"][codes["pair01"]]
    l02 = tables["pair02"][codes["pair02"]]
    l12 = tables["pair12"][codes["pair12"]]
    l123 = tables["triple"][codes["triple"]]
    pair = (l01 - l0 - l1) + (l02 - l0 - l2) + (l12 - l1 - l2)
    triple = l123 - l01 - l02 - l12 + l0 + l1 + l2
    score = pair + triple
    base = np.asarray(base_ranks, dtype=np.int64)
    cells = np.arange(A448_CANDIDATES, dtype=np.int64)
    return _exact_ranks(np.lexsort((cells, base, -score)))


def apply_frozen_a469(
    base_ranks: np.ndarray,
    interaction: np.ndarray,
    model: FrozenA469Model,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    base = np.asarray(base_ranks, dtype=np.int64)
    inter = np.asarray(interaction, dtype=np.int64)
    qb = quantile_bins(base, 8)
    qi = quantile_bins(inter, 4)
    score = model.residual_table[(qb.astype(np.int64) * 4 + qi).astype(np.int64)]
    gate = (qb < 4) & (score > 0)
    score_key = np.where(gate, score, 0)
    cells = np.arange(A448_CANDIDATES, dtype=np.int64)
    order = np.lexsort((cells, base, base, -score_key, -gate.astype(np.int8), qb))
    ranks = _exact_ranks(order)
    if not np.array_equal(quantile_bins(ranks, 8), qb):
        raise A469TransferError("A469 crossed an A465 bucket boundary")
    return ranks, gate.astype(np.bool_), score.astype(np.int64)


def load_frozen_a469_model(
    sibling_root: str | Path | None = None,
) -> FrozenA469Model:
    a465 = load_frozen_a465_model(sibling_root)
    root = a465.sibling_root
    _anchored(root, A467_SOURCE_RELATIVE, A467_SOURCE_SHA256)
    _anchored(root, A469_SOURCE_RELATIVE, A469_SOURCE_SHA256)
    result = _json_object(_anchored(root, A469_RESULT_RELATIVE, A469_RESULT_SHA256))
    model_raw = result.get("model")
    if not isinstance(model_raw, dict):
        raise A469TransferError("A469 model is missing")
    tables_raw = model_raw.get("copula_tables")
    residual_raw = model_raw.get("conditional_residual_table")
    if not isinstance(tables_raw, dict) or not isinstance(residual_raw, list):
        raise A469TransferError("A469 model tables differ")
    tables = {
        name: np.asarray(tables_raw[name], dtype=np.int64)
        for name in A469_TABLE_SIZES
        if name in tables_raw
    }
    if (
        result.get("attempt_id") != "A469"
        or result.get("evidence_stage")
        != "A465_PRESERVING_CONDITIONAL_INTERACTION_READER_QUALIFIED"
        or result.get("result_commitment_sha256") != A469_RESULT_COMMITMENT_SHA256
        or model_raw.get("model_commitment_sha256") != A469_MODEL_COMMITMENT_SHA256
        or model_raw.get("selected_spec") != A469_SELECTED_SPEC
        or model_raw.get("copula_spec") != A469_COPULA_SPEC
        or model_raw.get("bucket_crossing_allowed") is not False
        or model_raw.get("W52_target_labels_used") != 0
        or model_raw.get("W52_candidate_assignments_executed") != 0
    ):
        raise A469TransferError("A469 frozen selection semantics differ")
    return FrozenA469Model(
        sibling_root=root,
        copula_tables=tables,
        residual_table=np.asarray(residual_raw, dtype=np.int64),
        selected_spec=A469_SELECTED_SPEC,
        result_sha256=A469_RESULT_SHA256,
        result_commitment_sha256=A469_RESULT_COMMITMENT_SHA256,
        model_commitment_sha256=A469_MODEL_COMMITMENT_SHA256,
    )


def a469_rank_field_from_a465(
    field: A465RankField,
    *,
    model: FrozenA469Model | None = None,
) -> A469RankField:
    if not isinstance(field, A465RankField):
        raise TypeError("field must be A465RankField")
    frozen = load_frozen_a469_model() if model is None else model
    experts = {
        "A460": field.a460_ranks,
        "A462": field.a462_ranks,
        "A463": field.a463_ranks,
    }
    interaction = interaction_ranks(experts, field.final_ranks, frozen)
    final, gate, score = apply_frozen_a469(field.final_ranks, interaction, frozen)
    return A469RankField(
        base_ranks=field.final_ranks.astype(np.int16, copy=True),
        interaction_ranks=interaction,
        final_ranks=final,
        correction_gate=gate,
        correction_score=score,
    )


def a465_field_from_description(value: Mapping[str, object]) -> A465RankField:
    experts = value.get("expert_ranks")
    if not isinstance(experts, dict):
        raise A469TransferError("A465 description lacks expert ranks")
    try:
        return A465RankField(
            component_h_ranks=np.asarray(value["component_h_ranks"], dtype=np.int16),
            component_o_ranks=np.asarray(value["component_o_ranks"], dtype=np.int16),
            a460_ranks=np.asarray(experts["A460"], dtype=np.int16),
            a462_ranks=np.asarray(experts["A462"], dtype=np.int16),
            a463_ranks=np.asarray(experts["A463"], dtype=np.int16),
            final_ranks=np.asarray(value["final_ranks"], dtype=np.int16),
            directional_rank_sha256=cast(str, value["directional_rank_sha256"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise A469TransferError("A465 description geometry differs") from exc


__all__ = [
    "A469RankField",
    "A469TransferError",
    "A469_SELECTED_SPEC",
    "FrozenA469Model",
    "a465_field_from_description",
    "a469_rank_field_from_a465",
    "apply_frozen_a469",
    "interaction_ranks",
    "load_frozen_a469_model",
    "quantile_bins",
]
