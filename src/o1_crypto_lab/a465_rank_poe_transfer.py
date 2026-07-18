"""Exact A465 rank-Product-of-Experts over retained A448 raw telemetry."""

from __future__ import annotations

import gzip
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import numpy as np

from .a448_proof_byte_transfer import (
    A448_CANDIDATES,
    A448_FEATURE_SOURCE_RELATIVE,
    A448_FEATURE_SOURCE_SHA256,
    A448TransferError,
    FrozenA448Model,
    _anchored,
    _json_object,
    _load_sibling_module,
    a442_borda_ranks_from_shape532,
    exact_a275_shape532_from_run,
    load_frozen_a448_model,
)


A465_SELECTED_SPEC = {
    "candidate_id": "power_sum_p3_o1_w7_1_4",
    "family": "power_sum",
    "parameter": 3,
    "offset": 1,
    "coordinates": [7, 1, 4],
    "active_experts": ["A460", "A462", "A463"],
    "algebraic_degree": 3,
}
A465_EXPERTS = ("A460", "A462", "A463")
A465_COMPONENT_H = "hybrid_proof_top16_equal"
A465_COMPONENT_O = "proof_best_single"

A460_RESULT_RELATIVE = Path(
    "research/results/v1/"
    "chacha20_round20_w52_no_refit_frequency_scale_moonshot_a460_v1.json"
)
A462_RESULT_RELATIVE = Path(
    "research/results/v1/"
    "chacha20_round20_w52_no_refit_switching_wavelength_moonshot_a462_v1.json"
)
A463_RESULT_RELATIVE = Path(
    "research/results/v1/"
    "chacha20_round20_w52_no_refit_integer_wavelength_closure_a463_v1.json"
)
A465_RESULT_RELATIVE = Path(
    "research/results/v1/"
    "chacha20_round20_w52_no_refit_rank_product_of_experts_a465_v1.json"
)
A447_SOURCE_RELATIVE = Path(
    "research/experiments/"
    "chacha20_round20_w46_proof_antecedent_calibration_a447.py"
)
A448_SOURCE_RELATIVE = Path(
    "research/experiments/"
    "chacha20_round20_w46_full128_proof_antecedent_transfer_a448.py"
)
A458_SOURCE_RELATIVE = Path(
    "research/experiments/"
    "chacha20_round20_w52_no_refit_frequency_ray_extension_a458.py"
)
A463_SOURCE_RELATIVE = Path(
    "research/experiments/"
    "chacha20_round20_w52_no_refit_integer_wavelength_closure_a463.py"
)
A465_SOURCE_RELATIVE = Path(
    "research/experiments/"
    "chacha20_round20_w52_no_refit_rank_product_of_experts_a465.py"
)

A460_RESULT_SHA256 = "5d1d8c24e9ac161660e07ce48a92d88d6a3e135ac24efb9090fcf1cdea2ef88c"
A462_RESULT_SHA256 = "c8a94bf3ce721730e24e21739506005bc4a0f3b6b6e1ed7a6d2274ff7b60d461"
A463_RESULT_SHA256 = "568281979795264bdf1d0f3f35746114e7e91ada9d05d472f50797d3bccdcb75"
A465_RESULT_SHA256 = "a22ddbc7c204506980847bf0856b0f806f84f79d169551e08d713920afe28a62"
A447_SOURCE_SHA256 = "732579d73de55d8f544f5acd99104b581bedcf51956d773b3652b3e4ae786ca4"
A448_SOURCE_SHA256 = "33cf14799282e52a6e23857d15dba096ba61e003fdef8b53a2b6a93a5dcd9d60"
A458_SOURCE_SHA256 = "9b24dce3b2b0f3eff5ad9b7d623dc6b1982968088396114e6ac9286ad24ae159"
A463_SOURCE_SHA256 = "58aadd5aba3a0fcd76d6244da02522e5d5554fbca6f18917e363d4632dc882bc"
A465_SOURCE_SHA256 = "87e95be3355ae9e16015fded326458a6effa89fc873978e15838289f5d87ef4f"
A465_RESULT_COMMITMENT_SHA256 = (
    "30f563ddc9eade4d324b0b49f03390bc215d3ae44f5a5a319a9fbe5f4dc551e7"
)


class A465TransferError(RuntimeError):
    """The frozen A465 model or retained A448 stream differs."""


@dataclass(frozen=True)
class FrozenA465Model:
    sibling_root: Path
    patterns: Mapping[str, str]
    selected_spec: Mapping[str, object]
    result_sha256: str
    result_commitment_sha256: str


@dataclass(frozen=True)
class A465RankField:
    component_h_ranks: np.ndarray
    component_o_ranks: np.ndarray
    a460_ranks: np.ndarray
    a462_ranks: np.ndarray
    a463_ranks: np.ndarray
    final_ranks: np.ndarray
    directional_rank_sha256: str

    def __post_init__(self) -> None:
        exact = set(range(1, A448_CANDIDATES + 1))
        for field in (
            self.component_h_ranks,
            self.component_o_ranks,
            self.a460_ranks,
            self.a462_ranks,
            self.a463_ranks,
            self.final_ranks,
        ):
            if field.shape != (A448_CANDIDATES,) or set(field.tolist()) != exact:
                raise A465TransferError("A465 rank field is not an exact permutation")
            field.setflags(write=False)

    def describe(self) -> dict[str, object]:
        order = np.argsort(self.final_ranks, kind="stable").astype(int).tolist()
        return {
            "schema": "o1-256-a465-rank-poe-byte-field-v1",
            "selected_spec": A465_SELECTED_SPEC,
            "component_operators": {
                "H": A465_COMPONENT_H,
                "O": A465_COMPONENT_O,
            },
            "component_h_ranks": self.component_h_ranks.astype(int).tolist(),
            "component_o_ranks": self.component_o_ranks.astype(int).tolist(),
            "expert_ranks": {
                "A460": self.a460_ranks.astype(int).tolist(),
                "A462": self.a462_ranks.astype(int).tolist(),
                "A463": self.a463_ranks.astype(int).tolist(),
            },
            "final_ranks": self.final_ranks.astype(int).tolist(),
            "candidate_order": order,
            "candidate_order_uint8_sha256": hashlib.sha256(bytes(order)).hexdigest(),
            "directional_rank_sha256": self.directional_rank_sha256,
        }


def _exact_ranks(order: Sequence[int]) -> np.ndarray:
    values = np.asarray(order, dtype=np.int64)
    if values.shape != (A448_CANDIDATES,) or set(values.tolist()) != set(
        range(A448_CANDIDATES)
    ):
        raise A465TransferError("candidate order is not exact")
    ranks = np.empty(A448_CANDIDATES, dtype=np.int16)
    ranks[values] = np.arange(1, A448_CANDIDATES + 1, dtype=np.int16)
    return ranks


def _ranks_by_primary(primary: np.ndarray, baseline: np.ndarray) -> np.ndarray:
    values = np.asarray(primary)
    tie = np.asarray(baseline, dtype=np.int64)
    cells = np.arange(A448_CANDIDATES, dtype=np.int64)
    if values.shape != (A448_CANDIDATES,) or tie.shape != values.shape:
        raise A465TransferError("rank primary geometry differs")
    return _exact_ranks(np.lexsort((cells, tie, values)))


def _component_fields(
    directional: np.ndarray,
    baseline: np.ndarray,
    feature_order: Sequence[int],
) -> tuple[np.ndarray, np.ndarray]:
    order = np.asarray(feature_order, dtype=np.int64)
    if (
        directional.shape != (3051, A448_CANDIDATES)
        or order.shape != (3051,)
        or set(order.tolist()) != set(range(3051))
    ):
        raise A465TransferError("A447 complete feature order differs")
    best = _ranks_by_primary(directional[order[0]], baseline)
    top16_primary = directional[order[:16]].astype(np.int64).sum(axis=0)
    proof16 = _ranks_by_primary(top16_primary, baseline)
    hybrid16 = _ranks_by_primary(
        baseline.astype(np.int64) + proof16.astype(np.int64), baseline
    )
    return hybrid16, best


def first_encounter_ranks(
    component_h: np.ndarray,
    component_o: np.ndarray,
    pattern: str,
) -> np.ndarray:
    """Exact A458/A463 H/O proposal scheduler for one 256-cell field."""

    if not pattern or set(pattern) != {"H", "O"}:
        raise A465TransferError("A465 expert pattern must contain only H and O")
    ranks_by_symbol = {
        "H": np.asarray(component_h, dtype=np.int64),
        "O": np.asarray(component_o, dtype=np.int64),
    }
    first: np.ndarray | None = None
    for symbol in ("H", "O"):
        ranks = ranks_by_symbol[symbol]
        if ranks.shape != (A448_CANDIDATES,) or set(ranks.tolist()) != set(
            range(1, A448_CANDIDATES + 1)
        ):
            raise A465TransferError("A465 component rank field differs")
        slots = np.asarray(
            [index for index, value in enumerate(pattern) if value == symbol],
            dtype=np.int64,
        )
        zero = ranks - 1
        keys = len(pattern) * (zero // slots.size) + slots[zero % slots.size]
        first = keys if first is None else np.minimum(first, keys)
    if first is None or np.unique(first).size != A448_CANDIDATES:
        raise A465TransferError("A465 first-encounter keys are not unique")
    return _exact_ranks(np.argsort(first, kind="stable"))


def rank_product_of_experts(
    a460: np.ndarray,
    a462: np.ndarray,
    a463: np.ndarray,
) -> np.ndarray:
    """Exact selected A465 power-sum and total-order tie semantics."""

    ranks = [np.asarray(value, dtype=np.int64) for value in (a460, a462, a463)]
    exact = set(range(1, A448_CANDIDATES + 1))
    if any(value.shape != (A448_CANDIDATES,) or set(value.tolist()) != exact for value in ranks):
        raise A465TransferError("A465 expert field differs")
    shifted = [value + 1 for value in ranks]
    score = 7 * shifted[0] ** 3 + shifted[1] ** 3 + 4 * shifted[2] ** 3
    stack = np.stack(ranks)
    maximum = stack.max(axis=0)
    total = stack.sum(axis=0)
    cells = np.arange(A448_CANDIDATES, dtype=np.int64)
    order = np.lexsort(
        (cells, ranks[0], ranks[1], ranks[2], total, maximum, score)
    )
    return _exact_ranks(order)


def load_frozen_a465_model(
    sibling_root: str | Path | None = None,
) -> FrozenA465Model:
    a448 = load_frozen_a448_model(sibling_root)
    root = a448.sibling_root
    for relative, digest in (
        (A447_SOURCE_RELATIVE, A447_SOURCE_SHA256),
        (A448_SOURCE_RELATIVE, A448_SOURCE_SHA256),
        (A458_SOURCE_RELATIVE, A458_SOURCE_SHA256),
        (A463_SOURCE_RELATIVE, A463_SOURCE_SHA256),
        (A465_SOURCE_RELATIVE, A465_SOURCE_SHA256),
    ):
        _anchored(root, relative, digest)
    results = {
        "A460": _json_object(_anchored(root, A460_RESULT_RELATIVE, A460_RESULT_SHA256)),
        "A462": _json_object(_anchored(root, A462_RESULT_RELATIVE, A462_RESULT_SHA256)),
        "A463": _json_object(_anchored(root, A463_RESULT_RELATIVE, A463_RESULT_SHA256)),
    }
    a465 = _json_object(_anchored(root, A465_RESULT_RELATIVE, A465_RESULT_SHA256))
    expected_commitments = {
        "A460": "8d87c3b1da96e7fca7a75f57992f30f935b9e36693a79939fcc80634f822b002",
        "A462": "8f82e71336ef04c12a5b1655a1d09a99623da0fd10ea0a1761eb5e9cd6b4a77f",
        "A463": "c4d1fefa9fd412eceb8e383d8e033662be635c21550b0a376541b45a67b52b79",
    }
    patterns: dict[str, str] = {}
    for name, result in results.items():
        calibration = result.get("calibration")
        if (
            result.get("attempt_id") != name
            or result.get("result_commitment_sha256") != expected_commitments[name]
            or not isinstance(calibration, dict)
            or not isinstance(calibration.get("selected_pattern"), str)
        ):
            raise A465TransferError(f"{name} frozen expert differs")
        patterns[name] = cast(str, calibration["selected_pattern"])
    decision = a465.get("decision")
    calibration465 = a465.get("calibration")
    if (
        {name: len(value) for name, value in patterns.items()}
        != {"A460": 128, "A462": 192, "A463": 130}
        or a465.get("attempt_id") != "A465"
        or a465.get("result_commitment_sha256") != A465_RESULT_COMMITMENT_SHA256
        or a465.get("evidence_stage")
        != "STRICT_NO_REFIT_RANK_POE_W52_RECOVERY_STREAM_QUALIFIED"
        or not isinstance(decision, dict)
        or decision.get("selected_spec") != A465_SELECTED_SPEC
        or not isinstance(calibration465, dict)
        or calibration465.get("selected_spec") != A465_SELECTED_SPEC
    ):
        raise A465TransferError("A465 frozen selection semantics differ")
    return FrozenA465Model(
        sibling_root=root,
        patterns=patterns,
        selected_spec=A465_SELECTED_SPEC,
        result_sha256=A465_RESULT_SHA256,
        result_commitment_sha256=A465_RESULT_COMMITMENT_SHA256,
    )


def a465_rank_field_from_run(
    run: Mapping[str, object],
    *,
    a448_model: FrozenA448Model | None = None,
    a465_model: FrozenA465Model | None = None,
) -> A465RankField:
    frozen448 = load_frozen_a448_model() if a448_model is None else a448_model
    frozen465 = (
        load_frozen_a465_model(frozen448.sibling_root)
        if a465_model is None
        else a465_model
    )
    if frozen448.sibling_root != frozen465.sibling_root:
        raise A465TransferError("A448 and A465 sibling roots differ")
    shape = exact_a275_shape532_from_run(run, frozen448)
    baseline = a442_borda_ranks_from_shape532(shape, frozen448)
    feature_source = _load_sibling_module(
        root=frozen448.sibling_root,
        relative=A448_FEATURE_SOURCE_RELATIVE,
        expected_sha256=A448_FEATURE_SOURCE_SHA256,
        name="o1c33_exact_a465_proof_features",
    )
    feature_matrix, _base_names = feature_source.extract_proof_feature_matrix(run)
    normalized = feature_source.target_normalize(feature_matrix)
    directional, _generic_names = feature_source.exact_directional_rank_fields(
        normalized, baseline
    )
    h_ranks, o_ranks = _component_fields(
        directional,
        baseline,
        frozen448.complete_feature_order,
    )
    experts = {
        name: first_encounter_ranks(h_ranks, o_ranks, frozen465.patterns[name])
        for name in A465_EXPERTS
    }
    final = rank_product_of_experts(
        experts["A460"], experts["A462"], experts["A463"]
    )
    return A465RankField(
        component_h_ranks=h_ranks,
        component_o_ranks=o_ranks,
        a460_ranks=experts["A460"],
        a462_ranks=experts["A462"],
        a463_ranks=experts["A463"],
        final_ranks=final,
        directional_rank_sha256=hashlib.sha256(
            np.asarray(directional, dtype="<i2").tobytes()
        ).hexdigest(),
    )


def read_retained_a448_run(path: str | Path) -> Mapping[str, object]:
    payload = Path(path).resolve(strict=True).read_bytes()
    try:
        value = json.loads(gzip.decompress(payload))
    except (OSError, json.JSONDecodeError) as exc:
        raise A465TransferError("retained A448 artifact is not deterministic gzip JSON") from exc
    if not isinstance(value, dict):
        raise A465TransferError("retained A448 run is not an object")
    return cast(Mapping[str, object], value)


def revealed_byte_rank(field: A465RankField, target_byte: int) -> int:
    if (
        isinstance(target_byte, bool)
        or not isinstance(target_byte, int)
        or not 0 <= target_byte < A448_CANDIDATES
    ):
        raise A448TransferError("target_byte must be in 0..255")
    return int(field.final_ranks[target_byte])


__all__ = [
    "A465RankField",
    "A465TransferError",
    "A465_SELECTED_SPEC",
    "FrozenA465Model",
    "a465_rank_field_from_run",
    "first_encounter_ranks",
    "load_frozen_a465_model",
    "rank_product_of_experts",
    "read_retained_a448_run",
    "revealed_byte_rank",
]
