"""Target-separated 672-view panel for upstream solver evidence.

The panel operates on a fixed ``4096 x 10`` raw matrix at each of four solver
horizons.  It derives four ratio channels, applies three frozen transforms, and
projects every channel onto either the twelve linear Direct12 Walsh modes or the
complete linear-plus-pairwise shell.  Target addresses are deliberately absent
from projection and ordering; they can only be bound to an already frozen panel
through :func:`bind_target`.

The rank transform is retained as an exploratory breadcrumb but is explicitly
ineligible for streamable-mechanism selection.  Z-score and signed-log1p use
constant-size moment state and are selection eligible.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
from dataclasses import dataclass, replace
from numbers import Real
from typing import Mapping, Sequence

import numpy as np

from .walsh_memory import score_field_sha256


DOMAIN_BITS = 12
DOMAIN_SIZE = 1 << DOMAIN_BITS
HORIZONS = (1, 2, 4, 8)
RAW_CHANNEL_NAMES = (
    "conflicts",
    "decisions",
    "search_propagations",
    "learned_clause_accepted_stage",
    "learned_clause_offered_stage",
    "learned_clause_rejected_large_stage",
    "learned_literal_count_stage",
    "active_variables_delta",
    "irredundant_clauses_delta",
    "redundant_clauses_delta",
)
DERIVED_CHANNEL_NAMES = (
    "accepted_vs_conflicts",
    "accepted_per_conflict",
    "offered_per_conflict",
    "literals_per_conflict",
)
BASE_CHANNEL_NAMES = RAW_CHANNEL_NAMES + DERIVED_CHANNEL_NAMES
TRANSFORM_IDS = ("zscore", "signed-log1p", "rank")
SUPPORT_IDS = ("degree1", "degree1+2")
ORIENTATION_IDS = ("positive", "negative")
PANEL_VIEW_COUNT = (
    len(BASE_CHANNEL_NAMES)
    * len(HORIZONS)
    * len(TRANSFORM_IDS)
    * len(SUPPORT_IDS)
    * len(ORIENTATION_IDS)
)
PANEL_ID = "o1-upstream-solver-evidence-panel-672-v1"
SELECTION_PROCEDURE_ID = "o1-upstream-panel-streamable-rank-selection-v1"
EXACT_LABEL_NULL_ID = "o1-upstream-panel-exact-4096-label-null-v1"
SELECTION_ELIGIBLE_VIEW_COUNT = (
    len(BASE_CHANNEL_NAMES)
    * len(HORIZONS)
    * 2
    * len(SUPPORT_IDS)
    * len(ORIENTATION_IDS)
)
FIELD_SCHEMA = b"o1-upstream-raw-field-float64be-v1\x00"
TIE_POLICY = "score-descending-then-candidate-id-ascending"
SELECTION_TIE_POLICY = (
    "minimum-target-rank-then-fewer-registers-then-view-id-ascii"
)


class UpstreamPanelError(ValueError):
    """A field, transform, projection, label, or enumeration is invalid."""


def _finite(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise UpstreamPanelError(f"{field} must be a finite real number")
    result = float(value)
    if not math.isfinite(result):
        raise UpstreamPanelError(f"{field} must be a finite real number")
    return 0.0 if result == 0.0 else result


def _canonical_sha256(value: object) -> str:
    try:
        raw = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise UpstreamPanelError("value is not canonical finite ASCII JSON") from exc
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class UpstreamRawField:
    """Canonical four-horizon collection of aligned ``4096 x 10`` arrays."""

    horizon_arrays: tuple[tuple[tuple[float, ...], ...], ...]

    def __post_init__(self) -> None:
        try:
            horizons = tuple(
                tuple(
                    tuple(
                        _finite(value, f"horizon_arrays[{h}][{address}][{channel}]")
                        for channel, value in enumerate(row)
                    )
                    for address, row in enumerate(matrix)
                )
                for h, matrix in enumerate(self.horizon_arrays)
            )
        except TypeError as exc:
            raise UpstreamPanelError("horizon arrays must be nested sequences") from exc
        if len(horizons) != len(HORIZONS):
            raise UpstreamPanelError("field must contain horizons 1, 2, 4, and 8")
        for horizon_index, matrix in enumerate(horizons):
            if len(matrix) != DOMAIN_SIZE:
                raise UpstreamPanelError(
                    f"horizon {HORIZONS[horizon_index]} must contain 4096 rows"
                )
            if any(len(row) != len(RAW_CHANNEL_NAMES) for row in matrix):
                raise UpstreamPanelError("every raw row must contain exactly 10 channels")
            if any(
                value < 0.0
                for row in matrix
                for value in row[:7]
            ):
                raise UpstreamPanelError("solver count channels must be non-negative")
        object.__setattr__(self, "horizon_arrays", horizons)

    @classmethod
    def from_horizon_arrays(
        cls,
        arrays: Mapping[int, Sequence[Sequence[Real]]],
    ) -> "UpstreamRawField":
        """Build from a mapping whose values are aligned ``4096 x 10`` arrays."""

        if (
            not isinstance(arrays, Mapping)
            or any(isinstance(key, bool) or not isinstance(key, int) for key in arrays)
            or set(arrays) != set(HORIZONS)
        ):
            raise UpstreamPanelError("arrays must contain exactly horizons 1, 2, 4, and 8")
        return cls(
            tuple(
                tuple(tuple(row) for row in arrays[horizon])
                for horizon in HORIZONS
            )
        )

    @property
    def field_sha256(self) -> str:
        digest = hashlib.sha256()
        digest.update(FIELD_SCHEMA)
        digest.update(DOMAIN_SIZE.to_bytes(2, "big"))
        digest.update(len(RAW_CHANNEL_NAMES).to_bytes(1, "big"))
        for horizon, matrix in zip(HORIZONS, self.horizon_arrays):
            digest.update(horizon.to_bytes(1, "big"))
            for row in matrix:
                for value in row:
                    digest.update(struct.pack(">d", value))
        return digest.hexdigest()

    def raw_channel(self, name: str, horizon: int) -> tuple[float, ...]:
        if name not in RAW_CHANNEL_NAMES:
            raise UpstreamPanelError(f"unknown raw channel {name!r}")
        if horizon not in HORIZONS:
            raise UpstreamPanelError(f"unknown horizon {horizon!r}")
        channel = RAW_CHANNEL_NAMES.index(name)
        matrix = self.horizon_arrays[HORIZONS.index(horizon)]
        return tuple(row[channel] for row in matrix)


def base_channel_values(
    field: UpstreamRawField,
    channel_name: str,
    horizon: int,
) -> tuple[float, ...]:
    """Return one frozen raw or derived evidence channel."""

    if not isinstance(field, UpstreamRawField):
        raise TypeError("field must be an UpstreamRawField")
    if horizon not in HORIZONS:
        raise UpstreamPanelError(f"unknown horizon {horizon!r}")
    if channel_name in RAW_CHANNEL_NAMES:
        return field.raw_channel(channel_name, horizon)
    if channel_name not in DERIVED_CHANNEL_NAMES:
        raise UpstreamPanelError(f"unknown base channel {channel_name!r}")
    matrix = field.horizon_arrays[HORIZONS.index(horizon)]
    conflicts_index = RAW_CHANNEL_NAMES.index("conflicts")
    accepted_index = RAW_CHANNEL_NAMES.index("learned_clause_accepted_stage")
    offered_index = RAW_CHANNEL_NAMES.index("learned_clause_offered_stage")
    literals_index = RAW_CHANNEL_NAMES.index("learned_literal_count_stage")
    result: list[float] = []
    for row in matrix:
        conflicts = row[conflicts_index]
        accepted = row[accepted_index]
        offered = row[offered_index]
        literals = row[literals_index]
        if channel_name == "accepted_vs_conflicts":
            denominator = abs(accepted) + abs(conflicts)
            value = (accepted - conflicts) / denominator if denominator else 0.0
        elif channel_name == "accepted_per_conflict":
            value = accepted / (1.0 + conflicts)
        elif channel_name == "offered_per_conflict":
            value = offered / (1.0 + conflicts)
        else:
            value = literals / (1.0 + conflicts)
        result.append(0.0 if value == 0.0 else value)
    return tuple(result)


def _zscore(values: Sequence[float]) -> tuple[float, ...]:
    array = np.asarray(values, dtype=np.float64)
    if array.shape != (DOMAIN_SIZE,) or not np.isfinite(array).all():
        raise UpstreamPanelError("transform input must contain 4096 finite values")
    maximum = float(np.max(np.abs(array)))
    if maximum == 0.0:
        return (0.0,) * DOMAIN_SIZE
    # Normalize before moments so every finite float64 input stays inside
    # [-1,1]; raw squaring or summation can otherwise overflow at ~1e308.
    normalized = array / maximum
    if not np.isfinite(normalized).all():
        raise UpstreamPanelError("zscore normalization produced a non-finite value")
    mean = float(normalized.mean())
    scale = float(normalized.std())
    threshold = max(1e-12, abs(mean) * 1e-12)
    if scale <= threshold:
        return (0.0,) * DOMAIN_SIZE
    transformed = (normalized - mean) / scale
    if not np.isfinite(transformed).all():
        raise UpstreamPanelError("zscore produced a non-finite value")
    transformed[transformed == 0.0] = 0.0
    return tuple(float(value) for value in transformed)


def _midranks(values: Sequence[float]) -> tuple[float, ...]:
    array = np.asarray(values, dtype=np.float64)
    if array.shape != (DOMAIN_SIZE,) or not np.isfinite(array).all():
        raise UpstreamPanelError("rank input must contain 4096 finite values")
    order = np.argsort(array, kind="stable")
    result = np.empty(DOMAIN_SIZE, dtype=np.float64)
    start = 0
    while start < DOMAIN_SIZE:
        end = start + 1
        value = array[order[start]]
        while end < DOMAIN_SIZE and array[order[end]] == value:
            end += 1
        midrank = (start + end - 1) / 2.0
        result[order[start:end]] = midrank
        start = end
    return tuple(float(value) for value in result)


def transform_values(values: Sequence[float], transform_id: str) -> tuple[float, ...]:
    """Apply one exact panel transform, including population standardization."""

    checked = tuple(
        _finite(value, f"values[{index}]") for index, value in enumerate(values)
    )
    if len(checked) != DOMAIN_SIZE:
        raise UpstreamPanelError("transform input must contain exactly 4096 values")
    if transform_id == "zscore":
        return _zscore(checked)
    if transform_id == "signed-log1p":
        signed = tuple(math.copysign(math.log1p(abs(value)), value) for value in checked)
        return _zscore(signed)
    if transform_id == "rank":
        return _zscore(_midranks(checked))
    raise UpstreamPanelError(f"unknown transform {transform_id!r}")


def _fwht(values: Sequence[float]) -> np.ndarray:
    result = np.asarray(values, dtype=np.float64).copy()
    if result.shape != (DOMAIN_SIZE,) or not np.isfinite(result).all():
        raise UpstreamPanelError("Walsh input must contain 4096 finite values")
    width = 1
    while width < DOMAIN_SIZE:
        blocks = result.reshape(-1, width * 2)
        left = blocks[:, :width].copy()
        right = blocks[:, width:].copy()
        blocks[:, :width] = left + right
        blocks[:, width:] = left - right
        width *= 2
    return result


LINEAR_MASKS = tuple(mask for mask in range(1, DOMAIN_SIZE) if mask.bit_count() == 1)
PAIRWISE_MASKS = tuple(mask for mask in range(1, DOMAIN_SIZE) if mask.bit_count() == 2)
SUPPORT_MASKS = {
    "degree1": LINEAR_MASKS,
    "degree1+2": LINEAR_MASKS + PAIRWISE_MASKS,
}


@dataclass(frozen=True)
class PanelViewSpec:
    channel_name: str
    horizon: int
    transform_id: str
    support_id: str
    orientation: str

    def __post_init__(self) -> None:
        if self.channel_name not in BASE_CHANNEL_NAMES:
            raise UpstreamPanelError("unknown panel channel")
        if isinstance(self.horizon, bool) or not isinstance(self.horizon, int) or self.horizon not in HORIZONS:
            raise UpstreamPanelError("unknown panel horizon")
        if self.transform_id not in TRANSFORM_IDS:
            raise UpstreamPanelError("unknown panel transform")
        if self.support_id not in SUPPORT_IDS:
            raise UpstreamPanelError("unknown panel support")
        if self.orientation not in ORIENTATION_IDS:
            raise UpstreamPanelError("unknown panel orientation")

    @property
    def view_id(self) -> str:
        return (
            f"{self.channel_name}__h{self.horizon}__{self.transform_id}__"
            f"{self.support_id}__{self.orientation}"
        )

    @property
    def masks(self) -> tuple[int, ...]:
        return SUPPORT_MASKS[self.support_id]

    @property
    def register_count(self) -> int:
        return len(self.masks)

    @property
    def streamable(self) -> bool:
        return self.transform_id != "rank"

    @property
    def selection_eligible(self) -> bool:
        return self.streamable

    @property
    def ineligibility_reason(self) -> str | None:
        return None if self.selection_eligible else "rank-transform-requires-full-field-order"

    @property
    def spec_sha256(self) -> str:
        return _canonical_sha256(self.describe(include_hash=False))

    def describe(self, *, include_hash: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": "o1-upstream-panel-view-spec-v1",
            "panel_id": PANEL_ID,
            "view_id": self.view_id,
            "channel_name": self.channel_name,
            "horizon": self.horizon,
            "transform_id": self.transform_id,
            "support_id": self.support_id,
            "orientation": self.orientation,
            "register_count": self.register_count,
            "streamable": self.streamable,
            "selection_eligible": self.selection_eligible,
            "ineligibility_reason": self.ineligibility_reason,
        }
        if include_hash:
            value["spec_sha256"] = self.spec_sha256
        return value


def build_panel_specs() -> tuple[PanelViewSpec, ...]:
    """Return the canonical 14 x 4 x 3 x 2 x 2 view grid."""

    specs = tuple(
        PanelViewSpec(channel, horizon, transform, support, orientation)
        for channel in BASE_CHANNEL_NAMES
        for horizon in HORIZONS
        for transform in TRANSFORM_IDS
        for support in SUPPORT_IDS
        for orientation in ORIENTATION_IDS
    )
    if len(specs) != PANEL_VIEW_COUNT or len({spec.view_id for spec in specs}) != len(specs):
        raise AssertionError("canonical upstream panel cardinality differs")
    return specs


def project_view(field: UpstreamRawField, spec: PanelViewSpec) -> tuple[float, ...]:
    """Materialize one target-blind low-degree Walsh projection."""

    if not isinstance(field, UpstreamRawField) or not isinstance(spec, PanelViewSpec):
        raise TypeError("field and PanelViewSpec are required")
    base = base_channel_values(field, spec.channel_name, spec.horizon)
    transformed = transform_values(base, spec.transform_id)
    coefficients = _fwht(transformed)
    retained = np.zeros(DOMAIN_SIZE, dtype=np.float64)
    retained[np.asarray(spec.masks, dtype=np.int64)] = coefficients[
        np.asarray(spec.masks, dtype=np.int64)
    ]
    projected = _fwht(retained) / DOMAIN_SIZE
    if spec.orientation == "negative":
        projected = -projected
    projected[projected == 0.0] = 0.0
    if not np.isfinite(projected).all():
        raise UpstreamPanelError("projection produced a non-finite score")
    return tuple(float(value) for value in projected)


def _order_bytes(scores: Sequence[float]) -> tuple[bytes, int]:
    array = np.asarray(scores, dtype=np.float64)
    if array.shape != (DOMAIN_SIZE,) or not np.isfinite(array).all():
        raise UpstreamPanelError("order scores must contain 4096 finite values")
    addresses = np.arange(DOMAIN_SIZE, dtype=np.int64)
    order = np.lexsort((addresses, -array)).astype(">u2", copy=False)
    return order.tobytes(), DOMAIN_SIZE - int(np.unique(array).size)


def _decode_order(raw: bytes) -> tuple[int, ...]:
    if not isinstance(raw, bytes) or len(raw) != DOMAIN_SIZE * 2:
        raise UpstreamPanelError("complete order must be 8192 raw uint16be bytes")
    order = np.frombuffer(raw, dtype=">u2").astype(np.int64)
    if len(np.unique(order)) != DOMAIN_SIZE or int(order.min()) != 0 or int(order.max()) != DOMAIN_SIZE - 1:
        raise UpstreamPanelError("complete order is not a Direct12 permutation")
    return tuple(int(value) for value in order)


@dataclass(frozen=True)
class PanelViewResult:
    spec: PanelViewSpec
    projected_field_sha256: str
    order_uint16be: bytes
    tied_candidate_count: int
    projected_minimum: float
    projected_maximum: float
    projected_l2_energy: float
    target_rank: int | None = None
    target_gain_bits: float | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.spec, PanelViewSpec):
            raise TypeError("spec must be a PanelViewSpec")
        if len(self.projected_field_sha256) != 64:
            raise UpstreamPanelError("projected field hash must be SHA-256")
        _decode_order(self.order_uint16be)
        if not 0 <= self.tied_candidate_count < DOMAIN_SIZE:
            raise UpstreamPanelError("tied candidate count is invalid")
        for value in (
            self.projected_minimum,
            self.projected_maximum,
            self.projected_l2_energy,
        ):
            _finite(value, "projected metric")
        if self.target_rank is None:
            if self.target_gain_bits is not None:
                raise UpstreamPanelError("target gain requires a target rank")
        elif (
            isinstance(self.target_rank, bool)
            or not isinstance(self.target_rank, int)
            or not 1 <= self.target_rank <= DOMAIN_SIZE
            or self.target_gain_bits is None
        ):
            raise UpstreamPanelError("target rank binding is invalid")

    @property
    def order(self) -> tuple[int, ...]:
        return _decode_order(self.order_uint16be)

    @property
    def order_sha256(self) -> str:
        return hashlib.sha256(self.order_uint16be).hexdigest()

    def rank(self, address: int) -> int:
        if isinstance(address, bool) or not isinstance(address, int) or not 0 <= address < DOMAIN_SIZE:
            raise UpstreamPanelError("target address is outside Direct12")
        return self.order.index(address) + 1

    def describe(self, *, include_order: bool = False) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": "o1-upstream-panel-view-result-v1",
            "spec": self.spec.describe(),
            "projected_field_sha256": self.projected_field_sha256,
            "order_encoding": "raw-uint16be",
            "order_sha256": self.order_sha256,
            "order_cells": DOMAIN_SIZE,
            "tie_policy": TIE_POLICY,
            "tied_candidate_count": self.tied_candidate_count,
            "projected_minimum": self.projected_minimum,
            "projected_maximum": self.projected_maximum,
            "projected_l2_energy": self.projected_l2_energy,
            "target_rank": self.target_rank,
            "target_gain_bits": self.target_gain_bits,
            "target_labels_used": int(self.target_rank is not None),
        }
        if include_order:
            value["order"] = list(self.order)
        return value


@dataclass(frozen=True)
class UpstreamPanelResult:
    input_field_sha256: str
    views: tuple[PanelViewResult, ...]
    target_address: int | None = None
    selected_primary_view_id: str | None = None

    def __post_init__(self) -> None:
        if len(self.input_field_sha256) != 64:
            raise UpstreamPanelError("input field hash must be SHA-256")
        expected_ids = tuple(spec.view_id for spec in build_panel_specs())
        supplied_ids = tuple(view.spec.view_id for view in self.views)
        if supplied_ids != expected_ids:
            raise UpstreamPanelError("panel must contain every one of the 672 views")
        if self.target_address is None:
            if self.selected_primary_view_id is not None or any(
                view.target_rank is not None for view in self.views
            ):
                raise UpstreamPanelError("target-blind panel contains a target result")
        else:
            if (
                isinstance(self.target_address, bool)
                or not isinstance(self.target_address, int)
                or not 0 <= self.target_address < DOMAIN_SIZE
            ):
                raise UpstreamPanelError("target address is outside Direct12")
            if self.selected_primary_view_id is None or any(
                view.target_rank is None for view in self.views
            ):
                raise UpstreamPanelError("target-bound panel is incomplete")
            for view in self.views:
                rank = view.rank(self.target_address)
                gain = math.log2(DOMAIN_SIZE / rank)
                if (
                    view.target_rank != rank
                    or view.target_gain_bits != gain
                    or not math.isfinite(gain)
                ):
                    raise UpstreamPanelError(
                        "target-bound rank or gain differs from its frozen order"
                    )
            expected = _select_primary(self.views).spec.view_id
            if self.selected_primary_view_id != expected:
                raise UpstreamPanelError("selected primary differs from the frozen tie rule")

    @property
    def selected_primary(self) -> PanelViewResult | None:
        if self.selected_primary_view_id is None:
            return None
        return next(
            view for view in self.views if view.spec.view_id == self.selected_primary_view_id
        )

    def describe(self) -> dict[str, object]:
        return {
            "schema": "o1-upstream-panel-result-v1",
            "panel_id": PANEL_ID,
            "selection_procedure_id": SELECTION_PROCEDURE_ID,
            "input_field_sha256": self.input_field_sha256,
            "view_count": len(self.views),
            "selection_eligible_view_count": sum(
                view.spec.selection_eligible for view in self.views
            ),
            "target_address": self.target_address,
            "selected_primary_view_id": self.selected_primary_view_id,
            "selection_tie_policy": SELECTION_TIE_POLICY,
            "target_labels_used": int(self.target_address is not None),
            "views": [view.describe() for view in self.views],
        }


def _select_primary(views: Sequence[PanelViewResult]) -> PanelViewResult:
    eligible = [
        view
        for view in views
        if view.spec.selection_eligible and view.target_rank is not None
    ]
    if not eligible:
        raise UpstreamPanelError("no target-bound selection-eligible view exists")
    return min(
        eligible,
        key=lambda view: (
            int(view.target_rank),
            view.spec.register_count,
            view.spec.view_id,
        ),
    )


def run_upstream_panel(
    field: UpstreamRawField,
) -> UpstreamPanelResult:
    """Build all 672 target-blind orders without accepting a label."""

    if not isinstance(field, UpstreamRawField):
        raise TypeError("field must be an UpstreamRawField")
    views: list[PanelViewResult] = []
    coefficient_cache: dict[tuple[str, int, str], np.ndarray] = {}
    positive_projection_cache: dict[tuple[str, int, str, str], np.ndarray] = {}
    for spec in build_panel_specs():
        transform_key = (spec.channel_name, spec.horizon, spec.transform_id)
        coefficients = coefficient_cache.get(transform_key)
        if coefficients is None:
            base = base_channel_values(field, spec.channel_name, spec.horizon)
            coefficients = _fwht(transform_values(base, spec.transform_id))
            coefficient_cache[transform_key] = coefficients
        projection_key = (*transform_key, spec.support_id)
        positive = positive_projection_cache.get(projection_key)
        if positive is None:
            retained = np.zeros(DOMAIN_SIZE, dtype=np.float64)
            mask_indices = np.asarray(spec.masks, dtype=np.int64)
            retained[mask_indices] = coefficients[mask_indices]
            positive = _fwht(retained) / DOMAIN_SIZE
            positive[positive == 0.0] = 0.0
            positive_projection_cache[projection_key] = positive
        oriented = positive if spec.orientation == "positive" else -positive
        oriented[oriented == 0.0] = 0.0
        projected = tuple(float(value) for value in oriented)
        order_bytes, tied = _order_bytes(projected)
        array = np.asarray(projected, dtype=np.float64)
        views.append(
            PanelViewResult(
                spec=spec,
                projected_field_sha256=score_field_sha256(projected),
                order_uint16be=order_bytes,
                tied_candidate_count=tied,
                projected_minimum=float(array.min()),
                projected_maximum=float(array.max()),
                projected_l2_energy=float(np.dot(array, array)),
            )
        )
    return UpstreamPanelResult(
        input_field_sha256=field.field_sha256,
        views=tuple(views),
    )


def bind_target(panel: UpstreamPanelResult, target_address: int) -> UpstreamPanelResult:
    """Bind one revealed address to target-blind orders without recomputation."""

    if not isinstance(panel, UpstreamPanelResult):
        raise TypeError("panel must be an UpstreamPanelResult")
    if panel.target_address is not None:
        raise UpstreamPanelError("panel already has a bound target")
    if (
        isinstance(target_address, bool)
        or not isinstance(target_address, int)
        or not 0 <= target_address < DOMAIN_SIZE
    ):
        raise UpstreamPanelError("target address is outside Direct12")
    bound = tuple(
        replace(
            view,
            target_rank=(rank := view.rank(target_address)),
            target_gain_bits=math.log2(DOMAIN_SIZE / rank),
        )
        for view in panel.views
    )
    selected = _select_primary(bound)
    return UpstreamPanelResult(
        input_field_sha256=panel.input_field_sha256,
        views=bound,
        target_address=target_address,
        selected_primary_view_id=selected.spec.view_id,
    )


@dataclass(frozen=True)
class ExactLabelEnumeration:
    observed_target_address: int
    observed_selected_view_id: str
    observed_selected_rank: int
    eligible_view_ids: tuple[str, ...]
    minimum_selected_rank_by_label: tuple[int, ...]
    selected_view_index_by_label: tuple[int, ...]
    selected_rank_histogram: tuple[int, ...]
    favorable_label_count: int
    exact_familywise_p: float

    def __post_init__(self) -> None:
        if len(self.minimum_selected_rank_by_label) != DOMAIN_SIZE:
            raise UpstreamPanelError("enumeration must contain all 4096 labels")
        if len(self.selected_view_index_by_label) != DOMAIN_SIZE:
            raise UpstreamPanelError("enumeration view index must contain all labels")
        if len(self.selected_rank_histogram) != DOMAIN_SIZE:
            raise UpstreamPanelError("rank histogram must cover ranks 1 through 4096")
        if sum(self.selected_rank_histogram) != DOMAIN_SIZE:
            raise UpstreamPanelError("rank histogram does not enumerate 4096 labels")
        if not 0 <= self.favorable_label_count <= DOMAIN_SIZE:
            raise UpstreamPanelError("favorable label count is invalid")
        if self.exact_familywise_p != self.favorable_label_count / DOMAIN_SIZE:
            raise UpstreamPanelError("exact familywise probability differs")

    def selected_view_id(self, label: int) -> str:
        if isinstance(label, bool) or not isinstance(label, int) or not 0 <= label < DOMAIN_SIZE:
            raise UpstreamPanelError("label is outside Direct12")
        return self.eligible_view_ids[self.selected_view_index_by_label[label]]

    def describe(self, *, include_label_vectors: bool = False) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": "o1-upstream-panel-exact-label-fwer-v1",
            "null_id": EXACT_LABEL_NULL_ID,
            "selection_procedure_id": SELECTION_PROCEDURE_ID,
            "null_semantics": (
                "uniform enumeration of every Direct12 target label conditional on all "
                "target-blind frozen orders"
            ),
            "selection_procedure": SELECTION_TIE_POLICY,
            "labels_enumerated": DOMAIN_SIZE,
            "eligible_views": len(self.eligible_view_ids),
            "observed_target_address": self.observed_target_address,
            "observed_selected_view_id": self.observed_selected_view_id,
            "observed_selected_rank": self.observed_selected_rank,
            "favorable_label_count": self.favorable_label_count,
            "exact_familywise_p": self.exact_familywise_p,
            "selected_rank_histogram": list(self.selected_rank_histogram),
        }
        if include_label_vectors:
            value["minimum_selected_rank_by_label"] = list(
                self.minimum_selected_rank_by_label
            )
            value["selected_view_index_by_label"] = list(
                self.selected_view_index_by_label
            )
            value["eligible_view_ids"] = list(self.eligible_view_ids)
        return value


def exact_label_enumeration_fwer(
    panel: UpstreamPanelResult,
) -> ExactLabelEnumeration:
    """Enumerate all 4096 possible labels through the exact selection rule.

    This is a conditional uniform-label familywise null, not a permutation test
    over evidence values.  Rank-transform views are present in ``panel`` but are
    excluded because the complete selection procedure marks them ineligible.
    """

    if not isinstance(panel, UpstreamPanelResult):
        raise TypeError("panel must be an UpstreamPanelResult")
    if panel.target_address is None or panel.selected_primary is None:
        raise UpstreamPanelError("exact FWER requires a target-bound panel")
    eligible = tuple(
        sorted(
            (view for view in panel.views if view.spec.selection_eligible),
            key=lambda view: (view.spec.register_count, view.spec.view_id),
        )
    )
    if len(eligible) != SELECTION_ELIGIBLE_VIEW_COUNT:
        raise UpstreamPanelError("selection-eligible panel cardinality differs")
    best_rank = np.full(DOMAIN_SIZE, DOMAIN_SIZE + 1, dtype=np.int32)
    best_view = np.full(DOMAIN_SIZE, -1, dtype=np.int16)
    canonical_ranks = np.arange(1, DOMAIN_SIZE + 1, dtype=np.int32)
    for view_index, view in enumerate(eligible):
        order = np.frombuffer(view.order_uint16be, dtype=">u2").astype(np.int64)
        inverse = np.empty(DOMAIN_SIZE, dtype=np.int32)
        inverse[order] = canonical_ranks
        improves = inverse < best_rank
        best_rank[improves] = inverse[improves]
        best_view[improves] = view_index
    if np.any(best_view < 0) or np.any(best_rank > DOMAIN_SIZE):
        raise AssertionError("exact label enumeration left an unselected label")
    observed_rank = int(panel.selected_primary.target_rank)
    favorable = int(np.count_nonzero(best_rank <= observed_rank))
    histogram = np.bincount(best_rank, minlength=DOMAIN_SIZE + 1)[1:]
    return ExactLabelEnumeration(
        observed_target_address=int(panel.target_address),
        observed_selected_view_id=panel.selected_primary.spec.view_id,
        observed_selected_rank=observed_rank,
        eligible_view_ids=tuple(view.spec.view_id for view in eligible),
        minimum_selected_rank_by_label=tuple(int(value) for value in best_rank),
        selected_view_index_by_label=tuple(int(value) for value in best_view),
        selected_rank_histogram=tuple(int(value) for value in histogram),
        favorable_label_count=favorable,
        exact_familywise_p=favorable / DOMAIN_SIZE,
    )
