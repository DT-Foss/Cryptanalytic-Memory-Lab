"""Exact A291/A296 reader boundary for the next all-256 shallow-cube run."""

from __future__ import annotations

from dataclasses import dataclass
from numbers import Real
from typing import Iterable, Sequence, cast

import numpy as np

from .full256_action_pool import Full256ActionPool
from .shape532 import (
    FEATURE_NAMES,
    RawCell,
    standardized_group_scores,
    trajectory_shape532,
)


A291_HORIZONS = (1, 2, 4, 8)
A291_SELECTED_FEATURE_INDICES = (502, 504, 505, 508, 509, 510, 511, 514)
A291_SELECTED_FEATURE_NAMES = (
    "ratio_learned_clause_accepted_stage_versus_conflicts__h1__xor_gradient_l2",
    "ratio_learned_clause_accepted_stage_versus_conflicts__h2__raw_z",
    "ratio_learned_clause_accepted_stage_versus_conflicts__h2__xor_laplacian",
    "ratio_learned_clause_accepted_stage_versus_conflicts__h4__raw_z",
    "ratio_learned_clause_accepted_stage_versus_conflicts__h4__xor_laplacian",
    "ratio_learned_clause_accepted_stage_versus_conflicts__h4__xor_gradient_l2",
    "ratio_learned_clause_accepted_stage_versus_conflicts__h4__xor_gradient_maxabs",
    "ratio_learned_clause_accepted_stage_versus_conflicts__h8__xor_gradient_l2",
)

if tuple(FEATURE_NAMES[index] for index in A291_SELECTED_FEATURE_INDICES) != (
    A291_SELECTED_FEATURE_NAMES
):  # pragma: no cover - import-time contract protection.
    raise RuntimeError("A291 selected feature identity changed")


class A291A296TransferError(ValueError):
    """The frozen reader input differs from A291/A296."""


@dataclass(frozen=True)
class FAPCompatibilityReport:
    exact_mapping_available: bool
    observed_horizons: tuple[int, ...]
    missing_fields: tuple[str, ...]
    geometry_mismatches: tuple[str, ...]


def audit_fap_compatibility(pool: Full256ActionPool) -> FAPCompatibilityReport:
    """State exactly why the old H64/H65/H96 FAP cannot impersonate A291."""

    if not isinstance(pool, Full256ActionPool):
        raise TypeError("pool must be Full256ActionPool")
    return FAPCompatibilityReport(
        exact_mapping_available=False,
        observed_horizons=pool.horizons,
        missing_fields=(
            "learned_clause_accepted_stage_at_h1_h2_h4_h8",
            "conflicts_stage_delta_at_h1_h2_h4_h8",
        ),
        geometry_mismatches=(
            "FAP rows are independent bit/polarity actions, not one 256-cell cube",
            "FAP has no candidate-XOR neighborhood",
            f"FAP horizons {pool.horizons!r} differ from {A291_HORIZONS!r}",
        ),
    )


def require_exact_fap_mapping(pool: Full256ActionPool) -> None:
    """Reject the cached-field shortcut; the next run must measure RawCells."""

    report = audit_fap_compatibility(pool)
    raise A291A296TransferError(
        "exact A291/A296 mapping is unavailable: "
        + ", ".join((*report.missing_fields, *report.geometry_mismatches))
    )


def exact_a291_selected_channel_scores(
    cells: Iterable[RawCell],
    *,
    means: Sequence[float],
    scales: Sequence[float],
    coefficients: Sequence[float],
    feature_names: Sequence[str] = FEATURE_NAMES,
) -> np.ndarray:
    """Apply the frozen eight-contribution A291 score to one valid 256-cell cube."""

    if tuple(feature_names) != FEATURE_NAMES:
        raise A291A296TransferError("A291 532-feature ABI differs")
    coefficient = np.asarray(coefficients, dtype=np.float64)
    selected = np.asarray(A291_SELECTED_FEATURE_INDICES)
    if (
        coefficient.shape != (len(FEATURE_NAMES),)
        or not np.isfinite(coefficient).all()
        or np.any(coefficient[selected] <= 0.0)
    ):
        raise A291A296TransferError(
            "A291 coefficients must be finite and selected coefficients positive"
        )
    matrix = cast(Iterable[Sequence[Real]], trajectory_shape532(cells))
    scores = standardized_group_scores(
        matrix,
        means=cast(Sequence[Real], means),
        scales=cast(Sequence[Real], scales),
        coefficients=cast(Sequence[Real], coefficient.tolist()),
        groups={"A291_selected_eight": A291_SELECTED_FEATURE_INDICES},
    )["A291_selected_eight"]
    raw = np.asarray(scores, dtype=np.float64)
    if raw.shape != (256,) or not np.isfinite(raw).all():
        raise A291A296TransferError("A291 score must be finite float64[256]")
    return np.frombuffer(raw.tobytes(order="C"), dtype=np.float64)


__all__ = [
    "A291A296TransferError",
    "A291_HORIZONS",
    "A291_SELECTED_FEATURE_INDICES",
    "A291_SELECTED_FEATURE_NAMES",
    "FAPCompatibilityReport",
    "audit_fap_compatibility",
    "exact_a291_selected_channel_scores",
    "require_exact_fap_mapping",
]
