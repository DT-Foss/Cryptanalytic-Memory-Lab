"""Exact affine merge of frozen per-block parent-criticality potentials."""

from __future__ import annotations

import hashlib
import math
import struct
from collections.abc import Mapping, Sequence

import numpy as np

from .chacha_trace import UINT32_MASK
from .criticality_potential import (
    CriticalityPotentialError,
    CriticalityPotentialField,
    _canonical_field,
    compile_criticality_potential,
    score_potential_assignment,
)
from .full256_multiblock_cnf import (
    BLOCK_VARIABLE_STRIDE,
    MAXIMUM_BLOCK_COUNT,
    SHARED_KEY_VARIABLE_COUNT,
    SINGLE_BLOCK_VARIABLE_COUNT,
    remap_full256_variable,
)
from .proof_parent_criticality import FEATURE_NAMES, ParentCriticalityField


MULTIBLOCK_POTENTIAL_DOMAIN = b"O1-MULTIBLOCK-CRITICALITY-POTENTIAL-V1\0"


class MultiblockCriticalityPotentialError(CriticalityPotentialError):
    """Ordered fields, calibrations, remap, or complete score differ."""


def _float_array(value: object, *, field: str) -> np.ndarray:
    try:
        result = np.array(value, dtype=np.float64, copy=True)
    except (TypeError, ValueError) as exc:
        raise MultiblockCriticalityPotentialError(f"{field} differs") from exc
    if result.shape != (len(FEATURE_NAMES),) or not bool(np.all(np.isfinite(result))):
        raise MultiblockCriticalityPotentialError(f"{field} differs")
    return result


def _finite_scalar(value: object, *, field: str, positive: bool = False) -> float:
    if (
        isinstance(value, (bool, np.bool_))
        or not isinstance(value, (int, float, np.integer, np.floating))
        or not math.isfinite(float(value))
        or (positive and float(value) <= 0.0)
    ):
        raise MultiblockCriticalityPotentialError(f"{field} differs")
    return float(value)


def _ordered_inputs(
    fields: Sequence[ParentCriticalityField],
    *,
    counters: Sequence[int],
    feature_means: Sequence[Sequence[float] | np.ndarray],
    feature_stds: Sequence[Sequence[float] | np.ndarray],
    reader: Sequence[float] | np.ndarray,
    scalar_score_means: Sequence[float],
    scalar_score_stds: Sequence[float],
    block_weights: Sequence[float] | None,
) -> tuple[
    tuple[ParentCriticalityField, ...],
    tuple[int, ...],
    tuple[np.ndarray, ...],
    tuple[np.ndarray, ...],
    np.ndarray,
    tuple[float, ...],
    tuple[float, ...],
    tuple[float, ...],
]:
    if isinstance(fields, (str, bytes)):
        raise MultiblockCriticalityPotentialError("multiblock fields differ")
    field_rows = tuple(fields)
    count = len(field_rows)
    if not 1 <= count <= MAXIMUM_BLOCK_COUNT or any(
        not isinstance(field, ParentCriticalityField) for field in field_rows
    ):
        raise MultiblockCriticalityPotentialError("multiblock fields differ")
    counter_rows = tuple(counters)
    mean_rows = tuple(feature_means)
    std_rows = tuple(feature_stds)
    scalar_means_raw = tuple(scalar_score_means)
    scalar_stds_raw = tuple(scalar_score_stds)
    weights_raw = (1.0,) * count if block_weights is None else tuple(block_weights)
    if any(
        len(rows) != count
        for rows in (
            counter_rows,
            mean_rows,
            std_rows,
            scalar_means_raw,
            scalar_stds_raw,
            weights_raw,
        )
    ):
        raise MultiblockCriticalityPotentialError(
            "multiblock calibration count differs"
        )
    if any(
        isinstance(counter, (bool, np.bool_))
        or not isinstance(counter, (int, np.integer))
        or not 0 <= int(counter) <= UINT32_MASK
        for counter in counter_rows
    ):
        raise MultiblockCriticalityPotentialError("multiblock counters differ")
    normalized_counters = tuple(int(counter) for counter in counter_rows)
    if normalized_counters[-1] > UINT32_MASK or normalized_counters != tuple(
        normalized_counters[0] + index for index in range(count)
    ):
        raise MultiblockCriticalityPotentialError(
            "multiblock counters must be contiguous"
        )
    normalized_means = tuple(
        _float_array(value, field=f"feature_means[{index}]")
        for index, value in enumerate(mean_rows)
    )
    normalized_stds = tuple(
        _float_array(value, field=f"feature_stds[{index}]")
        for index, value in enumerate(std_rows)
    )
    if any(bool(np.any(value < 0.0)) for value in normalized_stds):
        raise MultiblockCriticalityPotentialError("feature standard deviation differs")
    normalized_reader = _float_array(reader, field="reader")
    normalized_scalar_means = tuple(
        _finite_scalar(value, field=f"scalar_score_means[{index}]")
        for index, value in enumerate(scalar_means_raw)
    )
    normalized_scalar_stds = tuple(
        _finite_scalar(value, field=f"scalar_score_stds[{index}]", positive=True)
        for index, value in enumerate(scalar_stds_raw)
    )
    normalized_weights = tuple(
        _finite_scalar(value, field=f"block_weights[{index}]")
        for index, value in enumerate(weights_raw)
    )
    if any(weight == 0.0 for weight in normalized_weights):
        raise MultiblockCriticalityPotentialError("block weights must be nonzero")
    return (
        field_rows,
        normalized_counters,
        normalized_means,
        normalized_stds,
        normalized_reader,
        normalized_scalar_means,
        normalized_scalar_stds,
        normalized_weights,
    )


def _source_sha256(
    fields: Sequence[ParentCriticalityField],
    counters: Sequence[int],
    means: Sequence[np.ndarray],
    stds: Sequence[np.ndarray],
    reader: np.ndarray,
    scalar_means: Sequence[float],
    scalar_stds: Sequence[float],
    weights: Sequence[float],
) -> str:
    digest = hashlib.sha256(MULTIBLOCK_POTENTIAL_DOMAIN)
    digest.update(
        struct.pack(
            "<HHII",
            len(fields),
            SHARED_KEY_VARIABLE_COUNT,
            SINGLE_BLOCK_VARIABLE_COUNT,
            BLOCK_VARIABLE_STRIDE,
        )
    )
    digest.update(np.ascontiguousarray(reader, dtype="<f8").tobytes())
    for block_index, field in enumerate(fields):
        payload = field.to_bytes()
        digest.update(
            struct.pack("<IIQ", block_index, counters[block_index], len(payload))
        )
        digest.update(payload)
        digest.update(np.ascontiguousarray(means[block_index], dtype="<f8").tobytes())
        digest.update(np.ascontiguousarray(stds[block_index], dtype="<f8").tobytes())
        digest.update(
            struct.pack(
                "<ddd",
                scalar_means[block_index],
                scalar_stds[block_index],
                weights[block_index],
            )
        )
    return digest.hexdigest()


def _local_potentials(
    fields: Sequence[ParentCriticalityField],
    means: Sequence[np.ndarray],
    stds: Sequence[np.ndarray],
    reader: np.ndarray,
) -> tuple[CriticalityPotentialField, ...]:
    return tuple(
        compile_criticality_potential(
            field,
            feature_mean=means[index],
            feature_std=stds[index],
            reader=reader,
        )
        for index, field in enumerate(fields)
    )


def compile_multiblock_criticality_potential(
    fields: Sequence[ParentCriticalityField],
    *,
    counters: Sequence[int],
    feature_means: Sequence[Sequence[float] | np.ndarray],
    feature_stds: Sequence[Sequence[float] | np.ndarray],
    reader: Sequence[float] | np.ndarray,
    scalar_score_means: Sequence[float],
    scalar_score_stds: Sequence[float],
    block_weights: Sequence[float] | None = None,
) -> CriticalityPotentialField:
    """Compile and merge ``sum(weight_b * scalar_z_b)`` exactly by scope."""

    (
        field_rows,
        counter_rows,
        mean_rows,
        std_rows,
        reader_row,
        scalar_mean_rows,
        scalar_std_rows,
        weight_rows,
    ) = _ordered_inputs(
        fields,
        counters=counters,
        feature_means=feature_means,
        feature_stds=feature_stds,
        reader=reader,
        scalar_score_means=scalar_score_means,
        scalar_score_stds=scalar_score_stds,
        block_weights=block_weights,
    )
    local = _local_potentials(field_rows, mean_rows, std_rows, reader_row)
    offset_terms: list[float] = []
    tables: dict[tuple[int, ...], np.ndarray] = {}
    for block_index, potential in enumerate(local):
        scale = weight_rows[block_index] / scalar_std_rows[block_index]
        offset_terms.append(
            weight_rows[block_index]
            * (potential.offset - scalar_mean_rows[block_index])
            / scalar_std_rows[block_index]
        )
        for factor in potential.factors:
            variables = tuple(
                remap_full256_variable(variable, block_index)
                for variable in factor.variables
            )
            energies = np.asarray(factor.energies, dtype=np.float64) * scale
            if not bool(np.all(np.isfinite(energies))):
                raise MultiblockCriticalityPotentialError(
                    "scaled multiblock factor is non-finite"
                )
            existing = tables.setdefault(variables, np.zeros_like(energies))
            if existing.shape != energies.shape:
                raise MultiblockCriticalityPotentialError(
                    "colliding multiblock factor widths differ"
                )
            existing += energies
            if not bool(np.all(np.isfinite(existing))):
                raise MultiblockCriticalityPotentialError(
                    "merged multiblock factor is non-finite"
                )
    offset = math.fsum(offset_terms)
    if not math.isfinite(offset):
        raise MultiblockCriticalityPotentialError(
            "multiblock potential offset is non-finite"
        )
    source = _source_sha256(
        field_rows,
        counter_rows,
        mean_rows,
        std_rows,
        reader_row,
        scalar_mean_rows,
        scalar_std_rows,
        weight_rows,
    )
    try:
        return _canonical_field(tables, offset=offset, source_sha256=source)
    except CriticalityPotentialError as exc:
        raise MultiblockCriticalityPotentialError(
            "compiled multiblock potential differs"
        ) from exc


def score_multiblock_criticality_components(
    fields: Sequence[ParentCriticalityField],
    assignment: Mapping[int, int],
    *,
    counters: Sequence[int],
    feature_means: Sequence[Sequence[float] | np.ndarray],
    feature_stds: Sequence[Sequence[float] | np.ndarray],
    reader: Sequence[float] | np.ndarray,
    scalar_score_means: Sequence[float],
    scalar_score_stds: Sequence[float],
    block_weights: Sequence[float] | None = None,
) -> float:
    """Score the unmerged components for complete-equivalence checks."""

    if not isinstance(assignment, Mapping):
        raise MultiblockCriticalityPotentialError(
            "multiblock complete assignment differs"
        )
    (
        field_rows,
        _,
        mean_rows,
        std_rows,
        reader_row,
        scalar_mean_rows,
        scalar_std_rows,
        weight_rows,
    ) = _ordered_inputs(
        fields,
        counters=counters,
        feature_means=feature_means,
        feature_stds=feature_stds,
        reader=reader,
        scalar_score_means=scalar_score_means,
        scalar_score_stds=scalar_score_stds,
        block_weights=block_weights,
    )
    local = _local_potentials(field_rows, mean_rows, std_rows, reader_row)
    terms: list[float] = []
    for block_index, potential in enumerate(local):
        local_assignment: dict[int, int] = {}
        for variable in potential.observed_variables:
            global_variable = remap_full256_variable(variable, block_index)
            spin = assignment.get(global_variable)
            if spin not in (-1, 1):
                raise MultiblockCriticalityPotentialError(
                    "multiblock complete assignment lacks variable"
                )
            local_assignment[variable] = spin
        raw_score = score_potential_assignment(potential, local_assignment)
        term = (
            weight_rows[block_index]
            * (raw_score - scalar_mean_rows[block_index])
            / scalar_std_rows[block_index]
        )
        if not math.isfinite(term):
            raise MultiblockCriticalityPotentialError(
                "multiblock component score is non-finite"
            )
        terms.append(term)
    result = math.fsum(terms)
    if not math.isfinite(result):
        raise MultiblockCriticalityPotentialError(
            "multiblock component sum is non-finite"
        )
    return result


def verify_multiblock_complete_score_equivalence(
    potential: CriticalityPotentialField,
    fields: Sequence[ParentCriticalityField],
    assignment: Mapping[int, int],
    *,
    counters: Sequence[int],
    feature_means: Sequence[Sequence[float] | np.ndarray],
    feature_stds: Sequence[Sequence[float] | np.ndarray],
    reader: Sequence[float] | np.ndarray,
    scalar_score_means: Sequence[float],
    scalar_score_stds: Sequence[float],
    block_weights: Sequence[float] | None = None,
    absolute_tolerance: float = 1e-12,
) -> float:
    """Fail closed unless merged and component complete scores agree."""

    tolerance = _finite_scalar(absolute_tolerance, field="absolute_tolerance")
    if tolerance < 0.0 or not isinstance(potential, CriticalityPotentialField):
        raise MultiblockCriticalityPotentialError(
            "complete-equivalence contract differs"
        )
    if not set(potential.observed_variables).issubset(assignment):
        raise MultiblockCriticalityPotentialError("merged complete assignment differs")
    merged = score_potential_assignment(potential, assignment)
    components = score_multiblock_criticality_components(
        fields,
        assignment,
        counters=counters,
        feature_means=feature_means,
        feature_stds=feature_stds,
        reader=reader,
        scalar_score_means=scalar_score_means,
        scalar_score_stds=scalar_score_stds,
        block_weights=block_weights,
    )
    if not math.isclose(merged, components, rel_tol=0.0, abs_tol=tolerance):
        raise MultiblockCriticalityPotentialError(
            "merged and component complete scores differ"
        )
    return merged


__all__ = [
    "MULTIBLOCK_POTENTIAL_DOMAIN",
    "MultiblockCriticalityPotentialError",
    "compile_multiblock_criticality_potential",
    "score_multiblock_criticality_components",
    "verify_multiblock_complete_score_equivalence",
]
