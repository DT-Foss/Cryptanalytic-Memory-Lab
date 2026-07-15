"""Pure-Python Direct12 trajectory-shape and frozen-pair primitives.

The module intentionally has no dependency on NumPy or on the source project
that first produced the artifacts.  Candidate identity is the row index, so a
complete input cover is always ordered from candidate 0 through candidate 255.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from numbers import Real
from typing import TypeAlias

HORIZONS = (1, 2, 4, 8)
RAW_CHANNELS = (
    "conflicts",
    "decisions",
    "search_propagations",
    "active_variables_delta",
    "irredundant_clauses_delta",
    "redundant_clauses_delta",
    "learned_clause_accepted_stage",
    "learned_clause_offered_stage",
    "learned_clause_rejected_large_stage",
    "learned_literal_count_stage",
    "learned_clause_length_mean",
    "learned_clause_length_std",
    "learned_clause_length_max",
)
SIGNED_RATIO_PAIRS = (
    ("decisions", "conflicts"),
    ("search_propagations", "decisions"),
    ("learned_clause_accepted_stage", "conflicts"),
    ("learned_literal_count_stage", "learned_clause_accepted_stage"),
)
CUBE_TRANSFORMS = (
    "raw_z",
    "xor_laplacian",
    "xor_gradient_l2",
    "xor_gradient_maxabs",
)
CANDIDATE_BITS = 8
CANDIDATE_COUNT = 1 << CANDIDATE_BITS
DIRECT12_SLICE_BITS = 4
DIRECT12_SLICE_COUNT = 1 << DIRECT12_SLICE_BITS
DIRECT12_CELL_COUNT = CANDIDATE_COUNT * DIRECT12_SLICE_COUNT
CONSTANT_ABSOLUTE_THRESHOLD = 1e-12
CONSTANT_RELATIVE_THRESHOLD = 1e-12

NumericRow: TypeAlias = Sequence[Real]
NumericMatrix: TypeAlias = Sequence[NumericRow]
RawCell: TypeAlias = Mapping[int, Mapping[str, Real]]


class Shape532Error(ValueError):
    """Raised when input geometry or a frozen reader parameter is invalid."""


def _base_feature_names() -> tuple[str, ...]:
    names: list[str] = []
    for channel in RAW_CHANNELS:
        names.extend(f"{channel}__profile_h{horizon}" for horizon in HORIZONS)
        names.extend(
            f"{channel}__first_difference_{left}_{right}"
            for left, right in zip(HORIZONS, HORIZONS[1:])
        )
        names.extend(
            f"{channel}__second_difference_{left}_{middle}_{right}"
            for left, middle, right in zip(HORIZONS, HORIZONS[1:], HORIZONS[2:])
        )
    for numerator, denominator in SIGNED_RATIO_PAIRS:
        names.extend(
            f"ratio_{numerator}_versus_{denominator}__h{horizon}"
            for horizon in HORIZONS
        )
    return tuple(names)


BASE_FEATURE_NAMES = _base_feature_names()
FEATURE_NAMES = tuple(
    f"{base_name}__{transform}"
    for base_name in BASE_FEATURE_NAMES
    for transform in CUBE_TRANSFORMS
)


def _names_sha256(names: Sequence[str]) -> str:
    raw = json.dumps(list(names), separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    return hashlib.sha256(raw).hexdigest()


BASE_FEATURE_NAMES_SHA256 = _names_sha256(BASE_FEATURE_NAMES)
FEATURE_NAMES_SHA256 = _names_sha256(FEATURE_NAMES)
EXPECTED_BASE_FEATURE_NAMES_SHA256 = (
    "89a4ddc5696a3312ca5d41d38c8f9b4facc9e750bcb85124b8de3b88b85dd93b"
)
EXPECTED_FEATURE_NAMES_SHA256 = (
    "83154bc39a17121debca0884f776fe09be890eab323428a668387fcf806c3012"
)
if (
    BASE_FEATURE_NAMES_SHA256 != EXPECTED_BASE_FEATURE_NAMES_SHA256
    or FEATURE_NAMES_SHA256 != EXPECTED_FEATURE_NAMES_SHA256
):  # pragma: no cover - protects the import-time feature contract
    raise RuntimeError("canonical Direct12 feature-name contract changed")


def _finite_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise Shape532Error(f"{field} must be a real number")
    result = float(value)
    if not math.isfinite(result):
        raise Shape532Error(f"{field} must be finite")
    return result


def _finite_vector(
    values: Sequence[Real] | Iterable[Real],
    *,
    length: int,
    field: str,
) -> tuple[float, ...]:
    try:
        result = tuple(
            _finite_number(value, f"{field}[{index}]")
            for index, value in enumerate(values)
        )
    except TypeError as error:
        raise Shape532Error(f"{field} must be iterable") from error
    if len(result) != length:
        raise Shape532Error(f"{field} must contain exactly {length} values")
    return result


def _finite_matrix(
    matrix: Iterable[Sequence[Real]],
    *,
    width: int,
    rows: int | None = None,
    field: str = "matrix",
) -> tuple[tuple[float, ...], ...]:
    try:
        result = tuple(
            _finite_vector(row, length=width, field=f"{field}[{row_index}]")
            for row_index, row in enumerate(matrix)
        )
    except TypeError as error:
        raise Shape532Error(f"{field} must be iterable") from error
    if rows is not None and len(result) != rows:
        raise Shape532Error(f"{field} must contain exactly {rows} rows")
    return result


def _validated_cells(cells: Iterable[RawCell]) -> tuple[RawCell, ...]:
    try:
        result = tuple(cells)
    except TypeError as error:
        raise Shape532Error("cells must be iterable") from error
    if len(result) != CANDIDATE_COUNT:
        raise Shape532Error("cells must contain the complete 256-candidate cover")
    expected_horizons = set(HORIZONS)
    expected_channels = set(RAW_CHANNELS)
    for candidate, cell in enumerate(result):
        if not isinstance(cell, Mapping) or set(cell) != expected_horizons:
            raise Shape532Error(
                f"cells[{candidate}] must contain exactly horizons {HORIZONS}"
            )
        for horizon in HORIZONS:
            row = cell[horizon]
            if not isinstance(row, Mapping) or set(row) != expected_channels:
                raise Shape532Error(
                    f"cells[{candidate}][{horizon}] must contain exactly the "
                    f"{len(RAW_CHANNELS)} canonical raw channels"
                )
            for channel in RAW_CHANNELS:
                _finite_number(
                    row[channel], f"cells[{candidate}][{horizon}][{channel!r}]"
                )
    return result


def _shape_vector(cell: RawCell) -> tuple[float, ...]:
    channel_values = {
        channel: tuple(float(cell[horizon][channel]) for horizon in HORIZONS)
        for channel in RAW_CHANNELS
    }
    profiles: dict[str, tuple[float, ...]] = {}
    result: list[float] = []
    for channel in RAW_CHANNELS:
        raw = channel_values[channel]
        scale = math.fsum(abs(value) for value in raw)
        profile = (
            tuple(value / scale for value in raw)
            if scale > 0.0
            else (0.0, 0.0, 0.0, 0.0)
        )
        profiles[channel] = profile
        first = tuple(profile[index + 1] - profile[index] for index in range(3))
        second = tuple(first[index + 1] - first[index] for index in range(2))
        result.extend(profile)
        result.extend(first)
        result.extend(second)
    for numerator, denominator in SIGNED_RATIO_PAIRS:
        left = channel_values[numerator]
        right = channel_values[denominator]
        for left_value, right_value in zip(left, right):
            scale = abs(left_value) + abs(right_value)
            result.append(
                (left_value - right_value) / scale if scale > 0.0 else 0.0
            )
    if len(result) != len(BASE_FEATURE_NAMES) or not all(
        math.isfinite(value) for value in result
    ):
        raise RuntimeError("Direct12 base feature construction failed")
    return tuple(result)


def trajectory_base133(cells: Iterable[RawCell]) -> tuple[tuple[float, ...], ...]:
    """Build the 133 scale-free temporal features for a complete cell cover."""

    return tuple(_shape_vector(cell) for cell in _validated_cells(cells))


def _population_mean_std(values: Sequence[float]) -> tuple[float, float]:
    if not values:
        raise Shape532Error("population cannot be empty")
    mean = math.fsum(values) / len(values)
    variance = math.fsum((value - mean) ** 2 for value in values) / len(values)
    # A negative value can only be a floating-point reduction artifact.
    return mean, math.sqrt(max(0.0, variance))


def candidate_cover_zscores(
    base_matrix: Iterable[Sequence[Real]],
) -> tuple[tuple[float, ...], ...]:
    """Population-standardize 133 features over the complete 256-cell cover.

    A column is exactly zeroed when ``std <= max(1e-12, abs(mean)*1e-12)``.
    This threshold is part of the frozen feature definition.
    """

    base = _finite_matrix(
        base_matrix,
        width=len(BASE_FEATURE_NAMES),
        rows=CANDIDATE_COUNT,
        field="base_matrix",
    )
    result = [[0.0] * len(BASE_FEATURE_NAMES) for _ in range(CANDIDATE_COUNT)]
    for feature_index in range(len(BASE_FEATURE_NAMES)):
        column = tuple(row[feature_index] for row in base)
        mean, scale = _population_mean_std(column)
        threshold = max(
            CONSTANT_ABSOLUTE_THRESHOLD,
            abs(mean) * CONSTANT_RELATIVE_THRESHOLD,
        )
        if scale <= threshold:
            continue
        for candidate, value in enumerate(column):
            result[candidate][feature_index] = (value - mean) / scale
    return tuple(tuple(row) for row in result)


def expand_cube_orbits(
    base_matrix: Iterable[Sequence[Real]],
) -> tuple[tuple[float, ...], ...]:
    """Expand 133 base features into the frozen base-major 532 layout."""

    standardized = candidate_cover_zscores(base_matrix)
    output: list[tuple[float, ...]] = []
    for candidate in range(CANDIDATE_COUNT):
        row: list[float] = []
        for feature_index in range(len(BASE_FEATURE_NAMES)):
            value = standardized[candidate][feature_index]
            residuals = tuple(
                value - standardized[candidate ^ (1 << bit)][feature_index]
                for bit in range(CANDIDATE_BITS)
            )
            row.extend(
                (
                    value,
                    math.fsum(residuals) / CANDIDATE_BITS,
                    math.sqrt(
                        math.fsum(residual * residual for residual in residuals)
                        / CANDIDATE_BITS
                    ),
                    max(abs(residual) for residual in residuals),
                )
            )
        if len(row) != len(FEATURE_NAMES) or not all(
            math.isfinite(value) for value in row
        ):
            raise RuntimeError("Direct12 cube-orbit expansion failed")
        output.append(tuple(row))
    return tuple(output)


def trajectory_shape532(
    cells: Iterable[RawCell],
) -> tuple[tuple[float, ...], ...]:
    """Build the complete 256 by 532 Direct12 trajectory-shape matrix."""

    return expand_cube_orbits(trajectory_base133(cells))


build_shape532 = trajectory_shape532


def standardized_contributions(
    matrix: Iterable[Sequence[Real]],
    *,
    means: Sequence[Real],
    scales: Sequence[Real],
    coefficients: Sequence[Real],
) -> tuple[tuple[float, ...], ...]:
    """Return the additive standardized coefficient contribution matrix."""

    coefficient = tuple(
        _finite_number(value, f"coefficients[{index}]")
        for index, value in enumerate(coefficients)
    )
    if not coefficient:
        raise Shape532Error("coefficients cannot be empty")
    width = len(coefficient)
    center = _finite_vector(means, length=width, field="means")
    scale = _finite_vector(scales, length=width, field="scales")
    if any(value <= 0.0 for value in scale):
        raise Shape532Error("scales must be strictly positive")
    values = _finite_matrix(matrix, width=width)
    return tuple(
        tuple(
            ((value - center[index]) / scale[index]) * coefficient[index]
            for index, value in enumerate(row)
        )
        for row in values
    )


def _validated_groups(
    groups: Mapping[str, Sequence[int]], width: int
) -> dict[str, tuple[int, ...]]:
    if not isinstance(groups, Mapping) or not groups:
        raise Shape532Error("groups must be a non-empty mapping")
    result: dict[str, tuple[int, ...]] = {}
    for name, raw_indices in groups.items():
        if not isinstance(name, str) or not name:
            raise Shape532Error("group names must be non-empty strings")
        indices = tuple(raw_indices)
        if (
            not indices
            or any(
                not isinstance(index, int)
                or isinstance(index, bool)
                or not 0 <= index < width
                for index in indices
            )
            or len(indices) != len(set(indices))
        ):
            raise Shape532Error(f"invalid feature indices for group {name!r}")
        result[name] = indices
    return result


def grouped_scores(
    contributions: Iterable[Sequence[Real]],
    groups: Mapping[str, Sequence[int]],
) -> dict[str, tuple[float, ...]]:
    """Sum additive contributions over explicit frozen feature-index groups."""

    rows = tuple(tuple(row) for row in contributions)
    if not rows:
        raise Shape532Error("contributions cannot be empty")
    width = len(rows[0])
    values = _finite_matrix(rows, width=width, field="contributions")
    selected = _validated_groups(groups, width)
    return {
        name: tuple(math.fsum(row[index] for index in indices) for row in values)
        for name, indices in selected.items()
    }


def standardized_group_scores(
    matrix: Iterable[Sequence[Real]],
    *,
    means: Sequence[Real],
    scales: Sequence[Real],
    coefficients: Sequence[Real],
    groups: Mapping[str, Sequence[int]],
) -> dict[str, tuple[float, ...]]:
    """Standardize, weight, and reduce explicit feature-index groups."""

    return grouped_scores(
        standardized_contributions(
            matrix, means=means, scales=scales, coefficients=coefficients
        ),
        groups,
    )


def normalized_cube_laplacian(scores: Sequence[Real]) -> tuple[float, ...]:
    """Return score minus the mean of all eight Hamming-one neighbors."""

    values = _finite_vector(scores, length=CANDIDATE_COUNT, field="scores")
    return tuple(
        values[candidate]
        - math.fsum(
            values[candidate ^ (1 << bit)] for bit in range(CANDIDATE_BITS)
        )
        / CANDIDATE_BITS
        for candidate in range(CANDIDATE_COUNT)
    )


def descending_midranks(scores: Sequence[Real]) -> tuple[float, ...]:
    """Return one-based descending midranks with exact tie handling."""

    values = _finite_vector(scores, length=CANDIDATE_COUNT, field="scores")
    order = sorted(range(CANDIDATE_COUNT), key=lambda index: -values[index])
    ranks = [0.0] * CANDIDATE_COUNT
    start = 0
    while start < CANDIDATE_COUNT:
        stop = start + 1
        while stop < CANDIDATE_COUNT and values[order[stop]] == values[order[start]]:
            stop += 1
        midrank = (start + 1 + stop) / 2.0
        for position in range(start, stop):
            ranks[order[position]] = midrank
        start = stop
    return tuple(ranks)


def descending_midrank(scores: Sequence[Real], candidate: int) -> float:
    """Return one candidate's one-based descending midrank."""

    if (
        not isinstance(candidate, int)
        or isinstance(candidate, bool)
        or candidate not in range(CANDIDATE_COUNT)
    ):
        raise Shape532Error("candidate must be an integer in 0...255")
    return descending_midranks(scores)[candidate]


def pair_score(left_scores: Sequence[Real], right_scores: Sequence[Real]) -> tuple[float, ...]:
    """Return A342's negative sum of the two descending-midrank fields."""

    left_ranks = descending_midranks(left_scores)
    right_ranks = descending_midranks(right_scores)
    return tuple(
        -(left + right) for left, right in zip(left_ranks, right_ranks)
    )


def within_slice_population_zscores(scores: Sequence[Real]) -> tuple[float, ...]:
    """Population-zscore each of the 16 fixed-low4 Direct12 slices."""

    values = _finite_vector(scores, length=DIRECT12_CELL_COUNT, field="scores")
    result = [0.0] * DIRECT12_CELL_COUNT
    for low4 in range(DIRECT12_SLICE_COUNT):
        cells = tuple(
            (high8 << DIRECT12_SLICE_BITS) | low4
            for high8 in range(CANDIDATE_COUNT)
        )
        field = tuple(values[cell] for cell in cells)
        mean, scale = _population_mean_std(field)
        if scale <= 0.0:
            raise Shape532Error(f"Direct12 slice {low4} has zero score variance")
        for cell, value in zip(cells, field):
            result[cell] = (value - mean) / scale
    return tuple(result)


def direct12_order(scores: Sequence[Real]) -> tuple[int, ...]:
    """Order all Direct12 cells by descending score, then ascending cell id."""

    values = _finite_vector(scores, length=DIRECT12_CELL_COUNT, field="scores")
    return tuple(
        sorted(
            range(DIRECT12_CELL_COUNT),
            key=lambda cell: (-values[cell], cell),
        )
    )


def direct12_order_uint16be_sha256(order: Sequence[int]) -> str:
    """Hash a complete Direct12 order as concatenated unsigned 16-bit BE cells."""

    values = tuple(order)
    if (
        len(values) != DIRECT12_CELL_COUNT
        or any(
            not isinstance(cell, int)
            or isinstance(cell, bool)
            or cell not in range(DIRECT12_CELL_COUNT)
            for cell in values
        )
        or len(set(values)) != DIRECT12_CELL_COUNT
    ):
        raise Shape532Error("order must be a complete Direct12 cell permutation")
    digest = hashlib.sha256()
    for cell in values:
        digest.update(cell.to_bytes(2, "big", signed=False))
    return digest.hexdigest()


@dataclass(frozen=True)
class Direct12FrozenPairResult:
    """Deterministic output of the complete frozen A342 pair interface."""

    raw_pair_scores: tuple[float, ...]
    slice_zscores: tuple[float, ...]
    order: tuple[int, ...]
    order_uint16be_sha256: str


def score_direct12_frozen_pair(
    slice_matrices: Iterable[Iterable[Sequence[Real]]]
    | Mapping[int, Iterable[Sequence[Real]]],
    *,
    means: Sequence[Real],
    scales: Sequence[Real],
    coefficients: Sequence[Real],
    pair_group_indices: Sequence[Sequence[int]],
) -> Direct12FrozenPairResult:
    """Apply the frozen two-view A342 reader to 16 ordered 256-cell slices.

    A sequence/iterable is interpreted in low4 order.  A mapping must contain
    exactly integer keys 0 through 15.  No reader fit or semantic-group
    inference occurs here: both feature-index groups are explicit inputs.
    """

    coefficient = tuple(
        _finite_number(value, f"coefficients[{index}]")
        for index, value in enumerate(coefficients)
    )
    if not coefficient:
        raise Shape532Error("coefficients cannot be empty")
    width = len(coefficient)
    center = _finite_vector(means, length=width, field="means")
    scale = _finite_vector(scales, length=width, field="scales")
    if any(value <= 0.0 for value in scale):
        raise Shape532Error("scales must be strictly positive")
    raw_groups = tuple(pair_group_indices)
    if len(raw_groups) != 2:
        raise Shape532Error("pair_group_indices must contain exactly two groups")
    groups = _validated_groups(
        {"left": raw_groups[0], "right": raw_groups[1]}, width
    )

    if isinstance(slice_matrices, Mapping):
        if set(slice_matrices) != set(range(DIRECT12_SLICE_COUNT)):
            raise Shape532Error("slice mapping must contain exactly low4 keys 0...15")
        slices: Iterable[tuple[int, Iterable[Sequence[Real]]]] = (
            (low4, slice_matrices[low4]) for low4 in range(DIRECT12_SLICE_COUNT)
        )
    else:
        slices = enumerate(slice_matrices)

    field = [0.0] * DIRECT12_CELL_COUNT
    slice_count = 0
    for low4, raw_matrix in slices:
        if low4 not in range(DIRECT12_SLICE_COUNT):
            raise Shape532Error("slice iterable contains more than 16 slices")
        matrix = _finite_matrix(
            raw_matrix,
            width=width,
            rows=CANDIDATE_COUNT,
            field=f"slice_matrices[{low4}]",
        )
        selected_scores: list[tuple[float, ...]] = []
        for indices in (groups["left"], groups["right"]):
            selected_scores.append(
                tuple(
                    math.fsum(
                        ((row[index] - center[index]) / scale[index])
                        * coefficient[index]
                        for index in indices
                    )
                    for row in matrix
                )
            )
        left = normalized_cube_laplacian(selected_scores[0])
        right = normalized_cube_laplacian(selected_scores[1])
        scores = pair_score(left, right)
        for high8, score in enumerate(scores):
            field[(high8 << DIRECT12_SLICE_BITS) | low4] = score
        slice_count += 1
    if slice_count != DIRECT12_SLICE_COUNT:
        raise Shape532Error("slice iterable must contain exactly 16 slices")

    normalized = within_slice_population_zscores(field)
    order = direct12_order(normalized)
    return Direct12FrozenPairResult(
        raw_pair_scores=tuple(field),
        slice_zscores=normalized,
        order=order,
        order_uint16be_sha256=direct12_order_uint16be_sha256(order),
    )

