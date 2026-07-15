"""Target-blind readers for normalized Stage-3 solver trajectories.

The module enforces the retrospective protocol as a lifecycle instead of relying
on call-site discipline:

``TRAIN labels -> fit candidates -> blind validation scores -> freeze plan``

Holdout features may be ranked at any time after fitting, but holdout labels are
rejected until the reader plan is frozen.  Validation selects among models fit
only on TRAIN; it never refits their parameters.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from enum import Enum
from statistics import fmean, median
from typing import Iterable, Mapping, Sequence

from .stage3 import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_SHA256,
    DatasetSplit,
    RevealedCellLabel,
    Stage3Dataset,
    Stage3Episode,
)
from .types import InformationLabel


class ReaderError(ValueError):
    """Raised when a reader or evaluation violates the split protocol."""


NORMALIZER_SCHEMA = "within-episode-median-mad-midrank-v1"
PLAN_SCHEMA = "o1-crypto-frozen-trajectory-reader-plan-v1"
TIE_POLICY = "score-descending-cell-index-ascending"
HOLDOUT_SPLITS = frozenset(
    {
        DatasetSplit.RETROSPECTIVE_HOLDOUT,
        DatasetSplit.TRANSFER_HOLDOUT,
        DatasetSplit.TEST,
        DatasetSplit.SEALED_DEPLOYMENT,
    }
)


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _identity(episode: Stage3Episode) -> tuple[str, str]:
    return episode.spec.family, episode.spec.target_id


def _label_identity(label: RevealedCellLabel) -> tuple[str, str]:
    return label.family, label.target_id


def _finite(value: float, field: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ReaderError(f"{field} must be finite")
    return result


def _mean_vector(rows: Sequence[Sequence[float]]) -> tuple[float, ...]:
    if not rows:
        raise ReaderError("cannot average an empty vector collection")
    width = len(rows[0])
    if width == 0 or any(len(row) != width for row in rows):
        raise ReaderError("vectors must be non-empty and rectangular")
    return tuple(fmean(row[index] for row in rows) for index in range(width))


def _unit_l2(values: Sequence[float]) -> tuple[float, ...]:
    norm = math.sqrt(sum(value * value for value in values))
    if norm == 0.0:
        return tuple(0.0 for _ in values)
    return tuple(value / norm for value in values)


def _midranks(values: Sequence[float]) -> tuple[float, ...]:
    """Map values to deterministic centered midranks in [-1, 1]."""

    count = len(values)
    if count < 2:
        raise ReaderError("midrank normalization requires at least two rows")
    ordered = sorted(range(count), key=lambda index: (values[index], index))
    result = [0.0] * count
    start = 0
    while start < count:
        end = start + 1
        while end < count and values[ordered[end]] == values[ordered[start]]:
            end += 1
        midpoint = (start + end - 1) / 2.0
        centered = 2.0 * midpoint / (count - 1) - 1.0
        for position in range(start, end):
            result[ordered[position]] = centered
        start = end
    return tuple(result)


def _robust_column(values: Sequence[float]) -> tuple[float, ...]:
    """Median/MAD normalize one episode column with a sparse-signal fallback."""

    center = float(median(values))
    deviations = [abs(value - center) for value in values]
    scale = 1.4826 * float(median(deviations))
    if scale == 0.0:
        # Sparse trajectory signals commonly have >50% exact ties.  A plain MAD
        # would erase their only non-zero cell, so use the median non-zero
        # deviation while keeping the median as the robust center.
        nonzero = [value for value in deviations if value > 0.0]
        scale = float(median(nonzero)) if nonzero else 0.0
    if scale == 0.0:
        return tuple(0.0 for _ in values)
    return tuple(max(-16.0, min(16.0, (value - center) / scale)) for value in values)


@dataclass(frozen=True)
class NormalizedEpisode:
    family: str
    target_id: str
    split: DatasetSplit
    robust: tuple[tuple[float, ...], ...]
    ranks: tuple[tuple[float, ...], ...]

    def matrix(self, transform: str) -> tuple[tuple[float, ...], ...]:
        if transform == "robust":
            return self.robust
        if transform == "rank":
            return self.ranks
        raise ReaderError(f"unknown normalization transform: {transform}")


def normalize_episode(episode: Stage3Episode) -> NormalizedEpisode:
    """Normalize every feature using only the 256 cells of this episode."""

    cells = sorted(episode.cells, key=lambda cell: cell.cell_index)
    if len(cells) != 256 or [cell.cell_index for cell in cells] != list(range(256)):
        raise ReaderError("an episode must contain exactly cells 0..255")
    width = len(FEATURE_NAMES)
    if any(len(cell.values) != width for cell in cells):
        raise ReaderError("episode feature width disagrees with the Stage-3 schema")
    columns: list[tuple[float, ...]] = []
    for feature_index in range(width):
        columns.append(
            tuple(
                _finite(cell.values[feature_index], f"feature[{feature_index}]")
                for cell in cells
            )
        )
    robust_columns = tuple(_robust_column(column) for column in columns)
    rank_columns = tuple(_midranks(column) for column in columns)
    robust = tuple(
        tuple(robust_columns[feature][cell] for feature in range(width))
        for cell in range(256)
    )
    ranks = tuple(
        tuple(rank_columns[feature][cell] for feature in range(width))
        for cell in range(256)
    )
    return NormalizedEpisode(
        family=episode.spec.family,
        target_id=episode.spec.target_id,
        split=episode.spec.split,
        robust=robust,
        ranks=ranks,
    )


@dataclass(frozen=True)
class OperatorSpec:
    """An executable, serializable operator fit exclusively on TRAIN labels."""

    name: str
    kind: str
    transform: str
    weights: tuple[float, ...] = ()
    positive_prototype: tuple[float, ...] = ()
    negative_prototype: tuple[float, ...] = ()
    metric: str = ""
    feature_index: int = -1
    direction: int = 0

    def __post_init__(self) -> None:
        if not self.name:
            raise ReaderError("operator name is required")
        if self.transform not in {"robust", "rank"}:
            raise ReaderError("operator transform must be robust or rank")
        width = len(FEATURE_NAMES)
        for field_name, values in (
            ("weights", self.weights),
            ("positive_prototype", self.positive_prototype),
            ("negative_prototype", self.negative_prototype),
        ):
            if values and len(values) != width:
                raise ReaderError(f"operator {field_name} has the wrong width")
            if any(not math.isfinite(value) for value in values):
                raise ReaderError(f"operator {field_name} must be finite")
        if self.kind == "linear":
            if len(self.weights) != width:
                raise ReaderError("linear operator requires one weight per feature")
        elif self.kind == "prototype":
            if self.metric not in {"l1", "l2", "linf"}:
                raise ReaderError("prototype metric must be l1, l2, or linf")
            if len(self.positive_prototype) != width or len(
                self.negative_prototype
            ) != width:
                raise ReaderError("prototype operator requires two full prototypes")
        elif self.kind == "feature":
            if not 0 <= self.feature_index < width or self.direction not in {-1, 1}:
                raise ReaderError("feature operator requires a valid index and direction")
        else:
            raise ReaderError(f"unknown operator kind: {self.kind}")

    def describe(self) -> dict[str, object]:
        return {
            "name": self.name,
            "kind": self.kind,
            "transform": self.transform,
            "weights": list(self.weights),
            "positive_prototype": list(self.positive_prototype),
            "negative_prototype": list(self.negative_prototype),
            "metric": self.metric,
            "feature_index": self.feature_index,
            "direction": self.direction,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "OperatorSpec":
        try:
            return cls(
                name=str(value["name"]),
                kind=str(value["kind"]),
                transform=str(value["transform"]),
                weights=tuple(float(item) for item in value.get("weights", [])),
                positive_prototype=tuple(
                    float(item) for item in value.get("positive_prototype", [])
                ),
                negative_prototype=tuple(
                    float(item) for item in value.get("negative_prototype", [])
                ),
                metric=str(value.get("metric", "")),
                feature_index=int(value.get("feature_index", -1)),
                direction=int(value.get("direction", 0)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ReaderError("invalid serialized operator") from exc

    def score(self, normalized: NormalizedEpisode) -> tuple[float, ...]:
        rows = normalized.matrix(self.transform)
        if self.kind == "linear":
            return tuple(
                sum(weight * value for weight, value in zip(self.weights, row, strict=True))
                for row in rows
            )
        if self.kind == "feature":
            return tuple(self.direction * row[self.feature_index] for row in rows)
        return tuple(
            _distance(row, self.negative_prototype, self.metric)
            - _distance(row, self.positive_prototype, self.metric)
            for row in rows
        )


def _distance(left: Sequence[float], right: Sequence[float], metric: str) -> float:
    differences = [abs(a - b) for a, b in zip(left, right, strict=True)]
    if metric == "l1":
        return sum(differences)
    if metric == "l2":
        return math.sqrt(sum(value * value for value in differences))
    if metric == "linf":
        return max(differences, default=0.0)
    raise ReaderError(f"unknown distance metric: {metric}")


@dataclass(frozen=True)
class RankedEpisode:
    family: str
    target_id: str
    split: DatasetSplit
    reader_name: str
    order: tuple[int, ...]
    scores: tuple[float, ...]
    feature_schema_sha256: str = FEATURE_SCHEMA_SHA256
    scored_cells: int = 256
    target_blind: bool = True

    def __post_init__(self) -> None:
        if len(self.order) != 256 or set(self.order) != set(range(256)):
            raise ReaderError("ranked episode order must be a permutation of 0..255")
        if len(self.scores) != 256 or any(
            not math.isfinite(value) for value in self.scores
        ):
            raise ReaderError("ranked episode must carry 256 finite scores")
        if self.scored_cells != 256 or not self.target_blind:
            raise ReaderError("all readers must score the same 256 target-blind cells")
        if self.feature_schema_sha256 != FEATURE_SCHEMA_SHA256:
            raise ReaderError("ranked episode uses an incompatible feature schema")

    def describe(self) -> dict[str, object]:
        return {
            "schema": "o1-crypto-ranked-stage3-episode-v1",
            "family": self.family,
            "target_id": self.target_id,
            "split": self.split.value,
            "reader_name": self.reader_name,
            "order": list(self.order),
            "scores": list(self.scores),
            "feature_schema_sha256": self.feature_schema_sha256,
            "scored_cells": self.scored_cells,
            "target_blind": self.target_blind,
            "tie_policy": TIE_POLICY,
        }


def rank_episode(episode: Stage3Episode, operator: OperatorSpec) -> RankedEpisode:
    normalized = normalize_episode(episode)
    scores = operator.score(normalized)
    order = tuple(sorted(range(256), key=lambda cell: (-scores[cell], cell)))
    return RankedEpisode(
        family=episode.spec.family,
        target_id=episode.spec.target_id,
        split=episode.spec.split,
        reader_name=operator.name,
        order=order,
        scores=scores,
    )


def baseline_rankings(episode: Stage3Episode) -> tuple[RankedEpisode, ...]:
    """Return equal-work numeric, public-hash and published-score controls."""

    numeric_scores = tuple(-float(cell) for cell in range(256))
    numeric_order = tuple(range(256))
    hash_scores = tuple(
        int.from_bytes(
            hashlib.sha256(
                (
                    episode.protocol_sha256
                    + ":"
                    + episode.public_challenge_sha256
                    + f":{cell:02x}"
                ).encode("ascii")
            ).digest()[:8],
            "big",
        )
        / float(1 << 64)
        for cell in range(256)
    )
    hash_order = tuple(sorted(range(256), key=lambda cell: (-hash_scores[cell], cell)))
    published_scores = tuple(float(value) for value in episode.baseline.score_field)
    return (
        RankedEpisode(
            family=episode.spec.family,
            target_id=episode.spec.target_id,
            split=episode.spec.split,
            reader_name="baseline.numeric_ascending",
            order=numeric_order,
            scores=numeric_scores,
        ),
        RankedEpisode(
            family=episode.spec.family,
            target_id=episode.spec.target_id,
            split=episode.spec.split,
            reader_name="baseline.public_hash",
            order=hash_order,
            scores=hash_scores,
        ),
        RankedEpisode(
            family=episode.spec.family,
            target_id=episode.spec.target_id,
            split=episode.spec.split,
            reader_name="baseline.published_target_blind_score",
            order=episode.baseline.complete_order,
            scores=published_scores,
        ),
    )


@dataclass(frozen=True)
class TargetRank:
    family: str
    target_id: str
    split: DatasetSplit
    rank: int
    log2_rank_gain: float
    reciprocal_rank: float

    def describe(self) -> dict[str, object]:
        return {
            "family": self.family,
            "target_id": self.target_id,
            "split": self.split.value,
            "rank": self.rank,
            "log2_rank_gain": self.log2_rank_gain,
            "reciprocal_rank": self.reciprocal_rank,
        }


@dataclass(frozen=True)
class TopKResult:
    k: int
    count: int
    rate: float

    def describe(self) -> dict[str, object]:
        return {"k": self.k, "count": self.count, "rate": self.rate}


@dataclass(frozen=True)
class RankingEvaluation:
    reader_name: str
    rows: tuple[TargetRank, ...]
    mean_log2_rank_gain: float
    median_log2_rank_gain: float
    top_k: tuple[TopKResult, ...]
    mean_reciprocal_rank: float

    def describe(self) -> dict[str, object]:
        return {
            "schema": "o1-crypto-stage3-ranking-evaluation-v1",
            "reader_name": self.reader_name,
            "targets": [row.describe() for row in self.rows],
            "summary": {
                "targets": len(self.rows),
                "mean_log2_rank_gain": self.mean_log2_rank_gain,
                "median_log2_rank_gain": self.median_log2_rank_gain,
                "top_k": [value.describe() for value in self.top_k],
                "mean_reciprocal_rank": self.mean_reciprocal_rank,
            },
        }

    def top_k_rate(self, k: int) -> float:
        for result in self.top_k:
            if result.k == k:
                return result.rate
        raise ReaderError(f"top-{k} was not evaluated")


def evaluate_rankings(
    rankings: Iterable[RankedEpisode],
    labels: Iterable[RevealedCellLabel],
    *,
    top_ks: Sequence[int] = (1, 4, 8, 16, 32),
) -> RankingEvaluation:
    """Evaluate target-blind orders against a physically separate label stream."""

    ranking_by_id: dict[tuple[str, str], RankedEpisode] = {}
    for ranking in rankings:
        key = (ranking.family, ranking.target_id)
        if key in ranking_by_id:
            raise ReaderError(f"duplicate ranking: {key}")
        ranking_by_id[key] = ranking
    label_by_id: dict[tuple[str, str], RevealedCellLabel] = {}
    for label in labels:
        key = _label_identity(label)
        if key in label_by_id:
            raise ReaderError(f"duplicate label: {key}")
        if not 0 <= label.correct_cell < 256:
            raise ReaderError(f"invalid correct cell for {key}")
        label_by_id[key] = label
    if not ranking_by_id or set(ranking_by_id) != set(label_by_id):
        raise ReaderError("rankings and labels must cover the same non-empty targets")
    reader_names = {ranking.reader_name for ranking in ranking_by_id.values()}
    if len(reader_names) != 1:
        raise ReaderError("one evaluation may contain only one reader")
    parsed_top_ks = tuple(sorted(set(int(k) for k in top_ks)))
    if not parsed_top_ks or parsed_top_ks[0] < 1 or parsed_top_ks[-1] > 256:
        raise ReaderError("top-k values must be unique integers in 1..256")
    rows: list[TargetRank] = []
    for key in sorted(ranking_by_id):
        ranking = ranking_by_id[key]
        label = label_by_id[key]
        if ranking.split is not label.split:
            raise ReaderError(f"ranking/label split mismatch for {key}")
        rank = ranking.order.index(label.correct_cell) + 1
        rows.append(
            TargetRank(
                family=key[0],
                target_id=key[1],
                split=ranking.split,
                rank=rank,
                log2_rank_gain=math.log2(256.0 / rank),
                reciprocal_rank=1.0 / rank,
            )
        )
    gains = [row.log2_rank_gain for row in rows]
    return RankingEvaluation(
        reader_name=next(iter(reader_names)),
        rows=tuple(rows),
        mean_log2_rank_gain=fmean(gains),
        median_log2_rank_gain=float(median(gains)),
        top_k=tuple(
            TopKResult(
                k=k,
                count=sum(row.rank <= k for row in rows),
                rate=fmean(row.rank <= k for row in rows),
            )
            for k in parsed_top_ks
        ),
        mean_reciprocal_rank=fmean(row.reciprocal_rank for row in rows),
    )


def _validate_labels_for_split(
    episodes: Sequence[Stage3Episode],
    labels: Iterable[RevealedCellLabel],
    split: DatasetSplit,
) -> tuple[RevealedCellLabel, ...]:
    selected = tuple(labels)
    expected = {_identity(episode) for episode in episodes if episode.spec.split is split}
    actual: dict[tuple[str, str], RevealedCellLabel] = {}
    for label in selected:
        key = _label_identity(label)
        if key in actual:
            raise ReaderError(f"duplicate label: {key}")
        if label.split is not split:
            raise ReaderError(f"{split.value} operation received a {label.split.value} label")
        if not 0 <= label.correct_cell < 256:
            raise ReaderError(f"invalid correct cell for {key}")
        actual[key] = label
    if not expected:
        raise ReaderError(f"dataset has no {split.value} episodes")
    if set(actual) != expected:
        missing = sorted(expected - set(actual))
        extra = sorted(set(actual) - expected)
        raise ReaderError(
            f"{split.value} labels do not match split ledger; missing={missing}, extra={extra}"
        )
    return tuple(actual[key] for key in sorted(actual))


def fit_operator_candidates(
    dataset: Stage3Dataset,
    labels: Iterable[RevealedCellLabel],
) -> tuple[OperatorSpec, ...]:
    """Fit all executable candidates, accepting TRAIN labels and nothing else."""

    train_episodes = tuple(
        episode for episode in dataset.episodes if episode.spec.split is DatasetSplit.TRAIN
    )
    train_labels = _validate_labels_for_split(train_episodes, labels, DatasetSplit.TRAIN)
    if any(label.information_label is not InformationLabel.TRAIN_LABEL for label in train_labels):
        raise ReaderError("operator fitting requires TRAIN_LABEL provenance")
    episode_by_id = {_identity(episode): episode for episode in train_episodes}
    normalized = {
        key: normalize_episode(episode) for key, episode in episode_by_id.items()
    }
    label_by_id = {_label_identity(label): label for label in train_labels}
    candidates: list[OperatorSpec] = []
    deltas_by_transform: dict[str, tuple[float, ...]] = {}
    for transform in ("robust", "rank"):
        positive_rows: list[tuple[float, ...]] = []
        negative_episode_means: list[tuple[float, ...]] = []
        for key in sorted(normalized):
            matrix = normalized[key].matrix(transform)
            correct = label_by_id[key].correct_cell
            positive_rows.append(matrix[correct])
            negative_episode_means.append(
                _mean_vector(tuple(row for cell, row in enumerate(matrix) if cell != correct))
            )
        positive_mean = _mean_vector(positive_rows)
        negative_mean = _mean_vector(negative_episode_means)
        delta = tuple(
            positive - negative
            for positive, negative in zip(positive_mean, negative_mean, strict=True)
        )
        deltas_by_transform[transform] = delta
        if transform == "robust":
            candidates.append(
                OperatorSpec(
                    name="contrast.robust.signed_mean",
                    kind="linear",
                    transform=transform,
                    weights=_unit_l2(delta),
                )
            )
            pooled: list[float] = []
            for feature_index, feature_delta in enumerate(delta):
                observations = [row[feature_index] for row in positive_rows] + [
                    row[feature_index] for row in negative_episode_means
                ]
                observation_mean = fmean(observations)
                variance = fmean(
                    (value - observation_mean) ** 2 for value in observations
                )
                pooled.append(feature_delta / (variance + 1e-9))
            candidates.append(
                OperatorSpec(
                    name="contrast.robust.fisher",
                    kind="linear",
                    transform=transform,
                    weights=_unit_l2(pooled),
                )
            )
            for metric in ("l1", "l2", "linf"):
                candidates.append(
                    OperatorSpec(
                        name=f"prototype.robust.{metric}",
                        kind="prototype",
                        transform=transform,
                        positive_prototype=positive_mean,
                        negative_prototype=negative_mean,
                        metric=metric,
                    )
                )
    for transform in ("robust", "rank"):
        for feature_index, delta in enumerate(deltas_by_transform[transform]):
            direction = 1 if delta >= 0.0 else -1
            candidates.append(
                OperatorSpec(
                    name=f"feature.{transform}.{feature_index:03d}.{direction:+d}",
                    kind="feature",
                    transform=transform,
                    feature_index=feature_index,
                    direction=direction,
                )
            )
    names = [candidate.name for candidate in candidates]
    if len(names) != len(set(names)):
        raise AssertionError("candidate naming collision")
    return tuple(sorted(candidates, key=lambda candidate: candidate.name))


@dataclass(frozen=True)
class CandidateBlindRankings:
    operator_name: str
    rankings: tuple[RankedEpisode, ...]


@dataclass(frozen=True)
class CandidateValidation:
    operator_name: str
    mean_log2_rank_gain: float
    median_log2_rank_gain: float
    mean_reciprocal_rank: float
    top1_rate: float
    top4_rate: float
    top8_rate: float
    top16_rate: float

    @classmethod
    def from_evaluation(cls, evaluation: RankingEvaluation) -> "CandidateValidation":
        return cls(
            operator_name=evaluation.reader_name,
            mean_log2_rank_gain=evaluation.mean_log2_rank_gain,
            median_log2_rank_gain=evaluation.median_log2_rank_gain,
            mean_reciprocal_rank=evaluation.mean_reciprocal_rank,
            top1_rate=evaluation.top_k_rate(1),
            top4_rate=evaluation.top_k_rate(4),
            top8_rate=evaluation.top_k_rate(8),
            top16_rate=evaluation.top_k_rate(16),
        )

    def describe(self) -> dict[str, object]:
        return {
            "operator_name": self.operator_name,
            "mean_log2_rank_gain": self.mean_log2_rank_gain,
            "median_log2_rank_gain": self.median_log2_rank_gain,
            "mean_reciprocal_rank": self.mean_reciprocal_rank,
            "top1_rate": self.top1_rate,
            "top4_rate": self.top4_rate,
            "top8_rate": self.top8_rate,
            "top16_rate": self.top16_rate,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "CandidateValidation":
        try:
            return cls(
                operator_name=str(value["operator_name"]),
                mean_log2_rank_gain=float(value["mean_log2_rank_gain"]),
                median_log2_rank_gain=float(value["median_log2_rank_gain"]),
                mean_reciprocal_rank=float(value["mean_reciprocal_rank"]),
                top1_rate=float(value["top1_rate"]),
                top4_rate=float(value["top4_rate"]),
                top8_rate=float(value["top8_rate"]),
                top16_rate=float(value["top16_rate"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ReaderError("invalid serialized validation metric") from exc


@dataclass(frozen=True)
class FrozenReaderPlan:
    """Immutable selection result; it contains no validation or holdout cells."""

    dataset_sha256: str
    feature_schema_sha256: str
    selected_operator: OperatorSpec
    train_targets: tuple[str, ...]
    validation_targets: tuple[str, ...]
    candidate_validation: tuple[CandidateValidation, ...]
    normalizer_schema: str = NORMALIZER_SCHEMA
    tie_policy: str = TIE_POLICY
    schema: str = PLAN_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != PLAN_SCHEMA:
            raise ReaderError("unsupported reader plan schema")
        if self.feature_schema_sha256 != FEATURE_SCHEMA_SHA256:
            raise ReaderError("reader plan feature schema mismatch")
        if self.normalizer_schema != NORMALIZER_SCHEMA or self.tie_policy != TIE_POLICY:
            raise ReaderError("reader plan normalization/tie contract mismatch")
        if len(self.dataset_sha256) != 64:
            raise ReaderError("reader plan requires a dataset SHA-256")
        names = [metric.operator_name for metric in self.candidate_validation]
        if self.selected_operator.name not in names:
            raise ReaderError("selected operator lacks validation metrics")
        if names != sorted(names) or len(names) != len(set(names)):
            raise ReaderError("candidate validation metrics must be sorted and unique")

    @property
    def plan_sha256(self) -> str:
        return _canonical_sha256(self.describe(include_hash=False))

    def describe(self, *, include_hash: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": self.schema,
            "dataset_sha256": self.dataset_sha256,
            "feature_schema_sha256": self.feature_schema_sha256,
            "normalizer_schema": self.normalizer_schema,
            "tie_policy": self.tie_policy,
            "selected_operator": self.selected_operator.describe(),
            "train_targets": list(self.train_targets),
            "validation_targets": list(self.validation_targets),
            "candidate_validation": [
                metric.describe() for metric in self.candidate_validation
            ],
            "information_boundary": {
                "operator_fit_split": DatasetSplit.TRAIN.value,
                "selection_split": DatasetSplit.VALIDATION.value,
                "refit_after_validation": False,
                "holdout_labels_used": False,
            },
        }
        if include_hash:
            value["plan_sha256"] = _canonical_sha256(value)
        return value

    def to_json(self) -> str:
        return json.dumps(self.describe(), sort_keys=True, indent=2, allow_nan=False) + "\n"

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "FrozenReaderPlan":
        try:
            raw_operator = value["selected_operator"]
            raw_metrics = value["candidate_validation"]
            if not isinstance(raw_operator, Mapping) or not isinstance(raw_metrics, list):
                raise ReaderError("invalid serialized reader plan members")
            plan = cls(
                schema=str(value["schema"]),
                dataset_sha256=str(value["dataset_sha256"]),
                feature_schema_sha256=str(value["feature_schema_sha256"]),
                normalizer_schema=str(value["normalizer_schema"]),
                tie_policy=str(value["tie_policy"]),
                selected_operator=OperatorSpec.from_dict(raw_operator),
                train_targets=tuple(str(item) for item in value["train_targets"]),
                validation_targets=tuple(
                    str(item) for item in value["validation_targets"]
                ),
                candidate_validation=tuple(
                    CandidateValidation.from_dict(item)
                    for item in raw_metrics
                    if isinstance(item, Mapping)
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ReaderError("invalid serialized reader plan") from exc
        supplied_hash = value.get("plan_sha256")
        if supplied_hash is not None and supplied_hash != plan.plan_sha256:
            raise ReaderError("serialized reader plan hash mismatch")
        return plan


def rank_with_plan(plan: FrozenReaderPlan, episode: Stage3Episode) -> RankedEpisode:
    if plan.feature_schema_sha256 != FEATURE_SCHEMA_SHA256:
        raise ReaderError("reader plan cannot score this feature schema")
    return rank_episode(episode, plan.selected_operator)


class ReaderLifecycle(str, Enum):
    NEW = "NEW"
    TRAIN_FITTED = "TRAIN_FITTED"
    FROZEN = "FROZEN"


class RetrospectiveReader:
    """Stateful guard for fit, target-blind selection, freeze and reveal."""

    def __init__(self, dataset: Stage3Dataset) -> None:
        if not dataset.episodes:
            raise ReaderError("reader dataset must not be empty")
        self.dataset = dataset
        self._state = ReaderLifecycle.NEW
        self._candidates: tuple[OperatorSpec, ...] = ()
        self._plan: FrozenReaderPlan | None = None

    @property
    def state(self) -> ReaderLifecycle:
        return self._state

    @property
    def plan(self) -> FrozenReaderPlan:
        if self._plan is None:
            raise ReaderError("reader plan is not frozen")
        return self._plan

    def fit(self, train_labels: Iterable[RevealedCellLabel]) -> tuple[str, ...]:
        if self._state is not ReaderLifecycle.NEW:
            raise ReaderError("reader candidates may be fit exactly once")
        self._candidates = fit_operator_candidates(self.dataset, train_labels)
        self._state = ReaderLifecycle.TRAIN_FITTED
        return tuple(candidate.name for candidate in self._candidates)

    def score_candidates(self, split: DatasetSplit) -> tuple[CandidateBlindRankings, ...]:
        """Score any feature split blindly; this API has no label parameter."""

        if self._state is ReaderLifecycle.NEW:
            raise ReaderError("fit TRAIN candidates before blind scoring")
        episodes = tuple(
            episode for episode in self.dataset.episodes if episode.spec.split is split
        )
        if not episodes:
            raise ReaderError(f"dataset has no {split.value} episodes")
        return tuple(
            CandidateBlindRankings(
                operator_name=candidate.name,
                rankings=tuple(rank_episode(episode, candidate) for episode in episodes),
            )
            for candidate in self._candidates
        )

    def freeze(
        self, validation_labels: Iterable[RevealedCellLabel]
    ) -> FrozenReaderPlan:
        if self._state is not ReaderLifecycle.TRAIN_FITTED:
            raise ReaderError("freeze requires one fitted, not-yet-frozen reader")
        validation_episodes = tuple(
            episode
            for episode in self.dataset.episodes
            if episode.spec.split is DatasetSplit.VALIDATION
        )
        labels = _validate_labels_for_split(
            validation_episodes, validation_labels, DatasetSplit.VALIDATION
        )
        if any(label.information_label is not InformationLabel.TRAIN_LABEL for label in labels):
            raise ReaderError("validation selection requires TRAIN_LABEL provenance")
        metrics: list[CandidateValidation] = []
        operator_by_name = {candidate.name: candidate for candidate in self._candidates}
        for blind in self.score_candidates(DatasetSplit.VALIDATION):
            evaluation = evaluate_rankings(blind.rankings, labels, top_ks=(1, 4, 8, 16))
            metrics.append(CandidateValidation.from_evaluation(evaluation))
        # Selection is entirely derived here; there is no API for claimed or
        # caller-supplied information gain.  Lexical name is the final tie-break.
        selected = min(
            metrics,
            key=lambda metric: (
                -metric.mean_log2_rank_gain,
                -metric.mean_reciprocal_rank,
                -metric.top8_rate,
                -metric.top16_rate,
                -metric.top4_rate,
                -metric.top1_rate,
                metric.operator_name,
            ),
        )
        train_targets = tuple(
            sorted(
                f"{episode.spec.family}/{episode.spec.target_id}"
                for episode in self.dataset.episodes
                if episode.spec.split is DatasetSplit.TRAIN
            )
        )
        validation_targets = tuple(
            sorted(
                f"{episode.spec.family}/{episode.spec.target_id}"
                for episode in validation_episodes
            )
        )
        self._plan = FrozenReaderPlan(
            dataset_sha256=self.dataset.dataset_sha256,
            feature_schema_sha256=FEATURE_SCHEMA_SHA256,
            selected_operator=operator_by_name[selected.operator_name],
            train_targets=train_targets,
            validation_targets=validation_targets,
            candidate_validation=tuple(sorted(metrics, key=lambda item: item.operator_name)),
        )
        self._state = ReaderLifecycle.FROZEN
        return self._plan

    def rank_split(self, split: DatasetSplit) -> tuple[RankedEpisode, ...]:
        if self._state is not ReaderLifecycle.FROZEN:
            raise ReaderError("selected-reader ranking requires a frozen plan")
        episodes = tuple(
            episode for episode in self.dataset.episodes if episode.spec.split is split
        )
        if not episodes:
            raise ReaderError(f"dataset has no {split.value} episodes")
        return tuple(rank_with_plan(self.plan, episode) for episode in episodes)

    def evaluate(self, labels: Iterable[RevealedCellLabel]) -> RankingEvaluation:
        """Reveal labels only after freeze, then evaluate the selected reader."""

        supplied = tuple(labels)
        if not supplied:
            raise ReaderError("evaluation labels must not be empty")
        if self._state is not ReaderLifecycle.FROZEN:
            if any(label.split in HOLDOUT_SPLITS for label in supplied):
                raise ReaderError("holdout labels are sealed until the reader plan is frozen")
            raise ReaderError("evaluation requires a frozen reader plan")
        if any(label.split is DatasetSplit.SEALED_DEPLOYMENT for label in supplied):
            raise ReaderError("SEALED_DEPLOYMENT labels may never be evaluated here")
        splits = {label.split for label in supplied}
        if len(splits) != 1:
            raise ReaderError("evaluate one dataset split at a time")
        split = next(iter(splits))
        episodes = tuple(
            episode for episode in self.dataset.episodes if episode.spec.split is split
        )
        validated = _validate_labels_for_split(episodes, supplied, split)
        if split in HOLDOUT_SPLITS and any(
            label.information_label is not InformationLabel.POST_REVEAL
            for label in validated
        ):
            raise ReaderError("holdout evaluation requires POST_REVEAL provenance")
        return evaluate_rankings(self.rank_split(split), validated)
