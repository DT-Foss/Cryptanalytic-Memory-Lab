"""Strict, target-blind ingestion of Fullround solver-trajectory artifacts.

This module deliberately separates attacker-computable discovery telemetry from
post-reveal labels.  The adapter never reads panel result files and never emits a
label.  A separate registry is the only API that can cross that boundary.
"""

from __future__ import annotations

import hashlib
import json
import math
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from .artifacts import ReadOnlyArtifactSource
from .types import InformationLabel


class Stage3Error(ValueError):
    """Raised when a trajectory artifact violates the Stage-3 contract."""


class DatasetSplit(str, Enum):
    TRAIN = "TRAIN"
    VALIDATION = "VALIDATION"
    RETROSPECTIVE_HOLDOUT = "RETROSPECTIVE_HOLDOUT"
    TRANSFER_HOLDOUT = "TRANSFER_HOLDOUT"
    TEST = "TEST"
    SEALED_DEPLOYMENT = "SEALED_DEPLOYMENT"


HORIZONS = (1, 2, 4, 8)
METRIC_NAMES = ("conflicts", "decisions", "search_propagations")


def _feature_names() -> tuple[str, ...]:
    names = [
        "cell.conflicts",
        "cell.decisions",
        "cell.search_propagations",
        "cell.active_variables_delta",
        "cell.irredundant_clauses_delta",
        "cell.redundant_clauses_delta",
        "cell.learned_clause_accepted_total",
        "cell.learned_clause_offered_total",
        "cell.learned_clause_rejected_large_total",
    ]
    for horizon in HORIZONS:
        prefix = f"h{horizon}."
        names.extend(
            prefix + suffix
            for suffix in (
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
                "learned_clause_length_max",
            )
        )
    return tuple(names)


FEATURE_NAMES = _feature_names()
FEATURE_SCHEMA_SHA256 = hashlib.sha256(
    ("\n".join(FEATURE_NAMES) + "\n").encode("utf-8")
).hexdigest()


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_int(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise Stage3Error(f"{field} must be an integer")
    return value


def _require_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise Stage3Error(f"{field} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise Stage3Error(f"{field} must be finite")
    return result


def _require_sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise Stage3Error(f"{field} must be a lowercase SHA-256")
    return value


def _require_safe_member(value: str, field: str) -> None:
    path = Path(value)
    if not value or path.is_absolute() or ".." in path.parts or "\x00" in value:
        raise Stage3Error(f"{field} is not a safe manifest member")


@dataclass(frozen=True)
class EpisodeSpec:
    family: str
    target_id: str
    unknown_key_bits: int
    split: DatasetSplit
    measurement_member: str
    order_member: str

    def __post_init__(self) -> None:
        if not self.family or not self.target_id:
            raise Stage3Error("family and target_id are required")
        if self.unknown_key_bits < 8:
            raise Stage3Error("unknown_key_bits must expose an eight-bit cell")
        _require_safe_member(self.measurement_member, "measurement_member")
        _require_safe_member(self.order_member, "order_member")
        if not self.measurement_member.endswith(".measurement.json.zst"):
            raise Stage3Error("measurement_member must be a .measurement.json.zst")
        if not self.order_member.endswith(".order.json"):
            raise Stage3Error("order_member must be an .order.json")


@dataclass(frozen=True)
class TargetBlindBaseline:
    name: str
    score_field: tuple[float, ...]
    complete_order: tuple[int, ...]
    selected_feature_indices: tuple[int, ...]
    score_field_sha256: str

    def describe(self) -> dict[str, object]:
        return {
            "name": self.name,
            "score_field": list(self.score_field),
            "complete_order": list(self.complete_order),
            "selected_feature_indices": list(self.selected_feature_indices),
            "score_field_sha256": self.score_field_sha256,
        }


@dataclass(frozen=True)
class SolverCellFeatures:
    cell_index: int
    prefix8: str
    values: tuple[float, ...]

    def describe(self) -> dict[str, object]:
        return {
            "cell_index": self.cell_index,
            "prefix8": self.prefix8,
            "values": list(self.values),
        }


@dataclass(frozen=True)
class Stage3Episode:
    spec: EpisodeSpec
    schema: str
    attempt_id: str
    cells: tuple[SolverCellFeatures, ...]
    baseline: TargetBlindBaseline
    measurement_compressed_sha256: str
    measurement_raw_sha256: str
    measurement_raw_bytes: int
    order_sha256: str
    protocol_sha256: str
    public_challenge_sha256: str
    cnf_sha256: str
    zstd_binary: str
    zstd_version: str

    @property
    def episode_sha256(self) -> str:
        return _canonical_sha256(self.describe())

    def describe(self) -> dict[str, object]:
        """Return only target-blind data; a label field does not exist here."""

        return {
            "schema": "o1-crypto-stage3-episode-v1",
            "family": self.spec.family,
            "target_id": self.spec.target_id,
            "unknown_key_bits": self.spec.unknown_key_bits,
            "split": self.spec.split.value,
            "source": {
                "measurement_member": self.spec.measurement_member,
                "measurement_compressed_sha256": self.measurement_compressed_sha256,
                "measurement_raw_sha256": self.measurement_raw_sha256,
                "measurement_raw_bytes": self.measurement_raw_bytes,
                "order_member": self.spec.order_member,
                "order_sha256": self.order_sha256,
                "protocol_sha256": self.protocol_sha256,
                "public_challenge_sha256": self.public_challenge_sha256,
                "cnf_sha256": self.cnf_sha256,
                "source_schema": self.schema,
                "source_attempt_id": self.attempt_id,
                "zstd_binary": self.zstd_binary,
                "zstd_version": self.zstd_version,
            },
            "feature_schema_sha256": FEATURE_SCHEMA_SHA256,
            "feature_names": list(FEATURE_NAMES),
            "cells": [cell.describe() for cell in self.cells],
            "target_blind_baseline": self.baseline.describe(),
            "information_boundary": {
                "target_label_available_to_adapter": False,
                "post_reveal_result_read": False,
                "elapsed_seconds_featured": False,
                "cell_index_is_address_not_feature": True,
            },
        }


@dataclass(frozen=True)
class Stage3Dataset:
    name: str
    episodes: tuple[Stage3Episode, ...]

    def __post_init__(self) -> None:
        identities = [(episode.spec.family, episode.spec.target_id) for episode in self.episodes]
        if len(identities) != len(set(identities)):
            raise Stage3Error("dataset contains duplicate episode identities")

    @property
    def dataset_sha256(self) -> str:
        return _canonical_sha256(self.describe(include_hash=False))

    def describe(self, *, include_hash: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": "o1-crypto-stage3-dataset-v1",
            "name": self.name,
            "feature_schema_sha256": FEATURE_SCHEMA_SHA256,
            "episodes": [episode.describe() for episode in self.episodes],
            "counts": {
                "episodes": len(self.episodes),
                "cells": sum(len(episode.cells) for episode in self.episodes),
                "stages": sum(len(episode.cells) * len(HORIZONS) for episode in self.episodes),
                "by_split": {
                    split.value: sum(
                        episode.spec.split is split for episode in self.episodes
                    )
                    for split in DatasetSplit
                },
            },
        }
        if include_hash:
            value["dataset_sha256"] = _canonical_sha256(value)
        return value


class BoundedZstdDecoder:
    """Decode zstd bytes while enforcing a hard output cap during streaming."""

    def __init__(self, binary: str | Path | None = None) -> None:
        selected = str(binary) if binary is not None else shutil.which("zstd")
        if not selected:
            raise Stage3Error("zstd is required for the pinned trajectory corpus")
        resolved = Path(selected).resolve()
        if not resolved.is_file():
            raise Stage3Error(f"zstd binary does not exist: {resolved}")
        self.binary = str(resolved)
        version = subprocess.run(
            [self.binary, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        if version.returncode != 0:
            raise Stage3Error("could not query zstd version")
        self.version = version.stdout.decode("utf-8", errors="replace").strip()

    def decode(self, compressed: bytes, *, max_output_bytes: int) -> bytes:
        if max_output_bytes < 1:
            raise Stage3Error("max_output_bytes must be positive")
        with tempfile.TemporaryFile() as source:
            source.write(compressed)
            source.seek(0)
            process = subprocess.Popen(
                [self.binary, "-dc", "--no-progress"],
                stdin=source,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            assert process.stdout is not None
            assert process.stderr is not None
            chunks: list[bytes] = []
            total = 0
            try:
                with process.stdout:
                    while True:
                        chunk = process.stdout.read(
                            min(1 << 16, max_output_bytes + 1 - total)
                        )
                        if not chunk:
                            break
                        chunks.append(chunk)
                        total += len(chunk)
                        if total > max_output_bytes:
                            process.kill()
                            process.wait(timeout=10)
                            raise Stage3Error(
                                "zstd output exceeds the declared byte cap"
                            )
                with process.stderr:
                    stderr = process.stderr.read()
                returncode = process.wait(timeout=30)
            except Exception:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
                process.stdout.close()
                process.stderr.close()
                raise
        if returncode != 0:
            message = stderr.decode("utf-8", errors="replace").strip()
            raise Stage3Error(f"zstd decoding failed: {message}")
        return b"".join(chunks)


class Stage3TrajectoryAdapter:
    """Load one normalized 256-cell trajectory without touching result labels."""

    def __init__(
        self,
        source: ReadOnlyArtifactSource,
        *,
        decoder: BoundedZstdDecoder | None = None,
        max_raw_bytes: int = 64 << 20,
        denied_member_fragments: Sequence[str] = (
            "progress",
            "a350",
            "prospective_recovery",
        ),
    ) -> None:
        if max_raw_bytes < 1:
            raise Stage3Error("max_raw_bytes must be positive")
        self.source = source
        self.decoder = decoder or BoundedZstdDecoder()
        self.max_raw_bytes = max_raw_bytes
        self.denied_member_fragments = tuple(
            fragment.lower() for fragment in denied_member_fragments
        )

    def _require_discovery_member(self, member: str) -> None:
        lowered = member.lower()
        if any(fragment in lowered for fragment in self.denied_member_fragments):
            raise Stage3Error(f"member is denied by the pre-result boundary: {member}")
        if not (member.endswith(".measurement.json.zst") or member.endswith(".order.json")):
            raise Stage3Error(f"adapter may only read measurement/order members: {member}")

    def load(self, spec: EpisodeSpec) -> Stage3Episode:
        self._require_discovery_member(spec.measurement_member)
        self._require_discovery_member(spec.order_member)
        order_bytes = self.source.read_bytes(spec.order_member)
        order_sha256 = hashlib.sha256(order_bytes).hexdigest()
        try:
            order = json.loads(order_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise Stage3Error("order is not valid UTF-8 JSON") from exc
        self._validate_order_identity(order, spec)

        metadata = order.get("measurement")
        if not isinstance(metadata, dict):
            raise Stage3Error("order.measurement must be an object")
        compressed = self.source.read_bytes(spec.measurement_member)
        compressed_sha256 = hashlib.sha256(compressed).hexdigest()
        if compressed_sha256 != _require_sha256(
            metadata.get("compressed_sha256"), "measurement.compressed_sha256"
        ):
            raise Stage3Error("compressed measurement hash disagrees with its order")
        compressed_bytes = _require_int(
            metadata.get("compressed_bytes"), "measurement.compressed_bytes"
        )
        if compressed_bytes != len(compressed):
            raise Stage3Error("compressed measurement byte count disagrees with its order")
        declared_path = metadata.get("path")
        if not isinstance(declared_path, str) or not spec.measurement_member.endswith(
            declared_path
        ):
            raise Stage3Error("measurement path disagrees with the selected member")
        raw_bytes = _require_int(metadata.get("raw_bytes"), "measurement.raw_bytes")
        if raw_bytes < 1 or raw_bytes > self.max_raw_bytes:
            raise Stage3Error("declared raw measurement exceeds the adapter byte budget")
        raw_sha256 = _require_sha256(
            metadata.get("raw_sha256"), "measurement.raw_sha256"
        )
        raw = self.decoder.decode(compressed, max_output_bytes=raw_bytes)
        if len(raw) != raw_bytes:
            raise Stage3Error("raw measurement byte count disagrees with its order")
        if hashlib.sha256(raw).hexdigest() != raw_sha256:
            raise Stage3Error("raw measurement hash disagrees with its order")
        try:
            measurement = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise Stage3Error("measurement is not valid UTF-8 JSON") from exc
        cells, cnf_sha256 = self._validate_and_extract(measurement, spec)
        baseline = self._baseline(order)
        return Stage3Episode(
            spec=spec,
            schema=str(measurement["schema"]),
            attempt_id=str(measurement["attempt_id"]),
            cells=cells,
            baseline=baseline,
            measurement_compressed_sha256=compressed_sha256,
            measurement_raw_sha256=raw_sha256,
            measurement_raw_bytes=raw_bytes,
            order_sha256=order_sha256,
            protocol_sha256=_require_sha256(order.get("protocol_sha256"), "protocol_sha256"),
            public_challenge_sha256=_require_sha256(
                order.get("public_challenge_sha256"), "public_challenge_sha256"
            ),
            cnf_sha256=cnf_sha256,
            zstd_binary=self.decoder.binary,
            zstd_version=self.decoder.version,
        )

    @staticmethod
    def _validate_order_identity(order: object, spec: EpisodeSpec) -> None:
        if not isinstance(order, dict):
            raise Stage3Error("order must be a JSON object")
        if order.get("target_id") != spec.target_id:
            raise Stage3Error("order target_id disagrees with the split ledger")
        if order.get("unknown_key_bits") != spec.unknown_key_bits:
            raise Stage3Error("order unknown_key_bits disagrees with the split ledger")
        if order.get("target_labels_used") != 0:
            raise Stage3Error("order used a target label")
        if order.get("model_refits") != 0:
            raise Stage3Error("order contains an in-target model refit")
        if order.get("model_free_UNKNOWN_stages") != 1024:
            raise Stage3Error("order does not attest all 1,024 model-free UNKNOWN stages")

    @staticmethod
    def _baseline(order: Mapping[str, object]) -> TargetBlindBaseline:
        raw_scores = order.get("score_field")
        raw_order = order.get("complete_coarse_order")
        raw_indices = order.get("selected_feature_indices")
        if not isinstance(raw_scores, list) or len(raw_scores) != 256:
            raise Stage3Error("score_field must contain 256 cells")
        scores = tuple(
            _require_number(value, f"score_field[{index}]")
            for index, value in enumerate(raw_scores)
        )
        if not isinstance(raw_order, list) or len(raw_order) != 256:
            raise Stage3Error("complete_coarse_order must contain 256 cells")
        complete_order = tuple(
            _require_int(value, f"complete_coarse_order[{index}]")
            for index, value in enumerate(raw_order)
        )
        if set(complete_order) != set(range(256)):
            raise Stage3Error("complete_coarse_order must be a permutation of 0..255")
        if not isinstance(raw_indices, list):
            raise Stage3Error("selected_feature_indices must be a list")
        selected = tuple(
            _require_int(value, f"selected_feature_indices[{index}]")
            for index, value in enumerate(raw_indices)
        )
        expected_score_sha = _require_sha256(
            order.get("score_field_sha256"), "score_field_sha256"
        )
        # The published artifact uses its own binary encoding hash. Preserve and pin
        # it instead of silently substituting a JSON-derived digest.
        return TargetBlindBaseline(
            name="published_target_blind_score",
            score_field=scores,
            complete_order=complete_order,
            selected_feature_indices=selected,
            score_field_sha256=expected_score_sha,
        )

    @staticmethod
    def _validate_and_extract(
        measurement: object, spec: EpisodeSpec
    ) -> tuple[tuple[SolverCellFeatures, ...], str]:
        if not isinstance(measurement, dict):
            raise Stage3Error("measurement must be a JSON object")
        if not isinstance(measurement.get("schema"), str) or not str(
            measurement["schema"]
        ).endswith("measurement-v1"):
            raise Stage3Error("unsupported measurement schema")
        if measurement.get("target_id") != spec.target_id:
            raise Stage3Error("measurement target_id disagrees with the split ledger")
        if measurement.get("unknown_key_bits") != spec.unknown_key_bits:
            raise Stage3Error("measurement unknown_key_bits disagrees with the split ledger")
        if measurement.get("target_label_available_to_measurement") is not False:
            raise Stage3Error("target label was available during measurement")
        if measurement.get("label_used_for_feature_construction_or_scoring") is not False:
            raise Stage3Error("target label was used during measurement/scoring")
        if measurement.get("complete_candidate_cover") is not True:
            raise Stage3Error("measurement is not a complete candidate cover")
        run = measurement.get("run")
        if not isinstance(run, dict):
            raise Stage3Error("measurement.run must be an object")
        for field in (
            "all_watchdogs_clear",
            "base_snapshot_identical_verified",
            "fresh_solver_per_candidate_verified",
        ):
            if run.get(field) is not True:
                raise Stage3Error(f"run.{field} must be true")
        if run.get("bounded_variable_addition_enabled") is not False:
            raise Stage3Error("bounded variable addition changes the comparison contract")
        if tuple(run.get("conflict_horizons", ())) != HORIZONS:
            raise Stage3Error("run conflict horizons are not [1,2,4,8]")
        cnf_sha256 = _require_sha256(run.get("cnf_sha256"), "run.cnf_sha256")
        raw_cells = run.get("cells")
        raw_stages = run.get("stages")
        if not isinstance(raw_cells, list) or len(raw_cells) != 256:
            raise Stage3Error("measurement must contain exactly 256 cells")
        if not isinstance(raw_stages, list) or len(raw_stages) != 1024:
            raise Stage3Error("measurement must contain exactly 1,024 stages")
        cell_by_index: dict[int, Mapping[str, object]] = {}
        for position, raw_cell in enumerate(raw_cells):
            if not isinstance(raw_cell, dict):
                raise Stage3Error(f"run.cells[{position}] must be an object")
            index = _require_int(raw_cell.get("cell_index"), f"run.cells[{position}].cell_index")
            if index in cell_by_index or not 0 <= index < 256:
                raise Stage3Error("cell indices must be unique in 0..255")
            if raw_cell.get("fresh_solver_instance") is not True:
                raise Stage3Error(f"cell {index} did not use a fresh solver")
            if raw_cell.get("final_status") != "unknown":
                raise Stage3Error(f"cell {index} has target-dependent terminal status")
            if raw_cell.get("stages_run") != 4 or raw_cell.get("terminal_stage_index") is not None:
                raise Stage3Error(f"cell {index} did not emit four nonterminal stages")
            prefix = raw_cell.get("prefix8")
            if not isinstance(prefix, str) or len(prefix) != 8 or any(
                bit not in "01" for bit in prefix
            ) or int(prefix, 2) != index:
                raise Stage3Error(f"cell {index} has a noncanonical prefix8")
            if tuple(raw_cell.get("metric_names", ())) != METRIC_NAMES:
                raise Stage3Error(f"cell {index} has unexpected metric names")
            cell_by_index[index] = raw_cell
        stage_by_cell: dict[int, dict[int, Mapping[str, object]]] = {
            index: {} for index in range(256)
        }
        for position, raw_stage in enumerate(raw_stages):
            if not isinstance(raw_stage, dict):
                raise Stage3Error(f"run.stages[{position}] must be an object")
            index = _require_int(raw_stage.get("cell_index"), f"run.stages[{position}].cell_index")
            if index not in stage_by_cell:
                raise Stage3Error("stage refers to an invalid cell")
            horizon = _require_int(raw_stage.get("horizon"), f"run.stages[{position}].horizon")
            if horizon not in HORIZONS or horizon in stage_by_cell[index]:
                raise Stage3Error(f"cell {index} has duplicate/invalid horizons")
            if raw_stage.get("status") != "unknown" or raw_stage.get("terminal") is not False:
                raise Stage3Error(f"cell {index} stage is not nonterminal UNKNOWN")
            if raw_stage.get("watchdog_fired") is not False or raw_stage.get("returncode") != 0:
                raise Stage3Error(f"cell {index} stage failed its execution gate")
            if raw_stage.get("model_bits_bit0_through_bit19") != []:
                raise Stage3Error(f"cell {index} stage contains model bits")
            if tuple(raw_stage.get("metric_names", ())) != METRIC_NAMES:
                raise Stage3Error(f"cell {index} stage has unexpected metric names")
            if raw_stage.get("prefix8") != cell_by_index[index].get("prefix8"):
                raise Stage3Error(f"cell {index} stage prefix disagrees with its cell")
            if raw_stage.get("assumptions") != cell_by_index[index].get("assumptions"):
                raise Stage3Error(f"cell {index} stage assumptions disagree with its cell")
            stage_by_cell[index][horizon] = raw_stage
        if any(set(stages) != set(HORIZONS) for stages in stage_by_cell.values()):
            raise Stage3Error("every cell must have exactly horizons [1,2,4,8]")
        extracted = tuple(
            Stage3TrajectoryAdapter._extract_cell(
                cell_by_index[index], stage_by_cell[index]
            )
            for index in range(256)
        )
        return extracted, cnf_sha256

    @staticmethod
    def _extract_cell(
        cell: Mapping[str, object], stages: Mapping[int, Mapping[str, object]]
    ) -> SolverCellFeatures:
        index = int(cell["cell_index"])
        metrics = cell.get("metrics_delta")
        if not isinstance(metrics, list) or len(metrics) != 3:
            raise Stage3Error(f"cell {index} metrics_delta must have length three")
        values = [
            *(
                _require_number(value, f"cell {index} metrics_delta")
                for value in metrics
            ),
            *(
                _require_number(cell.get(field), f"cell {index} {field}")
                for field in (
                    "active_variables_delta",
                    "irredundant_clauses_delta",
                    "redundant_clauses_delta",
                    "learned_clause_accepted_total",
                    "learned_clause_offered_total",
                    "learned_clause_rejected_large_total",
                )
            ),
        ]
        for horizon in HORIZONS:
            stage = stages[horizon]
            stage_metrics = stage.get("metrics_stage_delta")
            if not isinstance(stage_metrics, list) or len(stage_metrics) != 3:
                raise Stage3Error(
                    f"cell {index} horizon {horizon} metrics_stage_delta must have length three"
                )
            lengths = stage.get("learned_clause_lengths_stage")
            if not isinstance(lengths, list):
                raise Stage3Error(
                    f"cell {index} horizon {horizon} clause lengths must be a list"
                )
            parsed_lengths = [
                _require_int(value, f"cell {index} horizon {horizon} clause length")
                for value in lengths
            ]
            if any(value < 1 for value in parsed_lengths):
                raise Stage3Error("learned clause lengths must be positive")
            literal_count = _require_int(
                stage.get("learned_literal_count_stage"),
                f"cell {index} horizon {horizon} learned literal count",
            )
            if literal_count != sum(parsed_lengths):
                raise Stage3Error(
                    f"cell {index} horizon {horizon} literal count mismatch"
                )
            values.extend(
                _require_number(value, f"cell {index} horizon {horizon} metric")
                for value in stage_metrics
            )
            values.extend(
                _require_number(stage.get(field), f"cell {index} horizon {horizon} {field}")
                for field in (
                    "active_variables_delta",
                    "irredundant_clauses_delta",
                    "redundant_clauses_delta",
                    "learned_clause_accepted_stage",
                    "learned_clause_offered_stage",
                    "learned_clause_rejected_large_stage",
                    "learned_literal_count_stage",
                )
            )
            values.append(sum(parsed_lengths) / len(parsed_lengths) if parsed_lengths else 0.0)
            values.append(float(max(parsed_lengths, default=0)))
        if len(values) != len(FEATURE_NAMES):
            raise AssertionError("feature implementation and schema diverged")
        return SolverCellFeatures(
            cell_index=index,
            prefix8=str(cell["prefix8"]),
            values=tuple(values),
        )

    def load_dataset(self, name: str, specs: Iterable[EpisodeSpec]) -> Stage3Dataset:
        return Stage3Dataset(name=name, episodes=tuple(self.load(spec) for spec in specs))


@dataclass(frozen=True)
class RevealedCellLabel:
    family: str
    target_id: str
    split: DatasetSplit
    correct_cell: int
    source_member: str
    source_sha256: str
    information_label: InformationLabel

    def describe(self) -> dict[str, object]:
        return {
            "schema": "o1-crypto-stage3-revealed-label-v1",
            "family": self.family,
            "target_id": self.target_id,
            "split": self.split.value,
            "correct_cell": self.correct_cell,
            "source_member": self.source_member,
            "source_sha256": self.source_sha256,
            "information_label": self.information_label.value,
        }


class PostRevealLabelRegistry:
    """Physically separate reader for labels already revealed in panel results."""

    def __init__(
        self,
        source: ReadOnlyArtifactSource,
        specs: Iterable[EpisodeSpec],
    ) -> None:
        self.source = source
        self._specs = {spec.target_id: spec for spec in specs}
        if len(self._specs) == 0:
            raise Stage3Error("label registry requires at least one split-bound target")
        self._access_log: list[dict[str, object]] = []

    @property
    def access_log(self) -> tuple[dict[str, object], ...]:
        return tuple(dict(entry) for entry in self._access_log)

    def read_panel_result(
        self, result_member: str, *, purpose: str
    ) -> tuple[RevealedCellLabel, ...]:
        _require_safe_member(result_member, "result_member")
        if not purpose.strip():
            raise Stage3Error("post-reveal label access requires a recorded purpose")
        if "progress" in result_member.lower():
            raise Stage3Error("progress artifacts are never label registries")
        result_bytes = self.source.read_bytes(result_member)
        result_sha256 = hashlib.sha256(result_bytes).hexdigest()
        try:
            result = json.loads(result_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise Stage3Error("panel result is not valid UTF-8 JSON") from exc
        if not isinstance(result, dict) or not isinstance(result.get("targets"), list):
            raise Stage3Error("panel result must contain a targets list")
        labels: list[RevealedCellLabel] = []
        seen: set[str] = set()
        for position, target in enumerate(result["targets"]):
            if not isinstance(target, dict):
                raise Stage3Error(f"result.targets[{position}] must be an object")
            target_id = target.get("target_id")
            if target_id not in self._specs:
                continue
            spec = self._specs[str(target_id)]
            if spec.split in {DatasetSplit.TEST, DatasetSplit.SEALED_DEPLOYMENT}:
                raise Stage3Error(
                    f"refusing to reveal {spec.split.value} label for {spec.target_id}"
                )
            discovery = target.get("discovery")
            if not isinstance(discovery, dict):
                raise Stage3Error(f"target {target_id} lacks discovery data")
            fine_prefix12 = _require_int(
                discovery.get("fine_prefix12"), f"target {target_id} fine_prefix12"
            )
            correct_cell = fine_prefix12 >> 4
            if not 0 <= correct_cell < 256:
                raise Stage3Error(f"target {target_id} has invalid fine_prefix12")
            candidate = _require_int(
                discovery.get("candidate"), f"target {target_id} candidate"
            )
            candidate_cell = candidate >> (spec.unknown_key_bits - 8)
            if candidate_cell != correct_cell:
                raise Stage3Error(f"target {target_id} has inconsistent revealed labels")
            labels.append(
                RevealedCellLabel(
                    family=spec.family,
                    target_id=spec.target_id,
                    split=spec.split,
                    correct_cell=correct_cell,
                    source_member=result_member,
                    source_sha256=result_sha256,
                    information_label=(
                        InformationLabel.TRAIN_LABEL
                        if spec.split in {DatasetSplit.TRAIN, DatasetSplit.VALIDATION}
                        else InformationLabel.POST_REVEAL
                    ),
                )
            )
            seen.add(spec.target_id)
        expected = set(self._specs)
        missing = sorted(expected - seen)
        if missing:
            raise Stage3Error(
                "panel result did not provide every registry target: " + ", ".join(missing)
            )
        self._access_log.append(
            {
                "member": result_member,
                "sha256": result_sha256,
                "purpose": purpose,
                "targets": sorted(seen),
            }
        )
        return tuple(sorted(labels, key=lambda label: label.target_id))


def a296_a297_specs() -> tuple[EpisodeSpec, ...]:
    """Pinned retrospective split ledger for the first 256-cell adapter run."""

    result_root = "chronology/arx-carry-leak/research/results/v1"
    specs: list[EpisodeSpec] = []
    for width in (24, 28):
        family = "A296"
        directory = f"chacha20_round20_causal_search_gain_panel_a296_v1"
        for target_index in range(4):
            target_id = f"w{width}_t{target_index:02d}"
            split = (
                DatasetSplit.TRAIN
                if target_index < 2
                else DatasetSplit.VALIDATION
                if target_index == 2
                else DatasetSplit.RETROSPECTIVE_HOLDOUT
            )
            base = f"{result_root}/{directory}/{target_id}"
            specs.append(
                EpisodeSpec(
                    family=family,
                    target_id=target_id,
                    unknown_key_bits=width,
                    split=split,
                    measurement_member=base + ".measurement.json.zst",
                    order_member=base + ".order.json",
                )
            )
    directory = "chacha20_round20_w32_causal_search_gain_panel_a297_v1"
    for target_index in range(4):
        target_id = f"w32_t{target_index:02d}"
        base = f"{result_root}/{directory}/{target_id}"
        specs.append(
            EpisodeSpec(
                family="A297",
                target_id=target_id,
                unknown_key_bits=32,
                split=DatasetSplit.TRANSFER_HOLDOUT,
                measurement_member=base + ".measurement.json.zst",
                order_member=base + ".order.json",
            )
        )
    return tuple(specs)
