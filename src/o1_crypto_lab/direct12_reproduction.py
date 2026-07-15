"""Independent reproduction of the frozen Direct12 532-feature reader.

Only the immutable O1C-0003 snapshot is accepted.  Discovery matrices and
revealed calibration truth remain on separate APIs, and the A349 deployment
target has no truth API at all.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .direct12 import (
    A268_PREFLIGHT,
    A271_SIGNED_CHANNEL,
    A348_RESULT,
    A349_ORDER,
    CHANNEL_NAMES,
    HORIZONS,
    DatasetRole,
    Direct12CellMatrix,
    Direct12Error,
    Direct12Partition,
    finalized_direct12_adapter,
    finalized_direct12_label_registry,
)
from .shape532 import (
    BASE_FEATURE_NAMES_SHA256,
    FEATURE_NAMES,
    FEATURE_NAMES_SHA256,
    Direct12FrozenPairResult,
    direct12_order,
    direct12_order_uint16be_sha256,
    score_direct12_frozen_pair,
    trajectory_shape532,
)


class Direct12ReproductionError(ValueError):
    """A frozen config, source contract, or reproduced commitment differs."""


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise Direct12ReproductionError("value is not canonical finite ASCII JSON") from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise Direct12ReproductionError(f"{field} must be an object")
    return value


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise Direct12ReproductionError(f"{field} must be a list")
    return value


def _sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise Direct12ReproductionError(f"{field} must be a lowercase SHA-256")
    return value


def _finite_vector(value: object, field: str, *, width: int) -> tuple[float, ...]:
    raw = _sequence(value, field)
    if len(raw) != width:
        raise Direct12ReproductionError(f"{field} must contain {width} values")
    result: list[float] = []
    for index, item in enumerate(raw):
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise Direct12ReproductionError(f"{field}[{index}] must be numeric")
        number = float(item)
        if not math.isfinite(number):
            raise Direct12ReproductionError(f"{field}[{index}] must be finite")
        result.append(number)
    return tuple(result)


def _score_field_sha256(scores: Sequence[float]) -> str:
    """Historical Direct12 commitment: canonical JSON over float values."""

    return _canonical_sha256(list(scores))


def _cell_for_shape(cell: Direct12CellMatrix) -> dict[int, dict[str, float]]:
    return {
        horizon: {
            channel: cell.values[channel_index][horizon_index]
            for channel_index, channel in enumerate(CHANNEL_NAMES)
        }
        for horizon_index, horizon in enumerate(HORIZONS)
    }


def _shape_matrices(partition: Direct12Partition):
    expected_role = {
        "A348": DatasetRole.CALIBRATION,
        "A349": DatasetRole.SEALED_DEPLOYMENT,
    }.get(partition.attempt_id)
    if partition.role is not expected_role or len(partition.slices) != 16:
        raise Direct12ReproductionError(
            "shape scoring accepts only canonical A348/A349 sixteen-slice partitions"
        )
    for low4, source_slice in enumerate(partition.slices):
        if source_slice.low4 != low4:
            raise Direct12ReproductionError("Direct12 slice order is not low4 canonical")
        yield trajectory_shape532(_cell_for_shape(cell) for cell in source_slice.cells)


@dataclass(frozen=True)
class FrozenFieldCommitment:
    attempt_id: str
    raw_score_sha256: str
    raw_order_uint16be_sha256: str
    slice_z_score_sha256: str
    slice_z_order_uint16be_sha256: str
    raw_order: tuple[int, ...]
    slice_z_order: tuple[int, ...]
    first8: tuple[int, ...]

    @classmethod
    def from_result(
        cls, attempt_id: str, result: Direct12FrozenPairResult
    ) -> "FrozenFieldCommitment":
        raw_order = direct12_order(result.raw_pair_scores)
        return cls(
            attempt_id=attempt_id,
            raw_score_sha256=_score_field_sha256(result.raw_pair_scores),
            raw_order_uint16be_sha256=direct12_order_uint16be_sha256(raw_order),
            slice_z_score_sha256=_score_field_sha256(result.slice_zscores),
            slice_z_order_uint16be_sha256=result.order_uint16be_sha256,
            raw_order=raw_order,
            slice_z_order=result.order,
            first8=result.order[:8],
        )

    def describe(self, *, include_orders: bool = False) -> dict[str, object]:
        value: dict[str, object] = {
            "attempt_id": self.attempt_id,
            "raw_score_sha256": self.raw_score_sha256,
            "raw_order_uint16be_sha256": self.raw_order_uint16be_sha256,
            "slice_z_score_sha256": self.slice_z_score_sha256,
            "slice_z_order_uint16be_sha256": self.slice_z_order_uint16be_sha256,
            "first8": list(self.first8),
            "target_labels_used": 0,
        }
        if include_orders:
            value["raw_order"] = list(self.raw_order)
            value["slice_z_order"] = list(self.slice_z_order)
        return value


@dataclass(frozen=True)
class Direct12ReproductionResult:
    report: Mapping[str, object]
    a348_scores: tuple[float, ...]
    a349_scores: tuple[float, ...]
    a348_order: tuple[int, ...]
    a349_order: tuple[int, ...]
    success_gate_passed: bool

    def metrics(self) -> dict[str, object]:
        return {
            "schema": "o1-crypto-direct12-reproduction-metrics-v1",
            "success_gate_passed": self.success_gate_passed,
            "dataset_sha256": self.report["dataset_sha256"],
            "reader_contract_sha256": self.report["reader_contract_sha256"],
            "model_sha256": self.report["model"]["model_sha256"],
            "a348": self.report["a348"],
            "a349": self.report["a349"],
            "labels": self.report["labels"],
            "source_members": self.report["counts"]["source_members"],
            "measurement_shards": self.report["counts"]["measurement_shards"],
            "cells": self.report["counts"]["cells"],
            "solver_stages_reused": self.report["counts"]["solver_stages_reused"],
            "new_solver_calls": 0,
            "gpu_seconds": 0,
        }


FrozenCallback = Callable[[Mapping[str, object]], None]

_FORBIDDEN_CONFIG_KEYS = frozenset(
    {
        "confirmed_prefix12",
        "correct_prefix12",
        "expected_post_freeze_rank",
        "post_freeze_calibration_prefix12",
        "target_address",
        "target_prefix",
    }
)


def _reject_embedded_truth(value: object, *, path: str = "config") -> None:
    """Prevent a convenient config field from bypassing the post-freeze broker."""

    if isinstance(value, dict):
        for key, item in value.items():
            if key in _FORBIDDEN_CONFIG_KEYS:
                raise Direct12ReproductionError(
                    f"{path}.{key} is forbidden before order freeze"
                )
            _reject_embedded_truth(item, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_embedded_truth(item, path=f"{path}[{index}]")


def _validate_partition_counts(
    dataset_description: Mapping[str, object], config: Mapping[str, object]
) -> None:
    counts = _mapping(dataset_description.get("counts"), "dataset.counts")
    budgets = _mapping(config.get("budgets"), "config.budgets")
    expected = {
        "slices": budgets.get("measurement_shards"),
        "cells": budgets.get("cells"),
        "stages": budgets.get("solver_stages_reused"),
    }
    for field, value in expected.items():
        if counts.get(field) != value:
            raise Direct12ReproductionError(
                f"dataset {field} differs: {counts.get(field)!r} != {value!r}"
            )


def _assert_commitment(
    actual: str, expected: object, field: str
) -> None:
    if actual != _sha256(expected, field):
        raise Direct12ReproductionError(f"{field} reproduction differs")


def run_direct12_reproduction(
    config_path: Path,
    *,
    lab_root: Path,
    on_frozen: FrozenCallback | None = None,
) -> Direct12ReproductionResult:
    """Reproduce A348/A349 commitments, freeze orders, then open A348 truth."""

    try:
        config = _mapping(json.loads(config_path.read_bytes()), "config")
    except (OSError, json.JSONDecodeError) as exc:
        raise Direct12ReproductionError("could not read reproduction config") from exc
    if config.get("schema") != "o1-crypto-direct12-reproduction-config-v1":
        raise Direct12ReproductionError("reproduction config schema differs")
    if config.get("attempt_id") != "O1C-0004":
        raise Direct12ReproductionError("reproduction attempt ID differs")
    _reject_embedded_truth(config)
    snapshot = _mapping(config.get("snapshot"), "config.snapshot")
    capsule = (lab_root / str(snapshot.get("capsule"))).resolve()
    expected_capsule = (lab_root / "runs/20260715_123734_O1C-0003_direct12-source-snapshot").resolve()
    if capsule != expected_capsule:
        raise Direct12ReproductionError("only the finalized O1C-0003 capsule is allowed")
    try:
        capsule_manifest_sha256 = hashlib.sha256(
            (capsule / "artifacts.sha256").read_bytes()
        ).hexdigest()
    except OSError as exc:
        raise Direct12ReproductionError("O1C-0003 capsule manifest is missing") from exc
    _assert_commitment(
        capsule_manifest_sha256,
        snapshot.get("capsule_manifest_sha256"),
        "snapshot.capsule_manifest_sha256",
    )

    adapter = finalized_direct12_adapter()
    # The adapter verifies the complete capsule, descriptor and copied ledger.
    dataset = adapter.load_dataset()
    dataset_description = dataset.describe()
    _validate_partition_counts(dataset_description, config)
    a272, a348, a349 = dataset.partitions
    if (
        a272.role is not DatasetRole.TRAIN
        or a348.role is not DatasetRole.CALIBRATION
        or a349.role is not DatasetRole.SEALED_DEPLOYMENT
    ):
        raise Direct12ReproductionError("dataset role order differs")
    expected_ledger_sha256 = _sha256(
        snapshot.get("source_ledger_sha256"), "snapshot.source_ledger_sha256"
    )
    if any(
        source_slice.provenance.source_ledger_sha256 != expected_ledger_sha256
        for partition in dataset.partitions
        for source_slice in partition.slices
    ):
        raise Direct12ReproductionError("dataset source-ledger pin differs")

    # Only the two target-blind model/group documents cross the pre-freeze API.
    preflight = adapter.read_contract_json(A268_PREFLIGHT)
    signed = adapter.read_contract_json(A271_SIGNED_CHANNEL)
    frozen_model = _mapping(preflight.document.get("frozen_model"), "frozen_model")
    model = _mapping(frozen_model.get("model"), "frozen_model.model")
    model_config = _mapping(config.get("frozen_model"), "config.frozen_model")
    model_hash = _canonical_sha256(model)
    _assert_commitment(model_hash, model_config.get("model_sha256"), "model_sha256")
    width = int(model_config.get("dimensions", -1))
    if width != len(FEATURE_NAMES) or tuple(model.get("feature_names", ())) != FEATURE_NAMES:
        raise Direct12ReproductionError("frozen model feature names differ")
    if BASE_FEATURE_NAMES_SHA256 != model_config.get("base_feature_names_sha256"):
        raise Direct12ReproductionError("base feature-name hash differs")
    if FEATURE_NAMES_SHA256 != model_config.get("feature_names_sha256"):
        raise Direct12ReproductionError("feature-name hash differs")
    means = _finite_vector(model.get("means"), "model.means", width=width)
    scales = _finite_vector(model.get("scales"), "model.scales", width=width)
    coefficients = _finite_vector(
        model.get("coefficients"), "model.coefficients", width=width
    )
    if any(value <= 0.0 for value in scales):
        raise Direct12ReproductionError("model scales must be positive")
    if sum(value != 0.0 for value in coefficients) != model_config.get(
        "nonzero_coefficients"
    ):
        raise Direct12ReproductionError("model nonzero coefficient count differs")
    if float(model.get("ridge_lambda", -1.0)) != float(
        model_config.get("ridge_lambda", -2.0)
    ):
        raise Direct12ReproductionError("model ridge lambda differs")

    signed_model = _mapping(signed.document.get("frozen_model"), "signed.frozen_model")
    raw_groups = _sequence(
        signed_model.get("signed_semantic_groups"), "signed_semantic_groups"
    )
    groups: dict[str, tuple[int, ...]] = {}
    for index, raw_group in enumerate(raw_groups):
        group = _mapping(raw_group, f"signed_semantic_groups[{index}]")
        name = group.get("name")
        indices = group.get("feature_indices")
        if not isinstance(name, str) or not isinstance(indices, list):
            raise Direct12ReproductionError("signed semantic group schema differs")
        groups[name] = tuple(int(value) for value in indices)
    pair_config = _mapping(config.get("selected_pair"), "config.selected_pair")
    views = tuple(str(value) for value in _sequence(pair_config.get("views"), "views"))
    expected_indices = tuple(
        tuple(int(value) for value in _sequence(group, "group_indices"))
        for group in _sequence(pair_config.get("group_indices"), "group_indices")
    )
    suffix = "::normalized_8cube_graph_laplacian"
    if len(views) != 2 or any(not view.endswith(suffix) for view in views):
        raise Direct12ReproductionError("selected pair view contract differs")
    selected_indices = tuple(groups[view.removesuffix(suffix)] for view in views)
    if selected_indices != expected_indices:
        raise Direct12ReproductionError("selected pair group indices differ")

    a348_result = score_direct12_frozen_pair(
        _shape_matrices(a348),
        means=means,
        scales=scales,
        coefficients=coefficients,
        pair_group_indices=selected_indices,
    )
    a349_result = score_direct12_frozen_pair(
        _shape_matrices(a349),
        means=means,
        scales=scales,
        coefficients=coefficients,
        pair_group_indices=selected_indices,
    )
    a348_commitment = FrozenFieldCommitment.from_result("A348", a348_result)
    a349_commitment = FrozenFieldCommitment.from_result("A349", a349_result)
    a348_config = _mapping(config.get("a348"), "config.a348")
    a349_config = _mapping(config.get("a349"), "config.a349")
    for actual, field in (
        (a348_commitment.raw_score_sha256, "expected_pair_global_raw_score_sha256"),
        (
            a348_commitment.raw_order_uint16be_sha256,
            "expected_pair_global_raw_order_uint16be_sha256",
        ),
        (a348_commitment.slice_z_score_sha256, "expected_pair_slice_z_score_sha256"),
        (
            a348_commitment.slice_z_order_uint16be_sha256,
            "expected_pair_slice_z_order_uint16be_sha256",
        ),
    ):
        _assert_commitment(actual, a348_config.get(field), f"a348.{field}")
    for actual, field in (
        (a349_commitment.slice_z_score_sha256, "expected_pair_slice_z_score_sha256"),
        (
            a349_commitment.slice_z_order_uint16be_sha256,
            "expected_pair_slice_z_order_uint16be_sha256",
        ),
    ):
        _assert_commitment(actual, a349_config.get(field), f"a349.{field}")
    if list(a349_commitment.first8) != a349_config.get("expected_first8"):
        raise Direct12ReproductionError("A349 first-eight commitment differs")

    pre_reveal = {
        "schema": "o1-crypto-direct12-pre-reveal-orders-v1",
        "dataset_sha256": dataset.dataset_sha256,
        "model_sha256": model_hash,
        "reader_contract_documents": [preflight.describe(), signed.describe()],
        "selected_views": list(views),
        "selected_group_indices": [list(group) for group in selected_indices],
        "a348": a348_commitment.describe(include_orders=True),
        "a349": a349_commitment.describe(include_orders=True),
        "labels_read": {"A272": 0, "A348": 0, "A349": 0},
    }
    pre_reveal["pre_reveal_sha256"] = _canonical_sha256(pre_reveal)
    if on_frozen is not None:
        on_frozen(pre_reveal)

    # Only after both complete orders have been persisted may calibration truth
    # and source result documents enter the process-visible report.
    label_registry = finalized_direct12_label_registry()
    a348_truth = label_registry.a348_calibration_truth()
    a348_raw_rank = a348_commitment.raw_order.index(a348_truth.correct_prefix12) + 1
    a348_slice_z_rank = (
        a348_commitment.slice_z_order.index(a348_truth.correct_prefix12) + 1
    )
    a348_reference = adapter.read_contract_json(A348_RESULT)
    a349_reference = adapter.read_contract_json(A349_ORDER)
    a348_reference_rank_panel = _mapping(
        a348_reference.document.get("rank_panel"), "A348.rank_panel"
    )
    reference_pair = _mapping(
        a348_reference_rank_panel.get("A342_selected_pair_slice_z"),
        "A348.rank_panel.A342_selected_pair_slice_z",
    )
    if reference_pair.get("rank_one_based") != a348_slice_z_rank:
        raise Direct12ReproductionError("post-freeze A348 rank differs")
    reference_a349_order = tuple(
        int(value)
        for value in _sequence(
            a349_reference.document.get("selected_order"), "A349.selected_order"
        )
    )
    if reference_a349_order != a349_commitment.slice_z_order:
        raise Direct12ReproductionError("reproduced A349 order vector differs")
    contextual_commitment = _canonical_sha256(
        {
            "selected_view": a349_reference.document.get("selected_view"),
            "A345_public_challenge_sha256": a349_reference.document.get(
                "A345_public_challenge_sha256"
            ),
            "measurement_sha256": a349_reference.document.get("measurement_sha256"),
            "score_field_sha256": a349_commitment.slice_z_score_sha256,
            "selected_order_uint16be_sha256": (
                a349_commitment.slice_z_order_uint16be_sha256
            ),
            "target_labels_used": 0,
            "reader_refits": 0,
        }
    )
    _assert_commitment(
        contextual_commitment,
        a349_config.get("expected_order_commitment_sha256"),
        "a349.expected_order_commitment_sha256",
    )
    if contextual_commitment != a349_reference.document.get("order_commitment_sha256"):
        raise Direct12ReproductionError("A349 contextual order commitment differs")

    full_contract = adapter.load_reader_contract()
    report: dict[str, object] = {
        "schema": "o1-crypto-direct12-reproduction-v1",
        "attempt_id": "O1C-0004",
        "dataset_sha256": dataset.dataset_sha256,
        "dataset": dataset_description,
        "reader_contract_sha256": full_contract.contract_sha256,
        "reader_contract": full_contract.describe(),
        "model": {
            "model_sha256": model_hash,
            "base_feature_names_sha256": BASE_FEATURE_NAMES_SHA256,
            "feature_names_sha256": FEATURE_NAMES_SHA256,
            "dimensions": width,
            "nonzero_coefficients": sum(value != 0.0 for value in coefficients),
            "ridge_lambda": model.get("ridge_lambda"),
            "selected_views": list(views),
            "selected_group_indices": [list(group) for group in selected_indices],
        },
        "pre_reveal_sha256": pre_reveal["pre_reveal_sha256"],
        "a348": {
            **a348_commitment.describe(),
            "calibration_prefix12": a348_truth.correct_prefix12,
            "raw_rank_one_based": a348_raw_rank,
            "slice_z_rank_one_based": a348_slice_z_rank,
            "log2_rank_gain": 12.0 - math.log2(a348_slice_z_rank),
            "truth_source_sha256": a348_truth.source_sha256,
        },
        "a349": {
            **a349_commitment.describe(),
            "order_commitment_sha256": contextual_commitment,
            "reference_order_vector_exact": True,
            "target_label_available": False,
        },
        "labels": {
            "A272_training_labels_read": 0,
            "A348_calibration_labels_read_before_freeze": 0,
            "A348_calibration_labels_read_after_freeze": 1,
            "A349_labels_read": 0,
        },
        "counts": {
            "source_members": snapshot.get("members"),
            "measurement_shards": 52,
            "cells": 13312,
            "solver_stages_reused": 53248,
            "new_solver_calls": 0,
            "gpu_seconds": 0,
        },
        "information_boundary": {
            "source": "immutable O1C-0003 snapshot only",
            "sibling_paths_read": 0,
            "sibling_paths_written": 0,
            "A349_progress_or_outcome_read": False,
            "reader_refits": 0,
            "target_labels_used_for_selection": 0,
        },
        "success_gate_passed": True,
    }
    report["report_sha256"] = _canonical_sha256(report)
    return Direct12ReproductionResult(
        report=report,
        a348_scores=a348_result.slice_zscores,
        a349_scores=a349_result.slice_zscores,
        a348_order=a348_result.order,
        a349_order=a349_result.order,
        success_gate_passed=True,
    )
