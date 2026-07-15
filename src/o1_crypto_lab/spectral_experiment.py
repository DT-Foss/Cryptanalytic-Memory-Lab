"""O1C-0005 bounded-memory tournament over verified Direct12 score fields."""

from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable, Mapping, Sequence

from .artifacts import ReadOnlyArtifactSource
from .direct12 import (
    A268_PREFLIGHT,
    A271_SIGNED_CHANNEL,
    CHANNEL_NAMES,
    HORIZONS,
    Direct12Partition,
    finalized_direct12_adapter,
    finalized_direct12_label_registry,
)
from .run_capsule import RunCapsuleManager
from .multislot_spectral import (
    CALIBRATION_ONLY_FAMILY,
    FULL_BASIS_FAMILY,
    POOLED_TRAIN_CALIBRATION_FAMILY,
    UNIVERSAL_TRAIN_FAMILY,
    MultiSlotWalshMaskPolicy,
    MultiSlotWalshMemory,
    MultiSlotWalshPlan,
)
from .quantized_spectral import (
    QuantizedMultiSlotBitVault,
    QuantizedSpectralPlan,
    dictionary_ceiling,
)
from .o1o_selector import (
    BoundedMemoryArm,
    O1OSelector,
    SelectionThresholds,
    TopKFidelity,
    TopKGate,
)
from .shape532 import (
    direct12_order,
    direct12_order_uint16be_sha256,
    grouped_scores,
    normalized_cube_laplacian,
    pair_score,
    standardized_contributions,
    trajectory_shape532,
)
from .walsh_memory import (
    FrozenRanking,
    WalshPlan,
    WalshScoreMemory,
    energy_budget_masks,
    evaluate_approximation,
    fixed_budget_masks,
    score_field_sha256,
)
from .types import InformationLabel


class SpectralExperimentError(ValueError):
    """A tournament input, plan, lifecycle, or commitment differs."""


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
        raise SpectralExperimentError("value is not canonical finite ASCII JSON") from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise SpectralExperimentError(f"{field} must be an object")
    return value


def _list(value: object, field: str) -> list[object]:
    if not isinstance(value, list):
        raise SpectralExperimentError(f"{field} must be a list")
    return value


def _sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise SpectralExperimentError(f"{field} must be a lowercase SHA-256")
    return value


def _historical_score_sha256(scores: Sequence[float]) -> str:
    return _canonical_sha256(list(scores))


def _finite_field(value: object, field: str, *, size: int = 4096) -> tuple[float, ...]:
    raw = _list(value, field)
    if len(raw) != size:
        raise SpectralExperimentError(f"{field} must contain {size} values")
    result: list[float] = []
    for index, item in enumerate(raw):
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise SpectralExperimentError(f"{field}[{index}] must be numeric")
        number = float(item)
        if not math.isfinite(number):
            raise SpectralExperimentError(f"{field}[{index}] must be finite")
        result.append(number)
    return tuple(result)


class FrozenScoreSource:
    """Exact-member reader for an independently verified immutable capsule."""

    def __init__(
        self,
        *,
        lab_root: Path,
        capsule_relative: str,
        expected_manifest_sha256: str,
    ) -> None:
        relative = PurePosixPath(capsule_relative)
        if relative.is_absolute() or ".." in relative.parts:
            raise SpectralExperimentError("score capsule path must be lab-relative")
        self.capsule = (lab_root / capsule_relative).resolve()
        expected_root = lab_root.resolve()
        if self.capsule.parent != (expected_root / "runs").resolve():
            raise SpectralExperimentError("score capsule must be directly under lab runs/")
        manifest = self.capsule / "artifacts.sha256"
        expected = _sha256(expected_manifest_sha256, "expected_manifest_sha256")
        try:
            actual = hashlib.sha256(manifest.read_bytes()).hexdigest()
        except OSError as exc:
            raise SpectralExperimentError("score capsule manifest is unreadable") from exc
        if actual != expected:
            raise SpectralExperimentError("score capsule manifest commitment differs")
        for path in (self.capsule, *self.capsule.rglob("*")):
            if path.is_symlink():
                raise SpectralExperimentError("score capsule contains a symbolic link")
            if path.stat().st_mode & 0o222:
                raise SpectralExperimentError("score capsule is not immutable")
        self.source = ReadOnlyArtifactSource(
            self.capsule, manifest
        )
        if self.source.manifest_sha256 != expected:
            raise SpectralExperimentError("score source pinned a different manifest")
        self._opened_members: list[str] = []

    @property
    def opened_members(self) -> tuple[str, ...]:
        return tuple(self._opened_members)

    def read_field(
        self,
        member: str,
        *,
        attempt_id: str,
        expected_historical_sha256: str,
    ) -> tuple[float, ...]:
        if member not in {
            "artifacts/a348_score_field.json",
            "artifacts/a349_score_field.json",
        }:
            raise SpectralExperimentError("score member is outside the exact allowlist")
        try:
            value = _mapping(json.loads(self.source.read_bytes(member)), member)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SpectralExperimentError("score member is not valid JSON") from exc
        if (
            value.get("schema") != "o1-crypto-frozen-score-field-v1"
            or value.get("attempt_id") != attempt_id
            or value.get("target_label_present") is not False
        ):
            raise SpectralExperimentError("score field information boundary differs")
        scores = _finite_field(value.get("scores"), f"{member}.scores")
        order = tuple(int(item) for item in _list(value.get("order"), f"{member}.order"))
        if order != direct12_order(scores):
            raise SpectralExperimentError("score field order differs from its scores")
        if _historical_score_sha256(scores) != _sha256(
            expected_historical_sha256, "expected_historical_sha256"
        ):
            raise SpectralExperimentError("historical score-field commitment differs")
        self._opened_members.append(member)
        return scores


def _cell_for_shape(cell) -> dict[int, dict[str, float]]:
    return {
        horizon: {
            channel: cell.values[channel_index][horizon_index]
            for channel_index, channel in enumerate(CHANNEL_NAMES)
        }
        for horizon_index, horizon in enumerate(HORIZONS)
    }


def _population_zscore(values: Sequence[float]) -> tuple[float, ...]:
    if len(values) != 256:
        raise SpectralExperimentError("training score field must contain 256 cells")
    mean = math.fsum(values) / len(values)
    deviation = math.sqrt(
        math.fsum((value - mean) ** 2 for value in values) / len(values)
    )
    if deviation == 0.0 or not math.isfinite(deviation):
        raise SpectralExperimentError("training score field has zero/nonfinite variance")
    return tuple((value - mean) / deviation for value in values)


@dataclass(frozen=True)
class TrainingFieldSet:
    fields: tuple[tuple[float, ...], ...]
    field_sha256: tuple[str, ...]
    source_partition_sha256: str
    model_sha256: str

    @property
    def set_sha256(self) -> str:
        return _canonical_sha256(self.describe())

    def describe(self) -> dict[str, object]:
        return {
            "schema": "o1-crypto-a272-training-score-fields-v1",
            "fields": len(self.fields),
            "cells_per_field": 256,
            "field_sha256": list(self.field_sha256),
            "source_partition_sha256": self.source_partition_sha256,
            "model_sha256": self.model_sha256,
            "labels_read": 0,
        }


def build_a272_training_fields(
    partition: Direct12Partition,
    *,
    config: Mapping[str, object],
) -> TrainingFieldSet:
    """Apply the already-frozen reader to A272 without opening training truths."""

    if partition.attempt_id != "A272" or len(partition.slices) != 20:
        raise SpectralExperimentError("A272 training partition differs")
    adapter = finalized_direct12_adapter()
    model_document = adapter.read_contract_json(A268_PREFLIGHT)
    signed_document = adapter.read_contract_json(A271_SIGNED_CHANNEL)
    frozen_model = _mapping(model_document.document.get("frozen_model"), "frozen_model")
    model = _mapping(frozen_model.get("model"), "frozen_model.model")
    model_sha = _canonical_sha256(model)
    reader = _mapping(config.get("reader"), "config.reader")
    if model_sha != _sha256(reader.get("model_sha256"), "reader.model_sha256"):
        raise SpectralExperimentError("A272 reader model hash differs")
    means = tuple(float(value) for value in _list(model.get("means"), "model.means"))
    scales = tuple(float(value) for value in _list(model.get("scales"), "model.scales"))
    coefficients = tuple(
        float(value) for value in _list(model.get("coefficients"), "model.coefficients")
    )
    if not len(means) == len(scales) == len(coefficients) == 532:
        raise SpectralExperimentError("A272 model width differs")
    signed_model = _mapping(
        signed_document.document.get("frozen_model"), "signed.frozen_model"
    )
    groups: dict[str, tuple[int, ...]] = {}
    for raw in _list(
        signed_model.get("signed_semantic_groups"), "signed_semantic_groups"
    ):
        group = _mapping(raw, "signed_semantic_group")
        name = group.get("name")
        indices = group.get("feature_indices")
        if not isinstance(name, str) or not isinstance(indices, list):
            raise SpectralExperimentError("signed semantic group differs")
        groups[name] = tuple(int(value) for value in indices)
    suffix = "::normalized_8cube_graph_laplacian"
    views = tuple(str(value) for value in _list(reader.get("selected_views"), "views"))
    expected_indices = tuple(
        tuple(int(value) for value in _list(raw, "selected_group_indices"))
        for raw in _list(reader.get("selected_group_indices"), "selected_group_indices")
    )
    try:
        selected = tuple(groups[view.removesuffix(suffix)] for view in views)
    except KeyError as exc:
        raise SpectralExperimentError("selected semantic group is absent") from exc
    if len(selected) != 2 or selected != expected_indices:
        raise SpectralExperimentError("selected A272 groups differ")

    fields: list[tuple[float, ...]] = []
    for source_slice in partition.slices:
        matrix = trajectory_shape532(
            _cell_for_shape(cell) for cell in source_slice.cells
        )
        contributions = standardized_contributions(
            matrix,
            means=means,
            scales=scales,
            coefficients=coefficients,
        )
        grouped = grouped_scores(
            contributions, {"left": selected[0], "right": selected[1]}
        )
        field = _population_zscore(
            pair_score(
                normalized_cube_laplacian(grouped["left"]),
                normalized_cube_laplacian(grouped["right"]),
            )
        )
        fields.append(field)
    hashes = tuple(score_field_sha256(field) for field in fields)
    return TrainingFieldSet(
        fields=tuple(fields),
        field_sha256=hashes,
        source_partition_sha256=partition.partition_sha256,
        model_sha256=model_sha,
    )


def deterministic_random_masks(n_bits: int, budget: int, *, seed: int) -> tuple[int, ...]:
    domain = 1 << n_bits
    if not 1 <= budget < domain or isinstance(seed, bool) or not isinstance(seed, int):
        raise SpectralExperimentError("invalid deterministic random-mask request")
    key = seed.to_bytes(16, "big", signed=True)
    ranked = sorted(
        range(1, domain),
        key=lambda mask: (
            hashlib.blake2b(
                mask.to_bytes(2, "big"),
                key=key,
                person=b"o1c5-mask-null",
                digest_size=16,
            ).digest(),
            mask,
        ),
    )
    return tuple(sorted(ranked[:budget], key=lambda mask: (mask.bit_count(), mask)))


@dataclass(frozen=True)
class GlobalWalshArm:
    arm_id: str
    family: str
    masks: tuple[int, ...]
    mask_source_field_sha256: str | None
    o1o_eligible: bool

    @property
    def template_sha256(self) -> str:
        return _canonical_sha256(
            {
                "schema": "o1-crypto-global-walsh-template-v1",
                "arm_id": self.arm_id,
                "family": self.family,
                "masks": list(self.masks),
                "mask_source_field_sha256": self.mask_source_field_sha256,
                "o1o_eligible": self.o1o_eligible,
            }
        )

    def execute(self, scores: Sequence[float], *, top_ks: Sequence[int]) -> "ArmExecution":
        plan = WalshPlan.for_field(
            scores,
            masks=self.masks,
            name=self.arm_id,
            mask_family=self.family,
            mask_source_field_sha256=self.mask_source_field_sha256,
        )
        memory = WalshScoreMemory(plan)
        memory.observe_field(scores)
        frozen = memory.finalize()
        if not frozen.input_field_hash_verified:
            raise SpectralExperimentError("global Walsh field was not hash-bound")
        approximate = frozen.reconstruct()
        evaluation = evaluate_approximation(scores, approximate, top_ks=top_ks)
        ranking = frozen.freeze_ranking()
        plan_description = plan.describe()
        return ArmExecution(
            arm_id=self.arm_id,
            family=self.family,
            template_sha256=self.template_sha256,
            executable_plan_sha256=plan.plan_sha256,
            frozen_state_sha256=_canonical_sha256(list(frozen.coefficients)),
            order=ranking.order,
            order_uint16be_sha256=ranking.order_sha256,
            evaluation=evaluation.describe(),
            online_state=plan_description["state"],
            static_plan_storage=plan_description["static_plan_storage"],
            work=plan_description["work"],
            plan=plan_description,
            o1o_eligible=self.o1o_eligible,
            clips=0,
            labels=(
                frozenset({InformationLabel.CONTROL})
                if self.family == "a348-energy-global"
                else frozenset({InformationLabel.PUBLIC})
            ),
        )


@dataclass(frozen=True)
class ArmExecution:
    arm_id: str
    family: str
    template_sha256: str
    executable_plan_sha256: str
    frozen_state_sha256: str
    order: tuple[int, ...]
    order_uint16be_sha256: str
    evaluation: Mapping[str, object]
    online_state: Mapping[str, object]
    static_plan_storage: Mapping[str, object]
    work: Mapping[str, object]
    plan: Mapping[str, object]
    o1o_eligible: bool
    clips: int
    labels: frozenset[InformationLabel]

    def describe(self, *, include_order: bool = False, include_plan: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "arm_id": self.arm_id,
            "family": self.family,
            "template_sha256": self.template_sha256,
            "executable_plan_sha256": self.executable_plan_sha256,
            "frozen_state_sha256": self.frozen_state_sha256,
            "order_uint16be_sha256": self.order_uint16be_sha256,
            "evaluation": dict(self.evaluation),
            "online_state": dict(self.online_state),
            "static_plan_storage": dict(self.static_plan_storage),
            "work": dict(self.work),
            "o1o_eligible": self.o1o_eligible,
            "clips": self.clips,
            "labels": sorted(label.value for label in self.labels),
            "target_labels_used": 0,
        }
        if include_plan:
            value["plan"] = dict(self.plan)
        if include_order:
            value["order"] = list(self.order)
        return value


def build_global_arms(
    calibration_scores: Sequence[float], config: Mapping[str, object]
) -> tuple[GlobalWalshArm, ...]:
    section = _mapping(config.get("global_walsh"), "config.global_walsh")
    budgets = tuple(int(value) for value in _list(section.get("budgets"), "budgets"))
    seeds = tuple(int(value) for value in _list(section.get("random_seeds"), "random_seeds"))
    calibration_hash = score_field_sha256(calibration_scores)
    arms: list[GlobalWalshArm] = []
    for budget in budgets:
        if budget == 4096:
            arms.append(
                GlobalWalshArm(
                    arm_id="global-full-bank-k4096-ceiling",
                    family="full-bank-ceiling",
                    masks=tuple(range(4096)),
                    mask_source_field_sha256=None,
                    o1o_eligible=False,
                )
            )
            continue
        arms.append(
            GlobalWalshArm(
                arm_id=f"global-a348-energy-k{budget}",
                family="a348-energy-global",
                masks=energy_budget_masks(calibration_scores, budget),
                mask_source_field_sha256=calibration_hash,
                o1o_eligible=True,
            )
        )
        if budget in {78, 218, 512, 1024, 2048}:
            arms.append(
                GlobalWalshArm(
                    arm_id=f"global-low-degree-k{budget}-control",
                    family="low-degree-prefix-control",
                    masks=fixed_budget_masks(12, budget),
                    mask_source_field_sha256=None,
                    o1o_eligible=False,
                )
            )
        if budget in {218, 512, 1024, 2048}:
            for seed in seeds:
                arms.append(
                    GlobalWalshArm(
                        arm_id=f"global-candidate-id-random-k{budget}-s{seed}-control",
                        family="candidate-id-random-mask-control",
                        masks=deterministic_random_masks(12, budget, seed=seed),
                        mask_source_field_sha256=None,
                        o1o_eligible=False,
                    )
                )
    if len({arm.arm_id for arm in arms}) != len(arms):
        raise SpectralExperimentError("global arm IDs are not unique")
    return tuple(arms)


SelectorFrozenCallback = Callable[[Mapping[str, object]], Mapping[str, object]]
OrdersFrozenCallback = Callable[
    [Mapping[str, object], Mapping[str, tuple[int, ...]]], Mapping[str, object]
]


def _selector_persistence_receipt(
    value: object,
    *,
    future_template: Mapping[str, object],
) -> Mapping[str, object]:
    receipt = _mapping(value, "selector persistence receipt")
    if (
        receipt.get("schema")
        != "o1-crypto-future-template-persistence-receipt-v1"
        or receipt.get("persisted") is not True
        or receipt.get("future_template_sha256")
        != future_template.get("future_template_sha256")
        or receipt.get("persisted_payload_sha256")
        != _canonical_sha256(future_template)
    ):
        raise SpectralExperimentError("future-template persistence receipt differs")
    _sha256(receipt.get("artifact_sha256"), "receipt.artifact_sha256")
    return dict(receipt)


def _orders_persistence_receipt(
    value: object,
    *,
    pre_reveal: Mapping[str, object],
    orders: Mapping[str, tuple[int, ...]],
) -> Mapping[str, object]:
    receipt = _mapping(value, "orders persistence receipt")
    expected_hashes = {
        arm_id: hashlib.sha256(
            b"".join(address.to_bytes(2, "big") for address in order)
        ).hexdigest()
        for arm_id, order in sorted(orders.items())
    }
    if (
        receipt.get("schema") != "o1-crypto-orders-persistence-receipt-v1"
        or receipt.get("persisted") is not True
        or receipt.get("pre_reveal_sha256") != pre_reveal.get("pre_reveal_sha256")
        or receipt.get("order_count") != len(orders)
        or receipt.get("order_artifact_sha256_by_arm") != expected_hashes
        or receipt.get("order_artifact_set_sha256")
        != _canonical_sha256(expected_hashes)
    ):
        raise SpectralExperimentError("order persistence receipt differs")
    _sha256(
        receipt.get("pre_reveal_artifact_sha256"),
        "receipt.pre_reveal_artifact_sha256",
    )
    return dict(receipt)


def _top_k_fraction(evaluation: Mapping[str, object], k: int) -> float:
    rows = _list(evaluation.get("top_k_overlap"), "evaluation.top_k_overlap")
    for raw in rows:
        row = _mapping(raw, "evaluation.top_k_overlap[]")
        if row.get("k") == k:
            value = row.get("fraction")
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise SpectralExperimentError("top-k overlap fraction is not numeric")
            result = float(value)
            if not math.isfinite(result) or not 0.0 <= result <= 1.0:
                raise SpectralExperimentError("top-k overlap fraction is invalid")
            return result
    raise SpectralExperimentError(f"evaluation does not contain top-{k} overlap")


def _online_state_bytes(execution: ArmExecution) -> int:
    value = execution.online_state.get("serialized_online_state_bytes")
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise SpectralExperimentError(
            f"arm {execution.arm_id} has no valid online-state byte count"
        )
    return value


def _work_units(execution: ArmExecution) -> int:
    for field in (
        "full_direct12_pass_accumulations",
        "full_field_update_accumulations",
    ):
        value = execution.work.get(field)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    per_observation = execution.work.get("update_accumulations_per_observation")
    if (
        isinstance(per_observation, int)
        and not isinstance(per_observation, bool)
        and per_observation > 0
    ):
        return 4096 * per_observation
    raise SpectralExperimentError(f"arm {execution.arm_id} has no valid work count")


def _execute_multislot(
    arm_id: str,
    policy: MultiSlotWalshMaskPolicy,
    scores: Sequence[float],
    *,
    top_ks: Sequence[int],
    o1o_eligible: bool,
) -> ArmExecution:
    plan = MultiSlotWalshPlan.for_deployment_field(scores, policy, name=arm_id)
    memory = MultiSlotWalshMemory(plan)
    memory.observe_field(scores)
    frozen = memory.finalize()
    if not frozen.input_field_hash_verified:
        raise SpectralExperimentError("multi-slot Walsh field was not hash-bound")
    approximate = frozen.reconstruct()
    evaluation = evaluate_approximation(scores, approximate, top_ks=top_ks)
    ranking = frozen.freeze_ranking()
    description = plan.describe()
    if policy.family == UNIVERSAL_TRAIN_FAMILY:
        labels = frozenset({InformationLabel.INTERNAL_TRAIN})
    elif policy.family == POOLED_TRAIN_CALIBRATION_FAMILY:
        labels = frozenset(
            {InformationLabel.INTERNAL_TRAIN, InformationLabel.CONTROL}
        )
    elif policy.family == CALIBRATION_ONLY_FAMILY:
        labels = frozenset({InformationLabel.CONTROL})
    elif policy.family == FULL_BASIS_FAMILY:
        labels = frozenset({InformationLabel.PUBLIC})
    else:
        raise SpectralExperimentError("unknown multi-slot provenance family")
    return ArmExecution(
        arm_id=arm_id,
        family=policy.family,
        template_sha256=policy.policy_sha256,
        executable_plan_sha256=plan.plan_sha256,
        frozen_state_sha256=_canonical_sha256(frozen.describe()),
        order=ranking.order,
        order_uint16be_sha256=ranking.order_sha256,
        evaluation=evaluation.describe(),
        online_state=_mapping(description.get("state"), "multislot.state"),
        static_plan_storage=_mapping(
            description.get("static_plan_storage"), "multislot.static_plan_storage"
        ),
        work=_mapping(description.get("work"), "multislot.work"),
        plan=description,
        o1o_eligible=o1o_eligible,
        clips=0,
        labels=labels,
    )


@dataclass(frozen=True)
class MultiSlotArm:
    arm_id: str
    policy: MultiSlotWalshMaskPolicy
    o1o_eligible: bool = True

    @property
    def template_sha256(self) -> str:
        return self.policy.policy_sha256

    def execute(self, scores: Sequence[float], *, top_ks: Sequence[int]) -> ArmExecution:
        return _execute_multislot(
            self.arm_id,
            self.policy,
            scores,
            top_ks=top_ks,
            o1o_eligible=self.o1o_eligible,
        )

    def describe_template(self) -> dict[str, object]:
        return {
            "schema": "o1-crypto-multislot-arm-template-v1",
            "arm_id": self.arm_id,
            "family": self.policy.family,
            "policy": self.policy.describe(),
            "template_sha256": self.template_sha256,
            "o1o_eligible": self.o1o_eligible,
            "target_labels_used": 0,
        }


@dataclass(frozen=True)
class QuantizedArm:
    arm_id: str
    input_bits: int
    headroom: float
    calibration_field_sha256: str
    slot_scales: tuple[float, ...]
    o1o_eligible: bool

    def __post_init__(self) -> None:
        validation_plan = QuantizedSpectralPlan(
            input_bits=self.input_bits,
            headroom=self.headroom,
            slot_scales=self.slot_scales,
            calibration_field_sha256=self.calibration_field_sha256,
            deployment_field_sha256=self.calibration_field_sha256,
            name=self.arm_id,
        )
        object.__setattr__(self, "slot_scales", validation_plan.slot_scales)

    def plan_for_deployment(
        self, deployment_scores: Sequence[float]
    ) -> QuantizedSpectralPlan:
        return QuantizedSpectralPlan(
            input_bits=self.input_bits,
            headroom=self.headroom,
            slot_scales=self.slot_scales,
            calibration_field_sha256=self.calibration_field_sha256,
            deployment_field_sha256=score_field_sha256(deployment_scores),
            name=self.arm_id,
        )

    @property
    def template_sha256(self) -> str:
        return _canonical_sha256(
            {
                "schema": "o1-crypto-quantized-bit-vault-template-v1",
                "arm_id": self.arm_id,
                "input_bits": self.input_bits,
                "headroom": self.headroom,
                "calibration_field_sha256": self.calibration_field_sha256,
                "slot_scales_sha256": self._scale_plan.scales_sha256,
                "slot_scales": list(self.slot_scales),
                "o1o_eligible": self.o1o_eligible,
            }
        )

    @property
    def _scale_plan(self) -> QuantizedSpectralPlan:
        return QuantizedSpectralPlan(
            input_bits=self.input_bits,
            headroom=self.headroom,
            slot_scales=self.slot_scales,
            calibration_field_sha256=self.calibration_field_sha256,
            deployment_field_sha256=self.calibration_field_sha256,
            name=self.arm_id,
        )

    def describe_template(self) -> dict[str, object]:
        return {
            "schema": "o1-crypto-quantized-bit-vault-template-v1",
            "arm_id": self.arm_id,
            "family": "o1-multislot-quantized-walsh-bit-vault",
            "input_bits": self.input_bits,
            "headroom": self.headroom,
            "calibration_field_sha256": self.calibration_field_sha256,
            "slot_scales_sha256": self._scale_plan.scales_sha256,
            "slot_scales": list(self.slot_scales),
            "template_sha256": self.template_sha256,
            "o1o_eligible": self.o1o_eligible,
            "target_labels_used": 0,
        }

    @classmethod
    def from_template(cls, value: Mapping[str, object]) -> "QuantizedArm":
        template = _mapping(value, "quantized template")
        try:
            arm = cls(
                arm_id=str(template["arm_id"]),
                input_bits=int(template["input_bits"]),
                headroom=float(template["headroom"]),
                calibration_field_sha256=str(
                    template["calibration_field_sha256"]
                ),
                slot_scales=tuple(float(item) for item in template["slot_scales"]),
                o1o_eligible=bool(template["o1o_eligible"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise SpectralExperimentError("invalid quantized frozen template") from exc
        if arm.describe_template() != dict(template):
            raise SpectralExperimentError("quantized frozen template hash differs")
        return arm

    def execute(self, scores: Sequence[float], *, top_ks: Sequence[int]) -> ArmExecution:
        plan = self.plan_for_deployment(scores)
        memory = QuantizedMultiSlotBitVault(plan)
        memory.observe_field(scores)
        frozen = memory.finalize()
        evaluation = frozen.evaluate(scores, top_ks=top_ks)
        ranking = frozen.freeze_ranking()
        plan_description = plan.describe()
        work = {
            "quantizations_per_observation": 1,
            "update_character_evaluations_per_observation": 255,
            "update_accumulations_per_observation": 255,
            "full_direct12_pass_quantizations": 4096,
            "full_direct12_pass_character_evaluations": 4096 * 255,
            "full_direct12_pass_accumulations": 4096 * 255,
            "full_reconstruction_fwht_butterflies": 16 * 8 * 128,
            "ranking_items": 4096,
        }
        return ArmExecution(
            arm_id=self.arm_id,
            family="o1-multislot-quantized-walsh-bit-vault",
            template_sha256=self.template_sha256,
            executable_plan_sha256=plan.plan_sha256,
            frozen_state_sha256=frozen.state_sha256,
            order=ranking.order,
            order_uint16be_sha256=ranking.order_sha256,
            evaluation=evaluation.describe(),
            online_state=_mapping(
                plan_description.get("online_state"), "quantized.online_state"
            ),
            static_plan_storage=_mapping(
                plan_description.get("static_plan_storage"),
                "quantized.static_plan_storage",
            ),
            work=work,
            plan=plan_description,
            o1o_eligible=self.o1o_eligible,
            clips=frozen.clip_count,
            labels=frozenset({InformationLabel.CONTROL}),
        )


ArmTemplate = GlobalWalshArm | MultiSlotArm | QuantizedArm


def _describe_template(template: ArmTemplate) -> dict[str, object]:
    if isinstance(template, GlobalWalshArm):
        return {
            "schema": "o1-crypto-global-walsh-template-v1",
            "arm_id": template.arm_id,
            "family": template.family,
            "masks": list(template.masks),
            "mask_source_field_sha256": template.mask_source_field_sha256,
            "template_sha256": template.template_sha256,
            "o1o_eligible": template.o1o_eligible,
            "target_labels_used": 0,
        }
    return template.describe_template()


def build_multislot_arms(
    training: TrainingFieldSet,
    calibration_scores: Sequence[float],
    config: Mapping[str, object],
) -> tuple[MultiSlotArm, ...]:
    section = _mapping(config.get("multislot_walsh"), "config.multislot_walsh")
    total_budgets = tuple(
        int(value) for value in _list(section.get("total_budgets"), "total_budgets")
    )
    if not total_budgets or any(
        budget < 16 or budget > 4080 or budget % 16 for budget in total_budgets
    ):
        raise SpectralExperimentError(
            "multi-slot total budgets must be nonempty multiples of 16 in [16, 4080]"
        )
    arms: list[MultiSlotArm] = []
    for total in total_budgets:
        per_slot = total // 16
        policies = (
            (
                "a272-average-energy",
                MultiSlotWalshMaskPolicy.universal_train(
                    training.fields, budget=per_slot
                ),
            ),
            (
                "a272-a348-pooled-energy",
                MultiSlotWalshMaskPolicy.pooled_train_calibration(
                    training.fields, calibration_scores, budget=per_slot
                ),
            ),
            (
                "a348-average-energy",
                MultiSlotWalshMaskPolicy.calibration_only(
                    calibration_scores, budget=per_slot
                ),
            ),
        )
        for prefix, policy in policies:
            arms.append(
                MultiSlotArm(
                    arm_id=f"multislot-{prefix}-total-k{total}",
                    policy=policy,
                    o1o_eligible=True,
                )
            )
    arms.append(
        MultiSlotArm(
            arm_id="multislot-full-basis-total-k4096-ceiling",
            policy=MultiSlotWalshMaskPolicy.full_basis_ceiling(),
            o1o_eligible=False,
        )
    )
    return tuple(arms)


def build_quantized_arms(
    calibration_scores: Sequence[float], config: Mapping[str, object]
) -> tuple[QuantizedArm, ...]:
    section = _mapping(
        config.get("quantized_bit_vault"), "config.quantized_bit_vault"
    )
    bits = tuple(int(value) for value in _list(section.get("input_bits"), "input_bits"))
    headrooms = tuple(
        float(value)
        for value in _list(section.get("headroom_factors"), "headroom_factors")
    )
    eligible_headrooms = {
        float(value)
        for value in _list(
            section.get("o1o_eligible_headroom_factors"),
            "o1o_eligible_headroom_factors",
        )
    }
    if not bits or any(not 2 <= value <= 8 for value in bits):
        raise SpectralExperimentError("quantized input bits must be in [2, 8]")
    if not headrooms or any(not math.isfinite(value) or value < 1.0 for value in headrooms):
        raise SpectralExperimentError("quantized headroom factors must be finite and >= 1")
    arms: list[QuantizedArm] = []
    for input_bits in bits:
        for headroom in headrooms:
            arm_id = f"quantized-bit-vault-{input_bits}bit-h{headroom:g}"
            calibration_plan = QuantizedSpectralPlan.from_calibration(
                calibration_scores,
                calibration_scores,
                input_bits=input_bits,
                headroom=headroom,
                name=arm_id,
            )
            arms.append(
                QuantizedArm(
                    arm_id=arm_id,
                    input_bits=input_bits,
                    headroom=headroom,
                    calibration_field_sha256=(
                        calibration_plan.calibration_field_sha256
                    ),
                    slot_scales=calibration_plan.slot_scales,
                    o1o_eligible=headroom in eligible_headrooms,
                )
            )
    return tuple(arms)


def _selection_thresholds(config: Mapping[str, object]) -> SelectionThresholds:
    fidelity = _mapping(config.get("fidelity"), "config.fidelity")
    gate = _mapping(fidelity.get("o1o_gate"), "config.fidelity.o1o_gate")
    return SelectionThresholds(
        min_rank_spearman=float(gate.get("minimum_rank_spearman")),
        min_rank_kendall=float(gate.get("minimum_rank_kendall")),
        top_k_requirements=(
            TopKGate(32, float(gate.get("minimum_top32_overlap"))),
            TopKGate(128, float(gate.get("minimum_top128_overlap"))),
        ),
        max_serialized_online_state_bytes=int(
            gate.get("maximum_online_state_bytes")
        ),
        require_zero_calibration_clips=bool(
            gate.get("require_zero_calibration_clips")
        ),
    )


def _o1o_arm(execution: ArmExecution) -> BoundedMemoryArm:
    return BoundedMemoryArm(
        name=execution.arm_id,
        family=execution.family,
        memory_plan_sha256=execution.template_sha256,
        rank_spearman=float(execution.evaluation["rank_spearman"]),
        rank_kendall=float(execution.evaluation["rank_kendall"]),
        top_k_overlap=tuple(
            TopKFidelity(
                k=int(_mapping(row, "top_k_overlap[]")["k"]),
                fraction=float(_mapping(row, "top_k_overlap[]")["fraction"]),
            )
            for row in _list(
                execution.evaluation.get("top_k_overlap"),
                "execution.evaluation.top_k_overlap",
            )
        ),
        serialized_online_state_bytes=_online_state_bytes(execution),
        work_units=_work_units(execution),
        calibration_clip_count=execution.clips,
        labels=execution.labels | frozenset({InformationLabel.CONTROL}),
    )


def _execute_dictionary_control(
    template: QuantizedArm,
    scores: Sequence[float],
    *,
    top_ks: Sequence[int],
) -> tuple[dict[str, object], tuple[int, ...]]:
    plan = template.plan_for_deployment(scores)
    control = dictionary_ceiling(plan, scores)
    evaluation = control.evaluate(scores, top_ks=top_ks)
    ranking = control.freeze_ranking()
    description = control.describe()
    result = {
        "arm_id": f"{template.arm_id}-dictionary-control",
        "family": "dictionary_ceiling",
        "template_sha256": template.template_sha256,
        "executable_plan_sha256": plan.plan_sha256,
        "state_sha256": control.state_sha256,
        "order_uint16be_sha256": ranking.order_sha256,
        "evaluation": evaluation.describe(),
        "control_state": description,
        "o1o_eligible": False,
        "mechanism_claim_eligible": False,
        "reason": "direct candidate-indexed value table",
        "target_labels_used": 0,
    }
    return result, ranking.order


@dataclass(frozen=True)
class BoundedMemoryTournamentResult:
    report: Mapping[str, object]
    calibration_executions: tuple[ArmExecution, ...]
    deployment_executions: tuple[ArmExecution, ...]
    selected_future_template: Mapping[str, object]
    frozen_orders: Mapping[str, tuple[int, ...]]
    success_gate_passed: bool

    def metrics(self) -> dict[str, object]:
        selection = _mapping(self.report.get("o1o_selection"), "report.o1o_selection")
        comparisons = _mapping(self.report.get("comparisons"), "report.comparisons")
        costs = _mapping(self.report.get("costs"), "report.costs")
        labels = _mapping(self.report.get("labels"), "report.labels")
        success = _mapping(self.report.get("success_gates"), "report.success_gates")
        return {
            "schema": "o1-crypto-bounded-memory-tournament-metrics-v1",
            "success_gate_passed": self.success_gate_passed,
            "selected_arm": _mapping(selection.get("selected_arm"), "selected_arm"),
            "selection_sha256": selection.get("selection_sha256"),
            "comparisons": comparisons,
            "success_gates": success,
            "costs": costs,
            "labels": labels,
        }


def _load_config(config_path: Path) -> Mapping[str, object]:
    try:
        value = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SpectralExperimentError("tournament config is not valid UTF-8 JSON") from exc
    config = _mapping(value, "config")
    if (
        config.get("schema") != "o1-crypto-bounded-memory-tournament-config-v1"
        or config.get("attempt_id") != "O1C-0005"
        or config.get("claim_level") != "VALIDATION"
    ):
        raise SpectralExperimentError("tournament config identity differs")
    global_section = _mapping(config.get("global_walsh"), "global_walsh")
    multislot = _mapping(config.get("multislot_walsh"), "multislot_walsh")
    quantized = _mapping(config.get("quantized_bit_vault"), "quantized_bit_vault")
    development = _mapping(
        config.get("development_boundary"), "development_boundary"
    )
    budgets = _mapping(config.get("budgets"), "budgets")
    expected_global_policies = [
        "a348_energy",
        "low_degree_prefix",
        "candidate_id_random",
    ]
    expected_multislot_policies = [
        "a272_average_energy",
        "a272_a348_pooled_energy",
        "a348_average_energy",
    ]
    if global_section.get("policies") != expected_global_policies:
        raise SpectralExperimentError("global Walsh policy declaration differs")
    if (
        multislot.get("slots") != 16
        or multislot.get("slot_address_bits") != 8
        or multislot.get("policies") != expected_multislot_policies
        or multislot.get("training_fields") != 20
        or multislot.get("calibration_slots") != 16
    ):
        raise SpectralExperimentError("multi-slot architecture declaration differs")
    if (
        quantized.get("slots") != 16
        or quantized.get("modes_per_slot") != 255
        or quantized.get("dictionary_ceiling_control") is not True
    ):
        raise SpectralExperimentError("quantized Bit-Vault declaration differs")
    if (
        development.get("A349_target_or_outcome_available") is not False
        or development.get("A349_progress_read") is not False
        or development.get("A349_target_labels_used") != 0
        or development.get(
            "A349_target_blind_field_fidelity_was_inspected_during_mechanism_development"
        )
        is not True
        or development.get("A349_is_fresh_architecture_test") is not False
    ):
        raise SpectralExperimentError("development-boundary declaration differs")
    if (
        budgets.get("new_solver_calls") != 0
        or budgets.get("gpu_seconds") != 0
        or budgets.get("a272_training_fields") != 20
        or budgets.get("a348_calibration_cells") != 4096
        or budgets.get("a349_target_blind_development_cells") != 4096
        or budgets.get("A349_target_labels") != 0
    ):
        raise SpectralExperimentError("tournament budget declaration differs")
    return config


def _verified_capsule(
    root: Path,
    relative_path: object,
    expected_manifest_sha256: object,
    *,
    field_name: str,
    defer_artifact_content: bool = False,
) -> dict[str, object]:
    if not isinstance(relative_path, str):
        raise SpectralExperimentError(f"{field_name} path must be text")
    relative = PurePosixPath(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise SpectralExperimentError(f"{field_name} path must be lab-relative")
    capsule = (root / relative_path).resolve()
    if capsule.parent != (root / "runs").resolve():
        raise SpectralExperimentError(f"{field_name} must be directly under lab runs/")
    expected = _sha256(expected_manifest_sha256, f"{field_name}.manifest_sha256")
    if defer_artifact_content:
        manifest = capsule / "artifacts.sha256"
        try:
            actual = hashlib.sha256(manifest.read_bytes()).hexdigest()
        except OSError as exc:
            raise SpectralExperimentError(
                f"{field_name} manifest is unreadable"
            ) from exc
        if actual != expected:
            raise SpectralExperimentError(f"{field_name} manifest commitment differs")
        paths = (capsule, *capsule.rglob("*"))
        for path in paths:
            if path.is_symlink():
                raise SpectralExperimentError(
                    f"{field_name} capsule contains a symbolic link"
                )
            if path.stat().st_mode & 0o222:
                raise SpectralExperimentError(f"{field_name} capsule is writable")
        return {
            "capsule": relative_path,
            "manifest_sha256": actual,
            "manifest_pinned": True,
            "immutable_modes_checked": True,
            "artifact_content_verification": "deferred-member-local",
            "fully_verified": False,
        }
    report = RunCapsuleManager(root).verify(capsule)
    if not report.ok or report.manifest_sha256 != expected:
        raise SpectralExperimentError(f"{field_name} immutable verification differs")
    return {
        "capsule": relative_path,
        "manifest_sha256": report.manifest_sha256,
        "artifacts_checked": report.checked,
        "manifest_pinned": True,
        "immutable_modes_checked": True,
        "artifact_content_verification": "complete",
        "fully_verified": True,
    }


def _execution_by_id(
    executions: Sequence[ArmExecution], arm_id: str
) -> ArmExecution:
    for execution in executions:
        if execution.arm_id == arm_id:
            return execution
    raise SpectralExperimentError(f"required tournament arm is absent: {arm_id}")


def run_bounded_memory_tournament(
    config_path: Path,
    *,
    lab_root: Path | None = None,
    on_selector_frozen: SelectorFrozenCallback | None = None,
    on_orders_frozen: OrdersFrozenCallback | None = None,
) -> BoundedMemoryTournamentResult:
    """Run O1C-0005 with selection frozen before the A349 field is opened."""

    started = time.perf_counter()
    root = (lab_root or Path(__file__).resolve().parents[2]).resolve()
    path = config_path.resolve()
    if path.parent != (root / "configs").resolve():
        raise SpectralExperimentError("tournament config must be directly under lab configs/")
    config = _load_config(path)
    sources = _mapping(config.get("sources"), "config.sources")
    lifecycle: list[dict[str, object]] = []
    phase_times: dict[str, float] = {}

    source_started = time.perf_counter()
    o1c3 = _verified_capsule(
        root,
        sources.get("o1c_0003_capsule"),
        sources.get("o1c_0003_manifest_sha256"),
        field_name="O1C-0003",
    )
    o1c4 = _verified_capsule(
        root,
        sources.get("o1c_0004_capsule"),
        sources.get("o1c_0004_manifest_sha256"),
        field_name="O1C-0004",
        defer_artifact_content=True,
    )
    score_source = FrozenScoreSource(
        lab_root=root,
        capsule_relative=str(sources.get("o1c_0004_capsule")),
        expected_manifest_sha256=str(sources.get("o1c_0004_manifest_sha256")),
    )
    adapter = finalized_direct12_adapter()
    a272 = adapter.load_a272()
    lifecycle.append(
        {
            "sequence": len(lifecycle) + 1,
            "phase": "SOURCES_PINNED_WITH_STAGED_CONTENT_VERIFICATION",
            "O1C_0003_full_content_verified": True,
            "O1C_0004_manifest_pinned": True,
            "O1C_0004_content_policy": "member-local; A349 deferred",
            "A348_labels_read": 0,
            "A349_field_opened": False,
            "A349_labels_read": 0,
        }
    )
    phase_times["source_verification_seconds"] = time.perf_counter() - source_started

    calibration_started = time.perf_counter()
    a348_scores = score_source.read_field(
        str(sources.get("a348_score_member")),
        attempt_id="A348",
        expected_historical_sha256=str(
            sources.get("a348_historical_score_sha256")
        ),
    )
    training = build_a272_training_fields(a272, config=config)
    top_ks = tuple(
        int(value)
        for value in _list(
            _mapping(config.get("fidelity"), "config.fidelity").get("top_ks"),
            "config.fidelity.top_ks",
        )
    )
    if not top_ks or any(not 1 <= value <= 4096 for value in top_ks):
        raise SpectralExperimentError("fidelity top_ks are invalid")
    templates: tuple[ArmTemplate, ...] = (
        *build_global_arms(a348_scores, config),
        *build_multislot_arms(training, a348_scores, config),
        *build_quantized_arms(a348_scores, config),
    )
    if len({template.arm_id for template in templates}) != len(templates):
        raise SpectralExperimentError("tournament arm IDs are not unique")
    calibration_executions = tuple(
        template.execute(a348_scores, top_ks=top_ks) for template in templates
    )
    lifecycle.append(
        {
            "sequence": len(lifecycle) + 1,
            "phase": "A348_TARGET_BLIND_CALIBRATION_COMPLETE",
            "arms": len(calibration_executions),
            "A348_labels_read": 0,
            "A349_field_opened": False,
            "A349_labels_read": 0,
        }
    )
    phase_times["calibration_tournament_seconds"] = (
        time.perf_counter() - calibration_started
    )

    selection_started = time.perf_counter()
    selection_source_sha256 = _canonical_sha256(
        {
            "schema": "o1-crypto-o1o-selection-source-v1",
            "a272_training_field_set_sha256": training.set_sha256,
            "a272_source_partition_sha256": training.source_partition_sha256,
            "reader_model_sha256": training.model_sha256,
            "a348_score_field_sha256": score_field_sha256(a348_scores),
            "reader_sha256": _canonical_sha256(config.get("reader")),
            "global_walsh_config_sha256": _canonical_sha256(
                config.get("global_walsh")
            ),
            "multislot_walsh_config_sha256": _canonical_sha256(
                config.get("multislot_walsh")
            ),
            "quantized_bit_vault_config_sha256": _canonical_sha256(
                config.get("quantized_bit_vault")
            ),
            "fidelity_config_sha256": _canonical_sha256(config.get("fidelity")),
            "deployment_artifact_or_field_hash_used": False,
            "target_labels_used": 0,
        }
    )
    eligible_calibration = tuple(
        execution for execution in calibration_executions if execution.o1o_eligible
    )
    selector = O1OSelector(
        source_snapshot_sha256=selection_source_sha256,
        thresholds=_selection_thresholds(config),
    )
    selection = selector.select_and_freeze(
        _o1o_arm(execution) for execution in eligible_calibration
    )
    selected_id = selection.selected_arm.name
    selected_template_object = next(
        (template for template in templates if template.arm_id == selected_id), None
    )
    if selected_template_object is None:
        raise SpectralExperimentError("O1-O selected a nonexistent arm")
    selected_future_template = {
        "schema": "o1-crypto-o1o-frozen-future-memory-template-v1",
        "selection_sha256": selection.selection_sha256,
        "selection_source_sha256": selection_source_sha256,
        "selected_template": _describe_template(selected_template_object),
        "deployment_binding": {
            "status": "UNBOUND_AT_FREEZE",
            "score_content_exposed_to_selector": False,
            "score_content_parsed": False,
            "manifest_member_commitment_predeclared": True,
            "opaque_commitment_used_by_selection_rule": False,
            "target_label_present": False,
        },
        "future_test_proposal": selection.frozen_test_proposal.describe(),
        "target_model_sha256": selection.target_model_sha256,
        "score_source_members_opened_at_freeze": list(score_source.opened_members),
        "A348_labels_read": 0,
        "A349_field_opened": False,
        "A349_labels_read": 0,
    }
    if score_source.opened_members != (str(sources.get("a348_score_member")),):
        raise SpectralExperimentError(
            "score-source access log differs before O1-O future-plan freeze"
        )
    selected_future_template["future_template_sha256"] = _canonical_sha256(
        selected_future_template
    )
    selector_receipt: Mapping[str, object] | None = None
    if on_selector_frozen is not None:
        selector_receipt = _selector_persistence_receipt(
            on_selector_frozen(selected_future_template),
            future_template=selected_future_template,
        )
    lifecycle.append(
        {
            "sequence": len(lifecycle) + 1,
            "phase": (
                "O1O_FUTURE_TEMPLATE_PERSISTED"
                if selector_receipt is not None
                else "O1O_FUTURE_TEMPLATE_FROZEN_IN_MEMORY"
            ),
            "selected_arm": selected_id,
            "selection_sha256": selection.selection_sha256,
            "future_template_sha256": selected_future_template[
                "future_template_sha256"
            ],
            "A348_labels_read": 0,
            "A349_field_opened": False,
            "A349_labels_read": 0,
        }
    )
    phase_times["o1o_selection_seconds"] = time.perf_counter() - selection_started

    deployment_started = time.perf_counter()
    a349_scores = score_source.read_field(
        str(sources.get("a349_score_member")),
        attempt_id="A349",
        expected_historical_sha256=str(
            sources.get("a349_historical_score_sha256")
        ),
    )
    if score_source.opened_members != (
        str(sources.get("a348_score_member")),
        str(sources.get("a349_score_member")),
    ):
        raise SpectralExperimentError("score-source staged access order differs")
    lifecycle.append(
        {
            "sequence": len(lifecycle) + 1,
            "phase": "A349_TARGET_BLIND_SCORE_FIELD_OPENED",
            "selection_already_frozen": True,
            "A348_labels_read": 0,
            "A349_labels_read": 0,
        }
    )
    deployment_executions = tuple(
        template.execute(a349_scores, top_ks=top_ks) for template in templates
    )
    frozen_orders: dict[str, tuple[int, ...]] = {
        execution.arm_id: execution.order for execution in deployment_executions
    }
    dictionary_reports: list[dict[str, object]] = []
    if bool(
        _mapping(
            config.get("quantized_bit_vault"), "config.quantized_bit_vault"
        ).get("dictionary_ceiling_control")
    ):
        for template in templates:
            if isinstance(template, QuantizedArm):
                control, order = _execute_dictionary_control(
                    template, a349_scores, top_ks=top_ks
                )
                dictionary_reports.append(control)
                frozen_orders[str(control["arm_id"])] = order
    pre_reveal = {
        "schema": "o1-crypto-bounded-memory-pre-reveal-orders-v1",
        "selection_sha256": selection.selection_sha256,
        "future_template_sha256": selected_future_template[
            "future_template_sha256"
        ],
        "A348_calibration_order_sha256": {
            execution.arm_id: execution.order_uint16be_sha256
            for execution in calibration_executions
        },
        "A349_target_blind_order_sha256": {
            execution.arm_id: execution.order_uint16be_sha256
            for execution in deployment_executions
        },
        "A349_dictionary_control_order_sha256": {
            str(report["arm_id"]): str(report["order_uint16be_sha256"])
            for report in dictionary_reports
        },
        "complete_A349_orders": len(frozen_orders),
        "A348_labels_read": 0,
        "A349_labels_read": 0,
        "A349_truth_api_available": False,
    }
    pre_reveal["pre_reveal_sha256"] = _canonical_sha256(pre_reveal)
    orders_receipt: Mapping[str, object] | None = None
    if on_orders_frozen is not None:
        orders_receipt = _orders_persistence_receipt(
            on_orders_frozen(pre_reveal, frozen_orders),
            pre_reveal=pre_reveal,
            orders=frozen_orders,
        )
    lifecycle.append(
        {
            "sequence": len(lifecycle) + 1,
            "phase": (
                "ALL_A349_ORDERS_PERSISTED"
                if orders_receipt is not None
                else "ALL_A349_ORDERS_FROZEN_IN_MEMORY"
            ),
            "orders": len(frozen_orders),
            "pre_reveal_sha256": pre_reveal["pre_reveal_sha256"],
            "A348_labels_read": 0,
            "A349_labels_read": 0,
        }
    )
    phase_times["deployment_tournament_seconds"] = (
        time.perf_counter() - deployment_started
    )

    reveal_started = time.perf_counter()
    o1c4_fully_verified = _verified_capsule(
        root,
        sources.get("o1c_0004_capsule"),
        sources.get("o1c_0004_manifest_sha256"),
        field_name="O1C-0004",
    )
    a348_truth = finalized_direct12_label_registry().a348_calibration_truth()
    a348_ranks = {
        execution.arm_id: execution.order.index(a348_truth.correct_prefix12) + 1
        for execution in calibration_executions
    }
    lifecycle.append(
        {
            "sequence": len(lifecycle) + 1,
            "phase": "A348_CALIBRATION_TRUTH_OPENED_POST_FREEZE",
            "A348_labels_read": 1,
            "A349_labels_read": 0,
        }
    )
    phase_times["post_freeze_a348_audit_seconds"] = (
        time.perf_counter() - reveal_started
    )

    deployment_by_id = {execution.arm_id: execution for execution in deployment_executions}
    quant4_id = "quantized-bit-vault-4bit-h1.25"
    universal_id = "multislot-a272-average-energy-total-k2048"
    low_degree_id = "global-low-degree-k2048-control"
    sparse_id = "global-a348-energy-k2048"
    required_ids = (quant4_id, universal_id, low_degree_id, sparse_id)
    for arm_id in required_ids:
        if arm_id not in deployment_by_id:
            raise SpectralExperimentError(f"comparison arm is missing: {arm_id}")
    random_ids = tuple(
        arm_id
        for arm_id in deployment_by_id
        if arm_id.startswith("global-candidate-id-random-k2048-")
    )
    if not random_ids:
        raise SpectralExperimentError("matched candidate-ID random controls are absent")
    spearman = {
        arm_id: float(deployment_by_id[arm_id].evaluation["rank_spearman"])
        for arm_id in required_ids
    }
    random_spearman = {
        arm_id: float(deployment_by_id[arm_id].evaluation["rank_spearman"])
        for arm_id in random_ids
    }
    comparisons = {
        "quantized_4bit_h1_25_A349_rank_spearman": spearman[quant4_id],
        "quantized_4bit_h1_25_A349_top32_overlap": _top_k_fraction(
            deployment_by_id[quant4_id].evaluation, 32
        ),
        "a272_multislot_k2048_A349_rank_spearman": spearman[universal_id],
        "global_low_degree_k2048_A349_rank_spearman": spearman[low_degree_id],
        "global_a348_sparse_k2048_A349_rank_spearman": spearman[sparse_id],
        "candidate_id_random_k2048_A349_rank_spearman": random_spearman,
        "best_candidate_id_random_k2048_A349_rank_spearman": max(
            random_spearman.values()
        ),
        "distributed_minus_low_degree": spearman[universal_id]
        - spearman[low_degree_id],
        "distributed_minus_best_candidate_id_random": spearman[universal_id]
        - max(random_spearman.values()),
        "quantized_4bit_minus_sparse_a348_energy": spearman[quant4_id]
        - spearman[sparse_id],
    }
    selected_calibration = _execution_by_id(calibration_executions, selected_id)
    selected_deployment = _execution_by_id(deployment_executions, selected_id)
    success_gates = {
        "immutable_sources_verified": bool(
            o1c3["fully_verified"] and o1c4_fully_verified["fully_verified"]
        ),
        "future_template_persisted_before_A349_field_open": selector_receipt
        is not None
        and lifecycle[3]["phase"] == "A349_TARGET_BLIND_SCORE_FIELD_OPENED",
        "all_A349_orders_persisted_before_A348_truth": orders_receipt is not None
        and lifecycle[5]["phase"] == "A348_CALIBRATION_TRUTH_OPENED_POST_FREEZE",
        "o1o_selected_eligible_mechanism": selected_calibration.o1o_eligible,
        "o1o_selected_within_state_gate": _online_state_bytes(selected_calibration)
        <= _selection_thresholds(config).max_serialized_online_state_bytes,
        "quantized_4bit_A349_spearman_above_0_98": spearman[quant4_id] > 0.98,
        "distributed_support_beats_low_degree_at_k2048": spearman[universal_id]
        > spearman[low_degree_id],
        "distributed_support_beats_all_candidate_id_random_at_k2048": spearman[
            universal_id
        ]
        > max(random_spearman.values()),
        "dense_low_precision_beats_sparse_calibration_support": spearman[quant4_id]
        > spearman[sparse_id],
        "selected_deployment_has_no_candidate_rows": selected_deployment.online_state.get(
            "retained_candidate_rows"
        )
        == 0,
        "dictionary_controls_disqualified": all(
            report["mechanism_claim_eligible"] is False
            for report in dictionary_reports
        ),
        "A349_target_labels_zero": True,
    }
    success_gate_passed = all(success_gates.values())
    total_elapsed = time.perf_counter() - started
    phase_times["total_seconds"] = total_elapsed
    all_executions = (*calibration_executions, *deployment_executions)
    total_work = sum(_work_units(item) for item in all_executions)
    global_templates = tuple(
        template for template in templates if isinstance(template, GlobalWalshArm)
    )
    multislot_templates = tuple(
        template for template in templates if isinstance(template, MultiSlotArm)
    )
    quantized_templates = tuple(
        template for template in templates if isinstance(template, QuantizedArm)
    )
    global_energy_policy_fits = sum(
        template.family == "a348-energy-global" for template in global_templates
    )
    multislot_budget_count = (
        len(multislot_templates) - 1
    ) // 3  # three learned families plus one explicit ceiling
    policy_learning = {
        "global_A348_energy_policy_fits": global_energy_policy_fits,
        "global_4096_point_FWHT_butterflies": (
            global_energy_policy_fits * 12 * 4096 // 2
        ),
        "multislot_learned_budgets": multislot_budget_count,
        "multislot_256_point_source_FWHTs": multislot_budget_count
        * (20 + (20 + 16) + 16),
        "multislot_policy_FWHT_butterflies": multislot_budget_count
        * (20 + (20 + 16) + 16)
        * 8
        * 256
        // 2,
        "quantized_scale_calibration_field_scans": len(quantized_templates),
        "quantized_scale_calibration_values_examined": len(quantized_templates)
        * 4096,
        "A272_reader_feature_values_materialized": 20 * 256 * 532,
        "A272_reader_truth_labels_used": 0,
    }
    reconstruction_butterflies = sum(
        int(item.work.get("full_reconstruction_fwht_butterflies", 0))
        for item in all_executions
    )
    ranking_items = sum(
        int(item.work.get("ranking_items", 4096)) for item in all_executions
    ) + len(dictionary_reports) * 4096
    costs = {
        "calibration_arms": len(calibration_executions),
        "deployment_arms": len(deployment_executions),
        "dictionary_controls": len(dictionary_reports),
        "complete_A349_orders_frozen": len(frozen_orders),
        "declared_update_accumulations_calibration_plus_deployment": total_work,
        "offline_policy_learning": policy_learning,
        "reconstruction_and_evaluation": {
            "FWHT_butterflies_calibration_plus_deployment": (
                reconstruction_butterflies
            ),
            "ranking_items_calibration_deployment_and_dictionary": ranking_items,
            "dictionary_control_quantizations": len(dictionary_reports) * 4096,
            "dictionary_control_retained_candidate_entries": len(dictionary_reports)
            * 4096,
            "logical_peak_evaluator_workspace_bytes_lower_bound": (
                3 * 4096 * 8 + 2 * 4096 * 2
            ),
            "workspace_components": (
                "reference, approximation and error float64 fields plus two "
                "uint16 rankings; Python object heap and top-k sets not measured"
            ),
            "evaluator_workspace_counted_as_online_state": False,
        },
        "selected_template_static_storage": {
            "calibration_scores_retained": 0,
            "slot_scale_values": (
                16 if isinstance(selected_template_object, QuantizedArm) else 0
            ),
            "slot_scale_bytes": (
                128 if isinstance(selected_template_object, QuantizedArm) else 0
            ),
            "online_state_bytes": _online_state_bytes(selected_deployment),
        },
        "phase_seconds": phase_times,
        "new_solver_calls": 0,
        "gpu_seconds": 0,
        "A272_truth_labels_read": 0,
        "A348_truth_labels_read": 1,
        "A349_target_labels_read": 0,
    }
    report = {
        "schema": "o1-crypto-bounded-memory-tournament-v1",
        "attempt_id": "O1C-0005",
        "claim_level": "VALIDATION",
        "success_gate_passed": success_gate_passed,
        "sources": {
            "O1C-0003": o1c3,
            "O1C-0004_pre_freeze": o1c4,
            "O1C-0004_post_A349_open_full_verification": o1c4_fully_verified,
        },
        "development_boundary": dict(
            _mapping(config.get("development_boundary"), "development_boundary")
        ),
        "lifecycle": lifecycle,
        "training_fields": training.describe(),
        "templates": [_describe_template(template) for template in templates],
        "o1o_selection": selection.describe(),
        "selected_future_template": selected_future_template,
        "calibration_executions": [
            item.describe(include_plan=False) for item in calibration_executions
        ],
        "deployment_executions": [
            item.describe(include_plan=False) for item in deployment_executions
        ],
        "dictionary_controls": dictionary_reports,
        "pre_reveal": pre_reveal,
        "persistence_receipts": {
            "future_template": selector_receipt,
            "A349_orders": orders_receipt,
        },
        "A348_post_freeze_audit": {
            "correct_prefix12": a348_truth.correct_prefix12,
            "truth_source_member": a348_truth.source_member,
            "truth_source_sha256": a348_truth.source_sha256,
            "rank_one_based_by_arm": a348_ranks,
            "selected_arm_rank_one_based": a348_ranks[selected_id],
            "opened_after_all_A349_orders": True,
        },
        "A349": {
            "score_field_sha256": score_field_sha256(a349_scores),
            "historical_score_sha256": _historical_score_sha256(a349_scores),
            "target_blind_fidelity_only": True,
            "target_or_outcome_read": False,
            "progress_read": False,
            "target_labels_read": 0,
            "truth_api_available": False,
        },
        "comparisons": comparisons,
        "success_gates": success_gates,
        "costs": costs,
        "labels": {
            "A272_truth_labels_read": 0,
            "A348_truth_labels_read": 1,
            "A349_target_labels_read": 0,
        },
        "claim_boundary": {
            "bounded_state_in_stream_length": True,
            "no_KV_cache": True,
            "no_full_O_T_attention": True,
            "quantized_dense_bank_is_full_rank_not_sublinear_capacity": True,
            "dictionary_ceiling_is_not_a_valid_mechanism": True,
            "A349_is_not_a_fresh_architecture_test": True,
            "integrity_verifier_vs_experiment_reader": (
                "capsule integrity code may hash sealed bytes, but only exact "
                "member-local reads enter the experiment; the access log proves "
                "A349 score content entered only after selector freeze"
            ),
            "score_source_member_access_order": list(score_source.opened_members),
            "allowed_claim": "mechanistic validation and frozen-plan transfer",
        },
    }
    deterministic_report = json.loads(_canonical_bytes(report))
    deterministic_costs = _mapping(
        deterministic_report.get("costs"), "deterministic_report.costs"
    )
    deterministic_costs.pop("phase_seconds", None)
    report["deterministic_report_sha256"] = _canonical_sha256(
        deterministic_report
    )
    report["runtime_observation_sha256"] = _canonical_sha256(report)
    return BoundedMemoryTournamentResult(
        report=report,
        calibration_executions=calibration_executions,
        deployment_executions=deployment_executions,
        selected_future_template=selected_future_template,
        frozen_orders=dict(frozen_orders),
        success_gate_passed=success_gate_passed,
    )


__all__ = [
    "ArmExecution",
    "BoundedMemoryTournamentResult",
    "FrozenScoreSource",
    "GlobalWalshArm",
    "MultiSlotArm",
    "QuantizedArm",
    "SpectralExperimentError",
    "TrainingFieldSet",
    "build_a272_training_fields",
    "build_global_arms",
    "build_multislot_arms",
    "build_quantized_arms",
    "deterministic_random_masks",
    "run_bounded_memory_tournament",
]
