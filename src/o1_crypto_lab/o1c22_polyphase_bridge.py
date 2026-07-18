"""Canonical O1C-0022 packet transport into the allocation-invariant V2 state.

O1C-0022 emits one coordinate-local packet with H64/H65/H96 deltas.  Feeding
those packets as coordinate-major sparse full-width frames would be wrong: every
frame advances every resonator, so early coordinates would decay merely because
their ledger row appeared first.  This module instead transposes a complete K256
packet ledger into exactly three dense horizon-major ``float32[3, 256]`` groups.

Moving from the immutable O1C-0027 V1 state to this self-describing V2 basis is
a cold migration and requires one replay.  Once the three groups have been
consumed into V2, externally verified proposals that change only the frozen
readout temperature—or select the exact frozen horizon fit—can be bound without
replay.  This module validates a synthetic O1-O-shaped descriptor contract; it
does not itself authenticate an O1C-0023 decision graph.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import InitVar, dataclass
from typing import Mapping, Sequence

import numpy as np

from .o1c22_packet_codec import (
    FrozenMedianAbsQuantizer,
    O1C22PacketCodecError,
    PacketDeltaExtraction,
)
from .polyphase_sufficient_state_v2 import (
    BASIS_SHA256,
    KEY_BITS,
    POLE_COUNT,
    STATE_BYTES,
    WAVELENGTHS,
    PolyphaseReadoutSpec,
    PolyphaseSufficientState,
    ReplayRequiredError,
    read_polyphase_state,
)


BRIDGE_SCHEMA = "o1-256-o1c22-horizon-major-polyphase-bridge-v1"
STREAM_SCHEMA = "o1-256-o1c22-horizon-major-dense-stream-v1"
HOT_BINDING_SCHEMA = "o1-256-o1o-polyphase-hot-readout-binding-v1"
HOT_LINEAGE_SCHEMA = "o1-256-o1c22-polyphase-hot-readout-lineage-v1"
FIT_SCHEMA = "o1-256-nonnegative-horizon-readout-fit-v1"
O1C22_HORIZONS = (64, 65, 96)
ENCODING_NORMALIZED_FLOAT32 = "normalized_float32"
ENCODING_QUANTIZED_INT8_FLOAT32 = "quantized_int8_float32"
ENCODINGS = frozenset(
    {ENCODING_NORMALIZED_FLOAT32, ENCODING_QUANTIZED_INT8_FLOAT32}
)
GROUP_SHAPE = (len(O1C22_HORIZONS), len(WAVELENGTHS), KEY_BITS)
GROUP_BYTES = math.prod(GROUP_SHAPE) * np.dtype("<f4").itemsize
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_HOT_LINEAGE_FACTORY_TOKEN = object()
_FIT_FACTORY_TOKEN = object()
_BOUND_FACTORY_TOKEN = object()

# These IDs mirror the current O1C-0023 successor vocabulary for synthetic
# contract testing.  Only the first two alter a late-bound decision surface.
# Every other ID changes evidence,
# addressing, state semantics, lifecycle, or the target and therefore cannot
# reinterpret an already-consumed V2 state.
HOT_OPERATOR_IDS = frozenset(
    {
        "horizon_nonnegative_simplex_v1",
        "magnitude_confidence_calibration_v1",
    }
)
COLD_OPERATOR_IDS = frozenset(
    {
        "repair_operational_replay_v1",
        "repair_integrity_lifecycle_v1",
        "banked_coordinate_chunks_v1",
        "quantized_denoising_replication_v1",
        "quantizer_precision_clip_ladder_v1",
        "multislot_residual_vault_v1",
        "proof_ancestry_pair_residual_v1",
        "exact_contradiction_antecedent_reader_v1",
        "coordinate_phase_binding_repair_v1",
        "horizon_surprise_compounding_v1",
        "fold_growth_stability_v1",
        "prospective_full256_frozen_lineage_v1",
        "novel_policy_extension_required_v1",
    }
)


class O1C22PolyphaseBridgeError(ValueError):
    """A packet ledger, dense encoding, fit, or O1-O binding differs."""


def _canonical_json_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise O1C22PolyphaseBridgeError("document is not finite canonical JSON") from exc
    return rendered.encode("ascii")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise O1C22PolyphaseBridgeError(f"{field} must be lowercase SHA-256")
    return value


def decode_packet_delta_extraction(value: bytes) -> PacketDeltaExtraction:
    """Rehydrate one canonical packet ledger without changing pinned O1C-0019 code."""

    try:
        return PacketDeltaExtraction.from_bytes(value)
    except O1C22PacketCodecError as exc:
        raise O1C22PolyphaseBridgeError(str(exc)) from exc


def _immutable_float32(value: np.ndarray, shape: tuple[int, ...]) -> np.ndarray:
    array = np.asarray(value)
    if array.dtype != np.float32 or array.shape != shape or not np.all(np.isfinite(array)):
        raise O1C22PolyphaseBridgeError(
            f"dense evidence must be finite float32{list(shape)}"
        )
    frozen = np.frombuffer(
        np.array(array, dtype="<f4", order="C", copy=True).tobytes(order="C"),
        dtype="<f4",
    ).reshape(shape)
    frozen.setflags(write=False)
    return frozen


@dataclass(frozen=True)
class DenseHorizonMajorStream:
    """Three immutable dense groups derived from one complete K256 packet ledger."""

    encoding: str
    groups: np.ndarray
    source_stream_sha256: str
    action_pool_sha256: str
    reader_state_sha256: str
    active_coordinates_sha256: str
    packet_ledger_sha256: str
    quantizer_sha256: str
    maximum_absolute_float64_to_float32_error: float

    def __post_init__(self) -> None:
        if self.encoding not in ENCODINGS:
            raise O1C22PolyphaseBridgeError("unknown dense-stream encoding")
        object.__setattr__(self, "groups", _immutable_float32(self.groups, GROUP_SHAPE))
        for field in (
            "source_stream_sha256",
            "action_pool_sha256",
            "reader_state_sha256",
            "active_coordinates_sha256",
            "packet_ledger_sha256",
            "quantizer_sha256",
        ):
            _require_sha256(getattr(self, field), field)
        error = self.maximum_absolute_float64_to_float32_error
        if (
            isinstance(error, bool)
            or not isinstance(error, (int, float))
            or not math.isfinite(float(error))
            or float(error) < 0.0
        ):
            raise O1C22PolyphaseBridgeError("float32 cast error must be finite and nonnegative")
        object.__setattr__(
            self,
            "maximum_absolute_float64_to_float32_error",
            float(error),
        )

    @property
    def evidence_bytes(self) -> bytes:
        payload = self.groups.astype("<f4", copy=False).tobytes(order="C")
        if len(payload) != GROUP_BYTES:  # pragma: no cover
            raise AssertionError("dense stream width differs")
        return payload

    @property
    def evidence_sha256(self) -> str:
        return _sha256_bytes(self.evidence_bytes)

    @property
    def nonzero_values(self) -> int:
        return int(np.count_nonzero(self.groups))

    def describe(self) -> dict[str, object]:
        return {
            "schema": STREAM_SCHEMA,
            "bridge_schema": BRIDGE_SCHEMA,
            "encoding": self.encoding,
            "shape": list(GROUP_SHAPE),
            "dtype": "float32",
            "bytes": GROUP_BYTES,
            "source_stream_sha256": self.source_stream_sha256,
            "action_pool_sha256": self.action_pool_sha256,
            "reader_state_sha256": self.reader_state_sha256,
            "active_coordinates_sha256": self.active_coordinates_sha256,
            "packet_ledger_sha256": self.packet_ledger_sha256,
            "quantizer_sha256": self.quantizer_sha256,
            "packet_horizon_order": list(O1C22_HORIZONS),
            "polyphase_wavelength_order": list(WAVELENGTHS),
            "polyphase_basis_sha256": BASIS_SHA256,
            "coordinate_order": "canonical-key-bit-0-through-255",
            "packet_order_canonicalized": True,
            "groups_consumed_once": len(O1C22_HORIZONS),
            "nonzero_values": self.nonzero_values,
            "maximum_absolute_float64_to_float32_error": (
                self.maximum_absolute_float64_to_float32_error
            ),
            "evidence_sha256": self.evidence_sha256,
            "target_or_label_accesses": 0,
        }


def build_dense_horizon_major_stream(
    extraction: PacketDeltaExtraction,
    quantizer: FrozenMedianAbsQuantizer,
    *,
    encoding: str,
) -> DenseHorizonMajorStream:
    """Canonical-transpose one K256 coordinate ledger into three dense groups."""

    if not isinstance(extraction, PacketDeltaExtraction):
        raise TypeError("extraction must be lightweight PacketDeltaExtraction")
    if not isinstance(quantizer, FrozenMedianAbsQuantizer):
        raise TypeError("quantizer must be lightweight FrozenMedianAbsQuantizer")
    if encoding not in ENCODINGS:
        raise O1C22PolyphaseBridgeError("unknown dense-stream encoding")
    if (
        len(extraction.groups) != KEY_BITS
        or len(extraction.active_coordinates) != KEY_BITS
        or set(extraction.active_coordinates) != set(range(KEY_BITS))
        or extraction.ordered_horizons != O1C22_HORIZONS
        or quantizer.horizons != O1C22_HORIZONS
    ):
        raise O1C22PolyphaseBridgeError(
            "horizon-major bridge requires one complete K256 H64/H65/H96 ledger"
        )

    values64 = np.zeros(GROUP_SHAPE, dtype=np.float64)
    for packet in extraction.groups:
        for time_index, (horizon, delta) in enumerate(
            zip(packet.horizons, packet.incremental_deltas)
        ):
            wavelength_index = WAVELENGTHS.index(horizon)
            if encoding == ENCODING_NORMALIZED_FLOAT32:
                value = quantizer.normalized(horizon, delta)
            else:
                value = float(quantizer.quantize(horizon, delta))
            values64[time_index, wavelength_index, packet.coordinate] = value

    with np.errstate(over="ignore", invalid="ignore"):
        values32 = values64.astype(np.float32)
    if not np.all(np.isfinite(values32)):
        raise O1C22PolyphaseBridgeError(
            "finite normalized packet delta is not representable as float32"
        )
    cast_error = float(
        np.max(np.abs(values64 - values32.astype(np.float64)), initial=0.0)
    )
    first = extraction.groups[0]
    return DenseHorizonMajorStream(
        encoding=encoding,
        groups=values32,
        source_stream_sha256=extraction.source_stream_sha256,
        action_pool_sha256=extraction.action_pool_sha256,
        reader_state_sha256=extraction.reader_state_sha256,
        active_coordinates_sha256=first.active_coordinates_sha256,
        packet_ledger_sha256=extraction.public_packet_ledger_sha256,
        quantizer_sha256=quantizer.sha256,
        maximum_absolute_float64_to_float32_error=cast_error,
    )


def consume_dense_horizon_major_stream(
    stream: DenseHorizonMajorStream,
) -> PolyphaseSufficientState:
    """Consume the canonical three-group transport exactly once."""

    if not isinstance(stream, DenseHorizonMajorStream):
        raise TypeError("stream must be DenseHorizonMajorStream")
    state = PolyphaseSufficientState.initial()
    consumed = state.consume(stream.groups)
    if (
        consumed != len(O1C22_HORIZONS)
        or state.clock != len(O1C22_HORIZONS)
        or state.persistent_bytes != STATE_BYTES
    ):  # pragma: no cover
        raise AssertionError("canonical horizon-major state accounting differs")
    return state


def permute_dense_coordinates(
    stream: DenseHorizonMajorStream,
    permutation: Sequence[int],
) -> np.ndarray:
    """Return one matched dense coordinate permutation for a control state."""

    if not isinstance(stream, DenseHorizonMajorStream):
        raise TypeError("stream must be DenseHorizonMajorStream")
    mapping = tuple(permutation)
    if (
        len(mapping) != KEY_BITS
        or set(mapping) != set(range(KEY_BITS))
        or any(isinstance(value, bool) or not isinstance(value, int) for value in mapping)
    ):
        raise O1C22PolyphaseBridgeError("coordinate permutation must cover 0..255")
    result = np.zeros(GROUP_SHAPE, dtype=np.float32)
    result[:, :, np.asarray(mapping, dtype=np.int64)] = stream.groups
    result.setflags(write=False)
    return result


@dataclass(frozen=True)
class HotReadoutLineage:
    """Exact evidence/state/training lineage a hot reader is allowed to query."""

    encoding: str
    quantizer_sha256: str
    evidence_sha256: str
    state_sha256: str
    training_ledger_sha256: str
    fit_receipt_sha256: str
    fitted_slot_weights_sha256: str
    fitted_temperature: float
    fitted_readout_sha256: str
    lineage_receipt_sha256: str
    _factory_token: InitVar[object]

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _HOT_LINEAGE_FACTORY_TOKEN:
            raise O1C22PolyphaseBridgeError(
                "hot-readout lineage must be created by the verified factory"
            )
        if self.encoding not in ENCODINGS:
            raise O1C22PolyphaseBridgeError("hot-readout lineage encoding differs")
        for field in (
            "quantizer_sha256",
            "evidence_sha256",
            "state_sha256",
            "training_ledger_sha256",
            "fit_receipt_sha256",
            "fitted_slot_weights_sha256",
            "fitted_readout_sha256",
            "lineage_receipt_sha256",
        ):
            _require_sha256(getattr(self, field), field)
        if (
            isinstance(self.fitted_temperature, bool)
            or not isinstance(self.fitted_temperature, (int, float))
            or not math.isfinite(float(self.fitted_temperature))
            or not 0.0 < float(self.fitted_temperature) <= 1_000_000.0
        ):
            raise O1C22PolyphaseBridgeError("fitted lineage temperature differs")
        object.__setattr__(self, "fitted_temperature", float(self.fitted_temperature))
        if self.lineage_receipt_sha256 != _sha256_bytes(
            _canonical_json_bytes(self.unsigned_document())
        ):
            raise O1C22PolyphaseBridgeError("hot-readout lineage receipt differs")

    def unsigned_document(self) -> dict[str, object]:
        return {
            "schema": HOT_LINEAGE_SCHEMA,
            "bridge_schema": BRIDGE_SCHEMA,
            "state_basis_sha256": BASIS_SHA256,
            "encoding": self.encoding,
            "quantizer_sha256": self.quantizer_sha256,
            "evidence_sha256": self.evidence_sha256,
            "state_sha256": self.state_sha256,
            "training_ledger_sha256": self.training_ledger_sha256,
            "fit_receipt_sha256": self.fit_receipt_sha256,
            "fitted_slot_weights_sha256": self.fitted_slot_weights_sha256,
            "fitted_temperature_float64_hex": self.fitted_temperature.hex(),
            "fitted_readout_sha256": self.fitted_readout_sha256,
        }

    def describe(self) -> dict[str, object]:
        return {
            **self.unsigned_document(),
            "lineage_receipt_sha256": self.lineage_receipt_sha256,
        }


@dataclass(frozen=True)
class BoundHotReadout:
    """A frozen readout bound to one externally authenticated or synthetic descriptor."""

    operator_id: str
    operator_fingerprint: str
    source_result_sha256: str
    verified_decision_sha256: str
    policy_sha256: str
    lineage: HotReadoutLineage
    spec: PolyphaseReadoutSpec
    binding_sha256: str
    _factory_token: InitVar[object]

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _BOUND_FACTORY_TOKEN:
            raise O1C22PolyphaseBridgeError(
                "bound hot readout must be created by the binding factory"
            )
        if self.operator_id not in HOT_OPERATOR_IDS:
            raise O1C22PolyphaseBridgeError("operator is not a hot readout")
        _require_sha256(self.operator_fingerprint, "operator_fingerprint")
        _require_sha256(self.source_result_sha256, "source_result_sha256")
        _require_sha256(self.verified_decision_sha256, "verified_decision_sha256")
        _require_sha256(self.policy_sha256, "policy_sha256")
        _require_sha256(self.binding_sha256, "binding_sha256")
        if not isinstance(self.lineage, HotReadoutLineage):
            raise TypeError("lineage must be HotReadoutLineage")
        if not isinstance(self.spec, PolyphaseReadoutSpec):
            raise TypeError("spec must be PolyphaseReadoutSpec")
        if self.spec.basis_sha256 != BASIS_SHA256:
            raise ReplayRequiredError("hot readout is bound to a foreign state basis")
        if self.binding_sha256 != _sha256_bytes(
            _canonical_json_bytes(self.unsigned_document())
        ):
            raise O1C22PolyphaseBridgeError("hot-readout binding digest differs")

    def unsigned_document(self) -> dict[str, object]:
        return {
            "schema": HOT_BINDING_SCHEMA,
            "operator_id": self.operator_id,
            "operator_fingerprint": self.operator_fingerprint,
            "source_result_sha256": self.source_result_sha256,
            "verified_decision_sha256": self.verified_decision_sha256,
            "policy_sha256": self.policy_sha256,
            "state_basis_sha256": BASIS_SHA256,
            "lineage": self.lineage.describe(),
            "readout": self.spec.describe(),
            "o1o_is_scientific_weight_authority": False,
            "stream_replay_required": False,
        }

    def describe(self) -> dict[str, object]:
        return {**self.unsigned_document(), "binding_sha256": self.binding_sha256}


def bind_o1o_hot_readout(
    operator: Mapping[str, object],
    *,
    slot_weights: np.ndarray,
    temperature: float,
    lineage: HotReadoutLineage,
) -> BoundHotReadout:
    """Bind already-frozen weights to a structurally checked O1-O-shaped descriptor.

    The caller remains responsible for verifying a real O1C-0023 decision graph.
    O1-O may select an operator instance; it cannot fit or authorize the supplied
    scientific weights.  O1C-0028 itself supplies synthetic descriptors only.
    """

    if not isinstance(operator, Mapping):
        raise TypeError("operator must be a mapping")
    if not isinstance(lineage, HotReadoutLineage):
        raise TypeError("lineage must be HotReadoutLineage")
    try:
        operator_id = operator["operator_id"]
        fingerprint = operator["operator_fingerprint"]
        source_result = operator["source_result_sha256"]
        verified_decision = operator["verified_decision_sha256"]
        policy = operator["policy_sha256"]
        replaced: tuple[object, ...] = tuple(
            operator["replaced_components"]  # type: ignore[arg-type]
        )
    except (KeyError, TypeError) as exc:
        raise O1C22PolyphaseBridgeError("O1-O operator descriptor fields differ") from exc
    if not isinstance(operator_id, str):
        raise O1C22PolyphaseBridgeError("operator_id must be text")
    if operator_id in COLD_OPERATOR_IDS:
        raise ReplayRequiredError(
            f"O1-O operator {operator_id} changes a cold evidence/state component"
        )
    if operator_id not in HOT_OPERATOR_IDS:
        raise O1C22PolyphaseBridgeError("O1-O operator is not registered")
    expected_component = (
        "horizon_scale_weighting"
        if operator_id == "horizon_nonnegative_simplex_v1"
        else "magnitude_confidence"
    )
    if replaced != (expected_component,):
        raise O1C22PolyphaseBridgeError("hot operator replacement surface differs")
    fingerprint_value = _require_sha256(fingerprint, "operator_fingerprint")
    source_value = _require_sha256(source_result, "source_result_sha256")
    decision_value = _require_sha256(verified_decision, "verified_decision_sha256")
    policy_value = _require_sha256(policy, "policy_sha256")
    name = f"{operator_id}:{fingerprint_value[:12]}"
    spec = PolyphaseReadoutSpec(
        name=name,
        basis_sha256=BASIS_SHA256,
        slot_weights=slot_weights,
        temperature=temperature,
    )
    weights = spec.slot_weights
    actual_weights_sha256 = _sha256_bytes(
        weights.astype("<f4", copy=False).tobytes(order="C")
    )
    if operator_id == "horizon_nonnegative_simplex_v1":
        if set(operator) != {
            "operator_id",
            "operator_fingerprint",
            "source_result_sha256",
            "verified_decision_sha256",
            "policy_sha256",
            "replaced_components",
            "weight_contract",
        } or operator["weight_contract"] != "nonnegative_horizon_simplex_equal_poles":
            raise O1C22PolyphaseBridgeError("horizon-simplex operator contract differs")
        horizon_weights = weights[:, 0] * np.float32(POLE_COUNT)
        expected = np.repeat(
            (horizon_weights / np.float32(POLE_COUNT))[:, None],
            POLE_COUNT,
            axis=1,
        ).astype(np.float32, copy=False)
        if (
            bool((weights < 0.0).any())
            or not np.array_equal(weights, expected)
            or not math.isclose(
                float(horizon_weights.sum(dtype=np.float32)),
                1.0,
                rel_tol=0.0,
                abs_tol=2e-7,
            )
        ):
            raise O1C22PolyphaseBridgeError(
                "horizon-simplex weights must be nonnegative, pole-equal and normalized"
            )
        if (
            actual_weights_sha256 != lineage.fitted_slot_weights_sha256
            or spec.temperature != lineage.fitted_temperature
        ):
            raise ReplayRequiredError(
                "horizon operator differs from the frozen scientific fit"
            )
    else:
        if set(operator) != {
            "operator_id",
            "operator_fingerprint",
            "source_result_sha256",
            "verified_decision_sha256",
            "policy_sha256",
            "replaced_components",
            "calibration_scope",
            "frozen_slot_weights_sha256",
        } or operator["calibration_scope"] != "global_temperature_only":
            raise O1C22PolyphaseBridgeError("confidence operator contract differs")
        expected_weights_sha256 = _require_sha256(
            operator["frozen_slot_weights_sha256"],
            "frozen_slot_weights_sha256",
        )
        if (
            expected_weights_sha256 != lineage.fitted_slot_weights_sha256
            or actual_weights_sha256 != expected_weights_sha256
        ):
            raise ReplayRequiredError(
                "confidence operator attempted to replace frozen slot weights"
            )
    unsigned = {
        "schema": HOT_BINDING_SCHEMA,
        "operator_id": operator_id,
        "operator_fingerprint": fingerprint_value,
        "source_result_sha256": source_value,
        "verified_decision_sha256": decision_value,
        "policy_sha256": policy_value,
        "state_basis_sha256": BASIS_SHA256,
        "lineage": lineage.describe(),
        "readout": spec.describe(),
        "o1o_is_scientific_weight_authority": False,
        "stream_replay_required": False,
    }
    return BoundHotReadout(
        operator_id=operator_id,
        operator_fingerprint=fingerprint_value,
        source_result_sha256=source_value,
        verified_decision_sha256=decision_value,
        policy_sha256=policy_value,
        lineage=lineage,
        spec=spec,
        binding_sha256=_sha256_bytes(_canonical_json_bytes(unsigned)),
        _factory_token=_BOUND_FACTORY_TOKEN,
    )


def read_bound_hot_state(
    state: PolyphaseSufficientState,
    binding: BoundHotReadout,
) -> np.ndarray:
    """Query a hot reader only against its exact frozen state lineage."""

    if not isinstance(state, PolyphaseSufficientState):
        raise TypeError("state must be PolyphaseSufficientState")
    if not isinstance(binding, BoundHotReadout):
        raise TypeError("binding must be BoundHotReadout")
    before = state.sha256()
    if before != binding.lineage.state_sha256:
        raise ReplayRequiredError(
            "hot readout is bound to a different evidence/state lineage"
        )
    result = read_polyphase_state(state, binding.spec)
    if state.sha256() != before:  # pragma: no cover
        raise AssertionError("hot readout mutated its frozen state")
    return result


@dataclass(frozen=True)
class FittedHorizonReadout:
    """Deterministic nonnegative three-horizon ridge fit for BUILD-only folds."""

    horizon_weights: np.ndarray
    slot_weights: np.ndarray
    temperature: float
    alpha: float
    objective: float
    active_mask: int
    training_examples: int
    training_ledger_sha256: str
    fit_receipt_sha256: str
    abstained: bool
    _factory_token: InitVar[object]

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _FIT_FACTORY_TOKEN:
            raise O1C22PolyphaseBridgeError(
                "fitted readout must be created by the deterministic fit factory"
            )
        horizon = np.asarray(self.horizon_weights)
        slots = np.asarray(self.slot_weights)
        if (
            horizon.dtype != np.float32
            or horizon.shape != (len(WAVELENGTHS),)
            or slots.dtype != np.float32
            or slots.shape != (len(WAVELENGTHS), POLE_COUNT)
            or not np.all(np.isfinite(horizon))
            or not np.all(np.isfinite(slots))
            or bool((horizon < 0.0).any())
        ):
            raise O1C22PolyphaseBridgeError("fitted horizon weights differ")
        object.__setattr__(
            self,
            "horizon_weights",
            _immutable_float32(horizon, (len(WAVELENGTHS),)),
        )
        object.__setattr__(
            self,
            "slot_weights",
            _immutable_float32(slots, (len(WAVELENGTHS), POLE_COUNT)),
        )
        for field in ("temperature", "alpha", "objective"):
            value = getattr(self, field)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or float(value) < 0.0
            ):
                raise O1C22PolyphaseBridgeError(f"{field} must be finite and nonnegative")
            object.__setattr__(self, field, float(value))
        if self.temperature <= 0.0 or self.temperature > 1_000_000.0:
            raise O1C22PolyphaseBridgeError("fit temperature is outside readout bounds")
        with np.errstate(over="ignore", under="ignore", invalid="ignore"):
            temperature32 = np.float32(self.temperature)
        if not np.isfinite(temperature32) or temperature32 <= 0.0:
            raise O1C22PolyphaseBridgeError(
                "fit temperature must be positive finite float32"
            )
        object.__setattr__(self, "temperature", float(temperature32))
        if (
            isinstance(self.active_mask, bool)
            or not isinstance(self.active_mask, int)
            or not 0 <= self.active_mask < 1 << len(WAVELENGTHS)
            or isinstance(self.training_examples, bool)
            or not isinstance(self.training_examples, int)
            or self.training_examples < 1
            or not isinstance(self.abstained, bool)
            or self.abstained != (self.active_mask == 0)
        ):
            raise O1C22PolyphaseBridgeError("fit accounting differs")
        _require_sha256(self.training_ledger_sha256, "training_ledger_sha256")
        _require_sha256(self.fit_receipt_sha256, "fit_receipt_sha256")
        if self.abstained:
            if bool(np.any(horizon != 0.0)) or bool(np.any(slots != 0.0)):
                raise O1C22PolyphaseBridgeError("abstaining fit must have zero weights")
        elif (
            not bool(np.any(horizon > 0.0))
            or not math.isclose(float(horizon.sum()), 1.0, rel_tol=0.0, abs_tol=2e-7)
        ):
            raise O1C22PolyphaseBridgeError("active horizon fit must be a simplex")
        expected_slots = np.repeat(
            (horizon / np.float32(POLE_COUNT))[:, None],
            POLE_COUNT,
            axis=1,
        ).astype(np.float32, copy=False)
        if not np.array_equal(slots, expected_slots):
            raise O1C22PolyphaseBridgeError(
                "fitted slot weights must exactly represent the horizon simplex"
            )
        support_mask = sum(
            1 << index for index, value in enumerate(horizon) if value > 0.0
        )
        if self.active_mask != support_mask:
            raise O1C22PolyphaseBridgeError(
                "fitted active mask must exactly match nonzero horizon support"
            )
        if self.fit_receipt_sha256 != _sha256_bytes(
            _canonical_json_bytes(self.receipt_document())
        ):
            raise O1C22PolyphaseBridgeError("fitted readout receipt differs")

    def receipt_document(self) -> dict[str, object]:
        return {
            "schema": "o1-256-nonnegative-horizon-fit-receipt-v1",
            "horizon_weights_sha256": _sha256_bytes(
                self.horizon_weights.astype("<f4", copy=False).tobytes(order="C")
            ),
            "slot_weights_sha256": _sha256_bytes(
                self.slot_weights.astype("<f4", copy=False).tobytes(order="C")
            ),
            "temperature_float64_hex": self.temperature.hex(),
            "alpha_float64_hex": self.alpha.hex(),
            "objective_float64_hex": self.objective.hex(),
            "active_mask": self.active_mask,
            "training_examples": self.training_examples,
            "training_ledger_sha256": self.training_ledger_sha256,
            "abstained": self.abstained,
        }

    def describe(self) -> dict[str, object]:
        return {
            "schema": FIT_SCHEMA,
            "horizon_order": list(WAVELENGTHS),
            "horizon_weights": self.horizon_weights.tolist(),
            "slot_weights": self.slot_weights.tolist(),
            "temperature": self.temperature,
            "alpha": self.alpha,
            "objective": self.objective,
            "active_mask": self.active_mask,
            "training_examples": self.training_examples,
            "training_ledger_sha256": self.training_ledger_sha256,
            "fit_receipt_sha256": self.fit_receipt_sha256,
            "abstained": self.abstained,
            "fit_target": "shared-coordinate-polarity-without-intercept",
        }


def _horizon_features(state: PolyphaseSufficientState) -> np.ndarray:
    if not isinstance(state, PolyphaseSufficientState):
        raise TypeError("states must contain PolyphaseSufficientState values")
    # Equal pole averaging keeps the fitted operator exactly three-dimensional.
    return state.slots.real.astype(np.float64).mean(axis=1).T


def _solve_small_system(matrix: np.ndarray, rhs: np.ndarray) -> np.ndarray:
    """Solve a positive ridge system of width at most three without BLAS."""

    width = int(rhs.shape[0])
    if matrix.shape != (width, width) or not 1 <= width <= len(WAVELENGTHS):
        raise O1C22PolyphaseBridgeError("small linear system geometry differs")
    augmented = [
        [float(matrix[row, column]) for column in range(width)] + [float(rhs[row])]
        for row in range(width)
    ]
    for column in range(width):
        pivot = max(
            range(column, width),
            key=lambda row: (abs(augmented[row][column]), -row),
        )
        if augmented[pivot][column] == 0.0:
            raise O1C22PolyphaseBridgeError("ridge system is singular")
        augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
        pivot_value = augmented[column][column]
        for row in range(column + 1, width):
            factor = augmented[row][column] / pivot_value
            for index in range(column, width + 1):
                augmented[row][index] -= factor * augmented[column][index]
    solution = [0.0] * width
    for row in range(width - 1, -1, -1):
        residual = augmented[row][width] - sum(
            augmented[row][column] * solution[column]
            for column in range(row + 1, width)
        )
        solution[row] = residual / augmented[row][row]
    result = np.asarray(solution, dtype=np.float64)
    if not np.all(np.isfinite(result)):
        raise O1C22PolyphaseBridgeError("ridge solution is non-finite")
    return result


def fit_nonnegative_horizon_readout(
    states: Sequence[PolyphaseSufficientState],
    labels: np.ndarray,
    *,
    alpha: float,
) -> FittedHorizonReadout:
    """Fit one shared nonnegative H64/H96/H65 reader by exact active sets."""

    rows = tuple(states)
    targets = np.asarray(labels)
    if (
        not rows
        or targets.dtype != np.uint8
        or targets.shape != (len(rows), KEY_BITS)
        or bool(((targets != 0) & (targets != 1)).any())
    ):
        raise O1C22PolyphaseBridgeError("fit labels must be uint8[n,256] bits")
    if (
        isinstance(alpha, bool)
        or not isinstance(alpha, (int, float))
        or not math.isfinite(float(alpha))
        or float(alpha) <= 0.0
    ):
        raise O1C22PolyphaseBridgeError("alpha must be finite and positive")
    design = np.concatenate([_horizon_features(state) for state in rows], axis=0)
    response = (2.0 * targets.astype(np.float64) - 1.0).reshape(-1)
    if not np.all(np.isfinite(design)):
        raise O1C22PolyphaseBridgeError("fit design contains non-finite values")
    training_ledger_sha256 = _sha256_bytes(
        _canonical_json_bytes(
            {
                "schema": "o1-256-horizon-fit-training-ledger-v1",
                "state_sha256": [state.sha256() for state in rows],
                "labels_sha256": _sha256_bytes(targets.tobytes(order="C")),
                "labels_shape": list(targets.shape),
                "alpha_float64_hex": float(alpha).hex(),
            }
        )
    )

    best_key: tuple[float, int, int] | None = None
    best = np.zeros(len(WAVELENGTHS), dtype=np.float64)
    best_mask = 0
    for mask in range(1 << len(WAVELENGTHS)):
        active = tuple(index for index in range(len(WAVELENGTHS)) if mask & (1 << index))
        weights = np.zeros(len(WAVELENGTHS), dtype=np.float64)
        if active:
            matrix = design[:, active]
            # Explicit einsums avoid leaking stale Accelerate/BLAS floating-point
            # status flags into NumPy warnings on otherwise finite tiny systems.
            gram = np.einsum(
                "ni,nj->ij", matrix, matrix, dtype=np.float64, optimize=False
            ) + float(alpha) * np.eye(len(active))
            rhs = np.einsum(
                "ni,n->i", matrix, response, dtype=np.float64, optimize=False
            )
            solution = _solve_small_system(gram, rhs)
            if not np.all(np.isfinite(solution)) or bool((solution < -1e-12).any()):
                continue
            weights[np.asarray(active, dtype=np.int64)] = np.maximum(solution, 0.0)
        residual = (
            np.einsum(
                "nk,k->n", design, weights, dtype=np.float64, optimize=False
            )
            - response
        )
        objective = float(
            np.sum(residual * residual, dtype=np.float64)
            + float(alpha) * np.sum(weights * weights, dtype=np.float64)
        )
        key = (objective, len(active), mask)
        if best_key is None or key < best_key:
            best_key = key
            best = weights
            best_mask = mask
    if best_key is None:  # pragma: no cover
        raise O1C22PolyphaseBridgeError("no finite horizon active set exists")

    total = float(best.sum())
    if best_mask == 0 or total <= 0.0:
        horizon32 = np.zeros(len(WAVELENGTHS), dtype=np.float32)
        slots32 = np.zeros((len(WAVELENGTHS), POLE_COUNT), dtype=np.float32)
        temperature = 1.0
        best_mask = 0
    else:
        if not 1e-6 <= total <= 1e6:
            raise O1C22PolyphaseBridgeError("fitted horizon scale exceeds hot temperature")
        horizon32 = np.asarray(best / total, dtype=np.float32)
        # Re-normalize in float32 so the persisted simplex is self-consistent.
        horizon32 = np.asarray(horizon32 / horizon32.sum(dtype=np.float32), dtype=np.float32)
        slots32 = np.repeat(
            (horizon32 / np.float32(POLE_COUNT))[:, None],
            POLE_COUNT,
            axis=1,
        ).astype(np.float32, copy=False)
        temperature = 1.0 / total
    receipt_document = {
        "schema": "o1-256-nonnegative-horizon-fit-receipt-v1",
        "horizon_weights_sha256": _sha256_bytes(
            horizon32.astype("<f4", copy=False).tobytes(order="C")
        ),
        "slot_weights_sha256": _sha256_bytes(
            slots32.astype("<f4", copy=False).tobytes(order="C")
        ),
        "temperature_float64_hex": float(np.float32(temperature)).hex(),
        "alpha_float64_hex": float(alpha).hex(),
        "objective_float64_hex": float(best_key[0]).hex(),
        "active_mask": best_mask,
        "training_examples": design.shape[0],
        "training_ledger_sha256": training_ledger_sha256,
        "abstained": best_mask == 0,
    }
    return FittedHorizonReadout(
        horizon_weights=horizon32,
        slot_weights=slots32,
        temperature=temperature,
        alpha=float(alpha),
        objective=best_key[0],
        active_mask=best_mask,
        training_examples=design.shape[0],
        training_ledger_sha256=training_ledger_sha256,
        fit_receipt_sha256=_sha256_bytes(_canonical_json_bytes(receipt_document)),
        abstained=best_mask == 0,
        _factory_token=_FIT_FACTORY_TOKEN,
    )


def freeze_hot_readout_lineage(
    stream: DenseHorizonMajorStream,
    quantizer: FrozenMedianAbsQuantizer,
    state: PolyphaseSufficientState,
    fit: FittedHorizonReadout,
) -> HotReadoutLineage:
    """Verify and freeze one exact stream→state→training lineage receipt."""

    if not isinstance(stream, DenseHorizonMajorStream):
        raise TypeError("stream must be DenseHorizonMajorStream")
    if not isinstance(quantizer, FrozenMedianAbsQuantizer):
        raise TypeError("quantizer must be lightweight FrozenMedianAbsQuantizer")
    if not isinstance(state, PolyphaseSufficientState):
        raise TypeError("state must be PolyphaseSufficientState")
    if not isinstance(fit, FittedHorizonReadout):
        raise TypeError("fit must be FittedHorizonReadout")
    if stream.quantizer_sha256 != quantizer.sha256:
        raise ReplayRequiredError("stream is bound to a different frozen quantizer")
    verified_state = consume_dense_horizon_major_stream(stream)
    if verified_state.to_bytes() != state.to_bytes():
        raise ReplayRequiredError("state does not derive from the supplied dense evidence")
    fitted_slot_weights_sha256 = _sha256_bytes(
        fit.slot_weights.astype("<f4", copy=False).tobytes(order="C")
    )
    fitted_readout_unsigned = {
        "schema": "o1-256-fitted-hot-readout-receipt-v1",
        "basis_sha256": BASIS_SHA256,
        "slot_weights_sha256": fitted_slot_weights_sha256,
        "temperature_float64_hex": fit.temperature.hex(),
        "training_ledger_sha256": fit.training_ledger_sha256,
        "fit_receipt_sha256": fit.fit_receipt_sha256,
    }
    fitted_readout_sha256 = _sha256_bytes(
        _canonical_json_bytes(fitted_readout_unsigned)
    )
    unsigned = {
        "schema": HOT_LINEAGE_SCHEMA,
        "bridge_schema": BRIDGE_SCHEMA,
        "state_basis_sha256": BASIS_SHA256,
        "encoding": stream.encoding,
        "quantizer_sha256": quantizer.sha256,
        "evidence_sha256": stream.evidence_sha256,
        "state_sha256": state.sha256(),
        "training_ledger_sha256": fit.training_ledger_sha256,
        "fit_receipt_sha256": fit.fit_receipt_sha256,
        "fitted_slot_weights_sha256": fitted_slot_weights_sha256,
        "fitted_temperature_float64_hex": fit.temperature.hex(),
        "fitted_readout_sha256": fitted_readout_sha256,
    }
    return HotReadoutLineage(
        encoding=stream.encoding,
        quantizer_sha256=quantizer.sha256,
        evidence_sha256=stream.evidence_sha256,
        state_sha256=state.sha256(),
        training_ledger_sha256=fit.training_ledger_sha256,
        fit_receipt_sha256=fit.fit_receipt_sha256,
        fitted_slot_weights_sha256=fitted_slot_weights_sha256,
        fitted_temperature=fit.temperature,
        fitted_readout_sha256=fitted_readout_sha256,
        lineage_receipt_sha256=_sha256_bytes(_canonical_json_bytes(unsigned)),
        _factory_token=_HOT_LINEAGE_FACTORY_TOKEN,
    )


def read_fitted_horizon_state(
    state: PolyphaseSufficientState,
    fit: FittedHorizonReadout,
    *,
    name: str = "fitted_horizon_readout",
) -> np.ndarray:
    """Query one fitted reader, returning an exact zero prior on abstention."""

    if not isinstance(fit, FittedHorizonReadout):
        raise TypeError("fit must be FittedHorizonReadout")
    if fit.abstained:
        result = np.zeros(KEY_BITS, dtype=np.float32)
        result.setflags(write=False)
        return result
    spec = PolyphaseReadoutSpec(
        name=name,
        basis_sha256=BASIS_SHA256,
        slot_weights=fit.slot_weights,
        temperature=fit.temperature,
    )
    return read_polyphase_state(state, spec)


__all__ = [
    "BRIDGE_SCHEMA",
    "COLD_OPERATOR_IDS",
    "ENCODINGS",
    "ENCODING_NORMALIZED_FLOAT32",
    "ENCODING_QUANTIZED_INT8_FLOAT32",
    "FIT_SCHEMA",
    "GROUP_BYTES",
    "GROUP_SHAPE",
    "HOT_BINDING_SCHEMA",
    "HOT_LINEAGE_SCHEMA",
    "HOT_OPERATOR_IDS",
    "O1C22_HORIZONS",
    "STREAM_SCHEMA",
    "BoundHotReadout",
    "DenseHorizonMajorStream",
    "FittedHorizonReadout",
    "HotReadoutLineage",
    "O1C22PolyphaseBridgeError",
    "bind_o1o_hot_readout",
    "build_dense_horizon_major_stream",
    "consume_dense_horizon_major_stream",
    "decode_packet_delta_extraction",
    "fit_nonnegative_horizon_readout",
    "freeze_hot_readout_lineage",
    "permute_dense_coordinates",
    "read_bound_hot_state",
    "read_fitted_horizon_state",
]
