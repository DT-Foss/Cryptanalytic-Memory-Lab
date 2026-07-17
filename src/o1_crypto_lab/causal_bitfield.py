"""Bounded unary, interaction, and holographic O1 state for full256 probes."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from functools import lru_cache
from typing import Mapping

import numpy as np

from .cadical_sensor import KEY_BITS, MOTIF_DIMENSIONS
from .living_inverse import canonical_sha256


PLAN_SCHEMA = "o1-256-causal-bitfield-plan-v1"
STATE_SCHEMA = "o1-256-causal-bitfield-state-v1"
EVENT_SCHEMA = "o1-256-paired-causal-event-v1"
HORIZON_COUNT = 3
NEIGHBORS_PER_BIT = 8
INTERACTION_COUNT = KEY_BITS * NEIGHBORS_PER_BIT
HOLOGRAPHIC_FAMILIES = 4
HOLOGRAPHIC_CHANNELS = 128


class CausalBitfieldError(ValueError):
    """A bounded-state plan, event, or state transition is invalid."""


def _finite(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CausalBitfieldError(f"{field} must be a finite scalar")
    result = float(value)
    if not math.isfinite(result):
        raise CausalBitfieldError(f"{field} must be a finite scalar")
    return result


def _float_array(
    value: object, field: str, shape: tuple[int, ...]
) -> np.ndarray:
    try:
        result = np.asarray(value, dtype=np.float64)
    except (TypeError, ValueError) as exc:
        raise CausalBitfieldError(f"{field} is not a numeric array") from exc
    if result.shape != shape or not np.all(np.isfinite(result)):
        raise CausalBitfieldError(f"{field} must have shape {shape} and be finite")
    return result


def _neighbor_table() -> np.ndarray:
    table = np.empty((KEY_BITS, NEIGHBORS_PER_BIT), dtype=np.uint16)
    within_word_offsets = (1, -1, 7, 8, 12, 16)
    for bit in range(KEY_BITS):
        word, position = divmod(bit, 32)
        neighbors = [word * 32 + ((position + offset) % 32) for offset in within_word_offsets]
        neighbors.extend(
            (
                ((word + 1) % 8) * 32 + position,
                ((word + 4) % 8) * 32 + position,
            )
        )
        if len(neighbors) != NEIGHBORS_PER_BIT or len(set(neighbors)) != len(
            neighbors
        ):
            raise RuntimeError("fixed ARX neighbor graph contains duplicates")
        table[bit] = neighbors
    table.setflags(write=False)
    return table


ARX_NEIGHBORS = _neighbor_table()


@dataclass(frozen=True)
class CausalBitfieldPlan:
    horizons: tuple[int, int, int] = (64, 96, 65)
    horizon_weights: tuple[float, float, float] = (7.0, 1.0, 4.0)
    unary_clip: float = 1.0
    interaction_clip: float = 32.0
    holographic_clip: float = 32.0
    readout_temperature: float = 4.0
    phase_seed: int = 0x01C0012

    def __post_init__(self) -> None:
        if (
            len(self.horizons) != HORIZON_COUNT
            or len(set(self.horizons)) != HORIZON_COUNT
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 1
                for value in self.horizons
            )
        ):
            raise CausalBitfieldError("plan requires three distinct horizons")
        if len(self.horizon_weights) != HORIZON_COUNT:
            raise CausalBitfieldError("plan requires three horizon weights")
        for index, value in enumerate(self.horizon_weights):
            _finite(value, f"horizon_weights[{index}]")
        for field, value in (
            ("unary_clip", self.unary_clip),
            ("interaction_clip", self.interaction_clip),
            ("holographic_clip", self.holographic_clip),
            ("readout_temperature", self.readout_temperature),
        ):
            if _finite(value, field) <= 0:
                raise CausalBitfieldError(f"{field} must be positive")
        if isinstance(self.phase_seed, bool) or not isinstance(self.phase_seed, int):
            raise CausalBitfieldError("phase_seed must be an integer")

    @property
    def serialized_state_bytes(self) -> int:
        return (
            HORIZON_COUNT * KEY_BITS * 4
            + KEY_BITS * 4
            + INTERACTION_COUNT * 4
            + HOLOGRAPHIC_FAMILIES * HOLOGRAPHIC_CHANNELS * 8
            + KEY_BITS * 2
            + MOTIF_DIMENSIONS * 8
        )

    def _payload(self) -> dict[str, object]:
        return {
            "schema": PLAN_SCHEMA,
            "mechanism": "coordinate-bound-unary-arx-interaction-holographic-proof-state",
            "key_bits": KEY_BITS,
            "horizons": list(self.horizons),
            "horizon_weights": list(self.horizon_weights),
            "unary_clip": self.unary_clip,
            "interaction_clip": self.interaction_clip,
            "holographic_clip": self.holographic_clip,
            "readout_temperature": self.readout_temperature,
            "phase_seed": self.phase_seed,
            "arrays": {
                "unary_float32": [HORIZON_COUNT, KEY_BITS],
                "evidence_mass_float32": [KEY_BITS],
                "directed_arx_interactions_float32": [
                    KEY_BITS,
                    NEIGHBORS_PER_BIT,
                ],
                "holographic_complex64": [
                    HOLOGRAPHIC_FAMILIES,
                    HOLOGRAPHIC_CHANNELS,
                ],
                "probe_counts_uint16": [KEY_BITS],
                "family_stats_float64": [MOTIF_DIMENSIONS],
            },
            "neighbor_rule": {
                "within_word_offsets_mod32": [1, -1, 7, 8, 12, 16],
                "same_bit_words_mod8": [1, 4],
                "directed_edge_count": INTERACTION_COUNT,
                "neighbor_table_uint16le_sha256": hashlib.sha256(
                    ARX_NEIGHBORS.astype("<u2", copy=False).tobytes(order="C")
                ).hexdigest(),
            },
            "holographic_binding": {
                "address": "bit|horizon|motif-dimension|channel|phase-seed",
                "phase_hash": "blake2b-128-base-plus-channel-step",
                "families": HOLOGRAPHIC_FAMILIES,
                "channels_per_family": HOLOGRAPHIC_CHANNELS,
            },
            "serialized_state_bytes": self.serialized_state_bytes,
            "stream_length_dependent_state": False,
            "retained_probe_transcripts": 0,
            "retained_candidate_keys": 0,
        }

    @property
    def plan_sha256(self) -> str:
        return canonical_sha256(self._payload())

    def describe(self) -> dict[str, object]:
        value = self._payload()
        value["plan_sha256"] = self.plan_sha256
        return value


@dataclass(frozen=True)
class PairedCausalEvent:
    bit_index: int
    horizon: int
    unary_score: float
    information_mass: float
    motif_delta: np.ndarray
    key_touch_delta: np.ndarray
    source_pair_sha256: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.bit_index, bool)
            or not isinstance(self.bit_index, int)
            or not 0 <= self.bit_index < KEY_BITS
        ):
            raise CausalBitfieldError("event bit_index is outside the key")
        if (
            isinstance(self.horizon, bool)
            or not isinstance(self.horizon, int)
            or self.horizon < 1
        ):
            raise CausalBitfieldError("event horizon must be positive")
        object.__setattr__(self, "unary_score", _finite(self.unary_score, "unary_score"))
        object.__setattr__(
            self,
            "information_mass",
            _finite(self.information_mass, "information_mass"),
        )
        if self.information_mass < 0:
            raise CausalBitfieldError("information_mass must be non-negative")
        motif = _float_array(
            self.motif_delta, "motif_delta", (MOTIF_DIMENSIONS,)
        )
        key_touch = _float_array(
            self.key_touch_delta, "key_touch_delta", (KEY_BITS,)
        )
        motif.setflags(write=False)
        key_touch.setflags(write=False)
        object.__setattr__(self, "motif_delta", motif)
        object.__setattr__(self, "key_touch_delta", key_touch)
        if (
            not isinstance(self.source_pair_sha256, str)
            or len(self.source_pair_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.source_pair_sha256
            )
        ):
            raise CausalBitfieldError("source_pair_sha256 must be lowercase SHA-256")

    def describe(self) -> dict[str, object]:
        return {
            "schema": EVENT_SCHEMA,
            "bit_index": self.bit_index,
            "horizon": self.horizon,
            "unary_score": self.unary_score,
            "information_mass": self.information_mass,
            "motif_delta_l1": float(np.abs(self.motif_delta).sum()),
            "key_touch_delta_l1": float(np.abs(self.key_touch_delta).sum()),
            "source_pair_sha256": self.source_pair_sha256,
        }


@lru_cache(maxsize=128)
def _phase_vector(
    *, bit: int, horizon: int, dimension: int, seed: int
) -> np.ndarray:
    payload = (
        bit.to_bytes(2, "big")
        + horizon.to_bytes(4, "big")
        + dimension.to_bytes(1, "big")
        + (seed & ((1 << 64) - 1)).to_bytes(8, "big")
    )
    digest = hashlib.blake2b(
        payload, digest_size=16, person=b"o1c12holo"
    ).digest()
    base = np.uint64(int.from_bytes(digest[:8], "big"))
    step = np.uint64(int.from_bytes(digest[8:], "big") | 1)
    raw = base + np.arange(HOLOGRAPHIC_CHANNELS, dtype=np.uint64) * step
    angles = math.tau * raw.astype(np.float64) / float(1 << 64)
    result = np.exp(1j * angles).astype(np.complex64)
    result.setflags(write=False)
    return result


class CausalBitfieldAccumulator:
    """One-pass fixed-size state accumulator over exactly 768 paired events."""

    def __init__(self, plan: CausalBitfieldPlan) -> None:
        if not isinstance(plan, CausalBitfieldPlan):
            raise TypeError("plan must be CausalBitfieldPlan")
        self.plan = plan
        self.unary = np.zeros((HORIZON_COUNT, KEY_BITS), dtype=np.float32)
        self.evidence_mass = np.zeros(KEY_BITS, dtype=np.float32)
        self.interactions = np.zeros(
            (KEY_BITS, NEIGHBORS_PER_BIT), dtype=np.float32
        )
        self.holographic = np.zeros(
            (HOLOGRAPHIC_FAMILIES, HOLOGRAPHIC_CHANNELS),
            dtype=np.complex64,
        )
        self.probe_counts = np.zeros(KEY_BITS, dtype=np.uint16)
        self.family_stats = np.zeros(MOTIF_DIMENSIONS, dtype=np.float64)

    def update(self, event: PairedCausalEvent) -> None:
        count = int(self.probe_counts[event.bit_index])
        if count >= HORIZON_COUNT or event.horizon != self.plan.horizons[count]:
            raise CausalBitfieldError(
                "events must arrive once per bit in the frozen horizon order"
            )
        self.unary[count, event.bit_index] = np.float32(
            np.clip(event.unary_score, -self.plan.unary_clip, self.plan.unary_clip)
        )
        self.evidence_mass[event.bit_index] = np.float32(
            min(
                float(self.evidence_mass[event.bit_index])
                + event.information_mass,
                np.finfo(np.float32).max,
            )
        )
        horizon_weight = float(self.plan.horizon_weights[count])
        for edge, neighbor in enumerate(ARX_NEIGHBORS[event.bit_index]):
            value = (
                float(self.interactions[event.bit_index, edge])
                + horizon_weight * float(event.key_touch_delta[int(neighbor)])
            )
            self.interactions[event.bit_index, edge] = np.float32(
                np.clip(
                    value,
                    -self.plan.interaction_clip,
                    self.plan.interaction_clip,
                )
            )
        scale = 1.0 / math.sqrt(HOLOGRAPHIC_CHANNELS)
        for dimension, raw_amplitude in enumerate(event.motif_delta):
            amplitude = float(np.clip(raw_amplitude, -4.0, 4.0)) * scale
            if not amplitude:
                continue
            family = dimension // (MOTIF_DIMENSIONS // HOLOGRAPHIC_FAMILIES)
            current = self.holographic[family].astype(np.complex128)
            current += amplitude * _phase_vector(
                bit=event.bit_index,
                horizon=event.horizon,
                dimension=dimension,
                seed=self.plan.phase_seed,
            )
            real = np.clip(
                current.real,
                -self.plan.holographic_clip,
                self.plan.holographic_clip,
            )
            imag = np.clip(
                current.imag,
                -self.plan.holographic_clip,
                self.plan.holographic_clip,
            )
            self.holographic[family] = (real + 1j * imag).astype(np.complex64)
        self.family_stats += np.abs(event.motif_delta)
        self.probe_counts[event.bit_index] += 1

    def freeze(self, *, source_stream_sha256: str) -> "FrozenCausalBitfieldState":
        if not np.all(self.probe_counts == HORIZON_COUNT):
            raise CausalBitfieldError("cannot freeze before every bit has three probes")
        return FrozenCausalBitfieldState(
            plan=self.plan,
            unary=self.unary.copy(),
            evidence_mass=self.evidence_mass.copy(),
            interactions=self.interactions.copy(),
            holographic=self.holographic.copy(),
            probe_counts=self.probe_counts.copy(),
            family_stats=self.family_stats.copy(),
            source_stream_sha256=source_stream_sha256,
        )


@dataclass(frozen=True)
class FrozenCausalBitfieldState:
    plan: CausalBitfieldPlan
    unary: np.ndarray
    evidence_mass: np.ndarray
    interactions: np.ndarray
    holographic: np.ndarray
    probe_counts: np.ndarray
    family_stats: np.ndarray
    source_stream_sha256: str

    def __post_init__(self) -> None:
        arrays = (
            ("unary", self.unary, (HORIZON_COUNT, KEY_BITS), np.float32),
            ("evidence_mass", self.evidence_mass, (KEY_BITS,), np.float32),
            (
                "interactions",
                self.interactions,
                (KEY_BITS, NEIGHBORS_PER_BIT),
                np.float32,
            ),
            (
                "holographic",
                self.holographic,
                (HOLOGRAPHIC_FAMILIES, HOLOGRAPHIC_CHANNELS),
                np.complex64,
            ),
            ("probe_counts", self.probe_counts, (KEY_BITS,), np.uint16),
            (
                "family_stats",
                self.family_stats,
                (MOTIF_DIMENSIONS,),
                np.float64,
            ),
        )
        for name, raw, shape, dtype in arrays:
            value = np.asarray(raw)
            if value.shape != shape or value.dtype != dtype:
                raise CausalBitfieldError(
                    f"frozen {name} must have shape {shape} and dtype {dtype}"
                )
            if np.issubdtype(dtype, np.floating) or np.issubdtype(
                dtype, np.complexfloating
            ):
                if not np.all(np.isfinite(value)):
                    raise CausalBitfieldError(f"frozen {name} is not finite")
            value.setflags(write=False)
            object.__setattr__(self, name, value)
        if not np.all(self.probe_counts == HORIZON_COUNT):
            raise CausalBitfieldError("frozen state coverage differs")
        if (
            not isinstance(self.source_stream_sha256, str)
            or len(self.source_stream_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.source_stream_sha256
            )
        ):
            raise CausalBitfieldError("source stream binding is not SHA-256")

    def to_bytes(self) -> bytes:
        payload = b"".join(
            (
                self.unary.astype("<f4", copy=False).tobytes(order="C"),
                self.evidence_mass.astype("<f4", copy=False).tobytes(order="C"),
                self.interactions.astype("<f4", copy=False).tobytes(order="C"),
                self.holographic.astype("<c8", copy=False).tobytes(order="C"),
                self.probe_counts.astype("<u2", copy=False).tobytes(order="C"),
                self.family_stats.astype("<f8", copy=False).tobytes(order="C"),
            )
        )
        if len(payload) != self.plan.serialized_state_bytes:
            raise AssertionError("serialized causal bitfield width differs")
        return payload

    @property
    def state_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    def base_scores(self) -> np.ndarray:
        weights = np.asarray(self.plan.horizon_weights, dtype=np.float64)
        return np.einsum("h,hb->b", weights, self.unary.astype(np.float64))

    def corrected_scores(self) -> np.ndarray:
        """A469-style positive, bucket-local, identity-preserving correction."""

        base = self.base_scores()
        raw = np.zeros(KEY_BITS, dtype=np.float64)
        for bit in range(KEY_BITS):
            raw[bit] = math.fsum(
                float(self.interactions[bit, edge])
                * math.tanh(float(base[int(neighbor)]))
                for edge, neighbor in enumerate(ARX_NEIGHBORS[bit])
            )
        correction = np.sign(base) * np.minimum(
            0.25 * np.abs(base), 0.01 * np.abs(raw)
        )
        return base + correction

    def probabilities(self, *, corrected: bool = True) -> np.ndarray:
        scores = self.corrected_scores() if corrected else self.base_scores()
        logits = np.clip(scores / self.plan.readout_temperature, -30.0, 30.0)
        return 1.0 / (1.0 + np.exp(-logits))

    def describe(self) -> dict[str, object]:
        base = self.base_scores()
        corrected = self.corrected_scores()
        value = {
            "schema": STATE_SCHEMA,
            "plan": self.plan.describe(),
            "source_stream_sha256": self.source_stream_sha256,
            "state_sha256": self.state_sha256,
            "serialized_state_bytes": len(self.to_bytes()),
            "probe_events": int(self.probe_counts.sum()),
            "bits_covered": int(np.count_nonzero(self.probe_counts)),
            "unary_nonzero": int(np.count_nonzero(self.unary)),
            "interaction_nonzero": int(np.count_nonzero(self.interactions)),
            "holographic_nonzero": int(np.count_nonzero(self.holographic)),
            "evidence_mass_sum": float(self.evidence_mass.sum(dtype=np.float64)),
            "family_stats_sum": float(self.family_stats.sum()),
            "base_score_l1": float(np.abs(base).sum()),
            "corrected_score_l1": float(np.abs(corrected).sum()),
            "identity_preserving_sign_changes": int(
                np.count_nonzero(np.signbit(base) != np.signbit(corrected))
            ),
            "retained_probe_transcripts": 0,
            "retained_candidate_keys": 0,
        }
        value["state_metadata_sha256"] = canonical_sha256(value)
        return value


def state_swap_control(
    direct: FrozenCausalBitfieldState,
    swapped: FrozenCausalBitfieldState,
) -> dict[str, object]:
    """Verify exact polarity antisymmetry of signed state components."""

    checks = {
        "unary_negates": bool(np.array_equal(direct.unary, -swapped.unary)),
        "interactions_negate": bool(
            np.array_equal(direct.interactions, -swapped.interactions)
        ),
        "holographic_negates": bool(
            np.array_equal(direct.holographic, -swapped.holographic)
        ),
        "evidence_mass_invariant": bool(
            np.array_equal(direct.evidence_mass, swapped.evidence_mass)
        ),
        "family_stats_invariant": bool(
            np.array_equal(direct.family_stats, swapped.family_stats)
        ),
        "probe_counts_invariant": bool(
            np.array_equal(direct.probe_counts, swapped.probe_counts)
        ),
    }
    return {**checks, "passed": all(checks.values())}


def frozen_state_from_bytes(
    value: bytes,
    *,
    plan: CausalBitfieldPlan,
    source_stream_sha256: str,
) -> FrozenCausalBitfieldState:
    if not isinstance(value, bytes) or len(value) != plan.serialized_state_bytes:
        raise CausalBitfieldError("serialized causal bitfield length differs")
    offset = 0

    def take(count: int, dtype: str, shape: tuple[int, ...]) -> np.ndarray:
        nonlocal offset
        itemsize = np.dtype(dtype).itemsize
        end = offset + count * itemsize
        result = np.frombuffer(value[offset:end], dtype=dtype).reshape(shape).copy()
        offset = end
        return result

    unary = take(HORIZON_COUNT * KEY_BITS, "<f4", (HORIZON_COUNT, KEY_BITS))
    mass = take(KEY_BITS, "<f4", (KEY_BITS,))
    interactions = take(
        INTERACTION_COUNT, "<f4", (KEY_BITS, NEIGHBORS_PER_BIT)
    )
    holographic = take(
        HOLOGRAPHIC_FAMILIES * HOLOGRAPHIC_CHANNELS,
        "<c8",
        (HOLOGRAPHIC_FAMILIES, HOLOGRAPHIC_CHANNELS),
    )
    counts = take(KEY_BITS, "<u2", (KEY_BITS,))
    family = take(MOTIF_DIMENSIONS, "<f8", (MOTIF_DIMENSIONS,))
    if offset != len(value):  # pragma: no cover
        raise AssertionError("causal bitfield parser did not consume payload")
    return FrozenCausalBitfieldState(
        plan=plan,
        unary=unary,
        evidence_mass=mass,
        interactions=interactions,
        holographic=holographic,
        probe_counts=counts,
        family_stats=family,
        source_stream_sha256=source_stream_sha256,
    )


def plan_from_mapping(value: Mapping[str, object]) -> CausalBitfieldPlan:
    expected = {
        "horizons",
        "horizon_weights",
        "unary_clip",
        "interaction_clip",
        "holographic_clip",
        "readout_temperature",
        "phase_seed",
    }
    if set(value) != expected:
        raise CausalBitfieldError("causal bitfield plan fields differ")
    horizons = value["horizons"]
    weights = value["horizon_weights"]
    if not isinstance(horizons, list) or not isinstance(weights, list):
        raise CausalBitfieldError("causal horizons and weights must be arrays")
    return CausalBitfieldPlan(
        horizons=tuple(horizons),  # type: ignore[arg-type]
        horizon_weights=tuple(weights),  # type: ignore[arg-type]
        unary_clip=_finite(value["unary_clip"], "unary_clip"),
        interaction_clip=_finite(
            value["interaction_clip"], "interaction_clip"
        ),
        holographic_clip=_finite(
            value["holographic_clip"], "holographic_clip"
        ),
        readout_temperature=_finite(
            value["readout_temperature"], "readout_temperature"
        ),
        phase_seed=value["phase_seed"],  # type: ignore[arg-type]
    )
