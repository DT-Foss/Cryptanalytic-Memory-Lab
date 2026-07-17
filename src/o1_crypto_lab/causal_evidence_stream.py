"""Bounded O1 accumulation of weak, conflicting evidence for 256 latent bits.

O1C-0021 is the bridge between exact MQAR retention and cipher-native evidence.
The only secret-dependent public field is a noisy signed vote.  A frozen O1
reader carries a public sensor symbol across the next marker into a delayed
temporal operator, learns signed sensor reliability from BUILD outcomes, and writes
quantized evidence into one byte per latent coordinate.  Repeated groups are
suppressed with a fixed-width equality state.

The formal 256-bit layout is exactly 352 bytes:

* 80 bytes: one-head, four-channel, two-slot O1 fast state;
* 256 bytes: symmetric signed int8 evidence vault;
* 16 bytes: last public group identifier and accepted-update counter.

No transcript, candidate table, deduplication set, or stream-length-dependent
model state is retained.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
from copy import deepcopy
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Iterator, Mapping, Sequence

import numpy as np

from .o1_streaming_core import (
    O1FastState,
    O1StreamingCoreConfig,
    StreamingSelectiveHolographicCore,
    require_torch,
    torch,
)
from .selective_mqar import canonical_module_bytes


CAUSAL_EVIDENCE_SCHEMA = "o1-256-causal-evidence-stream-v1"
LEARNING_FREEZE_SCHEMA = "o1-256-causal-evidence-learning-freeze-v1"
PREDICTION_FREEZE_SCHEMA = "o1-256-causal-evidence-prediction-freeze-v1"
TRUTH_REVEAL_SCHEMA = "o1-256-causal-evidence-truth-reveal-v1"
RESULT_SCHEMA = "o1-256-causal-evidence-result-v1"
PREDICTION_INDEX_SCHEMA = "o1-256-causal-evidence-prediction-index-v1"
TRUTH_INDEX_SCHEMA = "o1-256-causal-evidence-truth-index-v1"

PRIMARY_ARM = "learned_recurrent"
PUBLIC_FSM_ARM = "outcome_table_public_fsm"
CONTROL_ARMS = (
    "zero_prior_baseline",
    "same_route_last",
    "same_route_unit_sum",
    "same_encoder_static_sum",
    "same_encoder_current_marker_sum",
    "shuffled_confidence",
    "all_open",
)
DIAGNOSTIC_ARMS = (PUBLIC_FSM_ARM,)
ORACLE_ARM = "oracle_grouped_bayes"
ALL_ARMS = (PRIMARY_ARM,) + CONTROL_ARMS + DIAGNOSTIC_ARMS + (ORACLE_ARM,)

_MASK64 = (1 << 64) - 1
_INITIAL_GROUP_ID = _MASK64
_LN2 = math.log(2.0)
_EPS32_TOLERANCE = 64.0 * float(np.finfo(np.float32).eps)
_NLL_TOLERANCE_BITS = 0.01
_DUPLICATE_NLL_TOLERANCE_BITS = 0.5
_DUPLICATE_PROBABILITY_TOLERANCE = 1.0 / 256.0
_MATERIAL_BITS = 8.0
_FINAL_NLL_MAX = 32.0
_ECE_MAX = 0.05
_BACKSLIDE_MAX_BITS = 1.0
_BUILD_OUTCOME_REPETITIONS = 16
_BUILD_STREAM_GROUPS = 32
_COEFFICIENT_TRAINING_LOGIT_SCALE = 0.5
_TEMPORAL_OPERATOR = "one-step-delayed-public-marker-v1"

# Event layout.  Evidence events deliberately omit the effective regime.  Each
# marker exposes only one public symbol; the preceding symbol is available only
# through temporal state (or an explicit public-FSM ceiling).
_MARKER = 0
_EVIDENCE = 1
_NUISANCE = 2
_NOVELTY = 3
_FAMILY = 4
_QUALITY = 12
_REGIME = 14
_NOISE = 18
_EVENT_DIMENSION = 21


class CausalEvidenceError(ValueError):
    """A protocol, state, lifecycle boundary, or scientific invariant differs."""


class EvidenceTruthAccessError(RuntimeError):
    """An evaluation truth ledger was touched before its reveal boundary."""


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            allow_nan=False,
            ensure_ascii=True,
        )
        + "\n"
    ).encode("ascii")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _positive_int(value: object, field: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise CausalEvidenceError(f"{field} must be an integer in [1,{maximum}]")
    return value


def _finite_float(
    value: object,
    field: str,
    *,
    minimum: float,
    maximum: float,
    inclusive_minimum: bool = False,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CausalEvidenceError(f"{field} must be numeric")
    result = float(value)
    lower = result >= minimum if inclusive_minimum else result > minimum
    if not math.isfinite(result) or not lower or result > maximum:
        bracket = "[" if inclusive_minimum else "("
        raise CausalEvidenceError(
            f"{field} must be finite in {bracket}{minimum},{maximum}]"
        )
    return result


def _integer_tuple(value: object, field: str) -> tuple[int, ...]:
    if (
        not isinstance(value, (list, tuple))
        or not value
        or any(isinstance(item, bool) or not isinstance(item, int) for item in value)
    ):
        raise CausalEvidenceError(f"{field} must be a non-empty integer sequence")
    result = tuple(int(item) for item in value)
    if len(set(result)) != len(result):
        raise CausalEvidenceError(f"{field} contains duplicates")
    return result


def _float_tuple(value: object, field: str) -> tuple[float, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise CausalEvidenceError(f"{field} must be a non-empty numeric sequence")
    return tuple(
        _finite_float(item, f"{field}[{index}]", minimum=0.0, maximum=1.0)
        for index, item in enumerate(value)
    )


def _splitmix64(values: np.ndarray, salt: int) -> np.ndarray:
    source = np.asarray(values, dtype=np.uint64)
    with np.errstate(over="ignore"):
        mixed = source + np.uint64(salt & _MASK64) + np.uint64(0x9E3779B97F4A7C15)
        mixed = (mixed ^ (mixed >> np.uint64(30))) * np.uint64(0xBF58476D1CE4E5B9)
        mixed = (mixed ^ (mixed >> np.uint64(27))) * np.uint64(0x94D049BB133111EB)
        return mixed ^ (mixed >> np.uint64(31))


def _compose_public_regime(previous_symbol: int, current_symbol: int) -> int:
    """Bind an evidence group to the preceding public marker symbol."""

    for value in (previous_symbol, current_symbol):
        if (
            isinstance(value, (bool, np.bool_))
            or not isinstance(value, (int, np.integer))
            or not 0 <= int(value) < 4
        ):
            raise CausalEvidenceError("public marker symbol is outside [0,3]")
    return int(previous_symbol)


def _public_marker_symbol(seed: int, group_index: int) -> int:
    """Return a deterministic public symbol independent of target material."""

    if group_index < 0:
        return 0
    mixed = _splitmix64(
        np.asarray([group_index], dtype=np.uint64), int(seed) ^ 0x51A7B01
    )[0]
    return int(mixed % np.uint64(4))


def _permutation(length: int, seed: int) -> np.ndarray:
    indices = np.arange(length, dtype=np.uint64)
    keys = _splitmix64(indices, seed)
    return np.lexsort((indices, keys)).astype(np.int64, copy=False)


def _pack_bool(values: np.ndarray) -> bytes:
    return np.packbits(np.asarray(values, dtype=np.bool_), bitorder="little").tobytes()


@dataclass(frozen=True)
class CausalEvidenceConfig:
    n_bits: int
    regime_count: int
    family_count: int
    quality_reliabilities: tuple[float, ...]
    coefficient_magnitudes: tuple[int, ...]
    orientation_matrix: tuple[tuple[int, ...], ...]
    event_dimension: int
    address_dimension: int
    model_dimension: int
    heads: int
    head_dimension: int
    holographic_slots: int
    feedforward_dimension: int
    phase_scale: float
    core_seed: int
    build_seeds: tuple[int, ...]
    calibration_seeds: tuple[int, ...]
    development_seeds: tuple[int, ...]
    evaluation_seeds: tuple[int, ...]
    independent_group_prefixes: tuple[int, ...]
    repeat_factors: tuple[int, ...]
    independent_comparison_groups: int
    independent_comparison_repeat_factor: int
    training_steps: int
    training_batch_size: int
    learning_rate: float
    temperature_grid_max: float
    temperature_grid_steps: int
    shuffled_label_seed: int
    cpu_threads: int

    def __post_init__(self) -> None:
        _positive_int(self.n_bits, "n_bits", 4096)
        _positive_int(self.regime_count, "regime_count", 16)
        _positive_int(self.family_count, "family_count", 32)
        if self.n_bits % self.family_count:
            raise CausalEvidenceError("n_bits must be divisible by family_count")
        if self.regime_count != 4 or self.family_count != 8:
            raise CausalEvidenceError("O1C-0021 requires four regimes and eight families")
        if len(self.quality_reliabilities) != len(self.coefficient_magnitudes):
            raise CausalEvidenceError("quality reliability/magnitude counts differ")
        if len(self.quality_reliabilities) != 2:
            raise CausalEvidenceError("O1C-0021 requires exactly two quality levels")
        for index, reliability in enumerate(self.quality_reliabilities):
            if not 0.5 < reliability < 1.0:
                raise CausalEvidenceError(
                    f"quality_reliabilities[{index}] must be in (0.5,1)"
                )
        if any(
            isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 8
            for value in self.coefficient_magnitudes
        ):
            raise CausalEvidenceError("coefficient magnitudes must be integers in [1,8]")
        derived_magnitudes = tuple(
            max(
                1,
                min(
                    8,
                    int(
                        round(
                            math.log(reliability / (1.0 - reliability))
                            / _COEFFICIENT_TRAINING_LOGIT_SCALE
                        )
                    ),
                ),
            )
            for reliability in self.quality_reliabilities
        )
        if self.coefficient_magnitudes != derived_magnitudes:
            raise CausalEvidenceError(
                "coefficient magnitudes must equal rounded outcome-logit magnitudes"
            )
        raw_orientation = tuple(item for row in self.orientation_matrix for item in row)
        if any(
            isinstance(item, bool) or not isinstance(item, int) or item not in (-1, 1)
            for item in raw_orientation
        ):
            raise CausalEvidenceError("orientation entries must be exact integers +/-1")
        try:
            matrix = np.asarray(self.orientation_matrix, dtype=np.int8)
        except ValueError as exc:
            raise CausalEvidenceError("orientation_matrix rows differ") from exc
        if (
            matrix.shape != (self.regime_count, self.family_count)
            or not bool(np.isin(matrix, (-1, 1)).all())
            or not bool((matrix.sum(axis=0) == 0).all())
            or not bool((matrix.sum(axis=1) == 0).all())
        ):
            raise CausalEvidenceError(
                "orientation_matrix must be balanced +/-1 by every row and column"
            )
        if self.event_dimension != _EVENT_DIMENSION:
            raise CausalEvidenceError(f"event_dimension must equal {_EVENT_DIMENSION}")
        if self.address_dimension < 2 or self.address_dimension % 2:
            raise CausalEvidenceError("address_dimension must be positive and even")
        if (self.heads, self.head_dimension, self.holographic_slots) != (1, 4, 2):
            raise CausalEvidenceError(
                "O1C-0021 requires the exact one-head/four-channel/two-slot core"
            )
        core = self.core_config
        if core.fast_state_bytes() != 80:
            raise CausalEvidenceError("O1 fast state must be exactly 80 bytes")
        splits = (
            set(self.build_seeds),
            set(self.calibration_seeds),
            set(self.development_seeds),
            set(self.evaluation_seeds),
        )
        if any(not split for split in splits) or any(
            left & right
            for index, left in enumerate(splits)
            for right in splits[index + 1 :]
        ):
            raise CausalEvidenceError(
                "BUILD/CAL/DEV/EVAL seeds must be non-empty and disjoint"
            )
        prefixes = self.independent_group_prefixes
        if (
            tuple(sorted(set(prefixes))) != prefixes
            or prefixes[0] != 1
            or len(prefixes) < 2
            or prefixes[-1] > 4096
        ):
            raise CausalEvidenceError(
                "independent_group_prefixes must be strictly increasing from one"
            )
        repeats = self.repeat_factors
        if tuple(sorted(set(repeats))) != repeats or repeats[0] != 1:
            raise CausalEvidenceError("repeat_factors must be sorted unique from one")
        if (
            self.independent_comparison_groups not in prefixes
            or self.independent_comparison_repeat_factor not in repeats
            or self.independent_comparison_groups
            * self.independent_comparison_repeat_factor
            != prefixes[-1]
        ):
            raise CausalEvidenceError(
                "independent replacement must match the longest slot count exactly"
            )
        for field, maximum in (
            ("training_steps", 100_000),
            ("training_batch_size", 1 << 18),
            ("temperature_grid_steps", 100_001),
            ("cpu_threads", 64),
        ):
            _positive_int(getattr(self, field), field, maximum)
        if self.cpu_threads != 1:
            raise CausalEvidenceError("O1C-0021 is frozen to one CPU thread")
        _finite_float(self.learning_rate, "learning_rate", minimum=0.0, maximum=10.0)
        _finite_float(
            self.temperature_grid_max,
            "temperature_grid_max",
            minimum=0.0,
            maximum=100.0,
        )
        for field in ("core_seed", "shuffled_label_seed"):
            if isinstance(getattr(self, field), bool) or not isinstance(
                getattr(self, field), int
            ):
                raise CausalEvidenceError(f"{field} must be an integer")

    @classmethod
    def from_mapping(cls, value: object) -> "CausalEvidenceConfig":
        if not isinstance(value, Mapping) or set(value) != set(cls.__dataclass_fields__):
            raise CausalEvidenceError("experiment fields differ")
        row = dict(value)
        for field in (
            "build_seeds",
            "calibration_seeds",
            "development_seeds",
            "evaluation_seeds",
        ):
            row[field] = _integer_tuple(row[field], field)
        for field in ("independent_group_prefixes", "repeat_factors"):
            row[field] = _integer_tuple(row[field], field)
        row["quality_reliabilities"] = _float_tuple(
            row["quality_reliabilities"], "quality_reliabilities"
        )
        magnitudes = row["coefficient_magnitudes"]
        if not isinstance(magnitudes, (list, tuple)):
            raise CausalEvidenceError("coefficient_magnitudes must be a sequence")
        row["coefficient_magnitudes"] = tuple(magnitudes)
        matrix = row["orientation_matrix"]
        if not isinstance(matrix, (list, tuple)) or any(
            not isinstance(item, (list, tuple)) for item in matrix
        ):
            raise CausalEvidenceError("orientation_matrix must be a matrix")
        row["orientation_matrix"] = tuple(tuple(item) for item in matrix)
        return cls(**row)

    @property
    def core_config(self) -> O1StreamingCoreConfig:
        return O1StreamingCoreConfig(
            event_dimension=self.event_dimension,
            address_dimension=self.address_dimension,
            model_dimension=self.model_dimension,
            heads=self.heads,
            head_dimension=self.head_dimension,
            holographic_slots=self.holographic_slots,
            feedforward_dimension=self.feedforward_dimension,
            phase_scale=self.phase_scale,
            seed=self.core_seed,
        )

    @property
    def live_state_bytes(self) -> int:
        return self.core_config.fast_state_bytes() + self.n_bits + 16

    @property
    def maximum_groups(self) -> int:
        return self.independent_group_prefixes[-1]

    @property
    def tokens_per_slot(self) -> int:
        return 1 + 2 * self.n_bits

    @property
    def planned_public_tokens(self) -> int:
        variant_slot_factor = sum(self.repeat_factors) + 3
        return (
            len(self.evaluation_seeds)
            * self.maximum_groups
            * self.tokens_per_slot
            * variant_slot_factor
        )

    @property
    def planned_reader_token_evaluations(self) -> int:
        # Logical gate work over every public token plus four coefficient readers
        # on every unique evidence token (recurrent, shuffled, reset, current-only).
        unique_variants = len(self.repeat_factors) + 3
        coefficient = (
            len(self.evaluation_seeds)
            * self.maximum_groups
            * self.n_bits
            * unique_variants
            * 4
        )
        marker_core_updates = (
            len(self.evaluation_seeds)
            * self.maximum_groups
            * unique_variants
            * 3
        )
        return self.planned_public_tokens + coefficient + marker_core_updates

    @property
    def planned_training_token_exposures(self) -> int:
        tokens_per_sequence = 2 * _BUILD_STREAM_GROUPS
        return (
            2
            * self.training_steps
            * self.training_batch_size
            * (tokens_per_sequence + 1)
        )

    @property
    def planned_public_fsm_build_outcome_lookups(self) -> int:
        sequences_per_reader = (
            len(self.build_seeds)
            * self.family_count
            * len(self.quality_reliabilities)
            * _BUILD_OUTCOME_REPETITIONS
            * 2
        )
        return 2 * sequences_per_reader * _BUILD_STREAM_GROUPS

    @property
    def planned_arm_token_updates(self) -> int:
        return self.planned_public_tokens * len(ALL_ARMS)

    @property
    def planned_calibration_public_tokens(self) -> int:
        return (
            2
            * len(self.calibration_seeds)
            * self.maximum_groups
            * self.tokens_per_slot
        )

    @property
    def planned_calibration_reader_token_evaluations(self) -> int:
        coefficient = (
            2
            * len(self.calibration_seeds)
            * self.maximum_groups
            * self.n_bits
            * 4
        )
        marker_core_updates = (
            2 * len(self.calibration_seeds) * self.maximum_groups * 3
        )
        return (
            self.planned_calibration_public_tokens
            + coefficient
            + marker_core_updates
        )

    @property
    def planned_public_fsm_calibration_table_lookups(self) -> int:
        return (
            2
            * len(self.calibration_seeds)
            * self.maximum_groups
            * self.n_bits
        )

    @property
    def planned_public_fsm_evaluation_table_lookups(self) -> int:
        variants = len(self.repeat_factors) + 3
        return (
            len(self.evaluation_seeds)
            * variants
            * self.maximum_groups
            * self.n_bits
        )

    @property
    def prediction_value_count(self) -> int:
        records_per_seed = (len(self.repeat_factors) + 3) * len(ALL_ARMS)
        return (
            len(self.evaluation_seeds)
            * records_per_seed
            * len(self.independent_group_prefixes)
            * self.n_bits
        )

    def describe(self) -> dict[str, object]:
        return {
            "schema": CAUSAL_EVIDENCE_SCHEMA,
            "n_bits": self.n_bits,
            "core": self.core_config.describe(),
            "live_state_bytes": self.live_state_bytes,
            "independent_group_prefixes": list(self.independent_group_prefixes),
            "repeat_factors": list(self.repeat_factors),
            "temporal_public_operator": _TEMPORAL_OPERATOR,
            "stream_length_dependent_model_state": False,
            "external_index_bytes": 0,
        }


@dataclass
class CausalEvidenceState:
    core_state: O1FastState
    evidence: np.ndarray
    last_group_id: int = _INITIAL_GROUP_ID
    accepted_updates: int = 0

    @classmethod
    def initial(
        cls, config: CausalEvidenceConfig, core: StreamingSelectiveHolographicCore
    ) -> "CausalEvidenceState":
        return cls(
            core_state=core.initial_state(1, device="cpu"),
            evidence=np.zeros(config.n_bits, dtype=np.int8),
        )

    def validate(self, config: CausalEvidenceConfig) -> None:
        self.core_state.validate(config.core_config)
        if self.core_state.batch_size != 1:
            raise CausalEvidenceError("causal evidence state batch must equal one")
        if self.evidence.shape != (config.n_bits,) or self.evidence.dtype != np.int8:
            raise CausalEvidenceError("evidence vault must be int8[n_bits]")
        if bool((self.evidence == np.int8(-128)).any()):
            raise CausalEvidenceError("evidence vault forbids asymmetric int8 value -128")
        for field, value in (
            ("last_group_id", self.last_group_id),
            ("accepted_updates", self.accepted_updates),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MASK64:
                raise CausalEvidenceError(f"{field} must be uint64-compatible")

    def to_bytes(self, config: CausalEvidenceConfig) -> bytes:
        self.validate(config)
        payload = b"".join(
            (
                self.core_state.to_bytes(config.core_config),
                self.evidence.tobytes(order="C"),
                struct.pack("<QQ", self.last_group_id, self.accepted_updates),
            )
        )
        if len(payload) != config.live_state_bytes:
            raise AssertionError("serialized causal evidence state width differs")
        return payload

    def sha256(self, config: CausalEvidenceConfig) -> str:
        return _sha256(self.to_bytes(config))

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        config: CausalEvidenceConfig,
    ) -> "CausalEvidenceState":
        if not isinstance(payload, bytes) or len(payload) != config.live_state_bytes:
            raise CausalEvidenceError("serialized causal evidence state length differs")
        core_bytes = config.core_config.fast_state_bytes()
        core_state = O1FastState.from_bytes(
            payload[:core_bytes],
            config=config.core_config,
            batch_size=1,
            device="cpu",
        )
        evidence = np.frombuffer(
            payload[core_bytes : core_bytes + config.n_bits], dtype=np.int8
        ).copy()
        last_group_id, accepted_updates = struct.unpack(
            "<QQ", payload[core_bytes + config.n_bits :]
        )
        result = cls(core_state, evidence, last_group_id, accepted_updates)
        result.validate(config)
        return result

    def add(self, coordinate: int, signed_delta: int) -> None:
        if not 0 <= coordinate < self.evidence.size:
            raise CausalEvidenceError("evidence coordinate is outside the vault")
        if isinstance(signed_delta, bool) or not isinstance(signed_delta, (int, np.integer)):
            raise CausalEvidenceError("signed_delta must be integral")
        if self.accepted_updates == _MASK64:
            raise CausalEvidenceError("accepted update counter overflow")
        value = int(self.evidence[coordinate]) + int(signed_delta)
        self.evidence[coordinate] = np.int8(max(-127, min(127, value)))
        self.accepted_updates += 1


@dataclass
class OutcomePublicFSMState:
    evidence: np.ndarray
    previous_symbol: int = 0
    last_group_id: int = _INITIAL_GROUP_ID
    accepted_updates: int = 0

    @classmethod
    def initial(cls, config: CausalEvidenceConfig) -> "OutcomePublicFSMState":
        return cls(evidence=np.zeros(config.n_bits, dtype=np.int8))

    @property
    def serialized_bytes(self) -> int:
        return int(self.evidence.nbytes) + 17

    def validate(self, config: CausalEvidenceConfig) -> None:
        if self.evidence.shape != (config.n_bits,) or self.evidence.dtype != np.int8:
            raise CausalEvidenceError("public FSM evidence vault must be int8[n_bits]")
        if bool((self.evidence == np.int8(-128)).any()):
            raise CausalEvidenceError("public FSM evidence vault forbids -128")
        if (
            isinstance(self.previous_symbol, bool)
            or not isinstance(self.previous_symbol, int)
            or not 0 <= self.previous_symbol < config.regime_count
        ):
            raise CausalEvidenceError("public FSM previous symbol differs")
        for field, value in (
            ("last_group_id", self.last_group_id),
            ("accepted_updates", self.accepted_updates),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value <= _MASK64
            ):
                raise CausalEvidenceError(f"public FSM {field} differs")

    def to_bytes(self, config: CausalEvidenceConfig) -> bytes:
        self.validate(config)
        payload = b"".join(
            (
                self.evidence.tobytes(order="C"),
                struct.pack(
                    "<BQQ",
                    self.previous_symbol,
                    self.last_group_id,
                    self.accepted_updates,
                ),
            )
        )
        if len(payload) != config.n_bits + 17:
            raise AssertionError("public FSM serialized state width differs")
        return payload

    def sha256(self, config: CausalEvidenceConfig) -> str:
        return _sha256(self.to_bytes(config))

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        config: CausalEvidenceConfig,
    ) -> "OutcomePublicFSMState":
        if not isinstance(payload, bytes) or len(payload) != config.n_bits + 17:
            raise CausalEvidenceError("serialized public FSM state length differs")
        evidence = np.frombuffer(payload[: config.n_bits], dtype=np.int8).copy()
        previous_symbol, last_group_id, accepted_updates = struct.unpack(
            "<BQQ", payload[config.n_bits :]
        )
        result = cls(evidence, previous_symbol, last_group_id, accepted_updates)
        result.validate(config)
        return result

    def add(self, coordinate: int, signed_delta: int) -> None:
        if not 0 <= coordinate < self.evidence.size:
            raise CausalEvidenceError("public FSM coordinate is outside the vault")
        if (
            isinstance(signed_delta, bool)
            or not isinstance(signed_delta, (int, np.integer))
        ):
            raise CausalEvidenceError("public FSM signed delta must be integral")
        if self.accepted_updates == _MASK64:
            raise CausalEvidenceError("public FSM update counter overflow")
        value = int(self.evidence[coordinate]) + int(signed_delta)
        self.evidence[coordinate] = np.int8(max(-127, min(127, value)))
        self.accepted_updates += 1


@dataclass(frozen=True)
class RevealedEvidenceTruth:
    bits: np.ndarray


class SealedEvidenceTruthLedger:
    def __init__(self, bits: np.ndarray) -> None:
        array = np.asarray(bits, dtype=np.uint8)
        if array.ndim != 1 or not bool(np.isin(array, (0, 1)).all()):
            raise CausalEvidenceError("truth ledger bits differ")
        self.__bits = array.copy()
        self.__reveal_count = 0

    @property
    def reveal_count(self) -> int:
        return self.__reveal_count

    def reveal(self) -> RevealedEvidenceTruth:
        self.__reveal_count += 1
        if self.__reveal_count != 1:
            raise EvidenceTruthAccessError("truth ledger may be revealed exactly once")
        return RevealedEvidenceTruth(self.__bits.copy())

    def __getitem__(self, _key: object) -> object:
        raise EvidenceTruthAccessError("sealed truth ledger is not indexable")

    def __iter__(self) -> Iterator[object]:
        raise EvidenceTruthAccessError("sealed truth ledger is not iterable")

    def __array__(self, *_args: object, **_kwargs: object) -> np.ndarray:
        raise EvidenceTruthAccessError("sealed truth ledger is not array-convertible")


@dataclass(frozen=True)
class PublicEvidenceGroup:
    group_index: int
    group_id: int
    coordinates: np.ndarray
    families: np.ndarray
    qualities: np.ndarray
    evidence_votes: np.ndarray
    nuisance_votes: np.ndarray
    evidence_events: np.ndarray
    nuisance_events: np.ndarray
    evidence_addresses: np.ndarray
    nuisance_addresses: np.ndarray
    marker_event: np.ndarray
    marker_address: np.ndarray

    def __post_init__(self) -> None:
        if (
            isinstance(self.group_index, bool)
            or not isinstance(self.group_index, int)
            or self.group_index < 0
        ):
            raise CausalEvidenceError("group_index must be a nonnegative integer")
        if (
            isinstance(self.group_id, bool)
            or not isinstance(self.group_id, int)
            or not 0 <= self.group_id < _INITIAL_GROUP_ID
        ):
            raise CausalEvidenceError(
                "group_id must be uint64-compatible and may not equal the sentinel"
            )
        width = int(self.coordinates.size)
        if (
            self.coordinates.shape != (width,)
            or self.families.shape != (width,)
            or self.qualities.shape != (width,)
            or self.evidence_votes.shape != (width,)
            or self.nuisance_votes.shape != (width,)
            or self.evidence_events.shape != (width, _EVENT_DIMENSION)
            or self.nuisance_events.shape != (width, _EVENT_DIMENSION)
            or self.evidence_addresses.ndim != 2
            or self.evidence_addresses.shape[0] != width
            or self.nuisance_addresses.shape != self.evidence_addresses.shape
            or self.marker_event.shape != (_EVENT_DIMENSION,)
            or self.marker_address.shape != (self.evidence_addresses.shape[1],)
        ):
            raise CausalEvidenceError("public evidence group fields differ")
        arrays = {
            "coordinates": (self.coordinates, np.integer),
            "families": (self.families, np.integer),
            "qualities": (self.qualities, np.integer),
            "evidence_votes": (self.evidence_votes, np.integer),
            "nuisance_votes": (self.nuisance_votes, np.integer),
            "evidence_events": (self.evidence_events, np.floating),
            "nuisance_events": (self.nuisance_events, np.floating),
            "evidence_addresses": (self.evidence_addresses, np.floating),
            "nuisance_addresses": (self.nuisance_addresses, np.floating),
            "marker_event": (self.marker_event, np.floating),
            "marker_address": (self.marker_address, np.floating),
        }
        for name, (value, kind) in arrays.items():
            if not np.issubdtype(value.dtype, kind):
                raise CausalEvidenceError(f"public group {name} dtype differs")
            copied = np.ascontiguousarray(value).copy()
            if np.issubdtype(copied.dtype, np.floating) and not bool(
                np.isfinite(copied).all()
            ):
                raise CausalEvidenceError(f"public group {name} is non-finite")
            copied.setflags(write=False)
            object.__setattr__(self, name, copied)
        if (
            bool((self.coordinates < 0).any())
            or bool((self.coordinates >= width).any())
            or len(np.unique(self.coordinates)) != width
            or bool((self.families < 0).any())
            or bool((self.families >= 8).any())
            or bool((self.qualities < 0).any())
            or bool((self.qualities >= 2).any())
            or not bool(np.isin(self.evidence_votes, (-1, 1)).all())
            or not bool(np.isin(self.nuisance_votes, (-1, 1)).all())
        ):
            raise CausalEvidenceError("public group semantic ranges differ")
        evidence_kind = self.evidence_events[:, :3]
        nuisance_kind = self.nuisance_events[:, :3]
        marker_kind = self.marker_event[:3]
        if (
            not bool((evidence_kind[:, _EVIDENCE] == 1.0).all())
            or bool(np.delete(evidence_kind, _EVIDENCE, axis=1).any())
            or not bool((nuisance_kind[:, _NUISANCE] == 1.0).all())
            or bool(np.delete(nuisance_kind, _NUISANCE, axis=1).any())
            or marker_kind[_MARKER] != 1.0
            or bool(np.delete(marker_kind, _MARKER).any())
        ):
            raise CausalEvidenceError("public group token-kind encoding differs")
        expected_family = np.zeros((width, 8), dtype=np.float32)
        expected_family[np.arange(width), self.families] = 1.0
        expected_quality = np.zeros((width, 2), dtype=np.float32)
        expected_quality[np.arange(width), self.qualities] = 1.0
        if (
            not np.array_equal(
                self.evidence_events[:, _FAMILY : _FAMILY + 8], expected_family
            )
            or not np.array_equal(
                self.nuisance_events[:, _FAMILY : _FAMILY + 8], expected_family
            )
            or not np.array_equal(
                self.evidence_events[:, _QUALITY : _QUALITY + 2], expected_quality
            )
            or not np.array_equal(
                self.nuisance_events[:, _QUALITY : _QUALITY + 2], expected_quality
            )
        ):
            raise CausalEvidenceError("public family/quality event binding differs")
        if (
            bool(self.evidence_events[:, _REGIME : _REGIME + 4].any())
            or bool(self.nuisance_events[:, _REGIME : _REGIME + 4].any())
            or bool(self.marker_event[_FAMILY : _REGIME].any())
            or int(
                np.count_nonzero(self.marker_event[_REGIME : _REGIME + 4] == 1.0)
            )
            != 1
            or float(self.marker_event[_REGIME : _REGIME + 4].sum()) != 1.0
        ):
            raise CausalEvidenceError("public regime event binding differs")


def _operator_address(
    token_kind: int,
    selector: np.ndarray,
    dimension: int,
) -> np.ndarray:
    values = np.asarray(selector, dtype=np.float64).reshape(-1)
    harmonics = np.arange(1, dimension // 2 + 1, dtype=np.float64)
    phase = (values[:, None] + 1.0 + 17.0 * token_kind) * harmonics[None, :] * 0.173
    result = np.empty((values.size, dimension), dtype=np.float32)
    result[:, 0::2] = np.sin(phase).astype(np.float32)
    result[:, 1::2] = np.cos(phase).astype(np.float32)
    return result


def _event_block(
    *,
    kind: int,
    novelty: bool,
    families: np.ndarray,
    qualities: np.ndarray,
    regimes: np.ndarray,
    noise_seed: int,
) -> np.ndarray:
    count = int(np.asarray(families).size)
    events = np.zeros((count, _EVENT_DIMENSION), dtype=np.float32)
    events[:, kind] = 1.0
    events[:, _NOVELTY] = 1.0 if novelty else -1.0
    family = np.asarray(families, dtype=np.int64)
    quality = np.asarray(qualities, dtype=np.int64)
    regime = np.asarray(regimes, dtype=np.int64)
    valid_family = family >= 0
    valid_quality = quality >= 0
    valid_regime = regime >= 0
    events[np.flatnonzero(valid_family), _FAMILY + family[valid_family]] = 1.0
    events[np.flatnonzero(valid_quality), _QUALITY + quality[valid_quality]] = 1.0
    events[np.flatnonzero(valid_regime), _REGIME + regime[valid_regime]] = 1.0
    local = np.arange(count, dtype=np.uint64)
    for index in range(3):
        mixed = _splitmix64(local, noise_seed ^ (0x9E37 * (index + 1)))
        events[:, _NOISE + index] = np.where(
            (mixed & np.uint64(1)) == 0, 0.25, -0.25
        ).astype(np.float32)
    return events


class PublicEvidenceEpisode:
    """Secret-independent metadata plus one allowed noisy-vote truth path."""

    def __init__(
        self,
        config: CausalEvidenceConfig,
        seed: int,
        *,
        complement: bool = False,
        id_permutation_salt: int = 0,
        coordinate_permutation_salt: int = 0,
        secret_material: bytes | None = None,
    ) -> None:
        self.config = config
        self.__metadata_seed = int(seed)
        self.__complement = bool(complement)
        self.__id_permutation_salt = int(id_permutation_salt)
        self.__coordinate_permutation_salt = int(coordinate_permutation_salt)
        if secret_material is None:
            # Deterministic material is for BUILD/CAL/DEV only.  The formal runner
            # supplies opaque post-learning-freeze material for every EVAL seed.
            secret_material = hashlib.sha256(
                struct.pack("<q", int(seed)) + b"o1c0021-nonformal-secret"
            ).digest()
        if not isinstance(secret_material, bytes) or len(secret_material) < 32:
            raise CausalEvidenceError("secret_material must contain at least 256 bits")
        self.__secret_material = bytes(secret_material)
        truth_width = (config.n_bits + 7) // 8
        truth_bytes = hashlib.shake_256(
            self.__secret_material + b"truth"
        ).digest(truth_width)
        bits = np.unpackbits(
            np.frombuffer(truth_bytes, dtype=np.uint8), bitorder="little"
        )[: config.n_bits].astype(np.uint8, copy=True)
        if complement:
            bits = np.uint8(1) - bits
        if coordinate_permutation_salt:
            mapping = _permutation(
                config.n_bits,
                self.__metadata_seed
                ^ coordinate_permutation_salt
                ^ 0xC00FD1A7,
            )
        else:
            mapping = np.arange(config.n_bits, dtype=np.int64)
        public_bits = np.empty_like(bits)
        public_bits[mapping] = bits
        self._logical_to_public = mapping
        self.__logical_bits = bits
        self.__ledger = SealedEvidenceTruthLedger(public_bits)
        group_indices = np.arange(config.maximum_groups, dtype=np.uint64)
        ids = _splitmix64(
            group_indices,
            self.__metadata_seed ^ self.__id_permutation_salt ^ 0x6A0A91D,
        )
        if bool((ids == np.uint64(_INITIAL_GROUP_ID)).any()) or len(np.unique(ids)) != ids.size:
            raise CausalEvidenceError("public group identifiers collide or hit sentinel")
        self.__group_ids = ids

    def take_ledger(self) -> SealedEvidenceTruthLedger:
        return self.__ledger

    @property
    def logical_to_public(self) -> np.ndarray:
        return self._logical_to_public.copy()

    def group(self, group_index: int) -> PublicEvidenceGroup:
        config = self.config
        if not 0 <= group_index < config.maximum_groups:
            raise CausalEvidenceError("group index is outside the registered horizon")
        logical_coordinates = _permutation(
            config.n_bits,
            self.__metadata_seed ^ (0xC001 * (group_index + 1)) ^ 0xC00A,
        )
        public_coordinates = self._logical_to_public[logical_coordinates]
        family_permutation = _permutation(
            config.n_bits, self.__metadata_seed ^ (0xFA11 * (group_index + 1))
        )
        families = np.empty(config.n_bits, dtype=np.int64)
        families[family_permutation] = np.tile(
            np.arange(config.family_count, dtype=np.int64),
            config.n_bits // config.family_count,
        )
        families = families[logical_coordinates]
        quality_permutation = _permutation(
            config.n_bits, self.__metadata_seed ^ (0x0A11 * (group_index + 1))
        )
        qualities = np.empty(config.n_bits, dtype=np.int64)
        qualities[quality_permutation] = np.arange(config.n_bits) % len(
            config.quality_reliabilities
        )
        qualities = qualities[logical_coordinates]
        current_symbol = _public_marker_symbol(self.__metadata_seed, group_index)
        previous_symbol = _public_marker_symbol(
            self.__metadata_seed, group_index - 1
        )
        regime = _compose_public_regime(previous_symbol, current_symbol)
        orientation = np.asarray(config.orientation_matrix, dtype=np.int8)[
            regime, families
        ]
        probabilities = np.asarray(config.quality_reliabilities, dtype=np.float64)[
            qualities
        ]
        correctness_words = np.frombuffer(
            hashlib.shake_256(
                self.__secret_material
                + b"correctness"
                + struct.pack("<I", group_index)
            ).digest(config.n_bits * 8),
            dtype="<u8",
        )
        correctness_uniform = (
            (correctness_words >> np.uint64(11)).astype(np.float64) + 0.5
        ) / float(1 << 53)
        correctness = np.where(
            correctness_uniform[logical_coordinates] < probabilities,
            1,
            -1,
        ).astype(np.int8)
        truth_sign = (2 * self.__logical_bits[logical_coordinates].astype(np.int8) - 1)
        evidence_votes = (truth_sign * orientation * correctness).astype(np.int8)
        nuisance_votes = np.where(
            (_splitmix64(
                logical_coordinates.astype(np.uint64),
                self.__metadata_seed ^ (0xD015 * (group_index + 1)) ^ 0xA015E,
            ) & np.uint64(1))
            == 0,
            1,
            -1,
        ).astype(np.int8)
        group_id = int(self.__group_ids[group_index])
        evidence_events = _event_block(
            kind=_EVIDENCE,
            novelty=True,
            families=families,
            qualities=qualities,
            regimes=np.full(config.n_bits, -1, dtype=np.int64),
            noise_seed=self.__metadata_seed ^ group_index ^ 0xE71D,
        )
        nuisance_events = _event_block(
            kind=_NUISANCE,
            novelty=True,
            families=families,
            qualities=qualities,
            regimes=np.full(config.n_bits, -1, dtype=np.int64),
            noise_seed=self.__metadata_seed ^ group_index ^ 0xA015E,
        )
        marker_event = _event_block(
            kind=_MARKER,
            novelty=True,
            families=np.asarray([-1]),
            qualities=np.asarray([-1]),
            regimes=np.asarray([current_symbol]),
            noise_seed=self.__metadata_seed ^ group_index ^ 0xAE61,
        )[0]
        selector = families + config.family_count * qualities
        return PublicEvidenceGroup(
            group_index=group_index,
            group_id=group_id,
            coordinates=public_coordinates.astype(np.int64, copy=False),
            families=families,
            qualities=qualities,
            evidence_votes=evidence_votes,
            nuisance_votes=nuisance_votes,
            evidence_events=evidence_events,
            nuisance_events=nuisance_events,
            evidence_addresses=_operator_address(
                _EVIDENCE, selector, config.address_dimension
            ),
            nuisance_addresses=_operator_address(
                _NUISANCE, selector, config.address_dimension
            ),
            marker_event=marker_event,
            marker_address=_operator_address(
                _MARKER, np.asarray([current_symbol]), config.address_dimension
            )[0],
        )


def build_public_evidence_episode(
    config: CausalEvidenceConfig,
    seed: int,
    **kwargs: object,
) -> tuple[PublicEvidenceEpisode, SealedEvidenceTruthLedger]:
    episode = PublicEvidenceEpisode(config, seed, **kwargs)
    return episode, episode.take_ledger()


if torch is not None:

    class LearnedCausalEvidenceReader(torch.nn.Module):
        """Shared learned route and signed reliability reader."""

        def __init__(self, config: CausalEvidenceConfig) -> None:
            super().__init__()
            self.config = config
            self.core = StreamingSelectiveHolographicCore(config.core_config)
            self.coefficient_head = torch.nn.Linear(
                config.model_dimension, 1, bias=False
            )
            self.route_head = torch.nn.Linear(config.event_dimension, 1, bias=True)
            with torch.random.fork_rng(devices=[]):
                torch.manual_seed(config.core_seed ^ 0xCA05A1)
                torch.nn.init.xavier_uniform_(self.coefficient_head.weight, gain=0.6)
                torch.nn.init.xavier_uniform_(self.route_head.weight, gain=0.2)
                torch.nn.init.zeros_(self.route_head.bias)

        def initial_state(self) -> O1FastState:
            return self.core.initial_state(1, device="cpu")

        def route_scores(self, events: np.ndarray) -> np.ndarray:
            array = np.asarray(events, dtype=np.float32)
            if array.ndim != 2 or array.shape[1] != self.config.event_dimension:
                raise CausalEvidenceError("route event array differs")
            with torch.no_grad():
                result = self.route_head(torch.from_numpy(array)).squeeze(-1)
            return result.detach().cpu().numpy().astype(np.float32, copy=False)

        def step_marker(
            self,
            event: np.ndarray,
            address: np.ndarray,
            state: O1FastState,
            *,
            update: bool,
        ) -> O1FastState:
            events = torch.from_numpy(
                np.asarray(event, dtype=np.float32).reshape(1, 1, -1)
            )
            addresses = torch.from_numpy(
                np.asarray(address, dtype=np.float32).reshape(1, 1, -1)
            )
            mask = torch.tensor([[bool(update)]], dtype=torch.bool)
            with torch.no_grad():
                _encoded, result = self.core(events, addresses, mask, state)
            return result

        def coefficients(
            self,
            events: np.ndarray,
            addresses: np.ndarray,
            state: O1FastState,
        ) -> np.ndarray:
            event_array = np.asarray(events, dtype=np.float32)
            address_array = np.asarray(addresses, dtype=np.float32)
            if (
                event_array.ndim != 2
                or event_array.shape[1] != self.config.event_dimension
                or address_array.shape
                != (event_array.shape[0], self.config.address_dimension)
            ):
                raise CausalEvidenceError("coefficient query arrays differ")
            event_tensor = torch.from_numpy(event_array[None, :, :])
            address_tensor = torch.from_numpy(address_array[None, :, :])
            mask = torch.zeros((1, event_array.shape[0]), dtype=torch.bool)
            with torch.no_grad():
                encoded, unchanged = self.core(
                    event_tensor, address_tensor, mask, state
                )
                values = self.coefficient_head(encoded).squeeze(0).squeeze(-1)
            if unchanged is not state:
                raise CausalEvidenceError("coefficient query changed the O1 state")
            return values.detach().cpu().numpy().astype(np.float32, copy=False)


else:  # pragma: no cover

    class LearnedCausalEvidenceReader:  # type: ignore[no-redef]
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            require_torch()


@dataclass(frozen=True)
class ReaderTrainingResult:
    name: str
    module: LearnedCausalEvidenceReader
    slow_state_bytes: bytes
    slow_state_sha256: str
    initial_slow_state_sha256: str
    changed_parameters: tuple[str, ...]
    public_fsm_coefficients: np.ndarray
    public_fsm_coefficients_sha256: str
    metrics: Mapping[str, object]


@dataclass(frozen=True)
class FrozenCausalEvidenceReader:
    primary: LearnedCausalEvidenceReader
    shuffled: LearnedCausalEvidenceReader
    route_threshold: float
    temperatures: Mapping[str, float]
    primary_slow_state_bytes: bytes
    shuffled_slow_state_bytes: bytes
    primary_slow_state_sha256: str
    shuffled_slow_state_sha256: str
    initial_state_sha256: str
    public_fsm_coefficients: np.ndarray
    public_fsm_coefficients_sha256: str
    training_metrics: Mapping[str, object]
    calibration_metrics: Mapping[str, object]


def _marker_event(
    config: CausalEvidenceConfig,
    regime: int,
    *,
    novelty: bool,
    noise_seed: int,
) -> tuple[np.ndarray, np.ndarray]:
    event = _event_block(
        kind=_MARKER,
        novelty=novelty,
        families=np.asarray([-1]),
        qualities=np.asarray([-1]),
        regimes=np.asarray([regime]),
        noise_seed=noise_seed,
    )[0]
    address = _operator_address(
        _MARKER, np.asarray([regime]), config.address_dimension
    )[0]
    return event, address


def _training_corpus(
    config: CausalEvidenceConfig,
    seeds: Sequence[int],
) -> tuple[
    np.ndarray,
    np.ndarray,
    np.ndarray,
    np.ndarray,
    np.ndarray,
    np.ndarray,
    np.ndarray,
]:
    sequence_events: list[np.ndarray] = []
    sequence_addresses: list[np.ndarray] = []
    observed_votes: list[np.ndarray] = []
    truth_targets: list[np.ndarray] = []
    shuffle_strata: list[int] = []
    route_events: list[np.ndarray] = []
    route_targets: list[float] = []
    orientation = np.asarray(config.orientation_matrix, dtype=np.int8)
    sequence_id = 0
    for seed in seeds:
        for family in range(config.family_count):
            for quality in range(len(config.quality_reliabilities)):
                for repetition in range(_BUILD_OUTCOME_REPETITIONS):
                    rows: list[np.ndarray] = []
                    addresses: list[np.ndarray] = []
                    votes: list[float] = []
                    truths: list[float] = []
                    previous_symbol = 0
                    public_stream_seed = (
                        int(seed) ^ (repetition * 0x9E37) ^ 0x51A7B01
                    )
                    for group_index in range(_BUILD_STREAM_GROUPS):
                        current_symbol = _public_marker_symbol(
                            public_stream_seed, group_index
                        )
                        marker, marker_address = _marker_event(
                            config,
                            current_symbol,
                            novelty=True,
                            noise_seed=(
                                public_stream_seed ^ group_index ^ 0xAE61
                            ),
                        )
                        evidence = _event_block(
                            kind=_EVIDENCE,
                            novelty=True,
                            families=np.asarray([family]),
                            qualities=np.asarray([quality]),
                            regimes=np.asarray([-1]),
                            noise_seed=(
                                public_stream_seed ^ group_index ^ 0xE71D
                            ),
                        )[0]
                        evidence_address = _operator_address(
                            _EVIDENCE,
                            np.asarray(
                                [family + config.family_count * quality]
                            ),
                            config.address_dimension,
                        )[0]
                        rows.extend((marker, evidence))
                        addresses.extend((marker_address, evidence_address))

                        public_index = np.asarray(
                            [
                                sequence_id * _BUILD_STREAM_GROUPS
                                + group_index
                            ],
                            dtype=np.uint64,
                        )
                        truth_word = _splitmix64(
                            public_index,
                            int(seed) ^ 0x7A17_7A17,
                        )[0]
                        correctness_word = _splitmix64(
                            public_index,
                            int(seed) ^ 0xC011_EC7,
                        )[0]
                        truth_bit = int(truth_word & np.uint64(1))
                        probability = config.quality_reliabilities[quality]
                        coin = float(
                            (correctness_word >> np.uint64(11)) + np.uint64(1)
                        ) / float(1 << 53)
                        correct = 1 if coin < probability else -1
                        effective_regime = _compose_public_regime(
                            previous_symbol, current_symbol
                        )
                        truth_sign = 2 * truth_bit - 1
                        vote = (
                            truth_sign
                            * int(orientation[effective_regime, family])
                            * correct
                        )
                        votes.append(float(vote))
                        truths.append(float(truth_bit))
                        previous_symbol = current_symbol

                    event_array = np.stack(rows).astype(np.float32, copy=False)
                    address_array = np.stack(addresses).astype(
                        np.float32, copy=False
                    )
                    vote_array = np.asarray(votes, dtype=np.float32)
                    truth_array = np.asarray(truths, dtype=np.float32)
                    stratum = family * len(config.quality_reliabilities) + quality
                    # Exact antithetic BUILD pairs expose identical public input
                    # and opposite truth/vote only.  Thus no metadata can explain
                    # the label and the optimizer sees outcome supervision alone.
                    for antithetic in (False, True):
                        sequence_events.append(event_array)
                        sequence_addresses.append(address_array)
                        observed_votes.append(
                            -vote_array if antithetic else vote_array
                        )
                        truth_targets.append(
                            1.0 - truth_array if antithetic else truth_array
                        )
                        shuffle_strata.append(stratum)

                    repeat = evidence.copy()
                    repeat[_NOVELTY] = -1.0
                    nuisance = evidence.copy()
                    nuisance[_EVIDENCE] = 0.0
                    nuisance[_NUISANCE] = 1.0
                    marker_repeat = marker.copy()
                    marker_repeat[_NOVELTY] = -1.0
                    for route_event, target in (
                        (evidence, 1.0),
                        (repeat, 0.0),
                        (nuisance, 0.0),
                        (marker, 1.0),
                        (marker_repeat, 0.0),
                    ):
                        route_events.append(route_event)
                        route_targets.append(target)
                    sequence_id += 1
    return (
        np.asarray(sequence_events, dtype=np.float32),
        np.asarray(sequence_addresses, dtype=np.float32),
        np.asarray(observed_votes, dtype=np.float32),
        np.asarray(truth_targets, dtype=np.float32),
        np.asarray(shuffle_strata, dtype=np.int16),
        np.asarray(route_events, dtype=np.float32),
        np.asarray(route_targets, dtype=np.float32),
    )


def _fit_outcome_public_fsm(
    config: CausalEvidenceConfig,
    events: np.ndarray,
    observed_votes: np.ndarray,
    truth_targets: np.ndarray,
) -> tuple[np.ndarray, dict[str, object]]:
    """Compile public delayed-marker outcomes into a bounded empirical table."""

    event_array = np.asarray(events, dtype=np.float32)
    votes = np.asarray(observed_votes, dtype=np.float32)
    truths = np.asarray(truth_targets, dtype=np.float32)
    if (
        event_array.ndim != 3
        or event_array.shape[1:] != (2 * _BUILD_STREAM_GROUPS, _EVENT_DIMENSION)
        or votes.shape != (event_array.shape[0], _BUILD_STREAM_GROUPS)
        or truths.shape != votes.shape
        or not bool(np.isin(votes, (-1.0, 1.0)).all())
        or not bool(np.isin(truths, (0.0, 1.0)).all())
    ):
        raise CausalEvidenceError("public FSM BUILD arrays differ")
    sums = np.zeros(
        (
            config.regime_count,
            config.family_count,
            len(config.quality_reliabilities),
        ),
        dtype=np.float64,
    )
    counts = np.zeros_like(sums, dtype=np.int64)
    for sequence_index in range(event_array.shape[0]):
        previous_symbol = 0
        for group_index in range(_BUILD_STREAM_GROUPS):
            marker = event_array[sequence_index, 2 * group_index]
            evidence = event_array[sequence_index, 2 * group_index + 1]
            marker_slice = marker[_REGIME : _REGIME + config.regime_count]
            family_slice = evidence[_FAMILY : _FAMILY + config.family_count]
            quality_slice = evidence[
                _QUALITY : _QUALITY + len(config.quality_reliabilities)
            ]
            if (
                marker[_MARKER] != 1.0
                or evidence[_EVIDENCE] != 1.0
                or int(np.count_nonzero(marker_slice == 1.0)) != 1
                or int(np.count_nonzero(family_slice == 1.0)) != 1
                or int(np.count_nonzero(quality_slice == 1.0)) != 1
            ):
                raise CausalEvidenceError("public FSM BUILD event semantics differ")
            current_symbol = int(np.argmax(marker_slice))
            family = int(np.argmax(family_slice))
            quality = int(np.argmax(quality_slice))
            truth_sign = 2 * int(truths[sequence_index, group_index]) - 1
            corrected = truth_sign * int(votes[sequence_index, group_index])
            sums[previous_symbol, family, quality] += corrected
            counts[previous_symbol, family, quality] += 1
            previous_symbol = current_symbol
    if bool((counts == 0).any()):
        raise CausalEvidenceError("public FSM BUILD table has an empty cell")
    means = sums / counts
    probabilities = np.clip(
        (1.0 + np.abs(means)) / 2.0,
        0.500001,
        0.999999,
    )
    magnitudes = np.clip(
        np.rint(
            np.log(probabilities / (1.0 - probabilities))
            / _COEFFICIENT_TRAINING_LOGIT_SCALE
        ),
        1,
        8,
    ).astype(np.int8)
    coefficients = (
        np.sign(means).astype(np.int8, copy=False) * magnitudes
    ).astype(np.int8, copy=False)
    coefficients = np.ascontiguousarray(coefficients)
    coefficients.setflags(write=False)
    payload = coefficients.tobytes(order="C")
    return coefficients, {
        "schema": "o1-256-outcome-public-fsm-build-v1",
        "supervision": "public-events-observed-votes-and-outcome-truth-only",
        "generator_orientation_or_reliability_labels_used": False,
        "shape": list(coefficients.shape),
        "bytes": len(payload),
        "sha256": _sha256(payload),
        "minimum_examples_per_cell": int(counts.min()),
        "maximum_examples_per_cell": int(counts.max()),
        "minimum_absolute_empirical_margin": float(np.abs(means).min()),
        "outcome_lookups": int(event_array.shape[0] * _BUILD_STREAM_GROUPS),
    }


def _parameter_snapshots(module: object) -> dict[str, bytes]:
    if not hasattr(module, "state_dict"):
        raise TypeError("module must expose state_dict")
    result: dict[str, bytes] = {}
    for name, tensor in module.state_dict().items():
        result[name] = (
            tensor.detach()
            .to(device="cpu", dtype=torch.float32)
            .contiguous()
            .numpy()
            .astype("<f4", copy=False)
            .tobytes(order="C")
        )
    return result


def train_causal_evidence_reader(
    config: CausalEvidenceConfig,
    *,
    name: str,
    shuffled_coefficients: bool,
) -> ReaderTrainingResult:
    require_torch()
    torch.set_num_threads(config.cpu_threads)
    module = LearnedCausalEvidenceReader(config)
    module.train()
    initial_bytes = canonical_module_bytes(module)
    initial_parameters = _parameter_snapshots(module)
    (
        events,
        addresses,
        observed_votes,
        truth_targets,
        shuffle_strata,
        route_events,
        route_targets,
    ) = _training_corpus(config, config.build_seeds)
    if shuffled_coefficients:
        shuffled_targets = truth_targets.copy()
        for stratum in np.unique(shuffle_strata):
            indices = np.flatnonzero(shuffle_strata == stratum)
            permutation = _permutation(
                indices.size,
                config.shuffled_label_seed ^ int(stratum) ^ 0x57A7A,
            )
            shuffled_targets[indices] = truth_targets[indices[permutation]]
        truth_targets = shuffled_targets
    public_fsm_coefficients, public_fsm_metrics = _fit_outcome_public_fsm(
        config,
        events,
        observed_votes,
        truth_targets,
    )
    event_tensor = torch.from_numpy(events)
    address_tensor = torch.from_numpy(addresses)
    vote_tensor = torch.from_numpy(observed_votes)
    truth_tensor = torch.from_numpy(truth_targets)
    route_event_tensor = torch.from_numpy(route_events)
    route_target_tensor = torch.from_numpy(route_targets)
    sequence_tokens = int(events.shape[1])
    if sequence_tokens != 2 * _BUILD_STREAM_GROUPS:
        raise CausalEvidenceError("BUILD stream token count differs")
    update_mask_template = torch.tensor(
        [[index % 2 == 0 for index in range(sequence_tokens)]],
        dtype=torch.bool,
    )
    optimizer = torch.optim.Adam(module.parameters(), lr=config.learning_rate)
    coefficient_losses: list[float] = []
    route_losses: list[float] = []
    count = events.shape[0]
    route_count = route_events.shape[0]
    stride = 104729
    for step in range(config.training_steps):
        indices = (
            np.arange(config.training_batch_size, dtype=np.int64) * stride
            + step * config.training_batch_size
        ) % count
        route_indices = (
            np.arange(config.training_batch_size, dtype=np.int64) * (stride + 2)
            + step * config.training_batch_size
        ) % route_count
        batch_events = event_tensor[indices]
        batch_addresses = address_tensor[indices]
        mask = update_mask_template.expand(config.training_batch_size, -1)
        encoded, _state = module.core(
            batch_events, batch_addresses, mask, state=None
        )
        predicted = module.coefficient_head(encoded[:, 1::2]).squeeze(-1)
        if predicted.shape != vote_tensor[indices].shape:
            raise CausalEvidenceError("BUILD outcome tensor shape differs")
        outcome_logits = (
            predicted
            * vote_tensor[indices]
            * _COEFFICIENT_TRAINING_LOGIT_SCALE
        )
        coefficient_loss = torch.nn.functional.binary_cross_entropy_with_logits(
            outcome_logits, truth_tensor[indices]
        )
        route_logits = module.route_head(route_event_tensor[route_indices]).squeeze(-1)
        route_loss = torch.nn.functional.binary_cross_entropy_with_logits(
            route_logits, route_target_tensor[route_indices]
        )
        loss = coefficient_loss + route_loss
        if not bool(torch.isfinite(loss)):
            raise CausalEvidenceError("causal reader training produced non-finite loss")
        optimizer.zero_grad(set_to_none=True)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(module.parameters(), max_norm=5.0)
        optimizer.step()
        coefficient_losses.append(float(coefficient_loss.detach()))
        route_losses.append(float(route_loss.detach()))
    module.eval()
    with torch.no_grad():
        full_mask = update_mask_template.expand(count, -1)
        encoded, _state = module.core(event_tensor, address_tensor, full_mask)
        output = module.coefficient_head(encoded[:, 1::2]).squeeze(-1)
        outcome_predictions = (output * vote_tensor) > 0.0
        outcome_accuracy = float(
            (outcome_predictions == (truth_tensor > 0.5)).to(torch.float32).mean()
        )
        route_scores = module.route_head(route_event_tensor).squeeze(-1)
        route_predictions = route_scores > 0.0
        route_accuracy_zero = float(
            (route_predictions == (route_target_tensor > 0.5))
            .to(torch.float32)
            .mean()
        )
    final_parameters = _parameter_snapshots(module)
    changed = tuple(
        name
        for name in sorted(initial_parameters)
        if initial_parameters[name] != final_parameters[name]
    )
    slow_bytes = canonical_module_bytes(module)
    return ReaderTrainingResult(
        name=name,
        module=module,
        slow_state_bytes=slow_bytes,
        slow_state_sha256=_sha256(slow_bytes),
        initial_slow_state_sha256=_sha256(initial_bytes),
        changed_parameters=changed,
        public_fsm_coefficients=public_fsm_coefficients,
        public_fsm_coefficients_sha256=str(public_fsm_metrics["sha256"]),
        metrics={
            "steps": config.training_steps,
            "batch_size": config.training_batch_size,
            "sequence_tokens": sequence_tokens,
            "outcome_labels_per_sequence": _BUILD_STREAM_GROUPS,
            "antithetic_public_pairing": True,
            "truth_correctness_hash_domains_separate": True,
            "coefficient_token_exposures": config.training_steps
            * config.training_batch_size
            * sequence_tokens,
            "route_token_exposures": config.training_steps
            * config.training_batch_size,
            "token_exposures": config.training_steps
            * config.training_batch_size
            * (sequence_tokens + 1),
            "coefficient_loss_first": coefficient_losses[0],
            "coefficient_loss_final": coefficient_losses[-1],
            "route_loss_first": route_losses[0],
            "route_loss_final": route_losses[-1],
            "build_outcome_accuracy": outcome_accuracy,
            "coefficient_training_supervision": "truth-outcome-only",
            "generator_orientation_or_reliability_labels_used": False,
            "coefficient_training_logit_scale": _COEFFICIENT_TRAINING_LOGIT_SCALE,
            "build_route_accuracy_at_zero": route_accuracy_zero,
            "shuffled_coefficients": shuffled_coefficients,
            "outcome_public_fsm": public_fsm_metrics,
        },
    )


def _calibrate_route_threshold(
    config: CausalEvidenceConfig,
    module: LearnedCausalEvidenceReader,
) -> tuple[float, dict[str, object]]:
    (
        _events,
        _addresses,
        _observed_votes,
        _truth_targets,
        _shuffle_strata,
        route_events,
        route_targets,
    ) = _training_corpus(config, config.calibration_seeds)
    scores = module.route_scores(route_events).astype(np.float64)
    positive = scores[route_targets == 1.0]
    negative = scores[route_targets == 0.0]
    if not positive.size or not negative.size:
        raise CausalEvidenceError("CAL route classes are empty")
    threshold = 0.5 * (float(positive.min()) + float(negative.max()))
    predictions = scores > threshold
    accuracy = float(np.mean(predictions == (route_targets == 1.0)))
    return threshold, {
        "threshold": threshold,
        "positive_min": float(positive.min()),
        "negative_max": float(negative.max()),
        "margin": float(positive.min() - negative.max()),
        "accuracy": accuracy,
        "examples": int(scores.size),
    }


def _quantized_coefficients(values: np.ndarray) -> np.ndarray:
    array = np.asarray(values, dtype=np.float32)
    return np.clip(np.rint(array), -8, 8).astype(np.int8)


class _IncrementalBoolPacker:
    def __init__(self) -> None:
        self._chunks: list[bytes] = []
        self._remainder = np.empty(0, dtype=np.bool_)
        self.length = 0

    def add(self, values: np.ndarray) -> None:
        array = np.asarray(values, dtype=np.bool_).reshape(-1)
        self.length += int(array.size)
        if self._remainder.size:
            array = np.concatenate((self._remainder, array))
        full = (array.size // 8) * 8
        if full:
            self._chunks.append(_pack_bool(array[:full]))
        self._remainder = array[full:].copy()

    def finish(self) -> bytes:
        if self._remainder.size:
            self._chunks.append(_pack_bool(self._remainder))
            self._remainder = np.empty(0, dtype=np.bool_)
        return b"".join(self._chunks)


@dataclass(frozen=True)
class EpisodeExecution:
    raw_scores: Mapping[str, np.ndarray]
    prefix_state_sha256: tuple[str, ...]
    final_state_bytes: bytes
    public_fsm_prefix_state_sha256: tuple[str, ...]
    public_fsm_final_state_bytes: bytes
    route_mask_bytes: bytes
    receipt: Mapping[str, object]
    work: Mapping[str, int]


def _slot_arrays(
    group: PublicEvidenceGroup,
    *,
    novel: bool,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    marker = group.marker_event.copy()
    evidence = group.evidence_events.copy()
    nuisance = group.nuisance_events.copy()
    novelty = 1.0 if novel else -1.0
    marker[_NOVELTY] = novelty
    evidence[:, _NOVELTY] = novelty
    nuisance[:, _NOVELTY] = novelty
    count = group.coordinates.size
    events = np.empty((1 + 2 * count, marker.size), dtype=np.float32)
    addresses = np.empty(
        (1 + 2 * count, group.marker_address.size), dtype=np.float32
    )
    coordinates = np.full(1 + 2 * count, -1, dtype=np.int64)
    votes = np.zeros(1 + 2 * count, dtype=np.int8)
    kinds = np.empty(1 + 2 * count, dtype=np.int8)
    events[0] = marker
    addresses[0] = group.marker_address
    kinds[0] = _MARKER
    events[1::2] = evidence
    events[2::2] = nuisance
    addresses[1::2] = group.evidence_addresses
    addresses[2::2] = group.nuisance_addresses
    coordinates[1::2] = group.coordinates
    coordinates[2::2] = group.coordinates
    votes[1::2] = group.evidence_votes
    votes[2::2] = group.nuisance_votes
    kinds[1::2] = _EVIDENCE
    kinds[2::2] = _NUISANCE
    return events, addresses, coordinates, votes, kinds


def _update_slot_hashes(
    hashers: Mapping[str, Any],
    *,
    group: PublicEvidenceGroup,
    novel: bool,
    events: np.ndarray,
    addresses: np.ndarray,
    coordinates: np.ndarray,
    votes: np.ndarray,
    kinds: np.ndarray,
) -> None:
    header = struct.pack("<QIB", group.group_id, group.group_index, int(novel))
    metadata = b"".join(
        (
            header,
            kinds.astype(np.int8, copy=False).tobytes(order="C"),
            coordinates.astype("<i2", copy=False).tobytes(order="C"),
            events.astype("<f4", copy=False).tobytes(order="C"),
            addresses.astype("<f4", copy=False).tobytes(order="C"),
        )
    )
    vote_bytes = votes.astype(np.int8, copy=False).tobytes(order="C")
    evidence_vote_bytes = group.evidence_votes.astype(np.int8, copy=False).tobytes(
        order="C"
    )
    negated_evidence_vote_bytes = (-group.evidence_votes).astype(
        np.int8, copy=False
    ).tobytes(order="C")
    hashers["metadata"].update(metadata)
    hashers["votes"].update(vote_bytes)
    hashers["evidence_votes"].update(evidence_vote_bytes)
    hashers["negated_evidence_votes"].update(negated_evidence_vote_bytes)
    hashers["stream"].update(metadata)
    hashers["stream"].update(vote_bytes)


def _route_mask_for_slot(
    module: LearnedCausalEvidenceReader,
    events: np.ndarray,
    threshold: float,
) -> tuple[np.ndarray, np.ndarray]:
    scores = module.route_scores(events)
    mask = scores.astype(np.float64) > float(threshold)
    return mask, scores


def execute_public_evidence_episode(
    config: CausalEvidenceConfig,
    reader: FrozenCausalEvidenceReader,
    episode: PublicEvidenceEpisode,
    *,
    repeat_factor: int,
) -> EpisodeExecution:
    """Execute one public episode without any truth-ledger access."""

    if repeat_factor not in config.repeat_factors:
        raise CausalEvidenceError("repeat factor is not registered")
    primary_state = CausalEvidenceState.initial(config, reader.primary.core)
    shuffled_state = CausalEvidenceState.initial(config, reader.shuffled.core)
    public_fsm_state = OutcomePublicFSMState.initial(config)
    static_initial = reader.primary.initial_state()
    initial_state_sha256 = primary_state.sha256(config)
    public_fsm_initial_state_sha256 = public_fsm_state.sha256(config)
    last_score = np.zeros(config.n_bits, dtype=np.int16)
    unit_score = np.zeros(config.n_bits, dtype=np.int32)
    static_score = np.zeros(config.n_bits, dtype=np.int32)
    current_marker_score = np.zeros(config.n_bits, dtype=np.int32)
    all_open_score = np.zeros(config.n_bits, dtype=np.int64)
    oracle_score = np.zeros(config.n_bits, dtype=np.float64)
    raw_by_arm = {
        arm: np.zeros(
            (len(config.independent_group_prefixes), config.n_bits),
            dtype=np.float64,
        )
        for arm in ALL_ARMS
    }
    prefix_lookup = {
        groups: index
        for index, groups in enumerate(config.independent_group_prefixes)
    }
    state_hashes: list[str] = []
    public_fsm_state_hashes: list[str] = []
    route_packer = _IncrementalBoolPacker()
    hashers = {
        name: hashlib.sha256()
        for name in (
            "metadata",
            "votes",
            "evidence_votes",
            "negated_evidence_votes",
            "stream",
            "accepted_updates",
        )
    }
    gate_token_evaluations = 0
    physical_tokens = 0
    coefficient_query_tokens = 0
    core_marker_updates = 0
    current_marker_control_updates = 0
    accepted_update_opportunities = 0
    public_fsm_table_lookups = 0
    orientation_matrix = np.asarray(config.orientation_matrix, dtype=np.int8)
    reliability = np.asarray(config.quality_reliabilities, dtype=np.float64)
    oracle_previous_public_symbol = 0
    public_fsm_coefficients = np.asarray(
        reader.public_fsm_coefficients, dtype=np.int8
    )
    if (
        public_fsm_coefficients.shape
        != (
            config.regime_count,
            config.family_count,
            len(config.quality_reliabilities),
        )
        or _sha256(public_fsm_coefficients.tobytes(order="C"))
        != reader.public_fsm_coefficients_sha256
    ):
        raise CausalEvidenceError("public FSM coefficient table differs")

    for group_index in range(config.maximum_groups):
        group = episode.group(group_index)
        for _slot in range(repeat_factor):
            novel = primary_state.last_group_id != group.group_id
            if novel != (shuffled_state.last_group_id != group.group_id):
                raise CausalEvidenceError("primary/shuffled novelty state differs")
            public_fsm_novel = public_fsm_state.last_group_id != group.group_id
            if public_fsm_novel != novel:
                raise CausalEvidenceError("primary/public FSM novelty state differs")
            events, addresses, coordinates, votes, kinds = _slot_arrays(
                group, novel=novel
            )
            route_mask, _route_scores = _route_mask_for_slot(
                reader.primary, events, reader.route_threshold
            )
            route_packer.add(route_mask)
            _update_slot_hashes(
                hashers,
                group=group,
                novel=novel,
                events=events,
                addresses=addresses,
                coordinates=coordinates,
                votes=votes,
                kinds=kinds,
            )
            gate_token_evaluations += int(events.shape[0])
            physical_tokens += int(events.shape[0])

            if bool(route_mask[0]):
                primary_state.core_state = reader.primary.step_marker(
                    events[0], addresses[0], primary_state.core_state, update=True
                )
                shuffled_state.core_state = reader.shuffled.step_marker(
                    events[0], addresses[0], shuffled_state.core_state, update=True
                )
                # Primary and shuffled readers are two distinct core calls.
                core_marker_updates += 2

            accepted = route_mask & (kinds != _MARKER)
            accepted_indices = np.flatnonzero(accepted)
            accepted_update_opportunities += int(accepted_indices.size)
            if accepted_indices.size:
                current_marker_state = reader.primary.step_marker(
                    events[0],
                    addresses[0],
                    static_initial,
                    update=bool(route_mask[0]),
                )
                current_marker_control_updates += int(bool(route_mask[0]))
                accepted_events = events[accepted_indices]
                accepted_addresses = addresses[accepted_indices]
                primary_coefficients = _quantized_coefficients(
                    reader.primary.coefficients(
                        accepted_events,
                        accepted_addresses,
                        primary_state.core_state,
                    )
                )
                shuffled_coefficients = _quantized_coefficients(
                    reader.shuffled.coefficients(
                        accepted_events,
                        accepted_addresses,
                        shuffled_state.core_state,
                    )
                )
                static_coefficients = _quantized_coefficients(
                    reader.primary.coefficients(
                        accepted_events,
                        accepted_addresses,
                        static_initial,
                    )
                )
                current_marker_coefficients = _quantized_coefficients(
                    reader.primary.coefficients(
                        accepted_events,
                        accepted_addresses,
                        current_marker_state,
                    )
                )
                coefficient_query_tokens += 4 * int(accepted_indices.size)
                for local, token_index in enumerate(accepted_indices):
                    coordinate = int(coordinates[token_index])
                    vote = int(votes[token_index])
                    primary_delta = int(primary_coefficients[local]) * vote
                    shuffled_delta = int(shuffled_coefficients[local]) * vote
                    static_delta = int(static_coefficients[local]) * vote
                    current_marker_delta = (
                        int(current_marker_coefficients[local]) * vote
                    )
                    primary_state.add(coordinate, primary_delta)
                    shuffled_state.add(coordinate, shuffled_delta)
                    last_score[coordinate] = np.int16(primary_delta)
                    unit_score[coordinate] += vote
                    static_score[coordinate] += static_delta
                    current_marker_score[coordinate] += current_marker_delta
                    hashers["accepted_updates"].update(
                        struct.pack(
                            "<Qhbbb",
                            group.group_id,
                            coordinate,
                            int(kinds[token_index]),
                            vote,
                            int(primary_coefficients[local]),
                        )
                    )

            # The compilable FSM is an independent public route: it owns its
            # delayed-marker symbol and duplicate state and accepts exactly the
            # novel evidence events.  It never borrows the learned O1 route.
            if public_fsm_novel:
                public_fsm_indices = np.flatnonzero(kinds == _EVIDENCE)
                if public_fsm_indices.size != config.n_bits:
                    raise CausalEvidenceError("public FSM evidence route width differs")
                for token_index in public_fsm_indices:
                    group_offset = (int(token_index) - 1) // 2
                    coordinate = int(coordinates[token_index])
                    vote = int(votes[token_index])
                    coefficient = int(
                        public_fsm_coefficients[
                            public_fsm_state.previous_symbol,
                            int(group.families[group_offset]),
                            int(group.qualities[group_offset]),
                        ]
                    )
                    public_fsm_state.add(coordinate, coefficient * vote)
                    public_fsm_table_lookups += 1

            # The intentionally open control consumes every offered signed token.
            np.add.at(
                all_open_score,
                coordinates[1:],
                votes[1:].astype(np.int64),
            )

            if novel:
                marker_slice = group.marker_event[
                    _REGIME : _REGIME + config.regime_count
                ]
                if int(np.count_nonzero(marker_slice == 1.0)) != 1:
                    raise CausalEvidenceError("public marker symbol is not one-hot")
                current_public_symbol = int(np.argmax(marker_slice))
                regime = _compose_public_regime(
                    oracle_previous_public_symbol, current_public_symbol
                )
                orientations = orientation_matrix[regime, group.families]
                llr = np.log(reliability[group.qualities] / (1.0 - reliability[group.qualities]))
                oracle_delta = group.evidence_votes.astype(np.float64) * orientations * llr
                np.add.at(oracle_score, group.coordinates, oracle_delta)
                oracle_previous_public_symbol = current_public_symbol
                public_fsm_state.previous_symbol = current_public_symbol

            primary_state.last_group_id = group.group_id
            shuffled_state.last_group_id = group.group_id
            public_fsm_state.last_group_id = group.group_id

        completed_groups = group_index + 1
        if completed_groups in prefix_lookup:
            prefix = prefix_lookup[completed_groups]
            raw_by_arm[PRIMARY_ARM][prefix] = primary_state.evidence.astype(np.float64)
            raw_by_arm["zero_prior_baseline"][prefix] = 0.0
            raw_by_arm["same_route_last"][prefix] = last_score.astype(np.float64)
            raw_by_arm["same_route_unit_sum"][prefix] = unit_score.astype(np.float64)
            raw_by_arm["same_encoder_static_sum"][prefix] = static_score.astype(
                np.float64
            )
            raw_by_arm["same_encoder_current_marker_sum"][prefix] = (
                current_marker_score.astype(np.float64)
            )
            raw_by_arm[PUBLIC_FSM_ARM][prefix] = public_fsm_state.evidence.astype(
                np.float64
            )
            raw_by_arm["shuffled_confidence"][prefix] = shuffled_state.evidence.astype(
                np.float64
            )
            raw_by_arm["all_open"][prefix] = all_open_score.astype(np.float64)
            raw_by_arm[ORACLE_ARM][prefix] = oracle_score
            state_hashes.append(primary_state.sha256(config))
            public_fsm_state_hashes.append(public_fsm_state.sha256(config))

    route_mask_bytes = route_packer.finish()
    if route_packer.length != physical_tokens:
        raise AssertionError("route mask length differs from physical stream")
    final_state_bytes = primary_state.to_bytes(config)
    public_fsm_final_state_bytes = public_fsm_state.to_bytes(config)
    work = {
        "physical_public_tokens": physical_tokens,
        "gate_token_evaluations": gate_token_evaluations,
        "coefficient_query_tokens": coefficient_query_tokens,
        "core_marker_updates": core_marker_updates,
        "current_marker_control_updates": current_marker_control_updates,
        "accepted_update_opportunities": accepted_update_opportunities,
        "public_fsm_table_lookups": public_fsm_table_lookups,
        "logical_arm_updates": physical_tokens * len(ALL_ARMS),
    }
    actual_compute = {
        "raw_tokens": physical_tokens,
        "gate_calls": gate_token_evaluations,
        "encoder_calls": coefficient_query_tokens
        + core_marker_updates
        + current_marker_control_updates,
        "query_calls": coefficient_query_tokens,
        "accepted_update_opportunities": accepted_update_opportunities,
        "public_fsm_table_lookups": public_fsm_table_lookups,
    }
    offered_compute = {
        "raw_tokens": physical_tokens,
        "gate_calls": physical_tokens,
        "encoder_calls": physical_tokens,
        "query_calls": physical_tokens,
        "update_opportunities": physical_tokens,
        "bytes_seen": physical_tokens
        * (config.event_dimension + config.address_dimension)
        * 4,
    }
    evidence_structure = {
        "unique_groups": config.maximum_groups,
        "repeat_factor": repeat_factor,
        "slot_count": config.maximum_groups * repeat_factor,
        "prefixes": list(config.independent_group_prefixes),
        "temporal_public_operator": _TEMPORAL_OPERATOR,
        "outcome_public_fsm": {
            "coefficient_table_bytes": int(public_fsm_coefficients.nbytes),
            "coefficient_table_sha256": reader.public_fsm_coefficients_sha256,
            "live_state_bytes": config.n_bits + 17,
            "operator_state_bytes": 1,
            "evidence_vault_bytes": config.n_bits,
            "duplicate_and_update_counters_bytes": 16,
            "routing": "independent-public-evidence-kind-and-own-duplicate-state",
        },
    }
    receipt = {
        "schema": "o1-256-causal-evidence-execution-receipt-v1",
        "repeat_factor": repeat_factor,
        "metadata_sha256": hashers["metadata"].hexdigest(),
        "vote_sha256": hashers["votes"].hexdigest(),
        "evidence_vote_sha256": hashers["evidence_votes"].hexdigest(),
        "negated_evidence_vote_sha256": hashers[
            "negated_evidence_votes"
        ].hexdigest(),
        "public_stream_sha256": hashers["stream"].hexdigest(),
        "route_mask_sha256": _sha256(route_mask_bytes),
        "accepted_update_ledger_sha256": hashers["accepted_updates"].hexdigest(),
        "initial_state_sha256": initial_state_sha256,
        "prefix_state_sha256": list(state_hashes),
        "final_state_sha256": _sha256(final_state_bytes),
        "public_fsm_initial_state_sha256": public_fsm_initial_state_sha256,
        "public_fsm_prefix_state_sha256": list(public_fsm_state_hashes),
        "public_fsm_final_state_sha256": _sha256(public_fsm_final_state_bytes),
        "primary_slow_state_sha256": reader.primary_slow_state_sha256,
        "actual_compute_work": actual_compute,
        "offered_compute_work": offered_compute,
        "offered_compute_work_sha256": _sha256(_canonical_json(offered_compute)),
        "prefix_offered_compute_work": [
            {
                "unique_groups": groups,
                "raw_tokens": groups * repeat_factor * config.tokens_per_slot,
                "sha256": _sha256(
                    _canonical_json(
                        {
                            "raw_tokens": groups
                            * repeat_factor
                            * config.tokens_per_slot,
                            "gate_calls": groups
                            * repeat_factor
                            * config.tokens_per_slot,
                            "encoder_calls": groups
                            * repeat_factor
                            * config.tokens_per_slot,
                            "query_calls": groups
                            * repeat_factor
                            * config.tokens_per_slot,
                            "update_opportunities": groups
                            * repeat_factor
                            * config.tokens_per_slot,
                            "bytes_seen": groups
                            * repeat_factor
                            * config.tokens_per_slot
                            * (config.event_dimension + config.address_dimension)
                            * 4,
                        }
                    )
                ),
            }
            for groups in config.independent_group_prefixes
        ],
        "evidence_structure": evidence_structure,
        "evidence_structure_sha256": _sha256(_canonical_json(evidence_structure)),
        "logical_to_public": episode.logical_to_public.tolist(),
        "state_bytes": len(final_state_bytes),
        "public_fsm_state_bytes": len(public_fsm_final_state_bytes),
    }
    return EpisodeExecution(
        raw_scores=raw_by_arm,
        prefix_state_sha256=tuple(state_hashes),
        final_state_bytes=final_state_bytes,
        public_fsm_prefix_state_sha256=tuple(public_fsm_state_hashes),
        public_fsm_final_state_bytes=public_fsm_final_state_bytes,
        route_mask_bytes=route_mask_bytes,
        receipt=receipt,
        work=work,
    )


def _stable_nll_bits(logits: np.ndarray, truth_bits: np.ndarray) -> float:
    values = np.asarray(logits, dtype=np.float64)
    truth = np.asarray(truth_bits, dtype=np.uint8)
    if values.shape != truth.shape or not bool(np.isfinite(values).all()):
        raise CausalEvidenceError("NLL arrays differ or contain non-finite values")
    signs = 2.0 * truth.astype(np.float64) - 1.0
    argument = -signs * values
    softplus = np.maximum(argument, 0.0) + np.log1p(np.exp(-np.abs(argument)))
    return float(np.sum(softplus) / _LN2)


def _fit_temperature(
    raw_scores: np.ndarray,
    truth_bits: np.ndarray,
    *,
    maximum: float,
    steps: int,
    signed: bool,
) -> tuple[float, float, int]:
    raw = np.asarray(raw_scores, dtype=np.float64)
    truth = np.asarray(truth_bits, dtype=np.uint8)
    if raw.shape != truth.shape or raw.ndim != 2:
        raise CausalEvidenceError("temperature calibration arrays differ")
    candidates = (
        np.linspace(-maximum, maximum, steps, dtype=np.float64)
        if signed
        else np.linspace(0.0, maximum, steps, dtype=np.float64)
    )
    best_temperature = 0.0
    best_nll = math.inf
    for candidate in candidates:
        nll = _stable_nll_bits(raw * candidate, truth)
        if nll < best_nll - 1e-12:
            best_nll = nll
            best_temperature = float(candidate)
    return best_temperature, best_nll, int(candidates.size * raw.size)


def calibrate_causal_evidence_readers(
    config: CausalEvidenceConfig,
    primary_training: ReaderTrainingResult,
    shuffled_training: ReaderTrainingResult,
) -> FrozenCausalEvidenceReader:
    threshold, route_metrics = _calibrate_route_threshold(
        config, primary_training.module
    )
    initial_core = primary_training.module.initial_state()
    initial_state_sha256 = initial_core.sha256(config.core_config)
    provisional = FrozenCausalEvidenceReader(
        primary=primary_training.module,
        shuffled=shuffled_training.module,
        route_threshold=threshold,
        temperatures={arm: 1.0 for arm in ALL_ARMS},
        primary_slow_state_bytes=primary_training.slow_state_bytes,
        shuffled_slow_state_bytes=shuffled_training.slow_state_bytes,
        primary_slow_state_sha256=primary_training.slow_state_sha256,
        shuffled_slow_state_sha256=shuffled_training.slow_state_sha256,
        initial_state_sha256=initial_state_sha256,
        public_fsm_coefficients=primary_training.public_fsm_coefficients,
        public_fsm_coefficients_sha256=(
            primary_training.public_fsm_coefficients_sha256
        ),
        training_metrics={
            "primary": dict(primary_training.metrics),
            "shuffled": dict(shuffled_training.metrics),
        },
        calibration_metrics={},
    )
    score_rows: dict[str, list[np.ndarray]] = {arm: [] for arm in ALL_ARMS}
    truth_rows: list[np.ndarray] = []
    calibration_work = {
        "episodes": 0,
        "physical_public_tokens": 0,
        "reader_token_evaluations": 0,
        "public_fsm_table_lookups": 0,
    }
    for seed in config.calibration_seeds:
        material = hashlib.sha256(
            struct.pack("<q", int(seed)) + b"o1c0021-calibration-material"
        ).digest()
        for complement in (False, True):
            episode, ledger = build_public_evidence_episode(
                config,
                seed,
                complement=complement,
                secret_material=material,
            )
            execution = execute_public_evidence_episode(
                config, provisional, episode, repeat_factor=1
            )
            truth = ledger.reveal().bits
            for arm in ALL_ARMS:
                score_rows[arm].append(
                    np.asarray(execution.raw_scores[arm], dtype=np.float64).reshape(
                        -1
                    )
                )
            truth_rows.append(
                np.broadcast_to(
                    truth,
                    (len(config.independent_group_prefixes), config.n_bits),
                )
                .copy()
                .reshape(-1)
            )
            calibration_work["episodes"] += 1
            calibration_work["physical_public_tokens"] += int(
                execution.work["physical_public_tokens"]
            )
            calibration_work["reader_token_evaluations"] += int(
                execution.work["gate_token_evaluations"]
                + execution.work["coefficient_query_tokens"]
                + execution.work["core_marker_updates"]
                + execution.work["current_marker_control_updates"]
            )
            calibration_work["public_fsm_table_lookups"] += int(
                execution.work["public_fsm_table_lookups"]
            )
    truth_matrix = np.stack(truth_rows)
    temperatures: dict[str, float] = {}
    temperature_metrics: dict[str, object] = {}
    temperature_evaluations = 0
    for arm in ALL_ARMS:
        if arm == ORACLE_ARM:
            temperatures[arm] = 1.0
            temperature_metrics[arm] = {
                "temperature": 1.0,
                "role": "grouped_bayes_ceiling",
            }
            continue
        if arm == "zero_prior_baseline":
            temperatures[arm] = 0.0
            temperature_metrics[arm] = {
                "temperature": 0.0,
                "nll_bits": float(truth_matrix.size),
                "grid_evaluations": 0,
            }
            continue
        raw_matrix = np.stack(score_rows[arm])
        temperature, nll, evaluations = _fit_temperature(
            raw_matrix,
            truth_matrix,
            maximum=config.temperature_grid_max,
            steps=config.temperature_grid_steps,
            signed=arm not in (PRIMARY_ARM, PUBLIC_FSM_ARM),
        )
        temperatures[arm] = temperature
        temperature_metrics[arm] = {
            "temperature": temperature,
            "nll_bits": nll,
            "grid_evaluations": evaluations,
            "signed_grid": arm not in (PRIMARY_ARM, PUBLIC_FSM_ARM),
            "bias": 0.0,
        }
        temperature_evaluations += evaluations
    primary_after = canonical_module_bytes(primary_training.module)
    shuffled_after = canonical_module_bytes(shuffled_training.module)
    if (
        primary_after != primary_training.slow_state_bytes
        or shuffled_after != shuffled_training.slow_state_bytes
    ):
        raise CausalEvidenceError("CAL changed a frozen slow state")
    calibration_metrics = {
        "route": route_metrics,
        "temperatures": temperature_metrics,
        "work": {
            **calibration_work,
            "temperature_grid_value_evaluations": temperature_evaluations,
        },
        "primary_slow_state_unchanged": True,
        "shuffled_slow_state_unchanged": True,
    }
    return FrozenCausalEvidenceReader(
        primary=primary_training.module,
        shuffled=shuffled_training.module,
        route_threshold=threshold,
        temperatures=temperatures,
        primary_slow_state_bytes=primary_training.slow_state_bytes,
        shuffled_slow_state_bytes=shuffled_training.slow_state_bytes,
        primary_slow_state_sha256=primary_training.slow_state_sha256,
        shuffled_slow_state_sha256=shuffled_training.slow_state_sha256,
        initial_state_sha256=initial_state_sha256,
        public_fsm_coefficients=primary_training.public_fsm_coefficients,
        public_fsm_coefficients_sha256=(
            primary_training.public_fsm_coefficients_sha256
        ),
        training_metrics={
            "primary": dict(primary_training.metrics),
            "shuffled": dict(shuffled_training.metrics),
        },
        calibration_metrics=calibration_metrics,
    )


def _serialize_prediction_records(
    config: CausalEvidenceConfig,
    records: Mapping[str, tuple[np.ndarray, str, np.ndarray]],
) -> tuple[bytes, bytes]:
    payload = bytearray()
    index_rows: list[dict[str, object]] = []
    for key in sorted(records):
        values, truth_key, logical_to_public = records[key]
        array = np.asarray(values, dtype=np.float32)
        mapping = np.asarray(logical_to_public, dtype=np.int64)
        if (
            array.shape
            != (len(config.independent_group_prefixes), config.n_bits)
            or not bool(np.isfinite(array).all())
            or mapping.shape != (config.n_bits,)
            or set(mapping.tolist()) != set(range(config.n_bits))
        ):
            raise CausalEvidenceError(f"prediction record differs: {key}")
        offset = len(payload) // 4
        raw = array.astype("<f4", copy=False).tobytes(order="C")
        payload.extend(raw)
        index_rows.append(
            {
                "key": key,
                "truth_key": truth_key,
                "offset_values": offset,
                "value_count": int(array.size),
                "shape": [len(config.independent_group_prefixes), config.n_bits],
                "dtype": "float32-little-endian",
                "sha256": _sha256(raw),
                "logical_to_public": mapping.tolist(),
            }
        )
    document = {
        "schema": PREDICTION_INDEX_SCHEMA,
        "n_bits": config.n_bits,
        "prefixes": list(config.independent_group_prefixes),
        "record_count": len(index_rows),
        "value_count": len(payload) // 4,
        "blob_sha256": _sha256(bytes(payload)),
        "records": index_rows,
    }
    return bytes(payload), _canonical_json(document)


def _parse_prediction_records(
    blob: bytes,
    index_payload: bytes,
) -> tuple[dict[str, np.ndarray], dict[str, dict[str, object]], dict[str, object]]:
    try:
        document = json.loads(index_payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CausalEvidenceError("prediction index is unreadable") from exc
    if (
        not isinstance(document, dict)
        or document.get("schema") != PREDICTION_INDEX_SCHEMA
        or document.get("blob_sha256") != _sha256(blob)
        or len(blob) % 4
    ):
        raise CausalEvidenceError("prediction index/blob commitment differs")
    records = document.get("records")
    if not isinstance(records, list) or document.get("record_count") != len(records):
        raise CausalEvidenceError("prediction record inventory differs")
    values = np.frombuffer(blob, dtype="<f4")
    parsed: dict[str, np.ndarray] = {}
    metadata: dict[str, dict[str, object]] = {}
    consumed = 0
    for row in records:
        if not isinstance(row, dict):
            raise CausalEvidenceError("prediction index row differs")
        key = row.get("key")
        shape = row.get("shape")
        offset = row.get("offset_values")
        count = row.get("value_count")
        if (
            not isinstance(key, str)
            or key in parsed
            or not isinstance(shape, list)
            or len(shape) != 2
            or any(isinstance(item, bool) or not isinstance(item, int) for item in shape)
            or isinstance(offset, bool)
            or not isinstance(offset, int)
            or isinstance(count, bool)
            or not isinstance(count, int)
            or offset != consumed
            or count != int(math.prod(shape))
            or offset + count > values.size
        ):
            raise CausalEvidenceError("prediction row bounds differ")
        raw = blob[4 * offset : 4 * (offset + count)]
        if row.get("sha256") != _sha256(raw):
            raise CausalEvidenceError("prediction row hash differs")
        array = values[offset : offset + count].reshape(tuple(shape)).astype(
            np.float64
        )
        if not bool(np.isfinite(array).all()):
            raise CausalEvidenceError("prediction row is non-finite")
        parsed[key] = array
        metadata[key] = row
        consumed += count
    if consumed != values.size or document.get("value_count") != consumed:
        raise CausalEvidenceError("prediction blob has trailing or missing values")
    return parsed, metadata, document


def _serialize_truth_records(
    records: Mapping[str, np.ndarray],
) -> tuple[bytes, bytes]:
    payload = bytearray()
    rows: list[dict[str, object]] = []
    for key in sorted(records):
        bits = np.asarray(records[key], dtype=np.uint8)
        if bits.ndim != 1 or bits.size % 8 or not bool(np.isin(bits, (0, 1)).all()):
            raise CausalEvidenceError(f"truth record differs: {key}")
        raw = np.packbits(bits, bitorder="little").tobytes(order="C")
        offset = len(payload)
        payload.extend(raw)
        rows.append(
            {
                "key": key,
                "offset_bytes": offset,
                "bytes": len(raw),
                "n_bits": int(bits.size),
                "bitorder": "little",
                "sha256": _sha256(raw),
            }
        )
    document = {
        "schema": TRUTH_INDEX_SCHEMA,
        "record_count": len(rows),
        "bytes": len(payload),
        "blob_sha256": _sha256(bytes(payload)),
        "records": rows,
    }
    return bytes(payload), _canonical_json(document)


def _parse_truth_records(
    blob: bytes,
    index_payload: bytes,
) -> tuple[dict[str, np.ndarray], dict[str, object]]:
    try:
        document = json.loads(index_payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CausalEvidenceError("truth index is unreadable") from exc
    if (
        not isinstance(document, dict)
        or document.get("schema") != TRUTH_INDEX_SCHEMA
        or document.get("blob_sha256") != _sha256(blob)
        or document.get("bytes") != len(blob)
    ):
        raise CausalEvidenceError("truth index/blob commitment differs")
    rows = document.get("records")
    if not isinstance(rows, list) or document.get("record_count") != len(rows):
        raise CausalEvidenceError("truth record inventory differs")
    result: dict[str, np.ndarray] = {}
    consumed = 0
    for row in rows:
        if not isinstance(row, dict):
            raise CausalEvidenceError("truth index row differs")
        key = row.get("key")
        offset = row.get("offset_bytes")
        width = row.get("bytes")
        n_bits = row.get("n_bits")
        if (
            not isinstance(key, str)
            or key in result
            or not isinstance(offset, int)
            or not isinstance(width, int)
            or not isinstance(n_bits, int)
            or offset != consumed
            or width * 8 != n_bits
            or offset + width > len(blob)
            or row.get("bitorder") != "little"
        ):
            raise CausalEvidenceError("truth row bounds differ")
        raw = blob[offset : offset + width]
        if row.get("sha256") != _sha256(raw):
            raise CausalEvidenceError("truth row hash differs")
        result[key] = np.unpackbits(
            np.frombuffer(raw, dtype=np.uint8), bitorder="little"
        ).astype(np.uint8, copy=False)
        consumed += width
    if consumed != len(blob):
        raise CausalEvidenceError("truth blob has trailing bytes")
    return result, document


def _sigmoid(values: np.ndarray) -> np.ndarray:
    logits = np.asarray(values, dtype=np.float64)
    result = np.empty_like(logits)
    nonnegative = logits >= 0.0
    result[nonnegative] = 1.0 / (1.0 + np.exp(-logits[nonnegative]))
    exponent = np.exp(logits[~nonnegative])
    result[~nonnegative] = exponent / (1.0 + exponent)
    return result


def _metric_curve(logits: np.ndarray, truth: np.ndarray) -> list[dict[str, object]]:
    values = np.asarray(logits, dtype=np.float64)
    bits = np.asarray(truth, dtype=np.uint8)
    if values.ndim != 2 or values.shape[1:] != bits.shape:
        raise CausalEvidenceError("metric curve arrays differ")
    signs = 2.0 * bits.astype(np.float64) - 1.0
    rows: list[dict[str, object]] = []
    for row in values:
        signed = signs * row
        probabilities = _sigmoid(row)
        nll = _stable_nll_bits(row, bits)
        rows.append(
            {
                "nll_bits": nll,
                "compression_bits": float(bits.size - nll),
                "accuracy": float(np.mean(signed > 0.0)),
                "correct_bits": int(np.count_nonzero(signed > 0.0)),
                "ties": int(np.count_nonzero(signed == 0.0)),
                "exact": bool((signed > 0.0).all()),
                "brier": float(np.mean((probabilities - bits) ** 2)),
                "minimum_signed_logit": float(np.min(signed)),
            }
        )
    return rows


def _ece_16(probabilities: np.ndarray, truths: np.ndarray) -> float:
    values = np.asarray(probabilities, dtype=np.float64).reshape(-1)
    bits = np.asarray(truths, dtype=np.uint8).reshape(-1)
    if values.shape != bits.shape:
        raise CausalEvidenceError("ECE arrays differ")
    bins = np.minimum((values * 16.0).astype(np.int64), 15)
    total = values.size
    ece = 0.0
    for index in range(16):
        selected = bins == index
        if bool(selected.any()):
            ece += (
                float(np.count_nonzero(selected))
                / float(total)
                * abs(float(values[selected].mean()) - float(bits[selected].mean()))
            )
    return ece


def _log_prefix_iauc(margins: np.ndarray, prefixes: Sequence[int]) -> float:
    values = np.asarray(margins, dtype=np.float64)
    x = np.log2(np.asarray(prefixes, dtype=np.float64))
    width = float(x[-1] - x[0])
    if values.shape != x.shape or width <= 0.0:
        raise CausalEvidenceError("IAUC prefix geometry differs")
    return float(
        np.sum(0.5 * (values[:-1] + values[1:]) * np.diff(x)) / width
    )


def recompute_causal_evidence_scores(
    config: CausalEvidenceConfig,
    *,
    prediction_blob: bytes,
    prediction_index: bytes,
    truth_blob: bytes,
    truth_index: bytes,
) -> dict[str, object]:
    predictions, prediction_rows, prediction_document = _parse_prediction_records(
        prediction_blob, prediction_index
    )
    truths, truth_document = _parse_truth_records(truth_blob, truth_index)
    expected_records = config.prediction_value_count
    if int(prediction_document["value_count"]) != expected_records:
        raise CausalEvidenceError("frozen prediction value count differs")

    curves: dict[str, list[dict[str, object]]] = {}
    for key, logits in predictions.items():
        truth_key = prediction_rows[key].get("truth_key")
        if not isinstance(truth_key, str) or truth_key not in truths:
            raise CausalEvidenceError(f"prediction truth link differs: {key}")
        curves[key] = _metric_curve(logits, truths[truth_key])

    gates: dict[str, bool] = {}
    primary_final_rows: list[dict[str, object]] = []
    primary_compressions: list[np.ndarray] = []
    primary_final_probabilities: list[np.ndarray] = []
    primary_final_truths: list[np.ndarray] = []
    for seed in config.evaluation_seeds:
        key = f"base/{seed}/{PRIMARY_ARM}"
        rows = curves[key]
        primary_final_rows.append(rows[-1])
        primary_compressions.append(
            np.asarray([row["compression_bits"] for row in rows], dtype=np.float64)
        )
        primary_final_probabilities.append(_sigmoid(predictions[key][-1]))
        primary_final_truths.append(truths[f"base/{seed}"])
    gates["primary_final_exact_every_seed"] = all(
        bool(row["exact"]) for row in primary_final_rows
    )
    gates["primary_final_positive_compression_every_seed"] = all(
        float(row["compression_bits"]) > _NLL_TOLERANCE_BITS
        for row in primary_final_rows
    )
    gates["primary_final_nll_at_most_32_every_seed"] = all(
        float(row["nll_bits"]) <= _FINAL_NLL_MAX for row in primary_final_rows
    )
    gates["primary_final_no_ties"] = all(
        int(row["ties"]) == 0 for row in primary_final_rows
    )
    growth = np.asarray([row[-1] - row[0] for row in primary_compressions])
    gates["independent_prefix_growth_every_seed"] = bool(
        (growth > _NLL_TOLERANCE_BITS).all()
    )
    gates["independent_prefix_mean_growth_material"] = bool(
        float(growth.mean()) >= _MATERIAL_BITS
    )
    mean_curve = np.mean(np.stack(primary_compressions), axis=0)
    total_backslide = float(np.maximum(0.0, mean_curve[:-1] - mean_curve[1:]).sum())
    gates["independent_prefix_backslide_bounded"] = (
        total_backslide <= _BACKSLIDE_MAX_BITS
    )
    aggregate_ece = _ece_16(
        np.stack(primary_final_probabilities), np.stack(primary_final_truths)
    )
    gates["primary_aggregate_ece_at_most_005"] = aggregate_ece <= _ECE_MAX

    control_summaries: dict[str, object] = {}
    for arm in CONTROL_ARMS:
        final_margins: list[float] = []
        iaucs: list[float] = []
        exact_cells = 0
        for seed, primary_curve in zip(config.evaluation_seeds, primary_compressions):
            rows = curves[f"base/{seed}/{arm}"]
            control_curve = np.asarray(
                [row["compression_bits"] for row in rows], dtype=np.float64
            )
            margins = primary_curve - control_curve
            final_margins.append(float(margins[-1]))
            iaucs.append(
                _log_prefix_iauc(margins, config.independent_group_prefixes)
            )
            exact_cells += int(bool(rows[-1]["exact"]))
        passed = (
            exact_cells == 0
            and min(final_margins) > _NLL_TOLERANCE_BITS
            and float(np.mean(final_margins)) >= _MATERIAL_BITS
            and float(np.mean(iaucs)) > _NLL_TOLERANCE_BITS
        )
        gates[f"control_{arm}_margin"] = passed
        control_summaries[arm] = {
            "terminal_margin_bits_by_seed": final_margins,
            "mean_terminal_margin_bits": float(np.mean(final_margins)),
            "log_prefix_iauc_by_seed": iaucs,
            "mean_log_prefix_iauc": float(np.mean(iaucs)),
            "longest_exact_cells": exact_cells,
            "passed": passed,
        }

    public_fsm_rows = [
        curves[f"base/{seed}/{PUBLIC_FSM_ARM}"][-1]
        for seed in config.evaluation_seeds
    ]
    gates["outcome_public_fsm_reference_exact_every_seed"] = all(
        bool(row["exact"])
        and float(row["nll_bits"]) <= _FINAL_NLL_MAX
        and int(row["ties"]) == 0
        for row in public_fsm_rows
    )
    public_fsm_complement_errors: list[float] = []
    public_fsm_id_errors: list[float] = []
    public_fsm_coordinate_errors: list[float] = []
    public_fsm_duplicates_exact = True
    for seed in config.evaluation_seeds:
        base = predictions[f"base/{seed}/{PUBLIC_FSM_ARM}"]
        complement = predictions[f"complement/{seed}/{PUBLIC_FSM_ARM}"]
        denominator = np.maximum(1.0, np.abs(base) + np.abs(complement))
        public_fsm_complement_errors.append(
            float(np.max(np.abs(base + complement) / denominator))
        )
        public_fsm_id_errors.append(
            float(
                np.max(
                    np.abs(
                        base
                        - predictions[f"id_permutation/{seed}/{PUBLIC_FSM_ARM}"]
                    )
                )
            )
        )
        coordinate_values = predictions[
            f"coordinate_permutation/{seed}/{PUBLIC_FSM_ARM}"
        ]
        mapping = np.asarray(
            prediction_rows[
                f"coordinate_permutation/{seed}/{PUBLIC_FSM_ARM}"
            ]["logical_to_public"],
            dtype=np.int64,
        )
        public_fsm_coordinate_errors.append(
            float(np.max(np.abs(base - coordinate_values[:, mapping])))
        )
        public_fsm_duplicates_exact = public_fsm_duplicates_exact and all(
            bool(
                np.array_equal(
                    base,
                    predictions[f"duplicate_r{factor}/{seed}/{PUBLIC_FSM_ARM}"],
                )
            )
            for factor in config.repeat_factors[1:]
        )
    gates["outcome_public_fsm_complement_antisymmetry"] = (
        max(public_fsm_complement_errors) <= _EPS32_TOLERANCE
    )
    gates["outcome_public_fsm_opaque_id_equivariance"] = (
        max(public_fsm_id_errors) <= _EPS32_TOLERANCE
    )
    gates["outcome_public_fsm_coordinate_equivariance"] = (
        max(public_fsm_coordinate_errors) <= _EPS32_TOLERANCE
    )
    gates["outcome_public_fsm_duplicate_expansion_invariant"] = (
        public_fsm_duplicates_exact
    )
    public_fsm_reference = {
        "role": "outcome-learned bounded public-FSM reference, not an O1 ablation",
        "live_state_bytes": config.n_bits + 17,
        "slow_table_bytes": (
            config.regime_count
            * config.family_count
            * len(config.quality_reliabilities)
        ),
        "final_by_seed": {
            str(seed): row
            for seed, row in zip(config.evaluation_seeds, public_fsm_rows)
        },
        "primary_minus_public_fsm_nll_bits_by_seed": [
            float(primary_final_rows[index]["nll_bits"])
            - float(public_fsm_rows[index]["nll_bits"])
            for index in range(len(config.evaluation_seeds))
        ],
        "maximum_complement_error": max(public_fsm_complement_errors),
        "maximum_opaque_id_error": max(public_fsm_id_errors),
        "maximum_coordinate_permutation_error": max(
            public_fsm_coordinate_errors
        ),
        "duplicates_exact": public_fsm_duplicates_exact,
        "claim": (
            "Parity does not establish O1 necessity; it makes this enumerable "
            "learned operator an explicit target for later O1-O graph compilation."
        ),
    }

    complement_errors: list[float] = []
    complement_probability_errors: list[float] = []
    metadata_pair_compressions: list[float] = []
    metadata_exact_cells = 0
    id_errors: list[float] = []
    coordinate_errors: list[float] = []
    for seed in config.evaluation_seeds:
        base = predictions[f"base/{seed}/{PRIMARY_ARM}"]
        complement = predictions[f"complement/{seed}/{PRIMARY_ARM}"]
        denominator = np.maximum(1.0, np.abs(base) + np.abs(complement))
        complement_errors.append(float(np.max(np.abs(base + complement) / denominator)))
        complement_probability_errors.append(
            float(np.max(np.abs(_sigmoid(base) + _sigmoid(complement) - 1.0)))
        )
        base_metadata = curves[f"base/{seed}/zero_prior_baseline"][-1]
        complement_metadata = curves[
            f"complement/{seed}/zero_prior_baseline"
        ][-1]
        metadata_pair_compressions.append(
            0.5
            * (
                float(base_metadata["compression_bits"])
                + float(complement_metadata["compression_bits"])
            )
        )
        metadata_exact_cells += int(bool(base_metadata["exact"])) + int(
            bool(complement_metadata["exact"])
        )
        id_values = predictions[f"id_permutation/{seed}/{PRIMARY_ARM}"]
        id_errors.append(float(np.max(np.abs(base - id_values))))
        coordinate_values = predictions[
            f"coordinate_permutation/{seed}/{PRIMARY_ARM}"
        ]
        mapping = np.asarray(
            prediction_rows[f"coordinate_permutation/{seed}/{PRIMARY_ARM}"][
                "logical_to_public"
            ],
            dtype=np.int64,
        )
        coordinate_errors.append(
            float(np.max(np.abs(base - coordinate_values[:, mapping])))
        )
    gates["complement_logit_antisymmetry"] = (
        max(complement_errors) <= _EPS32_TOLERANCE
    )
    gates["complement_probability_antisymmetry"] = (
        max(complement_probability_errors) <= _EPS32_TOLERANCE
    )
    gates["zero_prior_baseline_exact_null"] = (
        max(metadata_pair_compressions) <= _NLL_TOLERANCE_BITS
        and metadata_exact_cells == 0
    )
    gates["opaque_id_equality_equivariance"] = max(id_errors) <= _EPS32_TOLERANCE
    gates["coordinate_permutation_equivariance"] = (
        max(coordinate_errors) <= _EPS32_TOLERANCE
    )

    duplicate_summary: dict[str, object] = {}
    duplicate_pass = True
    for factor in config.repeat_factors[1:]:
        max_probability_error = 0.0
        max_nll_error = 0.0
        hard_equal = True
        exact_logits_equal = True
        signed_gains: list[float] = []
        for seed in config.evaluation_seeds:
            base_key = f"base/{seed}/{PRIMARY_ARM}"
            duplicate_key = f"duplicate_r{factor}/{seed}/{PRIMARY_ARM}"
            base = predictions[base_key]
            duplicate = predictions[duplicate_key]
            hard_equal = hard_equal and bool(
                np.array_equal(base > 0.0, duplicate > 0.0)
            )
            exact_logits_equal = exact_logits_equal and bool(
                np.array_equal(base, duplicate)
            )
            max_probability_error = max(
                max_probability_error,
                float(np.max(np.abs(_sigmoid(base) - _sigmoid(duplicate)))),
            )
            base_curve = curves[base_key]
            duplicate_curve = curves[duplicate_key]
            for base_row, duplicate_row in zip(base_curve, duplicate_curve):
                delta = float(duplicate_row["nll_bits"]) - float(base_row["nll_bits"])
                max_nll_error = max(max_nll_error, abs(delta))
                signed_gains.append(-delta)
        passed = (
            hard_equal
            and exact_logits_equal
            and max_probability_error <= _DUPLICATE_PROBABILITY_TOLERANCE
            and max_nll_error <= _DUPLICATE_NLL_TOLERANCE_BITS
        )
        duplicate_pass = duplicate_pass and passed
        duplicate_summary[str(factor)] = {
            "hard_predictions_equal": hard_equal,
            "exact_logits_equal": exact_logits_equal,
            "maximum_probability_error": max_probability_error,
            "maximum_nll_error_bits": max_nll_error,
            "maximum_signed_compression_gain_bits": max(signed_gains),
            "minimum_signed_compression_gain_bits": min(signed_gains),
            "passed": passed,
        }
    gates["duplicate_expansion_invariant"] = duplicate_pass

    comparison_prefix = config.independent_group_prefixes.index(
        config.independent_comparison_groups
    )
    comparison_factor = config.independent_comparison_repeat_factor
    independent_gains: list[float] = []
    duplicate_exact_cells = 0
    independent_exact_cells = 0
    for seed in config.evaluation_seeds:
        independent_row = curves[f"base/{seed}/{PRIMARY_ARM}"][-1]
        duplicate_row = curves[
            f"duplicate_r{comparison_factor}/{seed}/{PRIMARY_ARM}"
        ][comparison_prefix]
        independent_gains.append(
            float(duplicate_row["nll_bits"]) - float(independent_row["nll_bits"])
        )
        independent_exact_cells += int(bool(independent_row["exact"]))
        duplicate_exact_cells += int(bool(duplicate_row["exact"]))
    gates["independent_replacement_material_gain"] = (
        min(independent_gains) > _NLL_TOLERANCE_BITS
        and float(np.mean(independent_gains)) >= _MATERIAL_BITS
        and independent_exact_cells == len(config.evaluation_seeds)
        and duplicate_exact_cells == 0
    )

    oracle_rows = [
        curves[f"base/{seed}/{ORACLE_ARM}"][-1]
        for seed in config.evaluation_seeds
    ]
    gates["generator_oracle_ceiling_sufficient"] = all(
        bool(row["exact"])
        and float(row["compression_bits"]) > _NLL_TOLERANCE_BITS
        and float(row["nll_bits"]) <= _FINAL_NLL_MAX
        for row in oracle_rows
    )
    expected_regret_bits: list[float] = []
    realized_oracle_margin_bits: list[float] = []
    for seed in config.evaluation_seeds:
        primary_logits = predictions[f"base/{seed}/{PRIMARY_ARM}"][-1]
        oracle_logits = predictions[f"base/{seed}/{ORACLE_ARM}"][-1]
        primary_q = np.clip(_sigmoid(primary_logits), 1e-15, 1.0 - 1e-15)
        oracle_q = np.clip(_sigmoid(oracle_logits), 1e-15, 1.0 - 1e-15)
        kl = oracle_q * np.log2(oracle_q / primary_q) + (
            1.0 - oracle_q
        ) * np.log2((1.0 - oracle_q) / (1.0 - primary_q))
        expected_regret_bits.append(float(np.sum(kl)))
        realized_oracle_margin_bits.append(
            float(curves[f"base/{seed}/{PRIMARY_ARM}"][-1]["nll_bits"])
            - float(curves[f"base/{seed}/{ORACLE_ARM}"][-1]["nll_bits"])
        )
    gates["oracle_expected_regret_nonnegative"] = (
        min(expected_regret_bits) >= -_NLL_TOLERANCE_BITS
    )

    failed = sorted(name for name, passed in gates.items() if not passed)
    if not gates["generator_oracle_ceiling_sufficient"]:
        classification = "GENERATOR_CEILING_INSUFFICIENT"
    elif not all(
        gates[name]
        for name in (
            "outcome_public_fsm_reference_exact_every_seed",
            "outcome_public_fsm_complement_antisymmetry",
            "outcome_public_fsm_opaque_id_equivariance",
            "outcome_public_fsm_coordinate_equivariance",
            "outcome_public_fsm_duplicate_expansion_invariant",
        )
    ):
        classification = "PUBLIC_FSM_REFERENCE_INSUFFICIENT"
    elif not gates["zero_prior_baseline_exact_null"]:
        classification = "TRUTH_PATH_LEAKAGE"
    elif not all(
        gates[name]
        for name in (
            "complement_logit_antisymmetry",
            "complement_probability_antisymmetry",
            "opaque_id_equality_equivariance",
            "coordinate_permutation_equivariance",
        )
    ):
        classification = "COMPLEMENT_OR_EQUIVARIANCE_FAILURE"
    elif not gates["duplicate_expansion_invariant"]:
        positive = any(
            float(row["maximum_signed_compression_gain_bits"])
            > _DUPLICATE_NLL_TOLERANCE_BITS
            for row in duplicate_summary.values()
        )
        classification = (
            "DUPLICATE_CONFIDENCE_INFLATION"
            if positive
            else "DUPLICATE_INSTABILITY"
        )
    elif not gates["independent_replacement_material_gain"] or not all(
        gates[name]
        for name in (
            "independent_prefix_growth_every_seed",
            "independent_prefix_mean_growth_material",
            "independent_prefix_backslide_bounded",
        )
    ):
        classification = "NO_INDEPENDENT_COMPOUNDING"
    elif not gates["control_same_route_last_margin"]:
        classification = "ROUTING_OR_ONE_SHOT_SUFFICIENT"
    elif not gates["control_same_route_unit_sum_margin"]:
        classification = "DIRECT_SUM_SUFFICIENT"
    elif not gates["control_same_encoder_static_sum_margin"]:
        classification = "STATIC_ENCODER_SUM_SUFFICIENT"
    elif not gates["control_same_encoder_current_marker_sum_margin"]:
        classification = "CURRENT_MARKER_STATIC_SUM_SUFFICIENT"
    elif not all(
        gates[name]
        for name in (
            "control_shuffled_confidence_margin",
            "control_all_open_margin",
        )
    ):
        classification = "SHUFFLED_CONFIDENCE_OR_ALL_OPEN_CONTROL_FAILURE"
    elif not gates["primary_aggregate_ece_at_most_005"]:
        classification = "UNCALIBRATED_POSTERIOR"
    elif not all(
        gates[name]
        for name in (
            "primary_final_exact_every_seed",
            "primary_final_positive_compression_every_seed",
            "primary_final_nll_at_most_32_every_seed",
            "primary_final_no_ties",
        )
    ):
        classification = "NOT_EXACT_256"
    elif failed:
        classification = "INTEGRITY_LIFECYCLE_OR_MATCHED_WORK_FAILURE"
    else:
        classification = "EXACT_256_LEARNED_CAUSAL_ACCUMULATION"

    report = {
        "schema": "o1-256-causal-evidence-recomputed-scores-v1",
        "classification": classification,
        "success_gate_passed": classification
        == "EXACT_256_LEARNED_CAUSAL_ACCUMULATION"
        and not failed,
        "gates": gates,
        "failed_gates": failed,
        "tolerances": {
            "relative_float32": _EPS32_TOLERANCE,
            "nll_bits": _NLL_TOLERANCE_BITS,
            "duplicate_nll_bits": _DUPLICATE_NLL_TOLERANCE_BITS,
            "duplicate_probability": _DUPLICATE_PROBABILITY_TOLERANCE,
            "material_bits": _MATERIAL_BITS,
            "final_nll_max": _FINAL_NLL_MAX,
            "ece_max": _ECE_MAX,
            "backslide_max_bits": _BACKSLIDE_MAX_BITS,
        },
        "primary": {
            "final_by_seed": {
                str(seed): curves[f"base/{seed}/{PRIMARY_ARM}"][-1]
                for seed in config.evaluation_seeds
            },
            "compression_curve_by_seed": {
                str(seed): primary_compressions[index].tolist()
                for index, seed in enumerate(config.evaluation_seeds)
            },
            "growth_bits_by_seed": growth.tolist(),
            "mean_curve": mean_curve.tolist(),
            "total_mean_backslide_bits": total_backslide,
            "aggregate_ece_16": aggregate_ece,
        },
        "controls": control_summaries,
        "outcome_public_fsm_reference": public_fsm_reference,
        "complement": {
            "maximum_relative_logit_error": max(complement_errors),
            "maximum_probability_error": max(complement_probability_errors),
            "metadata_pair_compression_bits": metadata_pair_compressions,
            "metadata_exact_cells": metadata_exact_cells,
        },
        "equivariance": {
            "opaque_id_maximum_logit_error": max(id_errors),
            "coordinate_maximum_logit_error": max(coordinate_errors),
        },
        "duplicates": duplicate_summary,
        "independent_replacement": {
            "comparison_groups": config.independent_comparison_groups,
            "duplicate_factor": comparison_factor,
            "nll_gain_bits_by_seed": independent_gains,
            "mean_nll_gain_bits": float(np.mean(independent_gains)),
            "independent_exact_cells": independent_exact_cells,
            "duplicate_exact_cells": duplicate_exact_cells,
        },
        "oracle": {
            "final_by_seed": {
                str(seed): curves[f"base/{seed}/{ORACLE_ARM}"][-1]
                for seed in config.evaluation_seeds
            },
            "expected_regret_bits_by_seed": expected_regret_bits,
            "realized_primary_minus_oracle_nll_bits_by_seed": realized_oracle_margin_bits,
        },
        "prediction_blob_sha256": _sha256(prediction_blob),
        "prediction_index_sha256": _sha256(prediction_index),
        "truth_blob_sha256": _sha256(truth_blob),
        "truth_index_sha256": _sha256(truth_index),
        "truth_record_count": int(truth_document["record_count"]),
    }
    report["metrics_sha256"] = _sha256(_canonical_json(report))
    return report


@dataclass(frozen=True)
class CausalEvidenceResult:
    report: Mapping[str, object]
    success_gate_passed: bool


def _freeze_document(value: Mapping[str, object]) -> tuple[dict[str, object], bytes]:
    document = dict(value)
    if "freeze_sha256" in document:
        raise CausalEvidenceError("freeze document already contains its commitment")
    document["freeze_sha256"] = _sha256(_canonical_json(document))
    return document, _canonical_json(document)


def _artifact_commitments(artifacts: Mapping[str, bytes]) -> dict[str, object]:
    return {
        name: {"sha256": _sha256(payload), "bytes": len(payload)}
        for name, payload in sorted(artifacts.items())
    }


def _verify_freeze_document(
    document: Mapping[str, object],
    artifacts_without_document: Mapping[str, bytes],
) -> None:
    freeze_sha256 = document.get("freeze_sha256")
    if not isinstance(freeze_sha256, str):
        raise CausalEvidenceError("freeze document commitment is missing")
    unhashed = dict(document)
    del unhashed["freeze_sha256"]
    if freeze_sha256 != _sha256(_canonical_json(unhashed)):
        raise CausalEvidenceError("freeze document commitment differs")
    if document.get("artifact_commitments") != _artifact_commitments(
        artifacts_without_document
    ):
        raise CausalEvidenceError("freeze artifact commitments differ")


def _invoke_freeze_callback(
    callback: Callable[[Mapping[str, bytes], Mapping[str, object]], None] | None,
    artifacts: Mapping[str, bytes],
    document: Mapping[str, object],
    *,
    document_name: str,
) -> None:
    if document_name not in artifacts:
        raise CausalEvidenceError("freeze document artifact is missing")
    without_document = {
        name: payload for name, payload in artifacts.items() if name != document_name
    }
    _verify_freeze_document(document, without_document)
    expected_document = _canonical_json(document)
    if artifacts[document_name] != expected_document:
        raise CausalEvidenceError("freeze document artifact bytes differ")
    if callback is None:
        return
    callback_document = deepcopy(dict(document))
    callback_artifacts = MappingProxyType(dict(artifacts))
    callback(callback_artifacts, callback_document)
    if _canonical_json(callback_document) != expected_document:
        raise CausalEvidenceError("freeze callback mutated its document view")
    _verify_freeze_document(document, without_document)
    if artifacts[document_name] != expected_document:
        raise CausalEvidenceError("freeze callback changed committed artifact bytes")


def _serialize_secret_materials(
    materials: Mapping[int, bytes],
) -> tuple[bytes, bytes]:
    payload = bytearray()
    rows: list[dict[str, object]] = []
    for seed in sorted(materials):
        material = materials[seed]
        if not isinstance(material, bytes) or len(material) < 32:
            raise CausalEvidenceError("evaluation secret material is too short")
        offset = len(payload)
        payload.extend(material)
        rows.append(
            {
                "seed": seed,
                "offset_bytes": offset,
                "bytes": len(material),
                "sha256": _sha256(material),
            }
        )
    document = {
        "schema": "o1-256-causal-evidence-secret-material-index-v1",
        "record_count": len(rows),
        "bytes": len(payload),
        "blob_sha256": _sha256(bytes(payload)),
        "records": rows,
    }
    return bytes(payload), _canonical_json(document)


def _default_nonformal_material_provider(
    seeds: tuple[int, ...],
) -> tuple[Mapping[int, bytes], int]:
    return (
        {
            seed: hashlib.sha256(
                struct.pack("<q", seed) + b"o1c0021-nonformal-eval-material"
            ).digest()
            for seed in seeds
        },
        0,
    )


def _temperature_logits(
    execution: EpisodeExecution,
    reader: FrozenCausalEvidenceReader,
) -> dict[str, np.ndarray]:
    return {
        arm: (
            np.asarray(execution.raw_scores[arm], dtype=np.float64)
            * float(reader.temperatures[arm])
        ).astype(np.float32)
        for arm in ALL_ARMS
    }


def _execution_integrity_gates(
    config: CausalEvidenceConfig,
    receipts: Mapping[str, Mapping[str, object]],
    *,
    entropy_calls: int,
) -> tuple[dict[str, bool], dict[str, object]]:
    gates: dict[str, bool] = {}
    complement_rows: dict[str, object] = {}
    matched_work_rows: dict[str, object] = {}
    state_rows: dict[str, object] = {}
    public_fsm_state_rows: dict[str, object] = {}
    duplicate_state_rows: dict[str, object] = {}
    duplicate_public_fsm_state_rows: dict[str, object] = {}
    for seed in config.evaluation_seeds:
        base = receipts[f"base/{seed}"]
        complement = receipts[f"complement/{seed}"]
        complement_ok = (
            base["metadata_sha256"] == complement["metadata_sha256"]
            and base["route_mask_sha256"] == complement["route_mask_sha256"]
            and base["evidence_vote_sha256"]
            == complement["negated_evidence_vote_sha256"]
            and base["negated_evidence_vote_sha256"]
            == complement["evidence_vote_sha256"]
            and base["offered_compute_work_sha256"]
            == complement["offered_compute_work_sha256"]
        )
        complement_rows[str(seed)] = complement_ok
        base_prefix = base["prefix_offered_compute_work"][-1]
        duplicate = receipts[
            f"duplicate_r{config.independent_comparison_repeat_factor}/{seed}"
        ]
        comparison_index = config.independent_group_prefixes.index(
            config.independent_comparison_groups
        )
        duplicate_prefix = duplicate["prefix_offered_compute_work"][comparison_index]
        matched = base_prefix["sha256"] == duplicate_prefix["sha256"]
        matched_work_rows[str(seed)] = {
            "matched": matched,
            "independent_sha256": base_prefix["sha256"],
            "duplicate_sha256": duplicate_prefix["sha256"],
        }
        state_ok = all(
            int(receipts[f"{variant}/{seed}"]["state_bytes"])
            == config.live_state_bytes
            for variant in (
                "base",
                *(f"duplicate_r{factor}" for factor in config.repeat_factors[1:]),
                "complement",
                "id_permutation",
                "coordinate_permutation",
            )
        )
        state_rows[str(seed)] = state_ok
        public_fsm_state_ok = all(
            int(receipts[f"{variant}/{seed}"]["public_fsm_state_bytes"])
            == config.n_bits + 17
            for variant in (
                "base",
                *(f"duplicate_r{factor}" for factor in config.repeat_factors[1:]),
                "complement",
                "id_permutation",
                "coordinate_permutation",
            )
        )
        public_fsm_state_rows[str(seed)] = public_fsm_state_ok
        duplicate_state_ok = all(
            receipts[f"duplicate_r{factor}/{seed}"]["prefix_state_sha256"]
            == base["prefix_state_sha256"]
            and receipts[f"duplicate_r{factor}/{seed}"]["final_state_sha256"]
            == base["final_state_sha256"]
            for factor in config.repeat_factors[1:]
        )
        duplicate_state_rows[str(seed)] = duplicate_state_ok
        duplicate_public_fsm_state_ok = all(
            receipts[f"duplicate_r{factor}/{seed}"][
                "public_fsm_prefix_state_sha256"
            ]
            == base["public_fsm_prefix_state_sha256"]
            and receipts[f"duplicate_r{factor}/{seed}"][
                "public_fsm_final_state_sha256"
            ]
            == base["public_fsm_final_state_sha256"]
            for factor in config.repeat_factors[1:]
        )
        duplicate_public_fsm_state_rows[str(seed)] = (
            duplicate_public_fsm_state_ok
        )
    gates["complement_metadata_route_vote_integrity"] = all(
        bool(value) for value in complement_rows.values()
    )
    gates["independent_replacement_offered_work_matched"] = all(
        bool(value["matched"]) for value in matched_work_rows.values()
    )
    gates["live_state_exact_declared_width_every_execution"] = all(
        bool(value) for value in state_rows.values()
    )
    gates["formal_live_state_is_exactly_352_bytes"] = config.live_state_bytes == 352
    gates["public_fsm_live_state_exactly_273_bytes_every_execution"] = all(
        bool(value) for value in public_fsm_state_rows.values()
    )
    gates["duplicate_full_live_state_exactly_invariant"] = all(
        bool(value) for value in duplicate_state_rows.values()
    )
    gates["duplicate_public_fsm_live_state_exactly_invariant"] = all(
        bool(value) for value in duplicate_public_fsm_state_rows.values()
    )
    gates["fresh_post_learning_evaluation_material"] = entropy_calls == 1
    return gates, {
        "complement_by_seed": complement_rows,
        "independent_replacement_work_by_seed": matched_work_rows,
        "state_width_by_seed": state_rows,
        "public_fsm_state_width_by_seed": public_fsm_state_rows,
        "duplicate_state_invariance_by_seed": duplicate_state_rows,
        "duplicate_public_fsm_state_invariance_by_seed": (
            duplicate_public_fsm_state_rows
        ),
        "scientific_entropy_calls": entropy_calls,
    }


def run_causal_evidence_stream(
    config: CausalEvidenceConfig,
    *,
    on_learning_frozen: Callable[[Mapping[str, bytes], Mapping[str, object]], None]
    | None = None,
    on_predictions_frozen: Callable[[Mapping[str, bytes], Mapping[str, object]], None]
    | None = None,
    on_truth_revealed_before_scoring: Callable[
        [Mapping[str, bytes], Mapping[str, object]], None
    ]
    | None = None,
    evaluation_material_provider: Callable[
        [tuple[int, ...]], tuple[Mapping[int, bytes], int]
    ]
    | None = None,
) -> CausalEvidenceResult:
    """BUILD, CAL, freeze, blind EVAL, reveal, and recompute O1C-0021."""

    require_torch()
    primary_training = train_causal_evidence_reader(
        config, name="primary", shuffled_coefficients=False
    )
    shuffled_training = train_causal_evidence_reader(
        config, name="shuffled_confidence", shuffled_coefficients=True
    )
    reader = calibrate_causal_evidence_readers(
        config, primary_training, shuffled_training
    )
    learning_payloads: dict[str, bytes] = {
        "learning/primary_slow_state.bin": reader.primary_slow_state_bytes,
        "learning/shuffled_confidence_slow_state.bin": reader.shuffled_slow_state_bytes,
        "learning/outcome_public_fsm.i8": (
            reader.public_fsm_coefficients.tobytes(order="C")
        ),
        "learning/calibration.json": _canonical_json(
            {
                "schema": "o1-256-causal-evidence-calibration-v1",
                "route_threshold": reader.route_threshold,
                "temperatures": dict(reader.temperatures),
                "training": reader.training_metrics,
                "calibration": reader.calibration_metrics,
            }
        ),
    }
    learning_document, learning_document_payload = _freeze_document(
        {
            "schema": LEARNING_FREEZE_SCHEMA,
            "phase": "ALL_SLOW_STATES_FROZEN_BEFORE_EVALUATION_LEDGER_GENERATION",
            "evaluation_ledgers_generated": 0,
            "evaluation_tokens_seen": 0,
            "evaluation_slow_updates": 0,
            "primary_slow_state_sha256": reader.primary_slow_state_sha256,
            "shuffled_slow_state_sha256": reader.shuffled_slow_state_sha256,
            "initial_state_sha256": reader.initial_state_sha256,
            "outcome_public_fsm_sha256": (
                reader.public_fsm_coefficients_sha256
            ),
            "route_threshold": reader.route_threshold,
            "temperatures": dict(reader.temperatures),
            "artifact_commitments": _artifact_commitments(learning_payloads),
        }
    )
    learning_payloads["learning/learning_freeze.json"] = learning_document_payload
    _invoke_freeze_callback(
        on_learning_frozen,
        learning_payloads,
        learning_document,
        document_name="learning/learning_freeze.json",
    )
    if (
        canonical_module_bytes(reader.primary) != reader.primary_slow_state_bytes
        or canonical_module_bytes(reader.shuffled) != reader.shuffled_slow_state_bytes
    ):
        raise CausalEvidenceError("learning-freeze callback changed a slow state")

    provider = evaluation_material_provider or _default_nonformal_material_provider
    supplied_materials, entropy_calls = provider(config.evaluation_seeds)
    if (
        not isinstance(supplied_materials, Mapping)
        or set(supplied_materials) != set(config.evaluation_seeds)
        or isinstance(entropy_calls, bool)
        or not isinstance(entropy_calls, int)
        or entropy_calls < 0
    ):
        raise CausalEvidenceError("evaluation material provider result differs")
    materials = {seed: bytes(supplied_materials[seed]) for seed in config.evaluation_seeds}
    for material in materials.values():
        if len(material) < 32:
            raise CausalEvidenceError("evaluation material is shorter than 256 bits")
    if len(set(materials.values())) != len(materials):
        raise CausalEvidenceError("evaluation materials must be distinct by seed")

    prediction_records: dict[str, tuple[np.ndarray, str, np.ndarray]] = {}
    receipts: dict[str, Mapping[str, object]] = {}
    route_artifacts: dict[str, bytes] = {}
    state_artifacts: dict[str, bytes] = {}
    public_fsm_state_artifacts: dict[str, bytes] = {}
    ledgers: dict[str, SealedEvidenceTruthLedger] = {}
    evaluation_work = {
        "physical_public_tokens": 0,
        "gate_token_evaluations": 0,
        "coefficient_query_tokens": 0,
        "core_marker_updates": 0,
        "current_marker_control_updates": 0,
        "accepted_update_opportunities": 0,
        "public_fsm_table_lookups": 0,
        "logical_arm_updates": 0,
    }

    def record_execution(
        *,
        variant: str,
        seed: int,
        truth_key: str,
        episode: PublicEvidenceEpisode,
        execution: EpisodeExecution,
    ) -> None:
        key = f"{variant}/{seed}"
        if key in receipts:
            raise CausalEvidenceError("duplicate evaluation execution key")
        receipts[key] = dict(execution.receipt)
        logits = _temperature_logits(execution, reader)
        for arm in ALL_ARMS:
            prediction_records[f"{key}/{arm}"] = (
                logits[arm],
                truth_key,
                episode.logical_to_public,
            )
        safe = f"{variant}_{seed}"
        route_artifacts[f"prediction/routes/{safe}.bitpack"] = (
            execution.route_mask_bytes
        )
        state_artifacts[f"prediction/states/{safe}.bin"] = execution.final_state_bytes
        public_fsm_state_artifacts[f"prediction/fsm_states/{safe}.bin"] = (
            execution.public_fsm_final_state_bytes
        )
        for field in evaluation_work:
            evaluation_work[field] += int(execution.work[field])

    for seed in config.evaluation_seeds:
        material = materials[seed]
        base_episode, base_ledger = build_public_evidence_episode(
            config, seed, secret_material=material
        )
        ledgers[f"base/{seed}"] = base_ledger
        for factor in config.repeat_factors:
            execution = execute_public_evidence_episode(
                config, reader, base_episode, repeat_factor=factor
            )
            variant = "base" if factor == 1 else f"duplicate_r{factor}"
            record_execution(
                variant=variant,
                seed=seed,
                truth_key=f"base/{seed}",
                episode=base_episode,
                execution=execution,
            )
        variants = (
            (
                "complement",
                {
                    "complement": True,
                },
            ),
            (
                "id_permutation",
                {
                    "id_permutation_salt": 0x1D9E21,
                },
            ),
            (
                "coordinate_permutation",
                {
                    "coordinate_permutation_salt": 0xC00FD1A7,
                },
            ),
        )
        for variant, kwargs in variants:
            episode, ledger = build_public_evidence_episode(
                config,
                seed,
                secret_material=material,
                **kwargs,
            )
            truth_key = f"{variant}/{seed}"
            ledgers[truth_key] = ledger
            execution = execute_public_evidence_episode(
                config, reader, episode, repeat_factor=1
            )
            record_execution(
                variant=variant,
                seed=seed,
                truth_key=truth_key,
                episode=episode,
                execution=execution,
            )

    if any(ledger.reveal_count != 0 for ledger in ledgers.values()):
        raise CausalEvidenceError("evaluation truth was revealed before prediction freeze")
    prediction_blob, prediction_index_payload = _serialize_prediction_records(
        config, prediction_records
    )
    receipt_payload = _canonical_json(
        {
            "schema": "o1-256-causal-evidence-receipts-v1",
            "receipts": dict(sorted(receipts.items())),
        }
    )
    material_commitments = {
        str(seed): _sha256(materials[seed]) for seed in config.evaluation_seeds
    }
    prediction_payloads: dict[str, bytes] = {
        "prediction/evaluation_predictions.f32le": prediction_blob,
        "prediction/evaluation_predictions_index.json": prediction_index_payload,
        "prediction/evaluation_receipts.json": receipt_payload,
        **route_artifacts,
        **state_artifacts,
        **public_fsm_state_artifacts,
    }
    prediction_document, prediction_document_payload = _freeze_document(
        {
            "schema": PREDICTION_FREEZE_SCHEMA,
            "phase": "ALL_EVALUATION_PREDICTIONS_FROZEN_BEFORE_TRUTH_REVEAL",
            "parent_learning_freeze_sha256": learning_document["freeze_sha256"],
            "truth_ledger_count": len(ledgers),
            "truth_ledger_reveal_count": 0,
            "scorer_calls": 0,
            "evaluation_slow_updates": 0,
            "evaluation_seeds": list(config.evaluation_seeds),
            "prefixes": list(config.independent_group_prefixes),
            "arms": list(ALL_ARMS),
            "repeat_factors": list(config.repeat_factors),
            "transforms": [
                "complement",
                "id_permutation",
                "coordinate_permutation",
            ],
            "prediction_value_count": config.prediction_value_count,
            "secret_material_commitments": material_commitments,
            "artifact_commitments": _artifact_commitments(prediction_payloads),
        }
    )
    prediction_payloads[
        "prediction/prediction_freeze.json"
    ] = prediction_document_payload
    _invoke_freeze_callback(
        on_predictions_frozen,
        prediction_payloads,
        prediction_document,
        document_name="prediction/prediction_freeze.json",
    )

    truth_records: dict[str, np.ndarray] = {}
    for key, ledger in sorted(ledgers.items()):
        truth_records[key] = ledger.reveal().bits
    if any(ledger.reveal_count != 1 for ledger in ledgers.values()):
        raise CausalEvidenceError("evaluation truth ledger lifecycle differs")
    truth_blob, truth_index_payload = _serialize_truth_records(truth_records)
    material_blob, material_index_payload = _serialize_secret_materials(materials)
    truth_payloads: dict[str, bytes] = {
        "truth/evaluation_truth.bitpack": truth_blob,
        "truth/evaluation_truth_index.json": truth_index_payload,
        "truth/evaluation_secret_material.bin": material_blob,
        "truth/evaluation_secret_material_index.json": material_index_payload,
    }
    truth_document, truth_document_payload = _freeze_document(
        {
            "schema": TRUTH_REVEAL_SCHEMA,
            "phase": "RAW_EVALUATION_TRUTH_PERSISTED_AFTER_PREDICTION_FREEZE_BEFORE_SCORING",
            "parent_prediction_freeze_sha256": prediction_document["freeze_sha256"],
            "truth_ledger_count": len(ledgers),
            "truth_ledger_reveal_count_per_ledger": 1,
            "total_truth_ledgers_revealed": len(ledgers),
            "scorer_calls": 0,
            "bitorder": "little",
            "secret_material_commitments": material_commitments,
            "artifact_commitments": _artifact_commitments(truth_payloads),
        }
    )
    truth_payloads["truth/truth_reveal.json"] = truth_document_payload
    _invoke_freeze_callback(
        on_truth_revealed_before_scoring,
        truth_payloads,
        truth_document,
        document_name="truth/truth_reveal.json",
    )

    scores = recompute_causal_evidence_scores(
        config,
        prediction_blob=prediction_blob,
        prediction_index=prediction_index_payload,
        truth_blob=truth_blob,
        truth_index=truth_index_payload,
    )
    integrity_gates, integrity_detail = _execution_integrity_gates(
        config, receipts, entropy_calls=entropy_calls
    )
    all_gates = {**scores["gates"], **integrity_gates}
    failed_gates = sorted(name for name, passed in all_gates.items() if not passed)
    classification = str(scores["classification"])
    if any(not passed for passed in integrity_gates.values()):
        classification = "INTEGRITY_LIFECYCLE_OR_MATCHED_WORK_FAILURE"
    success = (
        classification == "EXACT_256_LEARNED_CAUSAL_ACCUMULATION"
        and not failed_gates
    )
    if (
        canonical_module_bytes(reader.primary) != reader.primary_slow_state_bytes
        or canonical_module_bytes(reader.shuffled) != reader.shuffled_slow_state_bytes
    ):
        raise CausalEvidenceError("EVAL changed a frozen slow state")
    total_slow_state_bytes = (
        len(reader.primary_slow_state_bytes)
        + len(reader.shuffled_slow_state_bytes)
        + int(reader.public_fsm_coefficients.nbytes)
    )
    report: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "classification": classification,
        "success_gate_passed": success,
        "gates": all_gates,
        "failed_gates": failed_gates,
        "scores": scores,
        "integrity": integrity_detail,
        "learning_freeze_sha256": learning_document["freeze_sha256"],
        "prediction_freeze_sha256": prediction_document["freeze_sha256"],
        "truth_reveal_sha256": truth_document["freeze_sha256"],
        "state": {
            "o1_fast_state_bytes": config.core_config.fast_state_bytes(),
            "evidence_vault_bytes": config.n_bits,
            "fixed_counters_bytes": 16,
            "total_live_state_bytes": config.live_state_bytes,
            "stream_length_dependent_model_state": False,
            "external_index_bytes": 0,
            "total_slow_state_bytes": total_slow_state_bytes,
            "outcome_public_fsm_live_state_bytes": config.n_bits + 17,
            "outcome_public_fsm_slow_table_bytes": int(
                reader.public_fsm_coefficients.nbytes
            ),
            "slow_state_billed_separately": True,
        },
        "work": {
            **evaluation_work,
            "calibration_physical_public_tokens": int(
                reader.calibration_metrics["work"]["physical_public_tokens"]
            ),
            "calibration_reader_token_evaluations": int(
                reader.calibration_metrics["work"]["reader_token_evaluations"]
            ),
            "public_fsm_calibration_table_lookups": int(
                reader.calibration_metrics["work"]["public_fsm_table_lookups"]
            ),
            "temperature_grid_value_evaluations": int(
                reader.calibration_metrics["work"][
                    "temperature_grid_value_evaluations"
                ]
            ),
            "training_token_exposures": int(
                primary_training.metrics["token_exposures"]
                + shuffled_training.metrics["token_exposures"]
            ),
            "public_fsm_build_outcome_lookups": int(
                primary_training.metrics["outcome_public_fsm"]["outcome_lookups"]
                + shuffled_training.metrics["outcome_public_fsm"][
                    "outcome_lookups"
                ]
            ),
            "public_fsm_evaluation_table_lookups": int(
                evaluation_work["public_fsm_table_lookups"]
            ),
            "scientific_entropy_calls": entropy_calls,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "native_solver_branches": 0,
            "mps_calls": 0,
            "gpu_calls": 0,
        },
        "artifacts": {
            "prediction_blob_sha256": _sha256(prediction_blob),
            "prediction_index_sha256": _sha256(prediction_index_payload),
            "truth_blob_sha256": _sha256(truth_blob),
            "truth_index_sha256": _sha256(truth_index_payload),
            "receipts_sha256": _sha256(receipt_payload),
        },
        "claim_boundary": (
            "Synthetic weak-evidence accumulation only; no ChaCha20 output or "
            "solver-native cipher signal is claimed. Public-FSM parity rules out "
            "any claim that O1 is necessary or superior on this synthetic task."
        ),
    }
    report["result_sha256"] = _sha256(_canonical_json(report))
    return CausalEvidenceResult(report=report, success_gate_passed=success)


__all__ = [
    "ALL_ARMS",
    "CAUSAL_EVIDENCE_SCHEMA",
    "CONTROL_ARMS",
    "DIAGNOSTIC_ARMS",
    "CausalEvidenceConfig",
    "CausalEvidenceError",
    "CausalEvidenceResult",
    "CausalEvidenceState",
    "EpisodeExecution",
    "EvidenceTruthAccessError",
    "FrozenCausalEvidenceReader",
    "LEARNING_FREEZE_SCHEMA",
    "LearnedCausalEvidenceReader",
    "ORACLE_ARM",
    "OutcomePublicFSMState",
    "PREDICTION_FREEZE_SCHEMA",
    "PRIMARY_ARM",
    "PUBLIC_FSM_ARM",
    "PREDICTION_INDEX_SCHEMA",
    "PublicEvidenceEpisode",
    "PublicEvidenceGroup",
    "RESULT_SCHEMA",
    "ReaderTrainingResult",
    "RevealedEvidenceTruth",
    "SealedEvidenceTruthLedger",
    "TRUTH_INDEX_SCHEMA",
    "TRUTH_REVEAL_SCHEMA",
    "build_public_evidence_episode",
    "calibrate_causal_evidence_readers",
    "execute_public_evidence_episode",
    "recompute_causal_evidence_scores",
    "run_causal_evidence_stream",
    "train_causal_evidence_reader",
]
