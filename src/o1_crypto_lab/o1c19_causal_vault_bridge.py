"""Label-free bridge from frozen O1C-0019 packet readers to the O1C-0021 vault.

The bridge deliberately starts *after* reader fitting.  A frozen O1C-0019
reader streams one public paired-branch action pool and exposes the exact
packet-local increments ``q_after - q_before`` already stored by
``MultiResolutionFastState.packet_evidence``.  This module then:

* selects nested public coordinate prefixes K=12/52/128/256;
* freezes one label-free median-absolute scale per ordered horizon;
* symmetrically quantizes each increment with explicit half-away-from-zero
  rounding and clipping to ``[-8, 8]``;
* accumulates the result in the exact 352-byte O1C-0021
  :class:`~o1_crypto_lab.causal_evidence_stream.CausalEvidenceState`; and
* carries raw-float, normalized-float, unit-sign, last-only and
  coordinate-shuffled controls with identical offered packet work.

No key, outcome, solver, candidate table, or reveal API is accepted anywhere
in the execution surface.  The frozen upstream O1C-0019 reader is model
storage and is therefore inventoried separately from the 352-byte live vault.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
from dataclasses import dataclass
from typing import Mapping, Sequence

import numpy as np

from .causal_evidence_stream import (
    CausalEvidenceConfig,
    CausalEvidenceState,
)
from .full256_action_pool import Full256ActionPool
from .online_causal_controller import CausalAction, KEY_BITS


BRIDGE_SCHEMA = "o1-256-o1c19-causal-vault-bridge-v1"
ACTIVE_COORDINATE_SCHEMA = "o1-256-o1c22-nested-active-coordinates-v1"
PACKET_DELTA_GROUP_SCHEMA = "o1-256-o1c22-packet-delta-group-v1"
MEDIAN_ABS_QUANTIZER_SCHEMA = "o1-256-o1c22-median-abs-quantizer-v1"
PACKET_EXTRACTION_SCHEMA = "o1-256-o1c22-packet-delta-extraction-v1"
BRIDGE_EXECUTION_SCHEMA = "o1-256-o1c22-causal-vault-execution-v1"

ACTIVE_COORDINATE_WIDTHS = (12, 52, 128, 256)
QUANTIZER_LIMIT = 8
FORMAL_VAULT_BYTES = 352

_MASK64 = (1 << 64) - 1
_ACTIVE_DOMAIN = b"o1c22-nested-active-coordinate-order-v1\x00"
_SHUFFLE_DOMAIN = b"o1c22-coordinate-shuffled-destination-v1\x00"
_GROUP_DOMAIN = b"o1c22-public-packet-delta-group-v1\x00"


class O1C19CausalVaultBridgeError(ValueError):
    """A bridge plan, public packet, state, or accounting invariant differs."""


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C19CausalVaultBridgeError(f"{field} must be a lowercase SHA-256")
    return value


def _require_uint64(value: object, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= _MASK64
    ):
        raise O1C19CausalVaultBridgeError(f"{field} must be uint64-compatible")
    return value


def _require_coordinate(value: object, field: str = "coordinate") -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < KEY_BITS
    ):
        raise O1C19CausalVaultBridgeError(f"{field} must be in [0,255]")
    return value


def _require_horizons(value: object, field: str = "horizons") -> tuple[int, ...]:
    try:
        result = tuple(value)  # type: ignore[arg-type]
    except TypeError as exc:
        raise O1C19CausalVaultBridgeError(
            f"{field} must be an integer sequence"
        ) from exc
    if (
        not result
        or tuple(sorted(result)) != result
        or len(set(result)) != len(result)
        or any(
            isinstance(item, bool)
            or not isinstance(item, int)
            or not 1 <= item <= np.iinfo(np.int32).max
            for item in result
        )
    ):
        raise O1C19CausalVaultBridgeError(
            f"{field} must be strictly increasing positive int32 values"
        )
    return result


def _require_permutation(value: object, field: str) -> tuple[int, ...]:
    try:
        result = tuple(value)  # type: ignore[arg-type]
    except TypeError as exc:
        raise O1C19CausalVaultBridgeError(
            f"{field} must be a 256-coordinate permutation"
        ) from exc
    if len(result) != KEY_BITS or set(result) != set(range(KEY_BITS)):
        raise O1C19CausalVaultBridgeError(
            f"{field} must be a 256-coordinate permutation"
        )
    if any(isinstance(item, bool) or not isinstance(item, int) for item in result):
        raise O1C19CausalVaultBridgeError(
            f"{field} must be a 256-coordinate permutation"
        )
    return result


def _float_hex(value: float) -> str:
    result = float(value)
    if not math.isfinite(result):
        raise O1C19CausalVaultBridgeError("serialized float must be finite")
    return result.hex()


def _float_from_hex(value: object, field: str) -> float:
    if not isinstance(value, str):
        raise O1C19CausalVaultBridgeError(f"{field} must be a float hex string")
    try:
        result = float.fromhex(value)
    except ValueError as exc:
        raise O1C19CausalVaultBridgeError(
            f"{field} must be a float hex string"
        ) from exc
    if not math.isfinite(result):
        raise O1C19CausalVaultBridgeError(f"{field} must be finite")
    return result


def deterministic_coordinate_permutation(
    source_stream_sha256: str,
    salt: int,
    *,
    shuffled_destination: bool = False,
) -> tuple[int, ...]:
    """Return a public SHA-256 permutation independent of target labels."""

    source = bytes.fromhex(
        _require_sha256(source_stream_sha256, "source_stream_sha256")
    )
    normalized_salt = _require_uint64(salt, "coordinate salt")
    domain = _SHUFFLE_DOMAIN if shuffled_destination else _ACTIVE_DOMAIN
    salt_bytes = struct.pack(">Q", normalized_salt)
    keyed = []
    for coordinate in range(KEY_BITS):
        digest = hashlib.sha256(
            domain + source + salt_bytes + struct.pack(">H", coordinate)
        ).digest()
        keyed.append((digest, coordinate))
    keyed.sort()
    return tuple(coordinate for _digest, coordinate in keyed)


@dataclass(frozen=True)
class NestedActiveCoordinatePlan:
    """Nested K-prefixes from one public, deterministic coordinate order."""

    source_stream_sha256: str
    salt: int

    def __post_init__(self) -> None:
        _require_sha256(self.source_stream_sha256, "source_stream_sha256")
        _require_uint64(self.salt, "coordinate salt")

    @property
    def coordinate_order(self) -> tuple[int, ...]:
        return deterministic_coordinate_permutation(
            self.source_stream_sha256,
            self.salt,
        )

    def active_coordinates(self, width: int) -> tuple[int, ...]:
        if width not in ACTIVE_COORDINATE_WIDTHS:
            raise O1C19CausalVaultBridgeError(
                "active width must be one of 12/52/128/256"
            )
        return self.coordinate_order[:width]

    def describe(self) -> dict[str, object]:
        order = self.coordinate_order
        return {
            "schema": ACTIVE_COORDINATE_SCHEMA,
            "source_stream_sha256": self.source_stream_sha256,
            "salt": self.salt,
            "derivation": "sha256-domain+source_stream_sha256+uint64be-salt+uint16be-coordinate",
            "coordinate_order": list(order),
            "active_widths": list(ACTIVE_COORDINATE_WIDTHS),
            "active_coordinates": {
                str(width): list(order[:width]) for width in ACTIVE_COORDINATE_WIDTHS
            },
            "label_accesses": 0,
        }

    def to_bytes(self) -> bytes:
        return _canonical_json(self.describe())

    @property
    def sha256(self) -> str:
        return _sha256_bytes(self.to_bytes())

    @classmethod
    def from_bytes(cls, value: bytes) -> "NestedActiveCoordinatePlan":
        try:
            row = json.loads(value.decode("ascii"))
        except (AttributeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise O1C19CausalVaultBridgeError(
                "active-coordinate plan is invalid JSON"
            ) from exc
        if not isinstance(row, Mapping):
            raise O1C19CausalVaultBridgeError(
                "active-coordinate plan must be an object"
            )
        try:
            result = cls(
                source_stream_sha256=row["source_stream_sha256"],
                salt=row["salt"],
            )
        except KeyError as exc:
            raise O1C19CausalVaultBridgeError(
                "active-coordinate plan fields differ"
            ) from exc
        if result.to_bytes() != value:
            raise O1C19CausalVaultBridgeError("active-coordinate plan is not canonical")
        return result


def _group_payload(group: "PacketDeltaGroup") -> dict[str, object]:
    return {
        "schema": PACKET_DELTA_GROUP_SCHEMA,
        "source_stream_sha256": group.source_stream_sha256,
        "action_pool_sha256": group.action_pool_sha256,
        "reader_state_sha256": group.reader_state_sha256,
        "active_coordinates_sha256": group.active_coordinates_sha256,
        "pair_sha256": group.pair_sha256,
        "coordinate": group.coordinate,
        "horizons": list(group.horizons),
        "incremental_deltas_float64_hex": [
            _float_hex(value) for value in group.incremental_deltas
        ],
        "incremental_work_units": list(group.incremental_work_units),
        "group_salt": group.group_salt,
        "delta_semantics": "exact-o1c19-q_after-minus-q_before",
        "packet_order": "strictly-increasing-controller-ordered-horizons",
        "label_accesses": 0,
    }


def _derived_group_digest(group: "PacketDeltaGroup") -> bytes:
    return hashlib.sha256(
        _GROUP_DOMAIN + _canonical_json(_group_payload(group))
    ).digest()


@dataclass(frozen=True)
class PacketDeltaGroup:
    """One coordinate-local, ordered packet emitted by a frozen O1C-0019 reader."""

    source_stream_sha256: str
    action_pool_sha256: str
    reader_state_sha256: str
    active_coordinates_sha256: str
    pair_sha256: str
    coordinate: int
    horizons: tuple[int, ...]
    incremental_deltas: tuple[float, ...]
    incremental_work_units: tuple[int, ...]
    group_salt: int = 0

    def __post_init__(self) -> None:
        _require_sha256(self.source_stream_sha256, "source_stream_sha256")
        _require_sha256(self.action_pool_sha256, "action_pool_sha256")
        _require_sha256(self.reader_state_sha256, "reader_state_sha256")
        _require_sha256(
            self.active_coordinates_sha256,
            "active_coordinates_sha256",
        )
        _require_sha256(self.pair_sha256, "pair_sha256")
        _require_coordinate(self.coordinate)
        horizons = _require_horizons(self.horizons)
        try:
            deltas = tuple(float(value) for value in self.incremental_deltas)
        except (TypeError, ValueError) as exc:
            raise O1C19CausalVaultBridgeError(
                "incremental_deltas must be numeric"
            ) from exc
        try:
            work = tuple(self.incremental_work_units)
        except TypeError as exc:
            raise O1C19CausalVaultBridgeError(
                "incremental_work_units must be an integer sequence"
            ) from exc
        if len(deltas) != len(horizons) or not all(math.isfinite(x) for x in deltas):
            raise O1C19CausalVaultBridgeError(
                "incremental_deltas must be finite and match horizons"
            )
        if len(work) != len(horizons) or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 1
            for value in work
        ):
            raise O1C19CausalVaultBridgeError(
                "incremental_work_units must be positive integers matching horizons"
            )
        previous = 0
        expected_work = []
        for horizon in horizons:
            expected_work.append(2 * (horizon - previous))
            previous = horizon
        if work != tuple(expected_work):
            raise O1C19CausalVaultBridgeError(
                "incremental work must equal twice each ordered horizon increment"
            )
        _require_uint64(self.group_salt, "group_salt")
        object.__setattr__(self, "horizons", horizons)
        object.__setattr__(self, "incremental_deltas", deltas)
        object.__setattr__(self, "incremental_work_units", work)

    @property
    def group_sha256(self) -> str:
        return _derived_group_digest(self).hex()

    @property
    def group_id(self) -> int:
        digest = _derived_group_digest(self)
        result = int.from_bytes(digest[:8], "big")
        if result == _MASK64:
            result = int.from_bytes(
                hashlib.sha256(digest + b"\x01").digest()[:8], "big"
            )
            if result == _MASK64:  # Cryptographically unreachable, still total.
                result = _MASK64 - 1
        return result

    @property
    def physical_work_units(self) -> int:
        return sum(self.incremental_work_units)

    def describe(self) -> dict[str, object]:
        row = _group_payload(self)
        row["group_id"] = self.group_id
        row["group_sha256"] = self.group_sha256
        row["physical_work_units"] = self.physical_work_units
        return row

    def to_bytes(self) -> bytes:
        return _canonical_json(self.describe())

    @classmethod
    def from_bytes(cls, value: bytes) -> "PacketDeltaGroup":
        try:
            row = json.loads(value.decode("ascii"))
        except (AttributeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise O1C19CausalVaultBridgeError("packet group is invalid JSON") from exc
        if not isinstance(row, Mapping):
            raise O1C19CausalVaultBridgeError("packet group must be an object")
        try:
            raw_deltas = row["incremental_deltas_float64_hex"]
            if not isinstance(raw_deltas, list):
                raise O1C19CausalVaultBridgeError("packet delta encoding differs")
            result = cls(
                source_stream_sha256=row["source_stream_sha256"],
                action_pool_sha256=row["action_pool_sha256"],
                reader_state_sha256=row["reader_state_sha256"],
                active_coordinates_sha256=row["active_coordinates_sha256"],
                pair_sha256=row["pair_sha256"],
                coordinate=row["coordinate"],
                horizons=tuple(row["horizons"]),
                incremental_deltas=tuple(
                    _float_from_hex(item, f"incremental_deltas[{index}]")
                    for index, item in enumerate(raw_deltas)
                ),
                incremental_work_units=tuple(row["incremental_work_units"]),
                group_salt=row["group_salt"],
            )
        except KeyError as exc:
            raise O1C19CausalVaultBridgeError("packet group fields differ") from exc
        if result.to_bytes() != value:
            raise O1C19CausalVaultBridgeError("packet group is not canonical")
        return result


def _ordered_group_ledger_sha256(groups: Sequence[PacketDeltaGroup]) -> str:
    digest = hashlib.sha256(b"O1C-0022/ordered-public-packet-ledger/v1\x00")
    for group in groups:
        payload = group.to_bytes()
        digest.update(struct.pack(">Q", len(payload)))
        digest.update(payload)
    return digest.hexdigest()


def active_coordinate_sequence_sha256(coordinates: Sequence[int]) -> str:
    """Commit to one ordered active-set prefix without any target material."""

    values = tuple(coordinates)
    if (
        not values
        or len(set(values)) != len(values)
        or any(
            _require_coordinate(value, "active coordinate") != value for value in values
        )
    ):
        raise O1C19CausalVaultBridgeError("active coordinates differ")
    return _sha256_bytes(
        _canonical_json(
            {
                "schema": "o1-256-o1c22-active-coordinate-sequence-v1",
                "coordinates": list(values),
            }
        )
    )


def _deterministic_median(values: Sequence[float]) -> float:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return 1.0
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    # This form avoids unnecessary overflow for very large finite values.
    return ordered[middle - 1] / 2.0 + ordered[middle] / 2.0


@dataclass(frozen=True)
class FrozenMedianAbsQuantizer:
    """Label-free per-horizon public median-|delta| quantizer."""

    horizons: tuple[int, ...]
    scales: tuple[float, ...]
    total_counts: tuple[int, ...]
    nonzero_counts: tuple[int, ...]
    public_replay_ledger_sha256: str

    def __post_init__(self) -> None:
        horizons = _require_horizons(self.horizons)
        try:
            scales = tuple(float(value) for value in self.scales)
            total = tuple(self.total_counts)
            nonzero = tuple(self.nonzero_counts)
        except (TypeError, ValueError) as exc:
            raise O1C19CausalVaultBridgeError(
                "quantizer vectors must be sequences"
            ) from exc
        if (
            len(scales) != len(horizons)
            or any(not math.isfinite(value) or value <= 0.0 for value in scales)
            or len(total) != len(horizons)
            or len(nonzero) != len(horizons)
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in total + nonzero
            )
            or any(nz > count for nz, count in zip(nonzero, total))
        ):
            raise O1C19CausalVaultBridgeError("quantizer scale/count vectors differ")
        _require_sha256(
            self.public_replay_ledger_sha256,
            "public_replay_ledger_sha256",
        )
        object.__setattr__(self, "horizons", horizons)
        object.__setattr__(self, "scales", scales)
        object.__setattr__(self, "total_counts", total)
        object.__setattr__(self, "nonzero_counts", nonzero)

    @classmethod
    def fit_public_replays(
        cls,
        groups: Sequence[PacketDeltaGroup],
        *,
        horizons: Sequence[int] | None = None,
    ) -> "FrozenMedianAbsQuantizer":
        """Freeze scales from public reader replays; no outcome surface exists."""

        rows = tuple(groups)
        if any(not isinstance(group, PacketDeltaGroup) for group in rows):
            raise TypeError("groups must contain PacketDeltaGroup values")
        if horizons is None:
            if not rows:
                raise O1C19CausalVaultBridgeError(
                    "empty public replay requires explicit horizons"
                )
            ordered_horizons = rows[0].horizons
        else:
            ordered_horizons = _require_horizons(horizons)
        if any(group.horizons != ordered_horizons for group in rows):
            raise O1C19CausalVaultBridgeError(
                "public replay packet horizons differ from the frozen order"
            )
        per_horizon: list[list[float]] = [[] for _ in ordered_horizons]
        for group in rows:
            for index, delta in enumerate(group.incremental_deltas):
                magnitude = abs(delta)
                if magnitude > 0.0:  # Finite is enforced by PacketDeltaGroup.
                    per_horizon[index].append(magnitude)
        scales = tuple(_deterministic_median(values) for values in per_horizon)
        return cls(
            horizons=ordered_horizons,
            scales=scales,
            total_counts=tuple(len(rows) for _ in ordered_horizons),
            nonzero_counts=tuple(len(values) for values in per_horizon),
            public_replay_ledger_sha256=_ordered_group_ledger_sha256(rows),
        )

    def _horizon_index(self, horizon: int) -> int:
        if isinstance(horizon, bool) or not isinstance(horizon, int):
            raise O1C19CausalVaultBridgeError("quantizer horizon must be integral")
        try:
            return self.horizons.index(horizon)
        except ValueError as exc:
            raise O1C19CausalVaultBridgeError(
                "quantizer horizon is not frozen"
            ) from exc

    def normalized(self, horizon: int, delta: float) -> float:
        index = self._horizon_index(horizon)
        value = float(delta)
        if not math.isfinite(value):
            raise O1C19CausalVaultBridgeError("packet delta must be finite")
        result = value / self.scales[index]
        if not math.isfinite(result):
            raise O1C19CausalVaultBridgeError("normalized packet delta overflowed")
        return result

    def quantize(self, horizon: int, delta: float) -> int:
        """Round half away from zero, then symmetrically clip to [-8,8]."""

        normalized = self.normalized(horizon, delta)
        magnitude = abs(normalized)
        rounded = (
            QUANTIZER_LIMIT
            if magnitude >= QUANTIZER_LIMIT - 0.5
            else int(math.floor(magnitude + 0.5))
        )
        return -rounded if normalized < 0.0 else rounded

    def describe(self) -> dict[str, object]:
        return {
            "schema": MEDIAN_ABS_QUANTIZER_SCHEMA,
            "horizons": list(self.horizons),
            "scales_float64_hex": [_float_hex(value) for value in self.scales],
            "total_counts": list(self.total_counts),
            "finite_nonzero_counts": list(self.nonzero_counts),
            "zero_median_fallback": 1.0,
            "public_replay_ledger_sha256": self.public_replay_ledger_sha256,
            "rounding": "floor(abs(x)+0.5)*sign",
            "clip": [-QUANTIZER_LIMIT, QUANTIZER_LIMIT],
            "label_accesses": 0,
        }

    def to_bytes(self) -> bytes:
        return _canonical_json(self.describe())

    @property
    def sha256(self) -> str:
        return _sha256_bytes(self.to_bytes())

    @classmethod
    def from_bytes(cls, value: bytes) -> "FrozenMedianAbsQuantizer":
        try:
            row = json.loads(value.decode("ascii"))
        except (AttributeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise O1C19CausalVaultBridgeError("quantizer is invalid JSON") from exc
        if not isinstance(row, Mapping):
            raise O1C19CausalVaultBridgeError("quantizer must be an object")
        try:
            raw_scales = row["scales_float64_hex"]
            if not isinstance(raw_scales, list):
                raise O1C19CausalVaultBridgeError("quantizer scale encoding differs")
            result = cls(
                horizons=tuple(row["horizons"]),
                scales=tuple(
                    _float_from_hex(value, f"scales[{index}]")
                    for index, value in enumerate(raw_scales)
                ),
                total_counts=tuple(row["total_counts"]),
                nonzero_counts=tuple(row["finite_nonzero_counts"]),
                public_replay_ledger_sha256=row["public_replay_ledger_sha256"],
            )
        except KeyError as exc:
            raise O1C19CausalVaultBridgeError("quantizer fields differ") from exc
        if result.to_bytes() != value:
            raise O1C19CausalVaultBridgeError("quantizer is not canonical")
        return result


@dataclass(frozen=True)
class PacketDeltaExtraction:
    """Auditable label-free extraction from one frozen O1C-0019 reader."""

    source_stream_sha256: str
    action_pool_sha256: str
    active_coordinates: tuple[int, ...]
    ordered_horizons: tuple[int, ...]
    groups: tuple[PacketDeltaGroup, ...]
    reader_state_sha256: str
    reader_state_bytes: int
    slow_state_sha256: str
    slow_state_bytes: int
    final_fast_state_sha256: str
    final_fast_state_bytes: int
    physical_work_units: int
    observed_slots: int

    def __post_init__(self) -> None:
        _require_sha256(self.source_stream_sha256, "source_stream_sha256")
        _require_sha256(self.action_pool_sha256, "action_pool_sha256")
        _require_sha256(self.reader_state_sha256, "reader_state_sha256")
        _require_sha256(self.slow_state_sha256, "slow_state_sha256")
        _require_sha256(self.final_fast_state_sha256, "final_fast_state_sha256")
        coordinates = tuple(self.active_coordinates)
        if (
            not coordinates
            or len(set(coordinates)) != len(coordinates)
            or any(
                _require_coordinate(value, "active coordinate") != value
                for value in coordinates
            )
        ):
            raise O1C19CausalVaultBridgeError("active coordinates differ")
        horizons = _require_horizons(self.ordered_horizons, "ordered_horizons")
        groups = tuple(self.groups)
        active_sha256 = active_coordinate_sequence_sha256(coordinates)
        if (
            len(groups) != len(coordinates)
            or any(not isinstance(group, PacketDeltaGroup) for group in groups)
            or tuple(group.coordinate for group in groups) != coordinates
            or any(group.horizons != horizons for group in groups)
            or any(
                group.source_stream_sha256 != self.source_stream_sha256
                for group in groups
            )
            or any(
                group.action_pool_sha256 != self.action_pool_sha256 for group in groups
            )
            or any(
                group.reader_state_sha256 != self.reader_state_sha256
                for group in groups
            )
            or any(group.active_coordinates_sha256 != active_sha256 for group in groups)
        ):
            raise O1C19CausalVaultBridgeError("extracted packet group ledger differs")
        for field in (
            "reader_state_bytes",
            "slow_state_bytes",
            "final_fast_state_bytes",
            "physical_work_units",
            "observed_slots",
        ):
            value = getattr(self, field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise O1C19CausalVaultBridgeError(f"{field} must be non-negative")
        if self.physical_work_units != sum(
            group.physical_work_units for group in groups
        ):
            raise O1C19CausalVaultBridgeError("extracted physical work differs")
        if self.observed_slots != len(groups) * len(horizons):
            raise O1C19CausalVaultBridgeError("extracted slot count differs")
        object.__setattr__(self, "active_coordinates", coordinates)
        object.__setattr__(self, "ordered_horizons", horizons)
        object.__setattr__(self, "groups", groups)

    @property
    def public_packet_ledger_sha256(self) -> str:
        return _ordered_group_ledger_sha256(self.groups)

    def describe(self) -> dict[str, object]:
        return {
            "schema": PACKET_EXTRACTION_SCHEMA,
            "source_stream_sha256": self.source_stream_sha256,
            "action_pool_sha256": self.action_pool_sha256,
            "active_coordinates": list(self.active_coordinates),
            "ordered_horizons": list(self.ordered_horizons),
            "groups": [group.describe() for group in self.groups],
            "public_packet_ledger_sha256": self.public_packet_ledger_sha256,
            "reader_state_sha256": self.reader_state_sha256,
            "reader_state_bytes": self.reader_state_bytes,
            "slow_state_sha256": self.slow_state_sha256,
            "slow_state_bytes": self.slow_state_bytes,
            "upstream_reader_billed_separately_from_live_vault": True,
            "final_fast_state_sha256": self.final_fast_state_sha256,
            "final_fast_state_bytes": self.final_fast_state_bytes,
            "physical_work_units": self.physical_work_units,
            "observed_slots": self.observed_slots,
            "delta_semantics": "exact-o1c19-q_after-minus-q_before",
            "current_target_supervised_updates": 0,
            "label_accesses": 0,
            "solver_calls": 0,
        }

    def to_bytes(self) -> bytes:
        return _canonical_json(self.describe())

    @property
    def sha256(self) -> str:
        return _sha256_bytes(self.to_bytes())


def extract_frozen_o1c19_packet_groups(
    controller: object,
    pool: Full256ActionPool,
    active_coordinates: Sequence[int],
    *,
    group_salt: int = 0,
) -> PacketDeltaExtraction:
    """Run a frozen reader over public pools and extract exact packet deltas.

    ``controller`` is intentionally accepted structurally so deterministic
    fixture readers can test the protocol without training.  A production
    caller supplies ``MultiResolutionCausalController``.  Only its frozen-state
    serialization and label-free ``run_action_order`` surface are used.
    """

    if not isinstance(pool, Full256ActionPool):
        raise TypeError("pool must be Full256ActionPool")
    required = (
        "config",
        "controller_config",
        "reader_state_bytes",
        "slow_state_bytes",
        "run_action_order",
    )
    if any(not hasattr(controller, name) for name in required):
        raise TypeError("controller lacks the frozen O1C-0019 reader surface")
    coordinates = tuple(active_coordinates)
    if (
        not coordinates
        or len(set(coordinates)) != len(coordinates)
        or any(
            _require_coordinate(value, "active coordinate") != value
            for value in coordinates
        )
    ):
        raise O1C19CausalVaultBridgeError("active coordinates differ")
    normalized_salt = _require_uint64(group_salt, "group_salt")
    config = controller.config
    multiresolution_config = controller.controller_config
    horizons = _require_horizons(
        multiresolution_config.ordered_horizons,
        "controller ordered_horizons",
    )
    if set(horizons) != set(config.horizons):
        raise O1C19CausalVaultBridgeError(
            "controller ordered horizons do not cover its base horizons"
        )

    reader_before = controller.reader_state_bytes()
    slow_before = controller.slow_state_bytes()
    if not isinstance(reader_before, bytes) or not isinstance(slow_before, bytes):
        raise O1C19CausalVaultBridgeError("frozen controller bytes differ")
    deepest = horizons[-1]
    action_order = tuple(
        CausalAction(coordinate, deepest).flat_index(config)
        for coordinate in coordinates
    )
    state = controller.run_action_order(pool, action_order)
    reader_after = controller.reader_state_bytes()
    slow_after = controller.slow_state_bytes()
    if reader_after != reader_before or slow_after != slow_before:
        raise O1C19CausalVaultBridgeError(
            "label-free packet extraction mutated frozen upstream state"
        )

    reader_sha256 = _sha256_bytes(reader_before)
    action_pool_sha256 = pool.action_pool_sha256
    active_coordinates_sha256 = active_coordinate_sequence_sha256(coordinates)

    expected_slots = len(coordinates) * len(horizons)
    expected_work = 2 * deepest * len(coordinates)
    if (
        state.decision_count != len(coordinates)
        or state.base.action_count != expected_slots
        or state.physical_work_units != expected_work
    ):
        raise O1C19CausalVaultBridgeError("upstream packet ledger differs")
    expected_coverage = np.zeros_like(state.base.coverage)
    for coordinate in coordinates:
        for horizon in horizons:
            expected_coverage[config.horizons.index(horizon), coordinate] = np.uint16(1)
    if not np.array_equal(state.base.coverage, expected_coverage):
        raise O1C19CausalVaultBridgeError("upstream packet coverage differs")

    groups = []
    work = []
    previous = 0
    for horizon in horizons:
        work.append(2 * (horizon - previous))
        previous = horizon
    for coordinate in coordinates:
        deltas = tuple(
            float(state.packet_evidence[config.horizons.index(horizon), coordinate])
            for horizon in horizons
        )
        groups.append(
            PacketDeltaGroup(
                source_stream_sha256=pool.source_stream_sha256,
                action_pool_sha256=action_pool_sha256,
                reader_state_sha256=reader_sha256,
                active_coordinates_sha256=active_coordinates_sha256,
                pair_sha256=pool.pair_sha256[coordinate],
                coordinate=coordinate,
                horizons=horizons,
                incremental_deltas=deltas,
                incremental_work_units=tuple(work),
                group_salt=normalized_salt,
            )
        )
    fast_state_bytes = state.to_bytes(multiresolution_config)
    return PacketDeltaExtraction(
        source_stream_sha256=pool.source_stream_sha256,
        action_pool_sha256=action_pool_sha256,
        active_coordinates=coordinates,
        ordered_horizons=horizons,
        groups=tuple(groups),
        reader_state_sha256=reader_sha256,
        reader_state_bytes=len(reader_before),
        slow_state_sha256=_sha256_bytes(slow_before),
        slow_state_bytes=len(slow_before),
        final_fast_state_sha256=_sha256_bytes(fast_state_bytes),
        final_fast_state_bytes=len(fast_state_bytes),
        physical_work_units=expected_work,
        observed_slots=expected_slots,
    )


def complement_packet_polarity(group: PacketDeltaGroup) -> PacketDeltaGroup:
    """Exact signed-reader polarity transform for antisymmetry controls."""

    if not isinstance(group, PacketDeltaGroup):
        raise TypeError("group must be PacketDeltaGroup")
    return PacketDeltaGroup(
        source_stream_sha256=group.source_stream_sha256,
        action_pool_sha256=group.action_pool_sha256,
        reader_state_sha256=group.reader_state_sha256,
        active_coordinates_sha256=group.active_coordinates_sha256,
        pair_sha256=group.pair_sha256,
        coordinate=group.coordinate,
        horizons=group.horizons,
        incremental_deltas=tuple(-value for value in group.incremental_deltas),
        incremental_work_units=group.incremental_work_units,
        group_salt=group.group_salt,
    )


def permute_packet_coordinate(
    group: PacketDeltaGroup,
    permutation: Sequence[int],
) -> PacketDeltaGroup:
    """Relabel one packet coordinate while preserving its public work/deltas."""

    if not isinstance(group, PacketDeltaGroup):
        raise TypeError("group must be PacketDeltaGroup")
    mapping = _require_permutation(permutation, "coordinate permutation")
    transformed_active_sha256 = _sha256_bytes(
        b"o1c22-coordinate-permuted-active-set-v1\x00"
        + bytes.fromhex(group.active_coordinates_sha256)
        + np.asarray(mapping, dtype=">u2").tobytes(order="C")
    )
    return PacketDeltaGroup(
        source_stream_sha256=group.source_stream_sha256,
        action_pool_sha256=group.action_pool_sha256,
        reader_state_sha256=group.reader_state_sha256,
        active_coordinates_sha256=transformed_active_sha256,
        pair_sha256=group.pair_sha256,
        coordinate=mapping[group.coordinate],
        horizons=group.horizons,
        incremental_deltas=group.incremental_deltas,
        incremental_work_units=group.incremental_work_units,
        group_salt=group.group_salt,
    )


def _saturating_int8_add(array: np.ndarray, coordinate: int, delta: int) -> None:
    value = int(array[coordinate]) + int(delta)
    array[coordinate] = np.int8(max(-127, min(127, value)))


def _formal_config(config: CausalEvidenceConfig) -> None:
    if not isinstance(config, CausalEvidenceConfig):
        raise TypeError("config must be CausalEvidenceConfig")
    if config.n_bits != KEY_BITS or config.live_state_bytes != FORMAL_VAULT_BYTES:
        raise O1C19CausalVaultBridgeError(
            "O1C-0022 requires the exact 256-bit/352-byte O1C-0021 state"
        )


@dataclass
class CausalVaultBridgeState:
    """Primary 352-byte vault plus separately billed diagnostic controls."""

    vault: CausalEvidenceState
    raw_float_accumulator: np.ndarray
    normalized_float_accumulator: np.ndarray
    unit_sign_sum: np.ndarray
    last_only: np.ndarray
    shuffled: np.ndarray
    shuffled_destinations: tuple[int, ...]

    @classmethod
    def initial(
        cls,
        config: CausalEvidenceConfig,
        core: object,
        shuffled_destinations: Sequence[int],
    ) -> "CausalVaultBridgeState":
        _formal_config(config)
        if not hasattr(core, "initial_state"):
            raise TypeError("core must expose initial_state")
        result = cls(
            vault=CausalEvidenceState.initial(config, core),
            raw_float_accumulator=np.zeros(KEY_BITS, dtype=np.float64),
            normalized_float_accumulator=np.zeros(KEY_BITS, dtype=np.float64),
            unit_sign_sum=np.zeros(KEY_BITS, dtype=np.int8),
            last_only=np.zeros(KEY_BITS, dtype=np.int8),
            shuffled=np.zeros(KEY_BITS, dtype=np.int8),
            shuffled_destinations=_require_permutation(
                shuffled_destinations,
                "shuffled destinations",
            ),
        )
        result.validate(config)
        return result

    def validate(self, config: CausalEvidenceConfig) -> None:
        _formal_config(config)
        self.vault.validate(config)
        for name, array in (
            ("raw_float_accumulator", self.raw_float_accumulator),
            ("normalized_float_accumulator", self.normalized_float_accumulator),
        ):
            if (
                not isinstance(array, np.ndarray)
                or array.shape != (KEY_BITS,)
                or array.dtype != np.float64
                or not np.all(np.isfinite(array))
            ):
                raise O1C19CausalVaultBridgeError(
                    f"{name} control must be finite float64[256]"
                )
        for name, array in (
            ("unit_sign_sum", self.unit_sign_sum),
            ("last_only", self.last_only),
            ("shuffled", self.shuffled),
        ):
            if (
                not isinstance(array, np.ndarray)
                or array.shape != (KEY_BITS,)
                or array.dtype != np.int8
                or bool((array == np.int8(-128)).any())
            ):
                raise O1C19CausalVaultBridgeError(
                    f"{name} control must be symmetric int8[256]"
                )
        self.shuffled_destinations = _require_permutation(
            self.shuffled_destinations,
            "shuffled destinations",
        )

    def clone(self, config: CausalEvidenceConfig) -> "CausalVaultBridgeState":
        self.validate(config)
        return CausalVaultBridgeState(
            vault=CausalEvidenceState.from_bytes(
                self.vault.to_bytes(config),
                config=config,
            ),
            raw_float_accumulator=self.raw_float_accumulator.copy(),
            normalized_float_accumulator=self.normalized_float_accumulator.copy(),
            unit_sign_sum=self.unit_sign_sum.copy(),
            last_only=self.last_only.copy(),
            shuffled=self.shuffled.copy(),
            shuffled_destinations=self.shuffled_destinations,
        )

    @property
    def primary_live_state_bytes(self) -> int:
        return FORMAL_VAULT_BYTES

    @property
    def control_live_state_bytes(self) -> int:
        return int(
            self.raw_float_accumulator.nbytes
            + self.normalized_float_accumulator.nbytes
            + self.unit_sign_sum.nbytes
            + self.last_only.nbytes
            + self.shuffled.nbytes
        )

    @property
    def static_control_plan_bytes(self) -> int:
        return KEY_BITS * np.dtype("<u2").itemsize

    def primary_bytes(self, config: CausalEvidenceConfig) -> bytes:
        payload = self.vault.to_bytes(config)
        if len(payload) != FORMAL_VAULT_BYTES:
            raise AssertionError("formal O1C-0021 vault width differs")
        return payload

    def control_bytes(self) -> bytes:
        return b"".join(
            (
                self.raw_float_accumulator.astype("<f8", copy=False).tobytes(order="C"),
                self.normalized_float_accumulator.astype("<f8", copy=False).tobytes(
                    order="C"
                ),
                self.unit_sign_sum.tobytes(order="C"),
                self.last_only.tobytes(order="C"),
                self.shuffled.tobytes(order="C"),
            )
        )

    def static_plan_bytes(self) -> bytes:
        return np.asarray(self.shuffled_destinations, dtype="<u2").tobytes(order="C")

    def control_sha256(self) -> str:
        return _sha256_bytes(self.control_bytes())

    def arm_values(self, config: CausalEvidenceConfig) -> dict[str, np.ndarray]:
        """Return exact uncalibrated prediction-arm vectors for the runner."""

        self.validate(config)
        return {
            "raw_float_delta_sum": self.raw_float_accumulator.copy(),
            "normalized_float_delta_sum": (self.normalized_float_accumulator.copy()),
            "quantized_int8_vault": self.vault.evidence.astype(np.float64),
            "last_horizon_only": self.last_only.astype(np.float64),
            "unit_sign_sum": self.unit_sign_sum.astype(np.float64),
            "coordinate_shuffled_vault": self.shuffled.astype(np.float64),
            "zero_prior": np.zeros(KEY_BITS, dtype=np.float64),
        }


@dataclass(frozen=True)
class BridgeGroupReceipt:
    group_id: int
    group_sha256: str
    coordinate: int
    shuffled_destination: int
    horizons: tuple[int, ...]
    quantized_deltas: tuple[int, ...]
    normalized_deltas: tuple[float, ...]
    offered_work_units: int
    accepted_work_units: int
    accepted: bool
    primary_state_sha256_before: str
    primary_state_sha256_after: str
    control_state_sha256_before: str
    control_state_sha256_after: str

    def __post_init__(self) -> None:
        _require_uint64(self.group_id, "group_id")
        if self.group_id == _MASK64:
            raise O1C19CausalVaultBridgeError("group_id may not equal the sentinel")
        _require_sha256(self.group_sha256, "group_sha256")
        _require_coordinate(self.coordinate)
        _require_coordinate(self.shuffled_destination, "shuffled destination")
        horizons = _require_horizons(self.horizons)
        if (
            len(self.quantized_deltas) != len(horizons)
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or not -QUANTIZER_LIMIT <= value <= QUANTIZER_LIMIT
                for value in self.quantized_deltas
            )
            or len(self.normalized_deltas) != len(horizons)
            or any(not math.isfinite(value) for value in self.normalized_deltas)
        ):
            raise O1C19CausalVaultBridgeError("receipt delta ledger differs")
        for field in ("offered_work_units", "accepted_work_units"):
            value = getattr(self, field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise O1C19CausalVaultBridgeError(f"{field} must be non-negative")
        if not isinstance(self.accepted, bool):
            raise O1C19CausalVaultBridgeError("receipt accepted flag must be boolean")
        if self.accepted_work_units != (
            self.offered_work_units if self.accepted else 0
        ):
            raise O1C19CausalVaultBridgeError("receipt accepted work differs")
        for field in (
            "primary_state_sha256_before",
            "primary_state_sha256_after",
            "control_state_sha256_before",
            "control_state_sha256_after",
        ):
            _require_sha256(getattr(self, field), field)
        if not self.accepted and (
            self.primary_state_sha256_before != self.primary_state_sha256_after
            or self.control_state_sha256_before != self.control_state_sha256_after
        ):
            raise O1C19CausalVaultBridgeError(
                "duplicate receipt changed primary or control state"
            )

    def describe(self) -> dict[str, object]:
        return {
            "group_id": self.group_id,
            "group_sha256": self.group_sha256,
            "coordinate": self.coordinate,
            "shuffled_destination": self.shuffled_destination,
            "horizons": list(self.horizons),
            "quantized_deltas": list(self.quantized_deltas),
            "normalized_deltas_float64_hex": [
                _float_hex(value) for value in self.normalized_deltas
            ],
            "offered_work_units": self.offered_work_units,
            "accepted_work_units": self.accepted_work_units,
            "accepted": self.accepted,
            "primary_state_sha256_before": self.primary_state_sha256_before,
            "primary_state_sha256_after": self.primary_state_sha256_after,
            "control_state_sha256_before": self.control_state_sha256_before,
            "control_state_sha256_after": self.control_state_sha256_after,
        }


class CausalVaultBridge:
    """Frozen quantizer and public route for atomic packet accumulation."""

    def __init__(
        self,
        config: CausalEvidenceConfig,
        quantizer: FrozenMedianAbsQuantizer,
        source_stream_sha256: str,
        *,
        action_pool_sha256: str,
        reader_state_sha256: str,
        active_coordinates_sha256: str,
    ) -> None:
        _formal_config(config)
        if not isinstance(quantizer, FrozenMedianAbsQuantizer):
            raise TypeError("quantizer must be FrozenMedianAbsQuantizer")
        self.config = config
        self.quantizer = quantizer
        self.source_stream_sha256 = _require_sha256(
            source_stream_sha256,
            "source_stream_sha256",
        )
        self.action_pool_sha256 = _require_sha256(
            action_pool_sha256,
            "action_pool_sha256",
        )
        self.reader_state_sha256 = _require_sha256(
            reader_state_sha256,
            "reader_state_sha256",
        )
        self.active_coordinates_sha256 = _require_sha256(
            active_coordinates_sha256,
            "active_coordinates_sha256",
        )

    def apply_group(
        self,
        state: CausalVaultBridgeState,
        group: PacketDeltaGroup,
    ) -> BridgeGroupReceipt:
        """Apply a whole coordinate packet or reject it without a byte change."""

        if not isinstance(state, CausalVaultBridgeState):
            raise TypeError("state must be CausalVaultBridgeState")
        if not isinstance(group, PacketDeltaGroup):
            raise TypeError("group must be PacketDeltaGroup")
        state.validate(self.config)
        if group.source_stream_sha256 != self.source_stream_sha256:
            raise O1C19CausalVaultBridgeError(
                "packet source differs from target stream"
            )
        if group.action_pool_sha256 != self.action_pool_sha256:
            raise O1C19CausalVaultBridgeError("packet action pool differs from target")
        if group.reader_state_sha256 != self.reader_state_sha256:
            raise O1C19CausalVaultBridgeError(
                "packet reader differs from frozen reader"
            )
        if group.active_coordinates_sha256 != self.active_coordinates_sha256:
            raise O1C19CausalVaultBridgeError("packet active set differs from target")
        if group.horizons != self.quantizer.horizons:
            raise O1C19CausalVaultBridgeError("packet horizons differ from quantizer")
        quantized = tuple(
            self.quantizer.quantize(horizon, delta)
            for horizon, delta in zip(group.horizons, group.incremental_deltas)
        )
        normalized = tuple(
            self.quantizer.normalized(horizon, delta)
            for horizon, delta in zip(group.horizons, group.incremental_deltas)
        )
        destination = state.shuffled_destinations[group.coordinate]
        primary_before_bytes = state.primary_bytes(self.config)
        primary_before = _sha256_bytes(primary_before_bytes)
        control_before_bytes = state.control_bytes()
        control_before = _sha256_bytes(control_before_bytes)

        if state.vault.last_group_id == group.group_id:
            # Return before touching counters, controls, core state, or vault.
            if state.primary_bytes(self.config) != primary_before_bytes:
                raise AssertionError("duplicate probe mutated the primary state")
            if state.control_bytes() != control_before_bytes:
                raise AssertionError("duplicate probe mutated the control state")
            return BridgeGroupReceipt(
                group_id=group.group_id,
                group_sha256=group.group_sha256,
                coordinate=group.coordinate,
                shuffled_destination=destination,
                horizons=group.horizons,
                quantized_deltas=quantized,
                normalized_deltas=normalized,
                offered_work_units=group.physical_work_units,
                accepted_work_units=0,
                accepted=False,
                primary_state_sha256_before=primary_before,
                primary_state_sha256_after=primary_before,
                control_state_sha256_before=control_before,
                control_state_sha256_after=control_before,
            )

        nonzero_updates = sum(value != 0 for value in quantized)
        if state.vault.accepted_updates > _MASK64 - nonzero_updates:
            raise O1C19CausalVaultBridgeError("accepted update counter would overflow")
        working = state.clone(self.config)
        for raw_value, q_value, normalized_value in zip(
            group.incremental_deltas,
            quantized,
            normalized,
        ):
            working.raw_float_accumulator[group.coordinate] += raw_value
            working.normalized_float_accumulator[group.coordinate] += normalized_value
            sign = int(raw_value > 0.0) - int(raw_value < 0.0)
            if sign:
                _saturating_int8_add(
                    working.unit_sign_sum,
                    group.coordinate,
                    sign,
                )
            # O1C-0022 freezes zero_updates_are_skipped=true.  The physical
            # slot remains in every offered/accepted work ledger, but a zero q
            # is not a vault update and does not advance accepted_updates.
            if q_value:
                working.vault.add(group.coordinate, q_value)
                _saturating_int8_add(working.shuffled, destination, q_value)
        working.last_only[group.coordinate] = np.int8(quantized[-1])
        working.vault.last_group_id = group.group_id
        working.validate(self.config)

        primary_after = _sha256_bytes(working.primary_bytes(self.config))
        control_after = working.control_sha256()
        state.vault = working.vault
        state.raw_float_accumulator = working.raw_float_accumulator
        state.normalized_float_accumulator = working.normalized_float_accumulator
        state.unit_sign_sum = working.unit_sign_sum
        state.last_only = working.last_only
        state.shuffled = working.shuffled
        state.shuffled_destinations = working.shuffled_destinations
        return BridgeGroupReceipt(
            group_id=group.group_id,
            group_sha256=group.group_sha256,
            coordinate=group.coordinate,
            shuffled_destination=destination,
            horizons=group.horizons,
            quantized_deltas=quantized,
            normalized_deltas=normalized,
            offered_work_units=group.physical_work_units,
            accepted_work_units=group.physical_work_units,
            accepted=True,
            primary_state_sha256_before=primary_before,
            primary_state_sha256_after=primary_after,
            control_state_sha256_before=control_before,
            control_state_sha256_after=control_after,
        )


@dataclass(frozen=True)
class CausalVaultBridgeExecution:
    """Final state and exact offered/accepted group ledger."""

    state: CausalVaultBridgeState
    receipts: tuple[BridgeGroupReceipt, ...]
    quantizer_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.state, CausalVaultBridgeState):
            raise TypeError("state must be CausalVaultBridgeState")
        if any(not isinstance(row, BridgeGroupReceipt) for row in self.receipts):
            raise TypeError("receipts must contain BridgeGroupReceipt values")
        _require_sha256(self.quantizer_sha256, "quantizer_sha256")

    @property
    def ledger_bytes(self) -> bytes:
        return _canonical_json([receipt.describe() for receipt in self.receipts])

    @property
    def ledger_sha256(self) -> str:
        return _sha256_bytes(self.ledger_bytes)

    def describe(self, config: CausalEvidenceConfig) -> dict[str, object]:
        self.state.validate(config)
        accepted = tuple(row for row in self.receipts if row.accepted)
        duplicate = tuple(row for row in self.receipts if not row.accepted)
        return {
            "schema": BRIDGE_EXECUTION_SCHEMA,
            "bridge_schema": BRIDGE_SCHEMA,
            "quantizer_sha256": self.quantizer_sha256,
            "groups_offered": len(self.receipts),
            "groups_accepted": len(accepted),
            "groups_duplicate": len(duplicate),
            "slots_offered": sum(len(row.horizons) for row in self.receipts),
            "slots_accepted": sum(len(row.horizons) for row in accepted),
            "physical_work_offered": sum(
                row.offered_work_units for row in self.receipts
            ),
            "physical_work_accepted": sum(
                row.accepted_work_units for row in self.receipts
            ),
            "nonzero_vault_updates_accepted": sum(
                sum(value != 0 for value in row.quantized_deltas) for row in accepted
            ),
            "zero_quantized_slots_accepted": sum(
                sum(value == 0 for value in row.quantized_deltas) for row in accepted
            ),
            "zero_updates_are_skipped": True,
            "primary_live_state_bytes": self.state.primary_live_state_bytes,
            "control_live_state_bytes": self.state.control_live_state_bytes,
            "static_control_plan_bytes": self.state.static_control_plan_bytes,
            "upstream_reader_billed_separately": True,
            "primary_state_sha256": _sha256_bytes(self.state.primary_bytes(config)),
            "control_state_sha256": self.state.control_sha256(),
            "static_control_plan_sha256": _sha256_bytes(self.state.static_plan_bytes()),
            "ledger_sha256": self.ledger_sha256,
            "duplicate_acceptance_rule": "consecutive-public-group-id-equality",
            "duplicate_primary_state_byte_invariant": all(
                row.accepted
                or row.primary_state_sha256_before == row.primary_state_sha256_after
                for row in self.receipts
            ),
            "controls": [
                "raw_float_delta_sum",
                "normalized_float_delta_sum",
                "int8_causal_vault",
                "unit_sign_sum",
                "last_horizon_only",
                "coordinate_shuffled_same_q_work",
                "zero_prior_implicit_exact_zeros",
            ],
            "zero_prior_representation": "implicit-float64/int8-zero-vectors",
            "current_target_supervised_updates": 0,
            "label_accesses": 0,
            "solver_calls": 0,
        }

    def artifacts(self, config: CausalEvidenceConfig) -> dict[str, bytes]:
        report = self.describe(config)
        return {
            "causal_vault_bridge_execution.json": _canonical_json(report),
            "causal_vault_bridge_ledger.json": self.ledger_bytes,
            "causal_vault_state.bin": self.state.primary_bytes(config),
            "raw_float_control.f64le": self.state.raw_float_accumulator.astype(
                "<f8", copy=False
            ).tobytes(order="C"),
            "normalized_float_control.f64le": (
                self.state.normalized_float_accumulator.astype(
                    "<f8", copy=False
                ).tobytes(order="C")
            ),
            "unit_sign_control.i8": self.state.unit_sign_sum.tobytes(order="C"),
            "last_only_control.i8": self.state.last_only.tobytes(order="C"),
            "shuffled_control.i8": self.state.shuffled.tobytes(order="C"),
            "shuffled_destinations.u16le": self.state.static_plan_bytes(),
        }


def execute_packet_delta_groups(
    bridge: CausalVaultBridge,
    state: CausalVaultBridgeState,
    groups: Sequence[PacketDeltaGroup],
) -> CausalVaultBridgeExecution:
    """Execute an ordered public packet stream without any truth surface."""

    if not isinstance(bridge, CausalVaultBridge):
        raise TypeError("bridge must be CausalVaultBridge")
    receipts = tuple(bridge.apply_group(state, group) for group in groups)
    state.validate(bridge.config)
    return CausalVaultBridgeExecution(
        state=state.clone(bridge.config),
        receipts=receipts,
        quantizer_sha256=bridge.quantizer.sha256,
    )


__all__ = [
    "ACTIVE_COORDINATE_SCHEMA",
    "ACTIVE_COORDINATE_WIDTHS",
    "BRIDGE_EXECUTION_SCHEMA",
    "BRIDGE_SCHEMA",
    "FORMAL_VAULT_BYTES",
    "MEDIAN_ABS_QUANTIZER_SCHEMA",
    "PACKET_DELTA_GROUP_SCHEMA",
    "PACKET_EXTRACTION_SCHEMA",
    "QUANTIZER_LIMIT",
    "BridgeGroupReceipt",
    "CausalVaultBridge",
    "CausalVaultBridgeExecution",
    "CausalVaultBridgeState",
    "FrozenMedianAbsQuantizer",
    "NestedActiveCoordinatePlan",
    "O1C19CausalVaultBridgeError",
    "PacketDeltaExtraction",
    "PacketDeltaGroup",
    "complement_packet_polarity",
    "deterministic_coordinate_permutation",
    "execute_packet_delta_groups",
    "extract_frozen_o1c19_packet_groups",
    "permute_packet_coordinate",
]
