"""Lightweight byte-exact codec for frozen O1C-0022 packet artifacts.

The historical O1C-0019 implementation imports the full controller/training
stack.  A read-only adapter needs only its published packet and quantizer ABIs.
This module independently validates and reproduces those canonical bytes using
the Python standard library, so formal hot-readout runs do not load PyTorch.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
from dataclasses import dataclass
from typing import Mapping, Sequence, cast


KEY_BITS = 256
QUANTIZER_LIMIT = 8
PACKET_DELTA_GROUP_SCHEMA = "o1-256-o1c22-packet-delta-group-v1"
MEDIAN_ABS_QUANTIZER_SCHEMA = "o1-256-o1c22-median-abs-quantizer-v1"
PACKET_EXTRACTION_SCHEMA = "o1-256-o1c22-packet-delta-extraction-v1"
_MASK64 = (1 << 64) - 1
_INT32_MAX = (1 << 31) - 1
_GROUP_DOMAIN = b"o1c22-public-packet-delta-group-v1\x00"
_LEDGER_DOMAIN = b"O1C-0022/ordered-public-packet-ledger/v1\x00"


class O1C22PacketCodecError(ValueError):
    """A frozen packet, extraction, or quantizer ABI differs."""


def _canonical_json(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise O1C22PacketCodecError("packet document is not canonical JSON") from exc
    return (rendered + "\n").encode("ascii")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C22PacketCodecError(f"{field} must be lowercase SHA-256")
    return value


def _require_uint64(value: object, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= _MASK64
    ):
        raise O1C22PacketCodecError(f"{field} must be uint64-compatible")
    return value


def _require_coordinate(value: object, field: str = "coordinate") -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < KEY_BITS
    ):
        raise O1C22PacketCodecError(f"{field} must be in [0,255]")
    return value


def _require_horizons(value: object, field: str = "horizons") -> tuple[int, ...]:
    try:
        result = tuple(cast(Sequence[object], value))
    except TypeError as exc:
        raise O1C22PacketCodecError(
            f"{field} must be an integer sequence"
        ) from exc
    if not result or any(
            isinstance(item, bool)
            or not isinstance(item, int)
            or not 1 <= item <= _INT32_MAX
            for item in result
    ):
        raise O1C22PacketCodecError(
            f"{field} must be strictly increasing positive int32 values"
        )
    integers = cast(tuple[int, ...], result)
    if tuple(sorted(integers)) != integers or len(set(integers)) != len(integers):
        raise O1C22PacketCodecError(
            f"{field} must be strictly increasing positive int32 values"
        )
    return integers


def _float_hex(value: float) -> str:
    result = float(value)
    if not math.isfinite(result):
        raise O1C22PacketCodecError("serialized float must be finite")
    return result.hex()


def _float_from_hex(value: object, field: str) -> float:
    if not isinstance(value, str):
        raise O1C22PacketCodecError(f"{field} must be a float hex string")
    try:
        result = float.fromhex(value)
    except ValueError as exc:
        raise O1C22PacketCodecError(
            f"{field} must be a float hex string"
        ) from exc
    if not math.isfinite(result):
        raise O1C22PacketCodecError(f"{field} must be finite")
    return result


@dataclass(frozen=True)
class PacketDeltaGroup:
    """One byte-compatible coordinate-local O1C-0022 packet."""

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
        for field in (
            "source_stream_sha256",
            "action_pool_sha256",
            "reader_state_sha256",
            "active_coordinates_sha256",
            "pair_sha256",
        ):
            _require_sha256(getattr(self, field), field)
        _require_coordinate(self.coordinate)
        horizons = _require_horizons(self.horizons)
        try:
            deltas = tuple(float(value) for value in self.incremental_deltas)
            work = tuple(self.incremental_work_units)
        except (TypeError, ValueError) as exc:
            raise O1C22PacketCodecError("packet delta vectors differ") from exc
        if len(deltas) != len(horizons) or not all(
            math.isfinite(value) for value in deltas
        ):
            raise O1C22PacketCodecError(
                "incremental deltas must be finite and match horizons"
            )
        if len(work) != len(horizons) or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 1
            for value in work
        ):
            raise O1C22PacketCodecError(
                "incremental work must be positive integers matching horizons"
            )
        previous = 0
        expected_work: list[int] = []
        for horizon in horizons:
            expected_work.append(2 * (horizon - previous))
            previous = horizon
        if work != tuple(expected_work):
            raise O1C22PacketCodecError(
                "incremental work must equal twice each ordered horizon increment"
            )
        _require_uint64(self.group_salt, "group_salt")
        object.__setattr__(self, "horizons", horizons)
        object.__setattr__(self, "incremental_deltas", deltas)
        object.__setattr__(self, "incremental_work_units", work)

    def _payload(self) -> dict[str, object]:
        return {
            "schema": PACKET_DELTA_GROUP_SCHEMA,
            "source_stream_sha256": self.source_stream_sha256,
            "action_pool_sha256": self.action_pool_sha256,
            "reader_state_sha256": self.reader_state_sha256,
            "active_coordinates_sha256": self.active_coordinates_sha256,
            "pair_sha256": self.pair_sha256,
            "coordinate": self.coordinate,
            "horizons": list(self.horizons),
            "incremental_deltas_float64_hex": [
                _float_hex(value) for value in self.incremental_deltas
            ],
            "incremental_work_units": list(self.incremental_work_units),
            "group_salt": self.group_salt,
            "delta_semantics": "exact-o1c19-q_after-minus-q_before",
            "packet_order": "strictly-increasing-controller-ordered-horizons",
            "label_accesses": 0,
        }

    @property
    def _derived_digest(self) -> bytes:
        return hashlib.sha256(_GROUP_DOMAIN + _canonical_json(self._payload())).digest()

    @property
    def group_sha256(self) -> str:
        return self._derived_digest.hex()

    @property
    def group_id(self) -> int:
        digest = self._derived_digest
        result = int.from_bytes(digest[:8], "big")
        if result == _MASK64:
            result = int.from_bytes(
                hashlib.sha256(digest + b"\x01").digest()[:8], "big"
            )
            if result == _MASK64:  # pragma: no cover - cryptographically unreachable
                result = _MASK64 - 1
        return result

    @property
    def physical_work_units(self) -> int:
        return sum(self.incremental_work_units)

    def describe(self) -> dict[str, object]:
        row = self._payload()
        row["group_id"] = self.group_id
        row["group_sha256"] = self.group_sha256
        row["physical_work_units"] = self.physical_work_units
        return row

    def to_bytes(self) -> bytes:
        return _canonical_json(self.describe())

    @classmethod
    def from_bytes(cls, value: bytes) -> "PacketDeltaGroup":
        row = _decode_mapping(value, "packet group")
        try:
            raw_deltas = row["incremental_deltas_float64_hex"]
            if not isinstance(raw_deltas, list):
                raise O1C22PacketCodecError("packet delta encoding differs")
            result = cls(
                source_stream_sha256=cast(str, row["source_stream_sha256"]),
                action_pool_sha256=cast(str, row["action_pool_sha256"]),
                reader_state_sha256=cast(str, row["reader_state_sha256"]),
                active_coordinates_sha256=cast(
                    str, row["active_coordinates_sha256"]
                ),
                pair_sha256=cast(str, row["pair_sha256"]),
                coordinate=cast(int, row["coordinate"]),
                horizons=tuple(cast(Sequence[int], row["horizons"])),
                incremental_deltas=tuple(
                    _float_from_hex(item, f"incremental_deltas[{index}]")
                    for index, item in enumerate(raw_deltas)
                ),
                incremental_work_units=tuple(
                    cast(Sequence[int], row["incremental_work_units"])
                ),
                group_salt=cast(int, row["group_salt"]),
            )
        except (KeyError, TypeError) as exc:
            raise O1C22PacketCodecError("packet group fields differ") from exc
        if result.to_bytes() != value:
            raise O1C22PacketCodecError("packet group is not canonical")
        return result


def _ordered_group_ledger_sha256(groups: Sequence[PacketDeltaGroup]) -> str:
    digest = hashlib.sha256(_LEDGER_DOMAIN)
    for group in groups:
        payload = group.to_bytes()
        digest.update(struct.pack(">Q", len(payload)))
        digest.update(payload)
    return digest.hexdigest()


def active_coordinate_sequence_sha256(coordinates: Sequence[int]) -> str:
    values = tuple(coordinates)
    if (
        not values
        or len(set(values)) != len(values)
        or any(
            _require_coordinate(value, "active coordinate") != value
            for value in values
        )
    ):
        raise O1C22PacketCodecError("active coordinates differ")
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
    return ordered[middle - 1] / 2.0 + ordered[middle] / 2.0


@dataclass(frozen=True)
class FrozenMedianAbsQuantizer:
    """Byte-compatible frozen public per-horizon median quantizer."""

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
            raise O1C22PacketCodecError("quantizer vectors differ") from exc
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
            raise O1C22PacketCodecError("quantizer scale/count vectors differ")
        _require_sha256(
            self.public_replay_ledger_sha256, "public_replay_ledger_sha256"
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
        rows = tuple(groups)
        if any(not isinstance(group, PacketDeltaGroup) for group in rows):
            raise TypeError("groups must contain lightweight PacketDeltaGroup values")
        if horizons is None:
            if not rows:
                raise O1C22PacketCodecError(
                    "empty public replay requires explicit horizons"
                )
            ordered_horizons = rows[0].horizons
        else:
            ordered_horizons = _require_horizons(horizons)
        if any(group.horizons != ordered_horizons for group in rows):
            raise O1C22PacketCodecError(
                "public replay packet horizons differ from the frozen order"
            )
        per_horizon: list[list[float]] = [[] for _ in ordered_horizons]
        for group in rows:
            for index, delta in enumerate(group.incremental_deltas):
                magnitude = abs(delta)
                if magnitude > 0.0:
                    per_horizon[index].append(magnitude)
        return cls(
            horizons=ordered_horizons,
            scales=tuple(_deterministic_median(values) for values in per_horizon),
            total_counts=tuple(len(rows) for _ in ordered_horizons),
            nonzero_counts=tuple(len(values) for values in per_horizon),
            public_replay_ledger_sha256=_ordered_group_ledger_sha256(rows),
        )

    def _horizon_index(self, horizon: int) -> int:
        if isinstance(horizon, bool) or not isinstance(horizon, int):
            raise O1C22PacketCodecError("quantizer horizon must be integral")
        try:
            return self.horizons.index(horizon)
        except ValueError as exc:
            raise O1C22PacketCodecError("quantizer horizon is not frozen") from exc

    def normalized(self, horizon: int, delta: float) -> float:
        value = float(delta)
        if not math.isfinite(value):
            raise O1C22PacketCodecError("packet delta must be finite")
        result = value / self.scales[self._horizon_index(horizon)]
        if not math.isfinite(result):
            raise O1C22PacketCodecError("normalized packet delta overflowed")
        return result

    def quantize(self, horizon: int, delta: float) -> int:
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
        row = _decode_mapping(value, "quantizer")
        try:
            raw_scales = row["scales_float64_hex"]
            if not isinstance(raw_scales, list):
                raise O1C22PacketCodecError("quantizer scale encoding differs")
            result = cls(
                horizons=tuple(cast(Sequence[int], row["horizons"])),
                scales=tuple(
                    _float_from_hex(item, f"scales[{index}]")
                    for index, item in enumerate(raw_scales)
                ),
                total_counts=tuple(cast(Sequence[int], row["total_counts"])),
                nonzero_counts=tuple(
                    cast(Sequence[int], row["finite_nonzero_counts"])
                ),
                public_replay_ledger_sha256=cast(
                    str, row["public_replay_ledger_sha256"]
                ),
            )
        except (KeyError, TypeError) as exc:
            raise O1C22PacketCodecError("quantizer fields differ") from exc
        if result.to_bytes() != value:
            raise O1C22PacketCodecError("quantizer is not canonical")
        return result


@dataclass(frozen=True)
class PacketDeltaExtraction:
    """Byte-compatible complete label-free O1C-0022 extraction."""

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
        for field in (
            "source_stream_sha256",
            "action_pool_sha256",
            "reader_state_sha256",
            "slow_state_sha256",
            "final_fast_state_sha256",
        ):
            _require_sha256(getattr(self, field), field)
        coordinates = tuple(self.active_coordinates)
        if (
            not coordinates
            or len(set(coordinates)) != len(coordinates)
            or any(
                _require_coordinate(value, "active coordinate") != value
                for value in coordinates
            )
        ):
            raise O1C22PacketCodecError("active coordinates differ")
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
                or group.action_pool_sha256 != self.action_pool_sha256
                or group.reader_state_sha256 != self.reader_state_sha256
                or group.active_coordinates_sha256 != active_sha256
                for group in groups
            )
        ):
            raise O1C22PacketCodecError("extracted packet group ledger differs")
        for field in (
            "reader_state_bytes",
            "slow_state_bytes",
            "final_fast_state_bytes",
            "physical_work_units",
            "observed_slots",
        ):
            value = getattr(self, field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise O1C22PacketCodecError(f"{field} must be nonnegative")
        if self.physical_work_units != sum(
            group.physical_work_units for group in groups
        ):
            raise O1C22PacketCodecError("extracted physical work differs")
        if self.observed_slots != len(groups) * len(horizons):
            raise O1C22PacketCodecError("extracted slot count differs")
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

    @classmethod
    def from_bytes(cls, value: bytes) -> "PacketDeltaExtraction":
        row = _decode_mapping(value, "packet extraction")
        try:
            raw_groups = row["groups"]
            if not isinstance(raw_groups, list):
                raise O1C22PacketCodecError(
                    "packet extraction groups must be a list"
                )
            groups = tuple(
                PacketDeltaGroup.from_bytes(_canonical_json(group))
                for group in raw_groups
            )
            result = cls(
                source_stream_sha256=cast(str, row["source_stream_sha256"]),
                action_pool_sha256=cast(str, row["action_pool_sha256"]),
                active_coordinates=tuple(
                    cast(Sequence[int], row["active_coordinates"])
                ),
                ordered_horizons=tuple(
                    cast(Sequence[int], row["ordered_horizons"])
                ),
                groups=groups,
                reader_state_sha256=cast(str, row["reader_state_sha256"]),
                reader_state_bytes=cast(int, row["reader_state_bytes"]),
                slow_state_sha256=cast(str, row["slow_state_sha256"]),
                slow_state_bytes=cast(int, row["slow_state_bytes"]),
                final_fast_state_sha256=cast(
                    str, row["final_fast_state_sha256"]
                ),
                final_fast_state_bytes=cast(int, row["final_fast_state_bytes"]),
                physical_work_units=cast(int, row["physical_work_units"]),
                observed_slots=cast(int, row["observed_slots"]),
            )
        except (KeyError, TypeError) as exc:
            raise O1C22PacketCodecError("packet extraction fields differ") from exc
        if result.to_bytes() != value:
            raise O1C22PacketCodecError("packet extraction is not canonical")
        return result


def _decode_mapping(value: bytes, name: str) -> Mapping[str, object]:
    try:
        row = json.loads(value.decode("ascii"))
    except (AttributeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise O1C22PacketCodecError(f"{name} is invalid JSON") from exc
    if not isinstance(row, Mapping):
        raise O1C22PacketCodecError(f"{name} must be an object")
    return cast(Mapping[str, object], row)


def complement_packet_polarity(group: PacketDeltaGroup) -> PacketDeltaGroup:
    if not isinstance(group, PacketDeltaGroup):
        raise TypeError("group must be lightweight PacketDeltaGroup")
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


__all__ = [
    "FrozenMedianAbsQuantizer",
    "O1C22PacketCodecError",
    "PacketDeltaExtraction",
    "PacketDeltaGroup",
    "active_coordinate_sequence_sha256",
    "complement_packet_polarity",
]
