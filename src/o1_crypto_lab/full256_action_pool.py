"""Immutable raw paired-branch action pools for full-256 causal learning.

The pool retains one fixed-width, public-only prefix summary for every requested
horizon, key coordinate, and assumption polarity.  It contains no key material
or outcome field.  Learned controllers derive exact signed and common-mode
views from the two raw polarities without reopening proof transcripts.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

import numpy as np

from .cadical_sensor import KEY_BITS, MOTIF_DIMENSIONS, ProofPrefixSummary
from .living_inverse import canonical_json_bytes


ACTION_POOL_SCHEMA = "o1-256-full256-action-pool-v1"
ACTION_POOL_BINARY_SCHEMA = "o1-256-full256-action-pool-binary-v1"
BRANCH_FEATURE_SCHEMA = "o1-256-proof-prefix-branch-features-v1"
ACTION_POOL_MAGIC = b"O1FAP1\x00"

POLARITIES = 2
RESOURCE_FIELDS = 3
SCALAR_FEATURES = 10
KEY_TOUCH_FEATURES = KEY_BITS
BRANCH_FEATURES = SCALAR_FEATURES + MOTIF_DIMENSIONS + KEY_TOUCH_FEATURES

SCALAR_FEATURE_NAMES = (
    "log1p_decisions",
    "log1p_propagations",
    "log1p_ticks",
    "log1p_derived_clause_count",
    "log1p_redundant_clause_count",
    "log1p_derived_literal_count",
    "log1p_antecedent_link_count",
    "log1p_maximum_ancestry_depth",
    "log1p_frontier_event_gap",
    "exact_conflict_event_present",
)
RESOURCE_FIELD_NAMES = (
    "solver_cpu_microseconds",
    "solver_wall_microseconds",
    "solver_peak_rss_bytes",
)


class Full256ActionPoolError(ValueError):
    """A branch feature, action-pool invariant, or binary differs."""


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise Full256ActionPoolError(f"{field} must be a lowercase SHA-256")
    return value


def _count(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise Full256ActionPoolError(f"{field} must be a non-negative integer")
    return value


def _readonly_copy(value: np.ndarray, dtype: np.dtype) -> np.ndarray:
    contiguous = np.array(value, dtype=dtype, copy=True, order="C")
    # WRITEABLE=False alone is reversible for owning arrays.  A bytes-backed
    # view makes the frozen pool physically immutable to callers as well.
    result = np.frombuffer(contiguous.tobytes(order="C"), dtype=dtype).reshape(
        contiguous.shape
    )
    if result.flags.writeable:  # pragma: no cover - bytes owners are read-only.
        raise AssertionError("action-pool array is unexpectedly writable")
    return result


def branch_feature_vector(summary: ProofPrefixSummary) -> np.ndarray:
    """Map one closed proof prefix to the canonical raw 330-wide vector."""

    if not isinstance(summary, ProofPrefixSummary):
        raise TypeError("summary must be ProofPrefixSummary")
    if (
        isinstance(summary.horizon, bool)
        or not isinstance(summary.horizon, int)
        or summary.horizon < 1
    ):
        raise Full256ActionPoolError("summary horizon must be positive")
    counts = (
        _count(summary.snapshot.decisions, "snapshot.decisions"),
        _count(summary.snapshot.propagations, "snapshot.propagations"),
        _count(summary.snapshot.ticks, "snapshot.ticks"),
        _count(summary.derived_clause_count, "derived_clause_count"),
        _count(summary.redundant_clause_count, "redundant_clause_count"),
        _count(summary.derived_literal_count, "derived_literal_count"),
        _count(summary.antecedent_link_count, "antecedent_link_count"),
        _count(summary.maximum_ancestry_depth, "maximum_ancestry_depth"),
        _count(summary.frontier_event_gap, "frontier_event_gap"),
    )
    if not isinstance(summary.exact_conflict_event_present, bool):
        raise Full256ActionPoolError("exact_conflict_event_present must be boolean")
    motif = np.asarray(summary.motif)
    key_touch = np.asarray(summary.key_touch)
    if motif.shape != (MOTIF_DIMENSIONS,) or not np.all(np.isfinite(motif)):
        raise Full256ActionPoolError(
            f"summary motif must be finite shape ({MOTIF_DIMENSIONS},)"
        )
    if key_touch.shape != (KEY_BITS,) or not np.all(np.isfinite(key_touch)):
        raise Full256ActionPoolError(
            f"summary key_touch must be finite shape ({KEY_BITS},)"
        )

    vector = np.empty(BRANCH_FEATURES, dtype=np.float32)
    with np.errstate(over="ignore", invalid="ignore"):
        vector[: SCALAR_FEATURES - 1] = np.log1p(
            np.asarray(counts, dtype=np.float64)
        ).astype(np.float32)
    vector[SCALAR_FEATURES - 1] = np.float32(summary.exact_conflict_event_present)
    motif_end = SCALAR_FEATURES + MOTIF_DIMENSIONS
    vector[SCALAR_FEATURES:motif_end] = motif.astype(np.float32)
    vector[motif_end:] = key_touch.astype(np.float32)
    if not np.all(np.isfinite(vector)):
        raise Full256ActionPoolError("branch feature mapping is non-finite")
    vector.setflags(write=False)
    return vector


def _array_inventory(
    pool: "Full256ActionPool",
) -> tuple[list[dict[str, object]], bytes]:
    rows: list[dict[str, object]] = []
    payloads: list[bytes] = []
    offset = 0
    for name, raw, dtype_name, dtype in (
        (
            "branch_features",
            pool.branch_features,
            "float32le",
            "<f4",
        ),
        (
            "final_resources",
            pool.final_resources,
            "uint64le",
            "<u8",
        ),
    ):
        payload = raw.astype(dtype, copy=False).tobytes(order="C")
        rows.append(
            {
                "name": name,
                "shape": list(raw.shape),
                "dtype": dtype_name,
                "offset": offset,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        payloads.append(payload)
        offset += len(payload)
    return rows, b"".join(payloads)


def _binary_header(
    pool: "Full256ActionPool",
    arrays: Sequence[Mapping[str, object]],
    payload_bytes: int,
) -> dict[str, object]:
    return {
        "schema": ACTION_POOL_BINARY_SCHEMA,
        "action_pool_schema": ACTION_POOL_SCHEMA,
        "branch_feature_schema": BRANCH_FEATURE_SCHEMA,
        "horizons": list(pool.horizons),
        "key_bits": KEY_BITS,
        "polarities": POLARITIES,
        "branch_feature_width": BRANCH_FEATURES,
        "resource_fields": list(RESOURCE_FIELD_NAMES),
        "pair_sha256": list(pool.pair_sha256),
        "source_stream_sha256": pool.source_stream_sha256,
        "arrays": [dict(row) for row in arrays],
        "payload_bytes": payload_bytes,
    }


@dataclass(frozen=True)
class Full256ActionPool:
    """Fixed public prefix pool with exact zero/one polarity retention."""

    horizons: tuple[int, ...]
    branch_features: np.ndarray
    final_resources: np.ndarray
    pair_sha256: tuple[str, ...]
    source_stream_sha256: str

    def __post_init__(self) -> None:
        try:
            horizons = tuple(self.horizons)
        except TypeError as exc:
            raise Full256ActionPoolError(
                "horizons must be an integer sequence"
            ) from exc
        if (
            not horizons
            or len(set(horizons)) != len(horizons)
            or any(
                isinstance(horizon, bool)
                or not isinstance(horizon, int)
                or not 1 <= horizon <= np.iinfo(np.int32).max
                for horizon in horizons
            )
        ):
            raise Full256ActionPoolError(
                "horizons must be non-empty, unique, positive int32 values"
            )
        features = np.asarray(self.branch_features)
        expected_shape = (
            len(horizons),
            KEY_BITS,
            POLARITIES,
            BRANCH_FEATURES,
        )
        if (
            features.shape != expected_shape
            or features.dtype != np.float32
            or not np.all(np.isfinite(features))
        ):
            raise Full256ActionPoolError(
                "branch_features must be finite float32[H,256,2,330]"
            )
        resources = np.asarray(self.final_resources)
        if resources.shape != (KEY_BITS, POLARITIES, RESOURCE_FIELDS):
            raise Full256ActionPoolError(
                "final_resources must have shape uint64[256,2,3]"
            )
        if resources.dtype != np.uint64:
            raise Full256ActionPoolError(
                "final_resources must have shape uint64[256,2,3]"
            )
        try:
            pairs = tuple(self.pair_sha256)
        except TypeError as exc:
            raise Full256ActionPoolError("pair_sha256 must contain 256 hashes") from exc
        if len(pairs) != KEY_BITS:
            raise Full256ActionPoolError("pair_sha256 must contain 256 hashes")
        for index, value in enumerate(pairs):
            _sha256(value, f"pair_sha256[{index}]")
        _sha256(self.source_stream_sha256, "source_stream_sha256")

        object.__setattr__(self, "horizons", horizons)
        object.__setattr__(
            self,
            "branch_features",
            _readonly_copy(features, np.dtype(np.float32)),
        )
        object.__setattr__(
            self,
            "final_resources",
            _readonly_copy(resources, np.dtype(np.uint64)),
        )
        object.__setattr__(self, "pair_sha256", pairs)

    @property
    def horizon_count(self) -> int:
        return len(self.horizons)

    @property
    def branch_count_per_horizon(self) -> int:
        return KEY_BITS * POLARITIES

    @property
    def raw_feature_bytes(self) -> int:
        return int(self.branch_features.nbytes)

    @property
    def resource_bytes(self) -> int:
        return int(self.final_resources.nbytes)

    def signed_field(self) -> np.ndarray:
        """Return F(1)-F(0) as immutable float32[H,256,330]."""

        result = np.subtract(
            self.branch_features[:, :, 1, :],
            self.branch_features[:, :, 0, :],
            dtype=np.float32,
        )
        result.setflags(write=False)
        return result

    def common_field(self) -> np.ndarray:
        """Return 0.5*(F(1)+F(0)) as immutable float32[H,256,330]."""

        result = np.add(
            self.branch_features[:, :, 1, :],
            self.branch_features[:, :, 0, :],
            dtype=np.float32,
        )
        result *= np.float32(0.5)
        result.setflags(write=False)
        return result

    def polarity_swapped(self) -> "Full256ActionPool":
        """Return the virtual assumption-swap control bound to the same source."""

        return Full256ActionPool(
            horizons=self.horizons,
            branch_features=self.branch_features[:, :, ::-1, :],
            final_resources=self.final_resources[:, ::-1, :],
            pair_sha256=self.pair_sha256,
            source_stream_sha256=self.source_stream_sha256,
        )

    def swap_control(self) -> dict[str, bool]:
        swapped = self.polarity_swapped()
        checks = {
            "signed_field_negates": bool(
                np.array_equal(swapped.signed_field(), -self.signed_field())
            ),
            "common_field_invariant": bool(
                np.array_equal(swapped.common_field(), self.common_field())
            ),
            "resources_follow_polarity": bool(
                np.array_equal(
                    swapped.final_resources,
                    self.final_resources[:, ::-1, :],
                )
            ),
            "source_binding_invariant": (
                swapped.source_stream_sha256 == self.source_stream_sha256
                and swapped.pair_sha256 == self.pair_sha256
            ),
        }
        return {**checks, "passed": all(checks.values())}

    def requested_conflicts_for(
        self,
        horizon: int,
        bits: Iterable[int] | None = None,
    ) -> int:
        """Bill both polarity branches for selected coordinates at one horizon."""

        if isinstance(horizon, bool) or not isinstance(horizon, int):
            raise Full256ActionPoolError("horizon must be an exact integer")
        if horizon not in self.horizons:
            raise Full256ActionPoolError("horizon is absent from the action pool")
        if bits is None:
            count = KEY_BITS
        else:
            try:
                selected = tuple(bits)
            except TypeError as exc:
                raise Full256ActionPoolError(
                    "bits must be a unique coordinate sequence"
                ) from exc
            if len(set(selected)) != len(selected) or any(
                isinstance(bit, bool)
                or not isinstance(bit, int)
                or not 0 <= bit < KEY_BITS
                for bit in selected
            ):
                raise Full256ActionPoolError(
                    "bits must be unique coordinates in [0,255]"
                )
            count = len(selected)
        return horizon * POLARITIES * count

    @property
    def all_prefix_requested_conflicts(self) -> int:
        """Work if every stored prefix were executed as an independent action."""

        return sum(self.requested_conflicts_for(horizon) for horizon in self.horizons)

    @property
    def maximum_horizon_sweep_requested_conflicts(self) -> int:
        """Work of the single max-horizon sweep that can yield all prefixes."""

        return self.requested_conflicts_for(max(self.horizons))

    @property
    def action_pool_sha256(self) -> str:
        return hashlib.sha256(serialize_action_pool(self)).hexdigest()

    @property
    def serialized_bytes(self) -> int:
        return len(serialize_action_pool(self))

    def byte_inventory(self) -> dict[str, object]:
        arrays, payload = _array_inventory(self)
        header = canonical_json_bytes(_binary_header(self, arrays, len(payload)))
        return {
            "magic_bytes": len(ACTION_POOL_MAGIC),
            "header_length_prefix_bytes": 8,
            "header_bytes": len(header),
            "payload_bytes": len(payload),
            "serialized_bytes": len(ACTION_POOL_MAGIC) + 8 + len(header) + len(payload),
            "arrays": arrays,
        }

    def describe(self) -> dict[str, object]:
        per_horizon = [
            {
                "horizon": horizon,
                "branches": self.branch_count_per_horizon,
                "requested_conflicts": self.requested_conflicts_for(horizon),
            }
            for horizon in self.horizons
        ]
        value: dict[str, object] = {
            "schema": ACTION_POOL_SCHEMA,
            "branch_feature_schema": BRANCH_FEATURE_SCHEMA,
            "horizons": list(self.horizons),
            "shape": list(self.branch_features.shape),
            "dtype": "float32le",
            "resource_shape": list(self.final_resources.shape),
            "resource_dtype": "uint64le",
            "resource_fields": list(RESOURCE_FIELD_NAMES),
            "feature_order": {
                "scalar": {
                    "columns_half_open": [0, SCALAR_FEATURES],
                    "names": list(SCALAR_FEATURE_NAMES),
                },
                "motif64": {
                    "columns_half_open": [
                        SCALAR_FEATURES,
                        SCALAR_FEATURES + MOTIF_DIMENSIONS,
                    ]
                },
                "key_touch256": {
                    "columns_half_open": [
                        SCALAR_FEATURES + MOTIF_DIMENSIONS,
                        BRANCH_FEATURES,
                    ]
                },
            },
            "source_stream_sha256": self.source_stream_sha256,
            "pair_hash_count": len(self.pair_sha256),
            "requested_conflict_accounting": {
                "per_horizon_full_sweep": per_horizon,
                "all_prefix_actions": self.all_prefix_requested_conflicts,
                "single_max_horizon_generation": (
                    self.maximum_horizon_sweep_requested_conflicts
                ),
                "prefixes_share_one_max_horizon_record": True,
            },
            "byte_inventory": self.byte_inventory(),
            "action_pool_sha256": self.action_pool_sha256,
            "immutable": True,
        }
        return value


def serialize_action_pool(pool: Full256ActionPool) -> bytes:
    """Serialize one action pool to canonical header-plus-array bytes."""

    if not isinstance(pool, Full256ActionPool):
        raise Full256ActionPoolError("pool must be Full256ActionPool")
    arrays, payload = _array_inventory(pool)
    header = canonical_json_bytes(_binary_header(pool, arrays, len(payload)))
    return ACTION_POOL_MAGIC + struct.pack(">Q", len(header)) + header + payload


def deserialize_action_pool(value: bytes) -> Full256ActionPool:
    """Parse and independently re-canonicalize a serialized action pool."""

    if not isinstance(value, bytes) or not value.startswith(ACTION_POOL_MAGIC):
        raise Full256ActionPoolError("action-pool binary magic differs")
    cursor = len(ACTION_POOL_MAGIC)
    if len(value) < cursor + 8:
        raise Full256ActionPoolError("action-pool binary header is truncated")
    header_length = struct.unpack(">Q", value[cursor : cursor + 8])[0]
    cursor += 8
    end_header = cursor + header_length
    if end_header > len(value):
        raise Full256ActionPoolError("action-pool binary header is truncated")
    try:
        header = json.loads(value[cursor:end_header].decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Full256ActionPoolError("action-pool binary header is invalid") from exc
    cursor = end_header
    expected_header_fields = {
        "schema",
        "action_pool_schema",
        "branch_feature_schema",
        "horizons",
        "key_bits",
        "polarities",
        "branch_feature_width",
        "resource_fields",
        "pair_sha256",
        "source_stream_sha256",
        "arrays",
        "payload_bytes",
    }
    if (
        not isinstance(header, dict)
        or set(header) != expected_header_fields
        or header.get("schema") != ACTION_POOL_BINARY_SCHEMA
        or header.get("action_pool_schema") != ACTION_POOL_SCHEMA
        or header.get("branch_feature_schema") != BRANCH_FEATURE_SCHEMA
        or header.get("key_bits") != KEY_BITS
        or header.get("polarities") != POLARITIES
        or header.get("branch_feature_width") != BRANCH_FEATURES
        or header.get("resource_fields") != list(RESOURCE_FIELD_NAMES)
    ):
        raise Full256ActionPoolError("action-pool binary schema differs")
    raw_horizons = header.get("horizons")
    raw_pairs = header.get("pair_sha256")
    if not isinstance(raw_horizons, list) or not isinstance(raw_pairs, list):
        raise Full256ActionPoolError("action-pool binary metadata differs")
    horizons = tuple(raw_horizons)
    expected_shapes = {
        "branch_features": (
            len(horizons),
            KEY_BITS,
            POLARITIES,
            BRANCH_FEATURES,
        ),
        "final_resources": (KEY_BITS, POLARITIES, RESOURCE_FIELDS),
    }
    expected_dtypes = {
        "branch_features": ("float32le", "<f4"),
        "final_resources": ("uint64le", "<u8"),
    }
    rows = header.get("arrays")
    if not isinstance(rows, list) or len(rows) != len(expected_shapes):
        raise Full256ActionPoolError("action-pool array inventory differs")
    arrays: dict[str, np.ndarray] = {}
    expected_offset = 0
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "name",
            "shape",
            "dtype",
            "offset",
            "bytes",
            "sha256",
        }:
            raise Full256ActionPoolError("action-pool array row differs")
        name = row.get("name")
        if not isinstance(name, str) or name not in expected_shapes or name in arrays:
            raise Full256ActionPoolError("action-pool array inventory differs")
        dtype_name, dtype = expected_dtypes[name]
        try:
            shape = tuple(int(dimension) for dimension in row["shape"])
            offset = int(row["offset"])
            byte_count = int(row["bytes"])
            expected_hash = str(row["sha256"])
        except (KeyError, TypeError, ValueError) as exc:
            raise Full256ActionPoolError("action-pool array row differs") from exc
        expected_bytes = math.prod(expected_shapes[name]) * np.dtype(dtype).itemsize
        if (
            shape != expected_shapes[name]
            or row.get("dtype") != dtype_name
            or offset != expected_offset
            or byte_count != expected_bytes
        ):
            raise Full256ActionPoolError("action-pool array layout differs")
        start = cursor + offset
        end = start + byte_count
        payload = value[start:end]
        if (
            len(payload) != byte_count
            or hashlib.sha256(payload).hexdigest() != expected_hash
        ):
            raise Full256ActionPoolError("action-pool array payload differs")
        try:
            arrays[name] = np.frombuffer(payload, dtype=dtype).reshape(shape).copy()
        except ValueError as exc:
            raise Full256ActionPoolError("action-pool array shape differs") from exc
        expected_offset += byte_count
    if set(arrays) != set(expected_shapes):
        raise Full256ActionPoolError("action-pool array set is incomplete")
    try:
        payload_bytes = int(header["payload_bytes"])
        pool = Full256ActionPool(
            horizons=horizons,
            branch_features=arrays["branch_features"],
            final_resources=arrays["final_resources"],
            pair_sha256=tuple(raw_pairs),
            source_stream_sha256=str(header["source_stream_sha256"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise Full256ActionPoolError("serialized action-pool fields differ") from exc
    if payload_bytes != expected_offset or len(value) != cursor + payload_bytes:
        raise Full256ActionPoolError("action-pool binary length differs")
    if serialize_action_pool(pool) != value:
        raise Full256ActionPoolError("action-pool binary is not canonical")
    return pool


__all__ = [
    "ACTION_POOL_BINARY_SCHEMA",
    "ACTION_POOL_MAGIC",
    "ACTION_POOL_SCHEMA",
    "BRANCH_FEATURES",
    "BRANCH_FEATURE_SCHEMA",
    "Full256ActionPool",
    "Full256ActionPoolError",
    "RESOURCE_FIELD_NAMES",
    "SCALAR_FEATURE_NAMES",
    "branch_feature_vector",
    "deserialize_action_pool",
    "serialize_action_pool",
]
