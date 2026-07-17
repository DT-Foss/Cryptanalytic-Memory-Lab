"""Literal O1-O ``.causal`` envelope for the O1C-0022 public FSM control.

This module deliberately does not import O1-O.  Its native package bootstraps a
knowledge directory and mutates in-memory indexes while loading; neither side
effect belongs in a scientific replay.  Instead, this module implements the
small portable boundary that O1-O actually consumes::

    b"CAUSAL" + uint16_be(1) + zlib(msgpack(graph))

The graph contains one bridge-intent triplet and the frozen 4 x 8 x 2 signed
coefficient table.  A matching standard fragment document resolves its outcome
to a generated read-only wrapper, which consumes canonical JSON groups and
emits a hash-bound receipt.  An environment-gated integration test can place
both fixtures in a disposable directory and exercise O1-O's native loader and
assembler; native natural-language selection remains outside the scientific
mechanism claim.

The replay state is byte-for-byte compatible with
``OutcomePublicFSMState``: 256 signed evidence bytes, one previous-marker byte,
then little-endian uint64 last-group and accepted-update counters.  A novel
group applies all 256 evidence events with the *previous* marker and commits the
current marker only afterwards.  Repeated group identifiers are atomic no-ops.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Final, Iterator, Mapping, Sequence

import numpy as np

try:  # O1-O's portable graph dependency; intentionally not O1-O itself.
    import msgpack
except ImportError:  # pragma: no cover - exercised only in a minimal install.
    msgpack = None  # type: ignore[assignment]


CAUSAL_MAGIC: Final = b"CAUSAL"
CAUSAL_VERSION: Final = 1
CAUSAL_HEADER_BYTES: Final = len(CAUSAL_MAGIC) + 2
BRIDGE_SCHEMA: Final = "o1-256-o1o-public-fsm-bridge-v1"
BRIDGE_INTENTS_FILENAME: Final = "bridge_intents.causal"
PUBLIC_FSM_INTENT: Final = "compose 256 bit causal evidence public fsm"
PUBLIC_FSM_FRAGMENT_KEY: Final = "outcome_table_public_fsm"
PUBLIC_FSM_FRAGMENT_FILENAME: Final = "o1_public_fsm_fragments.json"
PUBLIC_FSM_RECEIPT_SCHEMA: Final = "o1-256-o1o-public-fsm-receipt-v1"

N_BITS: Final = 256
REGIME_COUNT: Final = 4
FAMILY_COUNT: Final = 8
QUALITY_COUNT: Final = 2
COEFFICIENT_TABLE_SHAPE: Final = (REGIME_COUNT, FAMILY_COUNT, QUALITY_COUNT)
COEFFICIENT_TABLE_BYTES: Final = 64
PUBLIC_FSM_STATE_BYTES: Final = 273

_MASK64: Final = (1 << 64) - 1
_MAX_CAUSAL_BYTES: Final = 16 * 1024
_MAX_GRAPH_BYTES: Final = 8 * 1024
_MAX_GROUP_LINE_BYTES: Final = 32 * 1024
_MAX_GROUP_STREAM_BYTES: Final = 64 * 1024 * 1024
_TRIPLET: Final = {
    "trigger": PUBLIC_FSM_INTENT,
    "mechanism": "pipeline",
    "outcome": PUBLIC_FSM_FRAGMENT_KEY,
    "confidence": 1.0,
}


class O1OPublicFSMBridgeError(ValueError):
    """The O1-O envelope, frozen table, event, or replay state differs."""


def _mini_pack_messagepack(value: object, *, _depth: int = 0) -> bytes:
    """Encode the strict MessagePack subset used by this one fixed graph.

    The byte choices match ``msgpack.packb(..., use_bin_type=True)``: shortest
    integer/container prefixes, bin rather than raw for bytes, and float64.
    Keeping this tiny codec local lets a generated O1-O wrapper replay on a
    minimal Python installation without changing the native CAUSAL format.
    """

    if _depth > 8:
        raise O1OPublicFSMBridgeError("CAUSAL MessagePack nesting differs")
    if type(value) is int:
        if 0 <= value <= 0x7F:
            return bytes((value,))
        if -32 <= value < 0:
            return bytes((value & 0xFF,))
        if 0 <= value <= 0xFF:
            return b"\xcc" + struct.pack(">B", value)
        if 0 <= value <= 0xFFFF:
            return b"\xcd" + struct.pack(">H", value)
        if 0 <= value <= 0xFFFFFFFF:
            return b"\xce" + struct.pack(">I", value)
        if 0 <= value <= _MASK64:
            return b"\xcf" + struct.pack(">Q", value)
        if -0x80 <= value < -32:
            return b"\xd0" + struct.pack(">b", value)
        if -0x8000 <= value < -0x80:
            return b"\xd1" + struct.pack(">h", value)
        if -0x80000000 <= value < -0x8000:
            return b"\xd2" + struct.pack(">i", value)
        if -(1 << 63) <= value < -0x80000000:
            return b"\xd3" + struct.pack(">q", value)
        raise O1OPublicFSMBridgeError("CAUSAL MessagePack integer range differs")
    if type(value) is float:
        return b"\xcb" + struct.pack(">d", value)
    if isinstance(value, str):
        if not value.isascii():
            raise O1OPublicFSMBridgeError("CAUSAL MessagePack strings must be ASCII")
        encoded = value.encode("ascii")
        length = len(encoded)
        if length <= 31:
            return bytes((0xA0 | length,)) + encoded
        if length <= 0xFF:
            return b"\xd9" + struct.pack(">B", length) + encoded
        if length <= 0xFFFF:
            return b"\xda" + struct.pack(">H", length) + encoded
        raise O1OPublicFSMBridgeError("CAUSAL MessagePack string is too large")
    if isinstance(value, bytes):
        length = len(value)
        if length <= 0xFF:
            return b"\xc4" + struct.pack(">B", length) + value
        if length <= 0xFFFF:
            return b"\xc5" + struct.pack(">H", length) + value
        raise O1OPublicFSMBridgeError("CAUSAL MessagePack binary is too large")
    if isinstance(value, list):
        length = len(value)
        if length > 16:
            raise O1OPublicFSMBridgeError("CAUSAL MessagePack array is too large")
        if length <= 15:
            prefix = bytes((0x90 | length,))
        else:
            prefix = b"\xdc" + struct.pack(">H", length)
        return prefix + b"".join(
            _mini_pack_messagepack(item, _depth=_depth + 1) for item in value
        )
    if isinstance(value, dict):
        length = len(value)
        if length > 16:
            raise O1OPublicFSMBridgeError("CAUSAL MessagePack map is too large")
        if length <= 15:
            prefix = bytes((0x80 | length,))
        else:
            prefix = b"\xde" + struct.pack(">H", length)
        fields = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise O1OPublicFSMBridgeError("CAUSAL MessagePack map key differs")
            fields.append(_mini_pack_messagepack(key, _depth=_depth + 1))
            fields.append(_mini_pack_messagepack(item, _depth=_depth + 1))
        return prefix + b"".join(fields)
    raise O1OPublicFSMBridgeError("CAUSAL MessagePack value type differs")


class _MiniMessagePackDecoder:
    """Bounds-checked decoder for the exact local MessagePack subset."""

    def __init__(self, payload: bytes):
        self.payload = payload
        self.offset = 0

    def _take(self, length: int) -> bytes:
        if length < 0 or self.offset + length > len(self.payload):
            raise O1OPublicFSMBridgeError("CAUSAL MessagePack is truncated")
        result = self.payload[self.offset : self.offset + length]
        self.offset += length
        return result

    def _unsigned(self, width: int) -> int:
        return int.from_bytes(self._take(width), "big", signed=False)

    def _string(self, length: int) -> str:
        if length > 1024:
            raise O1OPublicFSMBridgeError("CAUSAL MessagePack string is too large")
        raw = self._take(length)
        if not raw.isascii():
            raise O1OPublicFSMBridgeError("CAUSAL MessagePack strings must be ASCII")
        return raw.decode("ascii")

    def _array(self, length: int, depth: int) -> list[object]:
        if length > 16:
            raise O1OPublicFSMBridgeError("CAUSAL MessagePack array is too large")
        return [self.unpack(depth + 1) for _ in range(length)]

    def _map(self, length: int, depth: int) -> dict[str, object]:
        if length > 16:
            raise O1OPublicFSMBridgeError("CAUSAL MessagePack map is too large")
        result: dict[str, object] = {}
        for _ in range(length):
            key = self.unpack(depth + 1)
            if not isinstance(key, str) or key in result:
                raise O1OPublicFSMBridgeError("CAUSAL MessagePack map key differs")
            result[key] = self.unpack(depth + 1)
        return result

    def unpack(self, depth: int = 0) -> object:
        if depth > 8:
            raise O1OPublicFSMBridgeError("CAUSAL MessagePack nesting differs")
        prefix = self._take(1)[0]
        if prefix <= 0x7F:
            return prefix
        if 0x80 <= prefix <= 0x8F:
            return self._map(prefix & 0x0F, depth)
        if 0x90 <= prefix <= 0x9F:
            return self._array(prefix & 0x0F, depth)
        if 0xA0 <= prefix <= 0xBF:
            return self._string(prefix & 0x1F)
        if prefix >= 0xE0:
            return prefix - 0x100
        if prefix == 0xC4:
            return self._take(self._unsigned(1))
        if prefix == 0xC5:
            return self._take(self._unsigned(2))
        if prefix == 0xCA:
            return struct.unpack(">f", self._take(4))[0]
        if prefix == 0xCB:
            return struct.unpack(">d", self._take(8))[0]
        if prefix == 0xCC:
            return self._unsigned(1)
        if prefix == 0xCD:
            return self._unsigned(2)
        if prefix == 0xCE:
            return self._unsigned(4)
        if prefix == 0xCF:
            return self._unsigned(8)
        if prefix == 0xD0:
            return struct.unpack(">b", self._take(1))[0]
        if prefix == 0xD1:
            return struct.unpack(">h", self._take(2))[0]
        if prefix == 0xD2:
            return struct.unpack(">i", self._take(4))[0]
        if prefix == 0xD3:
            return struct.unpack(">q", self._take(8))[0]
        if prefix == 0xD9:
            return self._string(self._unsigned(1))
        if prefix == 0xDA:
            return self._string(self._unsigned(2))
        if prefix == 0xDC:
            return self._array(self._unsigned(2), depth)
        if prefix == 0xDE:
            return self._map(self._unsigned(2), depth)
        raise O1OPublicFSMBridgeError("CAUSAL MessagePack prefix differs")


def _pack_messagepack(value: object) -> bytes:
    if msgpack is not None:
        return msgpack.packb(value, use_bin_type=True)
    return _mini_pack_messagepack(value)


def _unpack_messagepack(payload: bytes) -> object:
    if msgpack is not None:
        return msgpack.unpackb(
            payload,
            raw=False,
            strict_map_key=True,
            max_str_len=1024,
            max_bin_len=1024,
            max_array_len=16,
            max_map_len=16,
            max_ext_len=0,
        )
    decoder = _MiniMessagePackDecoder(payload)
    result = decoder.unpack()
    if decoder.offset != len(payload):
        raise O1OPublicFSMBridgeError("CAUSAL MessagePack has trailing data")
    return result


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _coefficient_bytes(table: np.ndarray) -> bytes:
    array = np.asarray(table)
    if array.shape != COEFFICIENT_TABLE_SHAPE or array.dtype != np.int8:
        raise O1OPublicFSMBridgeError("coefficient table must be exactly int8[4,8,2]")
    if not array.flags.c_contiguous:
        array = np.ascontiguousarray(array)
    payload = array.tobytes(order="C")
    if len(payload) != COEFFICIENT_TABLE_BYTES:
        raise AssertionError("coefficient table byte width differs")
    return payload


def _graph_for_table(table_bytes: bytes) -> dict[str, object]:
    return {
        "triplets": [dict(_TRIPLET)],
        "metadata": {
            "version": CAUSAL_VERSION,
            "source": "O1C-0022_bridge_intents",
            "generator": "o1-cryptanalytic-memory-lab",
            "bridge": {
                "schema": BRIDGE_SCHEMA,
                "coefficient_table_shape": list(COEFFICIENT_TABLE_SHAPE),
                "coefficient_table_dtype": "int8",
                "coefficient_table_nbytes": COEFFICIENT_TABLE_BYTES,
                "coefficient_table_i8": table_bytes,
                "coefficient_table_sha256": _sha256(table_bytes),
                "public_fsm_state_bytes": PUBLIC_FSM_STATE_BYTES,
                "duplicate_policy": "same-group-id-atomic-no-op",
                "marker_policy": "commit-after-evidence",
                "native_selection_fixture": BRIDGE_INTENTS_FILENAME,
                "native_selection_test": "optional-disposable-copy-only",
            },
        },
    }


def encode_public_fsm_bridge(table: np.ndarray) -> bytes:
    """Encode a frozen table in the exact portable O1-O CAUSAL container."""

    table_bytes = _coefficient_bytes(table)
    packed = _pack_messagepack(_graph_for_table(table_bytes))
    compressed = zlib.compress(packed, level=9)
    result = CAUSAL_MAGIC + struct.pack(">H", CAUSAL_VERSION) + compressed
    if len(result) > _MAX_CAUSAL_BYTES:
        raise AssertionError("fixed O1-O bridge exceeds its envelope bound")
    return result


def _safe_decompress(compressed: bytes) -> bytes:
    if not compressed:
        raise O1OPublicFSMBridgeError("CAUSAL graph payload is empty")
    decoder = zlib.decompressobj()
    try:
        raw = decoder.decompress(compressed, _MAX_GRAPH_BYTES + 1)
        if len(raw) > _MAX_GRAPH_BYTES or decoder.unconsumed_tail:
            raise O1OPublicFSMBridgeError("CAUSAL graph exceeds its size bound")
        raw += decoder.flush()
    except zlib.error as exc:
        raise O1OPublicFSMBridgeError("CAUSAL graph is not valid zlib data") from exc
    if len(raw) > _MAX_GRAPH_BYTES:
        raise O1OPublicFSMBridgeError("CAUSAL graph exceeds its size bound")
    if not decoder.eof or decoder.unused_data:
        raise O1OPublicFSMBridgeError(
            "CAUSAL graph is truncated or has trailing compressed data"
        )
    return raw


def _exact_dict(value: object, field: str, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise O1OPublicFSMBridgeError(f"{field} schema differs")
    if any(not isinstance(key, str) for key in value):
        raise O1OPublicFSMBridgeError(f"{field} has a non-string key")
    return value


def _validate_graph(graph: object) -> bytes:
    root = _exact_dict(graph, "CAUSAL graph", {"triplets", "metadata"})
    triplets = root["triplets"]
    if (
        not isinstance(triplets, list)
        or len(triplets) != 1
        or triplets[0] != _TRIPLET
        or not isinstance(triplets[0], dict)
    ):
        raise O1OPublicFSMBridgeError("bridge_intents triplet differs")

    metadata = _exact_dict(
        root["metadata"],
        "CAUSAL metadata",
        {"version", "source", "generator", "bridge"},
    )
    if (
        type(metadata["version"]) is not int
        or metadata["version"] != CAUSAL_VERSION
        or metadata["source"] != "O1C-0022_bridge_intents"
        or metadata["generator"] != "o1-cryptanalytic-memory-lab"
    ):
        raise O1OPublicFSMBridgeError("CAUSAL metadata identity differs")

    bridge = _exact_dict(
        metadata["bridge"],
        "public FSM bridge metadata",
        {
            "schema",
            "coefficient_table_shape",
            "coefficient_table_dtype",
            "coefficient_table_nbytes",
            "coefficient_table_i8",
            "coefficient_table_sha256",
            "public_fsm_state_bytes",
            "duplicate_policy",
            "marker_policy",
            "native_selection_fixture",
            "native_selection_test",
        },
    )
    if (
        bridge["schema"] != BRIDGE_SCHEMA
        or bridge["coefficient_table_shape"] != list(COEFFICIENT_TABLE_SHAPE)
        or bridge["coefficient_table_dtype"] != "int8"
        or type(bridge["coefficient_table_nbytes"]) is not int
        or bridge["coefficient_table_nbytes"] != COEFFICIENT_TABLE_BYTES
        or type(bridge["public_fsm_state_bytes"]) is not int
        or bridge["public_fsm_state_bytes"] != PUBLIC_FSM_STATE_BYTES
        or bridge["duplicate_policy"] != "same-group-id-atomic-no-op"
        or bridge["marker_policy"] != "commit-after-evidence"
        or bridge["native_selection_fixture"] != BRIDGE_INTENTS_FILENAME
        or bridge["native_selection_test"] != "optional-disposable-copy-only"
    ):
        raise O1OPublicFSMBridgeError("public FSM bridge contract differs")
    table_bytes = bridge["coefficient_table_i8"]
    if not isinstance(table_bytes, bytes) or len(table_bytes) != 64:
        raise O1OPublicFSMBridgeError("public FSM coefficient bytes differ")
    digest = bridge["coefficient_table_sha256"]
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or digest != _sha256(table_bytes)
    ):
        raise O1OPublicFSMBridgeError("public FSM coefficient digest differs")
    return table_bytes


@dataclass(frozen=True)
class FrozenO1OPublicFSMBridge:
    """Validated immutable view of one O1-O public-FSM graph."""

    coefficient_table_i8: bytes
    causal_sha256: str

    @property
    def coefficient_table(self) -> np.ndarray:
        """Return a caller-owned ``int8[4,8,2]`` table."""

        return (
            np.frombuffer(self.coefficient_table_i8, dtype=np.int8)
            .reshape(COEFFICIENT_TABLE_SHAPE)
            .copy()
        )


def decode_public_fsm_bridge(
    payload: bytes,
    *,
    expected_sha256: str | None = None,
) -> FrozenO1OPublicFSMBridge:
    """Validate and decode a lab-owned O1-O public-FSM graph.

    ``expected_sha256`` supplies authenticity when a capsule manifest already
    commits to the graph.  The native CAUSAL envelope itself provides zlib
    corruption detection, not a signature.
    """

    if not isinstance(payload, bytes):
        raise O1OPublicFSMBridgeError("CAUSAL payload must be bytes")
    if len(payload) <= CAUSAL_HEADER_BYTES or len(payload) > _MAX_CAUSAL_BYTES:
        raise O1OPublicFSMBridgeError("CAUSAL payload length differs")
    digest = _sha256(payload)
    if expected_sha256 is not None:
        if (
            not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
            or digest != expected_sha256
        ):
            raise O1OPublicFSMBridgeError("CAUSAL capsule digest differs")
    if payload[: len(CAUSAL_MAGIC)] != CAUSAL_MAGIC:
        raise O1OPublicFSMBridgeError("CAUSAL magic differs")
    version = struct.unpack(">H", payload[len(CAUSAL_MAGIC) : CAUSAL_HEADER_BYTES])[0]
    if version != CAUSAL_VERSION:
        raise O1OPublicFSMBridgeError("CAUSAL version differs")
    packed = _safe_decompress(payload[CAUSAL_HEADER_BYTES:])
    try:
        graph = _unpack_messagepack(packed)
    except Exception as exc:
        raise O1OPublicFSMBridgeError("CAUSAL MessagePack graph differs") from exc
    table_bytes = _validate_graph(graph)
    return FrozenO1OPublicFSMBridge(table_bytes, digest)


_PUBLIC_FSM_GENERATED_WRAPPER: Final = '''#!/usr/bin/env python3
"""O1-O-generated deterministic public-FSM replay wrapper."""

from o1_crypto_lab.o1o_public_fsm_bridge import public_fsm_replay_cli
from o1_crypto_lab.o1o_public_fsm_bridge import replay_public_fsm_request


def replay_o1o_public_fsm(graph, group_stream, initial_state=None):
    """Return the canonical receipt for one bounded-state replay."""
    return replay_public_fsm_request(
        graph, group_stream, initial_state=initial_state
    )


def main(argv=None):
    """Run the read-only local replay CLI."""
    return public_fsm_replay_cli(argv)


if __name__ == "__main__":
    raise SystemExit(main())
'''


def public_fsm_fragment_document() -> dict[str, dict[str, object]]:
    """Return a fresh O1-O fragment document for the graph outcome key.

    O1-O accepts both ``key -> code`` and the richer standard fixture form
    used here: ``key -> {code, imports, description}``.  Returning a fresh
    document prevents callers from mutating a process-global registry.
    """

    return {
        PUBLIC_FSM_FRAGMENT_KEY: {
            "code": _PUBLIC_FSM_GENERATED_WRAPPER,
            "imports": ["o1_crypto_lab.o1o_public_fsm_bridge"],
            "description": ("Deterministic O1C-0022 273-byte public-FSM stream replay"),
        }
    }


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise O1OPublicFSMBridgeError("canonical JSON value differs") from exc


def encode_public_fsm_fragment_document() -> bytes:
    """Encode the deterministic fragment fixture as canonical JSON bytes."""

    return _canonical_json(public_fsm_fragment_document())


def _load_graph_payload(source: bytes | str | os.PathLike[str]) -> bytes:
    if isinstance(source, bytes):
        return source
    if not isinstance(source, (str, os.PathLike)):
        raise O1OPublicFSMBridgeError("CAUSAL graph source differs")
    path = Path(source)
    try:
        with path.open("rb") as handle:
            payload = handle.read(_MAX_CAUSAL_BYTES + 1)
    except (OSError, ValueError) as exc:
        raise O1OPublicFSMBridgeError("CAUSAL graph path is unreadable") from exc
    if len(payload) > _MAX_CAUSAL_BYTES:
        raise O1OPublicFSMBridgeError("CAUSAL payload length differs")
    return payload


def _normalize_intent(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise O1OPublicFSMBridgeError("public FSM intent differs")
    normalized = value.lower().replace("-", " ").replace("_", " ")
    return " ".join(normalized.split())


def generate_public_fsm_wrapper(
    graph: bytes | str | os.PathLike[str],
    *,
    intent: str = PUBLIC_FSM_INTENT,
) -> str:
    """Resolve canonical intent -> graph triplet -> fragment -> wrapper.

    The graph and its table are fully validated before the outcome may select
    code.  The fragment registry is lab-owned and immutable-by-construction,
    so this helper never executes code supplied by the graph or filesystem.
    """

    payload = _load_graph_payload(graph)
    decode_public_fsm_bridge(payload)
    if _normalize_intent(intent) != _normalize_intent(PUBLIC_FSM_INTENT):
        raise O1OPublicFSMBridgeError("public FSM intent has no bridge triplet")
    outcome = _TRIPLET["outcome"]
    document = public_fsm_fragment_document()
    entry = document.get(outcome)
    if not isinstance(entry, dict) or set(entry) != {
        "code",
        "imports",
        "description",
    }:
        raise AssertionError("lab-owned public FSM fragment schema differs")
    code = entry["code"]
    if not isinstance(code, str) or code != _PUBLIC_FSM_GENERATED_WRAPPER:
        raise AssertionError("lab-owned public FSM fragment code differs")
    return code


def initial_public_fsm_state() -> bytes:
    """Return the canonical 273-byte initial replay state."""

    return bytes(N_BITS) + struct.pack("<BQQ", 0, _MASK64, 0)


@dataclass(frozen=True)
class PublicFSMGroupEvent:
    """One complete public group presented atomically to the FSM."""

    group_id: int
    coordinates: Sequence[int]
    families: Sequence[int]
    qualities: Sequence[int]
    evidence_votes: Sequence[int]
    marker_symbol: int

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "PublicFSMGroupEvent":
        """Parse the JSON-shaped event contract without coercing booleans."""

        expected = {
            "group_id",
            "coordinates",
            "families",
            "qualities",
            "evidence_votes",
            "marker_symbol",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise O1OPublicFSMBridgeError("public FSM group schema differs")
        sequences: dict[str, Sequence[int]] = {}
        for field in ("coordinates", "families", "qualities", "evidence_votes"):
            item = value[field]
            if not isinstance(item, (list, tuple)):
                raise O1OPublicFSMBridgeError(f"public FSM {field} differs")
            sequences[field] = item
        return cls(
            group_id=value["group_id"],  # type: ignore[arg-type]
            coordinates=sequences["coordinates"],
            families=sequences["families"],
            qualities=sequences["qualities"],
            evidence_votes=sequences["evidence_votes"],
            marker_symbol=value["marker_symbol"],  # type: ignore[arg-type]
        )


def _integer_vector(
    values: Sequence[int],
    field: str,
    *,
    minimum: int,
    maximum: int,
) -> np.ndarray:
    if isinstance(values, np.ndarray):
        if values.shape != (N_BITS,):
            raise O1OPublicFSMBridgeError(f"public FSM {field} width differs")
        if values.dtype.kind not in {"i", "u"}:
            raise O1OPublicFSMBridgeError(f"public FSM {field} must be integral")
        source = values
    else:
        if not isinstance(values, (list, tuple)) or len(values) != N_BITS:
            raise O1OPublicFSMBridgeError(f"public FSM {field} width differs")
        if any(type(value) is not int for value in values):
            raise O1OPublicFSMBridgeError(f"public FSM {field} must be integral")
        source = np.asarray(values, dtype=np.int64)
    if bool((source < minimum).any()) or bool((source > maximum).any()):
        raise O1OPublicFSMBridgeError(f"public FSM {field} range differs")
    result = source.astype(np.int64, copy=False)
    return result


def _validated_event(
    event: PublicFSMGroupEvent,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    if not isinstance(event, PublicFSMGroupEvent):
        raise O1OPublicFSMBridgeError("public FSM event type differs")
    if type(event.group_id) is not int or not 0 <= event.group_id < _MASK64:
        raise O1OPublicFSMBridgeError("public FSM group_id differs")
    if (
        type(event.marker_symbol) is not int
        or not 0 <= event.marker_symbol < REGIME_COUNT
    ):
        raise O1OPublicFSMBridgeError("public FSM marker symbol differs")
    coordinates = _integer_vector(
        event.coordinates, "coordinates", minimum=0, maximum=N_BITS - 1
    )
    if not np.array_equal(np.sort(coordinates), np.arange(N_BITS)):
        raise O1OPublicFSMBridgeError(
            "public FSM coordinates must be a permutation of [0,255]"
        )
    families = _integer_vector(
        event.families, "families", minimum=0, maximum=FAMILY_COUNT - 1
    )
    qualities = _integer_vector(
        event.qualities, "qualities", minimum=0, maximum=QUALITY_COUNT - 1
    )
    votes = _integer_vector(
        event.evidence_votes, "evidence_votes", minimum=-1, maximum=1
    )
    if not bool(np.isin(votes, (-1, 1)).all()):
        raise O1OPublicFSMBridgeError("public FSM evidence votes must be +/-1")
    return coordinates, families, qualities, votes


def _decode_state(payload: bytes) -> tuple[np.ndarray, int, int, int]:
    if not isinstance(payload, bytes) or len(payload) != PUBLIC_FSM_STATE_BYTES:
        raise O1OPublicFSMBridgeError("serialized public FSM state length differs")
    evidence = np.frombuffer(payload[:N_BITS], dtype=np.int8).copy()
    if bool((evidence == np.int8(-128)).any()):
        raise O1OPublicFSMBridgeError("public FSM evidence forbids -128")
    previous_symbol, last_group_id, accepted_updates = struct.unpack(
        "<BQQ", payload[N_BITS:]
    )
    if previous_symbol >= REGIME_COUNT:
        raise O1OPublicFSMBridgeError("public FSM previous symbol differs")
    return evidence, previous_symbol, last_group_id, accepted_updates


def replay_public_fsm_group(
    bridge: FrozenO1OPublicFSMBridge,
    state_payload: bytes,
    event: PublicFSMGroupEvent,
) -> bytes:
    """Replay one group with native duplicate and delayed-marker semantics."""

    if not isinstance(bridge, FrozenO1OPublicFSMBridge):
        raise O1OPublicFSMBridgeError("frozen O1-O bridge type differs")
    if len(bridge.coefficient_table_i8) != COEFFICIENT_TABLE_BYTES:
        raise O1OPublicFSMBridgeError("frozen O1-O coefficient table differs")

    # Validate everything before consulting duplicate state so a malformed
    # duplicate cannot smuggle an unvalidated marker or partial event.
    coordinates, families, qualities, votes = _validated_event(event)
    evidence, previous_symbol, last_group_id, accepted_updates = _decode_state(
        state_payload
    )
    if last_group_id == event.group_id:
        return state_payload
    if accepted_updates > _MASK64 - N_BITS:
        raise O1OPublicFSMBridgeError("public FSM update counter overflow")

    table = np.frombuffer(bridge.coefficient_table_i8, dtype=np.int8).reshape(
        COEFFICIENT_TABLE_SHAPE
    )
    coefficients = table[previous_symbol, families, qualities].astype(
        np.int16, copy=False
    )
    deltas = coefficients * votes.astype(np.int16, copy=False)
    updated = evidence.astype(np.int16)
    updated[coordinates] += deltas
    updated = np.clip(updated, -127, 127).astype(np.int8)

    # Marker commit is intentionally after every evidence lookup above.
    result = updated.tobytes(order="C") + struct.pack(
        "<BQQ",
        event.marker_symbol,
        event.group_id,
        accepted_updates + N_BITS,
    )
    if len(result) != PUBLIC_FSM_STATE_BYTES:
        raise AssertionError("public FSM replay state width differs")
    return result


def replay_public_fsm_stream(
    bridge: FrozenO1OPublicFSMBridge,
    events: Sequence[PublicFSMGroupEvent],
    *,
    initial_state: bytes | None = None,
) -> bytes:
    """Replay a finite fixture stream while retaining only the 273-byte state."""

    state = initial_public_fsm_state() if initial_state is None else initial_state
    for event in events:
        state = replay_public_fsm_group(bridge, state, event)
    return state


def _event_document(event: PublicFSMGroupEvent) -> dict[str, object]:
    coordinates, families, qualities, votes = _validated_event(event)
    return {
        "coordinates": coordinates.tolist(),
        "evidence_votes": votes.tolist(),
        "families": families.tolist(),
        "group_id": event.group_id,
        "marker_symbol": event.marker_symbol,
        "qualities": qualities.tolist(),
    }


def encode_public_fsm_group_stream(
    events: Sequence[PublicFSMGroupEvent],
) -> bytes:
    """Encode events as canonical JSON Lines without retaining replay state.

    Every line is a sorted, whitespace-free JSON object followed by exactly
    one LF.  This gives the CLI a byte-stable input commitment while retaining
    group-at-a-time replay semantics.
    """

    if not isinstance(events, (list, tuple)):
        raise O1OPublicFSMBridgeError("public FSM group stream differs")
    lines = [_canonical_json(_event_document(event)) for event in events]
    if any(len(line) > _MAX_GROUP_LINE_BYTES for line in lines):
        raise O1OPublicFSMBridgeError("public FSM group line is too large")
    payload = b"" if not lines else b"\n".join(lines) + b"\n"
    if len(payload) > _MAX_GROUP_STREAM_BYTES:
        raise O1OPublicFSMBridgeError("public FSM group stream is too large")
    return payload


def _group_stream_payload(value: bytes | str) -> bytes:
    if isinstance(value, bytes):
        payload = value
    elif isinstance(value, str):
        try:
            payload = value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise O1OPublicFSMBridgeError(
                "public FSM group stream must be canonical ASCII JSON"
            ) from exc
    else:
        raise O1OPublicFSMBridgeError("public FSM group stream differs")
    if len(payload) > _MAX_GROUP_STREAM_BYTES:
        raise O1OPublicFSMBridgeError("public FSM group stream is too large")
    return payload


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON constant: {value}")


def _iter_public_fsm_group_stream(payload: bytes) -> Iterator[PublicFSMGroupEvent]:
    if not payload:
        return
    if not payload.endswith(b"\n"):
        raise O1OPublicFSMBridgeError("public FSM group stream must end in one LF")
    for line_number, raw_line in enumerate(payload[:-1].split(b"\n"), start=1):
        if not raw_line or len(raw_line) > _MAX_GROUP_LINE_BYTES:
            raise O1OPublicFSMBridgeError(
                f"public FSM group line {line_number} differs"
            )
        try:
            text = raw_line.decode("ascii")
            value = json.loads(text, parse_constant=_reject_json_constant)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise O1OPublicFSMBridgeError(
                f"public FSM group line {line_number} is not JSON"
            ) from exc
        if not isinstance(value, dict):
            raise O1OPublicFSMBridgeError(
                f"public FSM group line {line_number} schema differs"
            )
        event = PublicFSMGroupEvent.from_mapping(value)
        document = _event_document(event)
        if _canonical_json(document) != raw_line:
            raise O1OPublicFSMBridgeError(
                f"public FSM group line {line_number} is not canonical"
            )
        yield event


@dataclass(frozen=True)
class PublicFSMReplayReceipt:
    """Immutable replay result with a canonical, hash-bound receipt."""

    graph_sha256: str
    group_stream_sha256: str
    initial_state_sha256: str
    group_count: int
    accepted_group_count: int
    duplicate_group_count: int
    final_state: bytes
    final_previous_symbol: int
    final_last_group_id: int
    final_accepted_updates: int

    def to_document(self) -> dict[str, object]:
        """Return a fresh JSON-shaped receipt including the exact final state."""

        return {
            "accepted_group_count": self.accepted_group_count,
            "duplicate_group_count": self.duplicate_group_count,
            "final_accepted_updates": self.final_accepted_updates,
            "final_last_group_id": self.final_last_group_id,
            "final_previous_symbol": self.final_previous_symbol,
            "final_state_hex": self.final_state.hex(),
            "final_state_sha256": _sha256(self.final_state),
            "fragment_key": PUBLIC_FSM_FRAGMENT_KEY,
            "graph_sha256": self.graph_sha256,
            "group_count": self.group_count,
            "group_stream_sha256": self.group_stream_sha256,
            "initial_state_sha256": self.initial_state_sha256,
            "public_fsm_state_bytes": PUBLIC_FSM_STATE_BYTES,
            "schema": PUBLIC_FSM_RECEIPT_SCHEMA,
        }

    def to_canonical_json(self) -> bytes:
        """Return the byte-stable receipt emitted by the wrapper and CLI."""

        return _canonical_json(self.to_document())


def run_public_fsm_replay(
    graph: bytes | str | os.PathLike[str],
    group_stream: bytes | str,
    *,
    initial_state: bytes | None = None,
) -> PublicFSMReplayReceipt:
    """Validate and replay a canonical public stream without filesystem writes."""

    graph_payload = _load_graph_payload(graph)
    bridge = decode_public_fsm_bridge(graph_payload)
    stream_payload = _group_stream_payload(group_stream)
    state = initial_public_fsm_state() if initial_state is None else initial_state
    _, _, _, initial_updates = _decode_state(state)
    initial_digest = _sha256(state)

    group_count = 0
    for event in _iter_public_fsm_group_stream(stream_payload):
        group_count += 1
        state = replay_public_fsm_group(bridge, state, event)

    _, previous_symbol, last_group_id, final_updates = _decode_state(state)
    update_delta = final_updates - initial_updates
    if update_delta < 0 or update_delta % N_BITS:
        raise AssertionError("public FSM replay update accounting differs")
    accepted_group_count = update_delta // N_BITS
    if accepted_group_count > group_count:
        raise AssertionError("public FSM replay group accounting differs")
    return PublicFSMReplayReceipt(
        graph_sha256=bridge.causal_sha256,
        group_stream_sha256=_sha256(stream_payload),
        initial_state_sha256=initial_digest,
        group_count=group_count,
        accepted_group_count=accepted_group_count,
        duplicate_group_count=group_count - accepted_group_count,
        final_state=state,
        final_previous_symbol=previous_symbol,
        final_last_group_id=last_group_id,
        final_accepted_updates=final_updates,
    )


def replay_public_fsm_request(
    graph: bytes | str | os.PathLike[str],
    group_stream: bytes | str,
    *,
    initial_state: bytes | None = None,
) -> bytes:
    """Return only the canonical replay receipt expected by generated code."""

    return run_public_fsm_replay(
        graph,
        group_stream,
        initial_state=initial_state,
    ).to_canonical_json()


def _read_group_stream_file(path: str | os.PathLike[str]) -> bytes:
    try:
        with Path(path).open("rb") as handle:
            payload = handle.read(_MAX_GROUP_STREAM_BYTES + 1)
    except (OSError, ValueError) as exc:
        raise O1OPublicFSMBridgeError(
            "public FSM group stream path is unreadable"
        ) from exc
    if len(payload) > _MAX_GROUP_STREAM_BYTES:
        raise O1OPublicFSMBridgeError("public FSM group stream is too large")
    return payload


def _parse_state_hex(value: str | None) -> bytes | None:
    if value is None:
        return None
    if len(value) != PUBLIC_FSM_STATE_BYTES * 2 or any(
        character not in "0123456789abcdefABCDEF" for character in value
    ):
        raise O1OPublicFSMBridgeError("public FSM initial-state hex differs")
    state = bytes.fromhex(value)
    _decode_state(state)
    return state


def public_fsm_replay_cli(
    argv: Sequence[str] | None = None,
    *,
    input_stream: BinaryIO | None = None,
    output_stream: BinaryIO | None = None,
) -> int:
    """Read a graph/groups and emit one receipt; never write another file."""

    parser = argparse.ArgumentParser(
        prog=PUBLIC_FSM_FRAGMENT_KEY,
        description="Replay canonical JSON groups through the 273-byte public FSM.",
    )
    parser.add_argument("--graph", required=True, help="Path to bridge_intents.causal")
    parser.add_argument(
        "--groups",
        default="-",
        help="Canonical JSONL group path, or '-' for stdin (default)",
    )
    parser.add_argument(
        "--state-hex",
        default=None,
        help="Optional exact 273-byte initial state encoded as hexadecimal",
    )
    args = parser.parse_args(argv)

    if args.groups == "-":
        source = input_stream if input_stream is not None else sys.stdin.buffer
        payload = source.read(_MAX_GROUP_STREAM_BYTES + 1)
        if not isinstance(payload, bytes):
            raise O1OPublicFSMBridgeError("public FSM CLI input must be binary")
        if len(payload) > _MAX_GROUP_STREAM_BYTES:
            raise O1OPublicFSMBridgeError("public FSM group stream is too large")
    else:
        payload = _read_group_stream_file(args.groups)

    receipt = replay_public_fsm_request(
        args.graph,
        payload,
        initial_state=_parse_state_hex(args.state_hex),
    )
    destination = output_stream if output_stream is not None else sys.stdout.buffer
    destination.write(receipt + b"\n")
    destination.flush()
    return 0


__all__ = [
    "BRIDGE_INTENTS_FILENAME",
    "BRIDGE_SCHEMA",
    "CAUSAL_HEADER_BYTES",
    "CAUSAL_MAGIC",
    "CAUSAL_VERSION",
    "COEFFICIENT_TABLE_BYTES",
    "COEFFICIENT_TABLE_SHAPE",
    "FrozenO1OPublicFSMBridge",
    "O1OPublicFSMBridgeError",
    "PUBLIC_FSM_FRAGMENT_FILENAME",
    "PUBLIC_FSM_FRAGMENT_KEY",
    "PUBLIC_FSM_INTENT",
    "PUBLIC_FSM_RECEIPT_SCHEMA",
    "PUBLIC_FSM_STATE_BYTES",
    "PublicFSMGroupEvent",
    "PublicFSMReplayReceipt",
    "decode_public_fsm_bridge",
    "encode_public_fsm_fragment_document",
    "encode_public_fsm_group_stream",
    "encode_public_fsm_bridge",
    "generate_public_fsm_wrapper",
    "initial_public_fsm_state",
    "public_fsm_fragment_document",
    "public_fsm_replay_cli",
    "replay_public_fsm_group",
    "replay_public_fsm_request",
    "replay_public_fsm_stream",
    "run_public_fsm_replay",
]
