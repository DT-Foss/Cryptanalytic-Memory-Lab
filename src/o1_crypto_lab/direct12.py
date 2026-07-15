"""Strict adapter for the immutable Direct12 source snapshot.

The production factory in this module has exactly one source: finalized run
``O1C-0003``.  The general constructor exists for SHA-256-ledger-backed test
fixtures and for an independently copied ``source_snapshot``; it is not a path
adapter for the mutable sibling repository.

Discovery data and revealed truths deliberately use different APIs.  In
particular, an A349 truth reader does not exist.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Mapping, Sequence

from .artifacts import ManifestError, ReadOnlyArtifactSource
from .run_capsule import RunCapsuleManager
from .stage3 import BoundedZstdDecoder, Stage3Error


class Direct12Error(ValueError):
    """A source byte or decoded trajectory violates the Direct12 contract."""


FINALIZED_CAPSULE = (
    Path(__file__).resolve().parents[2]
    / "runs"
    / "20260715_123734_O1C-0003_direct12-source-snapshot"
)
SNAPSHOT_PREFIX = "artifacts/source_snapshot/"
SNAPSHOT_DESCRIPTOR = "artifacts/source_snapshot.json"

# This is the exact denylist frozen in O1C-0003/config.json.  It is evaluated
# against every requested snapshot member before a filesystem read occurs.
DENIED_MEMBER_FRAGMENTS = (
    "a325_v1.json",
    "a345_progress",
    "a349_order_prospective_recovery_a350",
    "direct12_prospective_a345_validation_a349_v1.json",
    "direct12_prospective_a345_validation_a349_v1.md",
    "direct12_prospective_a345_validation_a349_v1.causal",
)

HORIZONS = (1, 2, 4, 8)
METRIC_NAMES = ("conflicts", "decisions", "search_propagations")
CHANNEL_NAMES = (
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
    "learned_clause_length_std",
    "learned_clause_length_max",
)
RAW_MATRIX_SCHEMA_SHA256 = hashlib.sha256(
    (
        "direct12-raw-matrix-v1\n"
        + "\n".join(
            f"{channel}@{horizon}"
            for channel in CHANNEL_NAMES
            for horizon in HORIZONS
        )
        + "\n"
    ).encode("utf-8")
).hexdigest()

A272_PROTOCOL = (
    "research/configs/"
    "chacha20_round20_selected_channel_prospective_validation_v1.json"
)
A268_PREFLIGHT = (
    "research/provenance/"
    "chacha20_round20_a268_prospective_trajectory_shape_preflight_v1.json"
)
A271_SIGNED_CHANNEL = (
    "research/configs/chacha20_round20_signed_channel_ablation_v1.json"
)
A272_RESULT = (
    "research/results/v1/"
    "chacha20_round20_selected_channel_prospective_validation_v1.json"
)
A348_DESIGN = (
    "research/configs/"
    "chacha20_round20_w46_direct12_sliced_reader_a348_design_v1.json"
)
A348_RESULT = (
    "research/results/v1/"
    "chacha20_round20_w46_direct12_sliced_reader_a348_v1.json"
)
A349_DESIGN = (
    "research/configs/"
    "chacha20_round20_w46_direct12_prospective_a345_validation_a349_design_v1.json"
)
A349_PREFLIGHT = (
    "research/results/v1/"
    "chacha20_round20_w46_direct12_prospective_a345_validation_a349_preflight_v1.json"
)
A349_ORDER = (
    "research/results/v1/"
    "chacha20_round20_w46_direct12_prospective_a345_validation_a349_order_v1.json"
)
READER_CONTRACT_MEMBERS = (
    A268_PREFLIGHT,
    A271_SIGNED_CHANNEL,
    A348_RESULT,
    A349_ORDER,
)

_SCHEMAS = {
    "A268_PREFLIGHT": "chacha20-round20-prospective-trajectory-shape-preflight-v1",
    "A271_SIGNED_CHANNEL": "chacha20-round20-signed-channel-ablation-protocol-v1",
    "A272_PROTOCOL": "chacha20-round20-selected-channel-prospective-validation-protocol-v1",
    "A272_RESULT": "chacha20-round20-selected-channel-prospective-validation-result-v1",
    "A272_MEASUREMENT": "chacha20-round20-selected-channel-prospective-measurement-v1",
    "A348_DESIGN": "chacha20-round20-w46-direct12-sliced-reader-a348-design-v1",
    "A348_RESULT": "chacha20-round20-w46-direct12-sliced-reader-a348-result-v1",
    "A348_MEASUREMENT": "chacha20-round20-w46-direct12-slice-a348-measurement-v1",
    "A349_DESIGN": "chacha20-round20-w46-direct12-prospective-a345-validation-a349-design-v1",
    "A349_PREFLIGHT": "chacha20-round20-w46-direct12-prospective-a345-validation-a349-preflight-v1",
    "A349_ORDER": "chacha20-round20-w46-direct12-prospective-a345-validation-a349-order-v1",
    "A349_MEASUREMENT": "chacha20-round20-w46-direct12-prospective-a345-validation-a349-slice-v1",
    "A355_MEASUREMENT": "chacha20-round20-w46-corrected-group-direct12-a355-slice-v1",
    "A356_MEASUREMENT": "chacha20-round20-w46-corrected-group-a345-transfer-a356-slice-v1",
}


class DatasetRole(str, Enum):
    TRAIN = "TRAIN"
    CALIBRATION = "CALIBRATION"
    SEALED_DEPLOYMENT = "SEALED_DEPLOYMENT"


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _require_mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise Direct12Error(f"{field} must be an object")
    return value


def _require_list(value: object, field: str) -> list[object]:
    if not isinstance(value, list):
        raise Direct12Error(f"{field} must be a list")
    return value


def _require_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise Direct12Error(f"{field} must be an integer")
    return value


def _require_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise Direct12Error(f"{field} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise Direct12Error(f"{field} must be finite")
    return result


def _require_sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise Direct12Error(f"{field} must be a lowercase SHA-256")
    return value


def _require_schema(
    value: Mapping[str, object], schema_key: str, attempt_id: str
) -> None:
    if value.get("schema") != _SCHEMAS[schema_key]:
        raise Direct12Error(f"{attempt_id} schema differs: {schema_key}")
    if value.get("attempt_id") != attempt_id:
        raise Direct12Error(f"{attempt_id} attempt identity differs")


def _require_safe_member(member: str) -> None:
    path = PurePosixPath(member)
    if (
        not member
        or path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\x00" in member
    ):
        raise Direct12Error(f"unsafe Direct12 member: {member!r}")


def _require_allowed_member(member: str) -> None:
    _require_safe_member(member)
    lowered = member.lower()
    for fragment in DENIED_MEMBER_FRAGMENTS:
        if fragment.lower() in lowered:
            raise Direct12Error(
                f"member is denied by the frozen O1C-0003 boundary: {member}"
            )


@dataclass(frozen=True)
class Direct12Provenance:
    metadata_member: str
    metadata_sha256: str
    measurement_member: str
    measurement_compressed_sha256: str
    measurement_compressed_bytes: int
    measurement_raw_sha256: str
    measurement_raw_bytes: int
    cnf_sha256: str
    source_manifest_sha256: str
    snapshot_descriptor_sha256: str
    source_ledger_sha256: str
    zstd_binary: str
    zstd_version: str

    def describe(self) -> dict[str, object]:
        return {
            "metadata_member": self.metadata_member,
            "metadata_sha256": self.metadata_sha256,
            "measurement_member": self.measurement_member,
            "measurement_compressed_sha256": self.measurement_compressed_sha256,
            "measurement_compressed_bytes": self.measurement_compressed_bytes,
            "measurement_raw_sha256": self.measurement_raw_sha256,
            "measurement_raw_bytes": self.measurement_raw_bytes,
            "cnf_sha256": self.cnf_sha256,
            "source_manifest_sha256": self.source_manifest_sha256,
            "snapshot_descriptor_sha256": self.snapshot_descriptor_sha256,
            "source_ledger_sha256": self.source_ledger_sha256,
            "zstd_binary": self.zstd_binary,
            "zstd_version": self.zstd_version,
        }


@dataclass(frozen=True)
class Direct12CellMatrix:
    """One address and its raw ``13 channels x 4 horizons`` matrix."""

    cell_index: int
    prefix8: str
    values: tuple[tuple[float, float, float, float], ...]

    def __post_init__(self) -> None:
        if not 0 <= self.cell_index < 256:
            raise Direct12Error("cell_index must be in 0..255")
        if self.prefix8 != f"{self.cell_index:08b}":
            raise Direct12Error("prefix8 is not the canonical cell address")
        if len(self.values) != len(CHANNEL_NAMES) or any(
            len(row) != len(HORIZONS) for row in self.values
        ):
            raise Direct12Error("raw matrix must have shape 13 x 4")

    def describe(self) -> dict[str, object]:
        return {
            "cell_index": self.cell_index,
            "prefix8": self.prefix8,
            "values": [list(row) for row in self.values],
        }


@dataclass(frozen=True)
class Direct12Slice:
    role: DatasetRole
    attempt_id: str
    slice_id: str
    low4: int | None
    cells: tuple[Direct12CellMatrix, ...]
    matrix_sha256: str
    provenance: Direct12Provenance

    def __post_init__(self) -> None:
        if len(self.cells) != 256 or tuple(
            cell.cell_index for cell in self.cells
        ) != tuple(range(256)):
            raise Direct12Error("slice cells must be canonical 0..255")
        if self.low4 is not None and not 0 <= self.low4 < 16:
            raise Direct12Error("low4 must be in 0..15")
        expected = _canonical_sha256([cell.describe() for cell in self.cells])
        if self.matrix_sha256 != expected:
            raise Direct12Error("slice matrix hash differs")

    def global_cell_index(self, cell_index: int) -> int:
        if not 0 <= cell_index < 256:
            raise Direct12Error("cell_index must be in 0..255")
        if self.low4 is None:
            return cell_index
        return (cell_index << 4) | self.low4

    def describe(self, *, include_matrix: bool = False) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": "o1-crypto-direct12-slice-v1",
            "role": self.role.value,
            "attempt_id": self.attempt_id,
            "slice_id": self.slice_id,
            "low4": self.low4,
            "cells": len(self.cells),
            "stages": len(self.cells) * len(HORIZONS),
            "raw_values": len(self.cells) * len(CHANNEL_NAMES) * len(HORIZONS),
            "matrix_schema_sha256": RAW_MATRIX_SCHEMA_SHA256,
            "matrix_sha256": self.matrix_sha256,
            "provenance": self.provenance.describe(),
            "information_boundary": {
                "revealed_truth_present": False,
                "elapsed_seconds_featured": False,
                "model_bits_present": False,
            },
        }
        if include_matrix:
            value["matrix"] = [cell.describe() for cell in self.cells]
        return value


@dataclass(frozen=True)
class Direct12Commitment:
    name: str
    sha256: str

    def describe(self) -> dict[str, str]:
        return {"name": self.name, "sha256": self.sha256}


@dataclass(frozen=True)
class Direct12Partition:
    role: DatasetRole
    attempt_id: str
    slices: tuple[Direct12Slice, ...]
    commitments: tuple[Direct12Commitment, ...]
    frozen_candidate_order: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        if any(item.role is not self.role for item in self.slices):
            raise Direct12Error("partition contains a foreign dataset role")
        if any(item.attempt_id != self.attempt_id for item in self.slices):
            raise Direct12Error("partition contains a foreign attempt")
        ids = tuple(item.slice_id for item in self.slices)
        if len(ids) != len(set(ids)):
            raise Direct12Error("partition contains duplicate slice IDs")
        if self.role is DatasetRole.SEALED_DEPLOYMENT:
            if len(self.frozen_candidate_order) != 4096 or set(
                self.frozen_candidate_order
            ) != set(range(4096)):
                raise Direct12Error("sealed candidate order must permute 0..4095")
        elif self.frozen_candidate_order:
            raise Direct12Error("only SEALED_DEPLOYMENT may carry a frozen order")

    @property
    def partition_sha256(self) -> str:
        return _canonical_sha256(self.describe(include_hash=False))

    def describe(self, *, include_hash: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": "o1-crypto-direct12-partition-v1",
            "role": self.role.value,
            "attempt_id": self.attempt_id,
            "matrix_schema_sha256": RAW_MATRIX_SCHEMA_SHA256,
            "slices": [item.describe() for item in self.slices],
            "counts": {
                "slices": len(self.slices),
                "cells": sum(len(item.cells) for item in self.slices),
                "stages": sum(len(item.cells) * len(HORIZONS) for item in self.slices),
                "raw_values": sum(
                    len(item.cells) * len(CHANNEL_NAMES) * len(HORIZONS)
                    for item in self.slices
                ),
            },
            "commitments": [item.describe() for item in self.commitments],
            "frozen_candidate_order": {
                "count": len(self.frozen_candidate_order),
                "uint16be_sha256": (
                    hashlib.sha256(
                        b"".join(
                            value.to_bytes(2, "big")
                            for value in self.frozen_candidate_order
                        )
                    ).hexdigest()
                    if self.frozen_candidate_order
                    else None
                ),
            },
        }
        if include_hash:
            value["partition_sha256"] = _canonical_sha256(value)
        return value


@dataclass(frozen=True)
class Direct12Dataset:
    partitions: tuple[Direct12Partition, ...]

    def __post_init__(self) -> None:
        roles = tuple(partition.role for partition in self.partitions)
        if roles != (
            DatasetRole.TRAIN,
            DatasetRole.CALIBRATION,
            DatasetRole.SEALED_DEPLOYMENT,
        ):
            raise Direct12Error("dataset roles must be TRAIN/CALIBRATION/SEALED_DEPLOYMENT")

    @property
    def slices(self) -> tuple[Direct12Slice, ...]:
        return tuple(item for partition in self.partitions for item in partition.slices)

    @property
    def dataset_sha256(self) -> str:
        return _canonical_sha256(self.describe(include_hash=False))

    def describe(self, *, include_hash: bool = True) -> dict[str, object]:
        slices = self.slices
        value: dict[str, object] = {
            "schema": "o1-crypto-direct12-dataset-v1",
            "matrix_schema_sha256": RAW_MATRIX_SCHEMA_SHA256,
            "partitions": [partition.describe() for partition in self.partitions],
            "counts": {
                "partitions": len(self.partitions),
                "slices": len(slices),
                "cells": sum(len(item.cells) for item in slices),
                "stages": sum(len(item.cells) * len(HORIZONS) for item in slices),
                "raw_values": sum(
                    len(item.cells) * len(CHANNEL_NAMES) * len(HORIZONS)
                    for item in slices
                ),
                "by_role": {
                    role.value: sum(len(partition.slices) for partition in self.partitions if partition.role is role)
                    for role in DatasetRole
                },
            },
            "information_boundary": {
                "truth_api_separate": True,
                "A349_truth_available": False,
                "denied_member_fragments": list(DENIED_MEMBER_FRAGMENTS),
            },
        }
        if include_hash:
            value["dataset_sha256"] = _canonical_sha256(value)
        return value


@dataclass(frozen=True)
class ReaderContractDocument:
    """One exact allowlisted reader/model commitment document."""

    member: str
    sha256: str
    schema: str
    attempt_id: str
    document: Mapping[str, object]

    def describe(self, *, include_document: bool = False) -> dict[str, object]:
        value: dict[str, object] = {
            "member": self.member,
            "sha256": self.sha256,
            "schema": self.schema,
            "attempt_id": self.attempt_id,
        }
        if include_document:
            # Round-trip through canonical JSON so callers cannot mutate the
            # adapter's retained object through a nested reference.
            value["document"] = json.loads(_canonical_bytes(self.document))
        return value


@dataclass(frozen=True)
class Direct12ReaderContract:
    documents: tuple[ReaderContractDocument, ...]

    def __post_init__(self) -> None:
        if tuple(item.member for item in self.documents) != READER_CONTRACT_MEMBERS:
            raise Direct12Error("reader contract members differ from the exact allowlist")

    def get(self, member: str) -> ReaderContractDocument:
        for document in self.documents:
            if document.member == member:
                return document
        raise Direct12Error(f"member is not in the reader contract allowlist: {member}")

    @property
    def contract_sha256(self) -> str:
        return _canonical_sha256(self.describe(include_hash=False))

    def describe(self, *, include_hash: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": "o1-crypto-direct12-reader-contract-v1",
            "documents": [item.describe() for item in self.documents],
            "information_boundary": {
                "exact_allowlist": list(READER_CONTRACT_MEMBERS),
                "denied_progress_or_outcome_read": False,
            },
        }
        if include_hash:
            value["contract_sha256"] = _canonical_sha256(value)
        return value


class Direct12Adapter:
    """Read target-safe matrices from a verified snapshot ledger."""

    def __init__(
        self,
        source: ReadOnlyArtifactSource,
        *,
        member_prefix: str = "",
        decoder: BoundedZstdDecoder | None = None,
        max_raw_bytes: int = 8 << 20,
        snapshot_descriptor_sha256: str | None = None,
        source_ledger_sha256: str | None = None,
    ) -> None:
        if max_raw_bytes < 1:
            raise Direct12Error("max_raw_bytes must be positive")
        if member_prefix:
            _require_safe_member(member_prefix.rstrip("/"))
        elif source.root.name != "source_snapshot":
            raise Direct12Error(
                "a direct source must be an independently copied source_snapshot"
            )
        self.source = source
        self.member_prefix = member_prefix
        try:
            self.decoder = decoder or BoundedZstdDecoder()
        except Stage3Error as exc:
            raise Direct12Error(str(exc)) from exc
        self.max_raw_bytes = max_raw_bytes
        self.snapshot_descriptor_sha256 = (
            _require_sha256(snapshot_descriptor_sha256, "snapshot_descriptor_sha256")
            if snapshot_descriptor_sha256 is not None
            else source.manifest_sha256
        )
        self.source_ledger_sha256 = (
            _require_sha256(source_ledger_sha256, "source_ledger_sha256")
            if source_ledger_sha256 is not None
            else source.manifest_sha256
        )

    def _source_member(self, member: str) -> str:
        _require_allowed_member(member)
        return f"{self.member_prefix}{member}" if self.member_prefix else member

    def _read_bytes(self, member: str) -> bytes:
        source_member = self._source_member(member)
        try:
            return self.source.read_bytes(source_member)
        except (ManifestError, UnicodeDecodeError) as exc:
            raise Direct12Error(f"verified source read failed: {member}") from exc

    def _read_json(self, member: str) -> tuple[Mapping[str, object], str]:
        raw = self._read_bytes(member)
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise Direct12Error(f"member is not valid UTF-8 JSON: {member}") from exc
        return _require_mapping(value, member), hashlib.sha256(raw).hexdigest()

    def read_contract_json(self, member: str) -> ReaderContractDocument:
        """Read one model/group/reference document from an exact allowlist."""

        if member not in READER_CONTRACT_MEMBERS:
            raise Direct12Error(
                f"member is not in the reader contract allowlist: {member}"
            )
        document, digest = self._read_json(member)
        schema = document.get("schema")
        attempt_id = document.get("attempt_id")
        if not isinstance(schema, str) or not isinstance(attempt_id, str):
            raise Direct12Error("reader contract identity must be text")
        return ReaderContractDocument(
            member=member,
            sha256=digest,
            schema=schema,
            attempt_id=attempt_id,
            document=document,
        )

    def load_reader_contract(self) -> Direct12ReaderContract:
        """Load the frozen model, semantic groups, and reference commitments."""

        contract = Direct12ReaderContract(
            documents=tuple(
                self.read_contract_json(member) for member in READER_CONTRACT_MEMBERS
            )
        )
        a268 = contract.get(A268_PREFLIGHT)
        a271 = contract.get(A271_SIGNED_CHANNEL)
        a348 = contract.get(A348_RESULT)
        a349 = contract.get(A349_ORDER)
        expected_identities = (
            (a268, _SCHEMAS["A268_PREFLIGHT"], "A268"),
            (a271, _SCHEMAS["A271_SIGNED_CHANNEL"], "A271"),
            (a348, _SCHEMAS["A348_RESULT"], "A348"),
            (a349, _SCHEMAS["A349_ORDER"], "A349"),
        )
        for document, schema, attempt_id in expected_identities:
            if document.schema != schema or document.attempt_id != attempt_id:
                raise Direct12Error(f"reader contract {attempt_id} identity differs")
        a268_model = _require_mapping(
            a268.document.get("frozen_model"), "A268.frozen_model"
        )
        model = _require_mapping(a268_model.get("model"), "A268.frozen_model.model")
        feature_names = _require_list(model.get("feature_names"), "A268 feature_names")
        coefficients = _require_list(model.get("coefficients"), "A268 coefficients")
        means = _require_list(model.get("means"), "A268 means")
        scales = _require_list(model.get("scales"), "A268 scales")
        if not (
            len(feature_names)
            == len(coefficients)
            == len(means)
            == len(scales)
            == 532
        ):
            raise Direct12Error("A268 frozen reader must bind 532 aligned features")
        for index, value in enumerate((*coefficients, *means, *scales)):
            _require_number(value, f"A268 model scalar[{index}]")
        _require_number(model.get("intercept"), "A268 intercept")
        model_sha = _require_sha256(a268_model.get("model_sha256"), "A268 model_sha256")
        a271_frozen = _require_mapping(
            a271.document.get("frozen_model"), "A271.frozen_model"
        )
        if (
            a271_frozen.get("feature_count") != 532
            or a271_frozen.get("model_sha256") != model_sha
            or a271_frozen.get("nonzero_coefficient_count") != 476
        ):
            raise Direct12Error("A271 semantic groups do not bind the A268 model")
        groups = _require_list(
            a271_frozen.get("signed_semantic_groups"),
            "A271 signed_semantic_groups",
        )
        if len(groups) != 32:
            raise Direct12Error("A271 must bind 32 signed semantic groups")
        anchors = _require_mapping(a271.document.get("anchors"), "A271.anchors")
        if (
            anchors.get("A268_preflight_path") != A268_PREFLIGHT
            or anchors.get("A268_preflight_sha256") != a268.sha256
        ):
            raise Direct12Error("A271 does not bind the copied A268 preflight")
        a349_anchors = _require_mapping(a349.document.get("anchors"), "A349.anchors")
        a348_anchor = _require_mapping(
            a349_anchors.get("A348_result"), "A349.anchors.A348_result"
        )
        if a348_anchor.get("path") != A348_RESULT or a348_anchor.get("sha256") != a348.sha256:
            raise Direct12Error("A349 order does not bind the copied A348 result")
        return contract

    @staticmethod
    def _validate_ledger(
        value: object,
        *,
        expected: int,
        identity_field: str,
    ) -> tuple[Mapping[str, object], ...]:
        rows = _require_list(value, "measurement_ledger")
        if len(rows) != expected:
            raise Direct12Error(f"measurement ledger must contain {expected} rows")
        result = tuple(
            _require_mapping(row, f"measurement_ledger[{index}]")
            for index, row in enumerate(rows)
        )
        identities = tuple(_require_int(row.get(identity_field), identity_field) if identity_field == "low4" else row.get(identity_field) for row in result)
        expected_identities: tuple[object, ...]
        if identity_field == "low4":
            expected_identities = tuple(range(expected))
        else:
            expected_identities = tuple(dict.fromkeys(identities))
            if len(expected_identities) != expected:
                raise Direct12Error("measurement ledger slice IDs must be unique")
        if identity_field == "low4" and identities != expected_identities:
            raise Direct12Error("measurement ledger low4 order must be canonical 0..15")
        for index, row in enumerate(result):
            path = row.get("path")
            if not isinstance(path, str):
                raise Direct12Error(f"measurement_ledger[{index}].path must be text")
            _require_allowed_member(path)
            if row.get("resumed") is not False:
                raise Direct12Error("resumed Direct12 measurements are outside this corpus")
            compressed_bytes = _require_int(row.get("compressed_bytes"), "compressed_bytes")
            raw_bytes = _require_int(row.get("raw_bytes"), "raw_bytes")
            if compressed_bytes < 1 or raw_bytes < 1:
                raise Direct12Error("measurement byte counts must be positive")
            _require_sha256(row.get("compressed_sha256"), "compressed_sha256")
            _require_sha256(row.get("raw_sha256"), "raw_sha256")
        return result

    def _decode_measurement(
        self,
        ledger: Mapping[str, object],
    ) -> tuple[Mapping[str, object], str, str, int, int]:
        member = ledger.get("path")
        if not isinstance(member, str):
            raise Direct12Error("measurement ledger path must be text")
        compressed = self._read_bytes(member)
        compressed_sha256 = hashlib.sha256(compressed).hexdigest()
        expected_compressed_sha256 = _require_sha256(
            ledger.get("compressed_sha256"), "compressed_sha256"
        )
        compressed_bytes = _require_int(
            ledger.get("compressed_bytes"), "compressed_bytes"
        )
        if compressed_sha256 != expected_compressed_sha256 or len(compressed) != compressed_bytes:
            raise Direct12Error("compressed measurement disagrees with its ledger")
        raw_bytes = _require_int(ledger.get("raw_bytes"), "raw_bytes")
        if raw_bytes < 1 or raw_bytes > self.max_raw_bytes:
            raise Direct12Error("declared raw measurement exceeds the byte budget")
        try:
            raw = self.decoder.decode(compressed, max_output_bytes=raw_bytes)
        except Stage3Error as exc:
            raise Direct12Error(str(exc)) from exc
        raw_sha256 = hashlib.sha256(raw).hexdigest()
        if len(raw) != raw_bytes or raw_sha256 != _require_sha256(
            ledger.get("raw_sha256"), "raw_sha256"
        ):
            raise Direct12Error("raw measurement disagrees with its ledger")
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise Direct12Error("decoded measurement is not valid UTF-8 JSON") from exc
        return (
            _require_mapping(value, "measurement"),
            compressed_sha256,
            raw_sha256,
            compressed_bytes,
            raw_bytes,
        )

    @staticmethod
    def _validate_run_and_extract(
        measurement: Mapping[str, object],
        *,
        attempt_id: str,
        schema_key: str,
        slice_id: str,
        low4: int | None,
        expected_assumption_variables: Sequence[int] | None = None,
        expected_fixed_unit_literals: Sequence[int] | None = None,
    ) -> tuple[tuple[Direct12CellMatrix, ...], str]:
        _require_schema(measurement, schema_key, attempt_id)
        if measurement.get("complete_candidate_cover") is not True:
            raise Direct12Error("measurement is not a complete candidate cover")
        if attempt_id == "A272":
            if measurement.get("label") != slice_id:
                raise Direct12Error("A272 measurement slice ID differs")
            if measurement.get("label_used_only_after_fixed_measurement") is not True:
                raise Direct12Error("A272 fixed-measurement label gate differs")
            cnf = _require_mapping(measurement.get("cnf_instantiation"), "cnf_instantiation")
            top_cnf_sha256 = _require_sha256(cnf.get("sha256"), "cnf_instantiation.sha256")
        else:
            if measurement.get("low4") != low4:
                raise Direct12Error(f"{attempt_id} measurement low4 differs")
            if measurement.get("target_label_available_to_measurement") is not False:
                raise Direct12Error("target label was available during measurement")
            if measurement.get("label_used_for_feature_construction_or_scoring") is not False:
                raise Direct12Error("target label was used during measurement/scoring")
            top_cnf_sha256 = _require_sha256(measurement.get("cnf_sha256"), "cnf_sha256")
            if expected_fixed_unit_literals is not None:
                fixed_units = tuple(
                    _require_int(value, "fixed_unit_literals")
                    for value in _require_list(
                        measurement.get("fixed_unit_literals"),
                        "fixed_unit_literals",
                    )
                )
                expected_units = tuple(expected_fixed_unit_literals)
                if fixed_units != expected_units or any(
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    or value == 0
                    for value in expected_units
                ):
                    raise Direct12Error(
                        f"{attempt_id} fixed low4 literals differ from the corrected codec"
                    )
        run = _require_mapping(measurement.get("run"), "measurement.run")
        for field in (
            "all_watchdogs_clear",
            "base_snapshot_identical_verified",
            "fresh_solver_per_candidate_verified",
            "learned_clause_identity_complete",
        ):
            if run.get(field) is not True:
                raise Direct12Error(f"run.{field} must be true")
        if run.get("bounded_variable_addition_enabled") is not False:
            raise Direct12Error("bounded variable addition changes the corpus")
        if tuple(run.get("conflict_horizons", ())) != HORIZONS:
            raise Direct12Error("conflict horizons must be [1,2,4,8]")
        if run.get("learned_clause_canonical_order") != "absolute_variable_then_signed_literal":
            raise Direct12Error("learned-clause canonical order differs")
        if run.get("learned_clause_maximum_size") != 64:
            raise Direct12Error("learned-clause maximum size differs")
        cnf_sha256 = _require_sha256(run.get("cnf_sha256"), "run.cnf_sha256")
        if cnf_sha256 != top_cnf_sha256:
            raise Direct12Error("top-level and run CNF hashes disagree")
        summary = _require_mapping(run.get("summary"), "run.summary")
        expected_summary = {
            "cells": 256,
            "stages_emitted": 1024,
            "fresh_solver_instances": 256,
            "configured_stages_per_nonterminal_cell": 4,
            "unknown_cells": 256,
            "sat_cells": 0,
            "unsat_cells": 0,
            "base_copy_source_solved": False,
            "base_snapshot_identical": True,
            "bounded_variable_addition_enabled": False,
        }
        for field, expected in expected_summary.items():
            if summary.get(field) != expected:
                raise Direct12Error(f"run.summary.{field} differs")
        if tuple(summary.get("conflict_horizons", ())) != HORIZONS:
            raise Direct12Error("summary conflict horizons differ")
        if tuple(summary.get("metric_names", ())) != METRIC_NAMES:
            raise Direct12Error("summary metric order differs")
        if summary.get("learned_clause_maximum_size") != 64:
            raise Direct12Error("summary clause cap differs")

        raw_order = _require_list(run.get("order"), "run.order")
        canonical_prefixes = [f"{index:08b}" for index in range(256)]
        if raw_order != canonical_prefixes:
            raise Direct12Error("run.order is not the canonical prefix order")
        raw_cells = _require_list(run.get("cells"), "run.cells")
        raw_stages = _require_list(run.get("stages"), "run.stages")
        if len(raw_cells) != 256 or len(raw_stages) != 1024:
            raise Direct12Error("measurement must contain 256 cells and 1,024 stages")

        cells = tuple(
            _require_mapping(value, f"run.cells[{index}]")
            for index, value in enumerate(raw_cells)
        )
        assumptions_by_cell: list[tuple[int, ...]] = []
        base_variables: tuple[int, ...] | None = None
        for index, cell in enumerate(cells):
            prefix = canonical_prefixes[index]
            if cell.get("cell_index") != index or cell.get("prefix8") != prefix:
                raise Direct12Error("cell/prefix order is not canonical")
            if (
                cell.get("fresh_solver_instance") is not True
                or cell.get("final_status") != "unknown"
                or cell.get("stages_run") != 4
                or cell.get("terminal_stage_index") is not None
            ):
                raise Direct12Error(f"cell {index} is not fresh, UNKNOWN and nonterminal")
            if tuple(cell.get("metric_names", ())) != METRIC_NAMES:
                raise Direct12Error(f"cell {index} metric order differs")
            assumptions = tuple(
                _require_int(value, f"cell {index} assumption")
                for value in _require_list(cell.get("assumptions"), f"cell {index} assumptions")
            )
            if len(assumptions) != 8 or any(value == 0 for value in assumptions):
                raise Direct12Error(f"cell {index} must have eight nonzero assumptions")
            variables = tuple(abs(value) for value in assumptions)
            if len(set(variables)) != 8:
                raise Direct12Error(f"cell {index} assumptions repeat a variable")
            if base_variables is None:
                base_variables = variables
            if variables != base_variables:
                raise Direct12Error("cell assumption coordinates changed")
            if expected_assumption_variables is not None:
                expected_variables = tuple(expected_assumption_variables)
                if variables != expected_variables or any(
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    or value <= 0
                    for value in expected_variables
                ):
                    raise Direct12Error(
                        f"{attempt_id} high8 assumptions differ from the corrected codec"
                    )
            expected_signs = tuple(
                variable if bit == "1" else -variable
                for variable, bit in zip(variables, prefix, strict=True)
            )
            if assumptions != expected_signs:
                raise Direct12Error(f"cell {index} assumptions do not encode prefix8")
            assumptions_by_cell.append(assumptions)

        stages: list[list[Mapping[str, object]]] = [[] for _ in range(256)]
        for position, raw_stage in enumerate(raw_stages):
            stage = _require_mapping(raw_stage, f"run.stages[{position}]")
            cell_index = position // len(HORIZONS)
            stage_index = position % len(HORIZONS)
            horizon = HORIZONS[stage_index]
            prefix = canonical_prefixes[cell_index]
            if (
                stage.get("cell_index") != cell_index
                or stage.get("stage_index") != stage_index
                or stage.get("horizon") != horizon
                or stage.get("prefix8") != prefix
            ):
                raise Direct12Error("stage stream is not canonical cell/horizon order")
            if stage.get("assumptions") != list(assumptions_by_cell[cell_index]):
                raise Direct12Error("stage assumptions differ from their cell")
            if (
                stage.get("status") != "unknown"
                or stage.get("terminal") is not False
                or stage.get("watchdog_fired") is not False
                or stage.get("returncode") != 0
                or stage.get("conflict_budget_exhausted") is not True
                or stage.get("model_bits_bit0_through_bit19") != []
                or stage.get("failed_assumptions") != []
            ):
                raise Direct12Error(
                    f"cell {cell_index} horizon {horizon} failed UNKNOWN/model/watchdog gates"
                )
            if tuple(stage.get("metric_names", ())) != METRIC_NAMES:
                raise Direct12Error("stage metric order differs")
            metrics = _require_list(stage.get("metrics_stage_delta"), "metrics_stage_delta")
            if len(metrics) != 3:
                raise Direct12Error("metrics_stage_delta must contain three channels")
            for metric_index, metric in enumerate(metrics):
                _require_number(metric, f"metrics_stage_delta[{metric_index}]")
            lengths = tuple(
                _require_int(value, "learned_clause_lengths_stage")
                for value in _require_list(
                    stage.get("learned_clause_lengths_stage"),
                    "learned_clause_lengths_stage",
                )
            )
            if any(value < 1 or value > 64 for value in lengths):
                raise Direct12Error("learned clause length is outside 1..64")
            if _require_int(
                stage.get("learned_literal_count_stage"),
                "learned_literal_count_stage",
            ) != sum(lengths):
                raise Direct12Error("learned literal count differs from clause lengths")
            offered = _require_int(
                stage.get("learned_clause_offered_stage"),
                "learned_clause_offered_stage",
            )
            accepted = _require_int(
                stage.get("learned_clause_accepted_stage"),
                "learned_clause_accepted_stage",
            )
            rejected = _require_int(
                stage.get("learned_clause_rejected_large_stage"),
                "learned_clause_rejected_large_stage",
            )
            if min(offered, accepted, rejected) < 0 or accepted + rejected != offered:
                raise Direct12Error("learned clause stage accounting differs")
            stages[cell_index].append(stage)

        extracted: list[Direct12CellMatrix] = []
        for cell_index, stage_rows in enumerate(stages):
            if len(stage_rows) != 4:
                raise Direct12Error(f"cell {cell_index} does not have four stages")
            by_channel = [[], [], [], [], [], [], [], [], [], [], [], [], []]
            for stage in stage_rows:
                metrics = _require_list(stage.get("metrics_stage_delta"), "metrics_stage_delta")
                for index in range(3):
                    by_channel[index].append(_require_number(metrics[index], METRIC_NAMES[index]))
                for index, name in enumerate(CHANNEL_NAMES[3:10], start=3):
                    by_channel[index].append(_require_number(stage.get(name), name))
                lengths = [
                    float(_require_int(value, "learned_clause_length"))
                    for value in _require_list(
                        stage.get("learned_clause_lengths_stage"),
                        "learned_clause_lengths_stage",
                    )
                ]
                if lengths:
                    mean = math.fsum(lengths) / len(lengths)
                    variance = math.fsum((value - mean) ** 2 for value in lengths) / len(lengths)
                    std = math.sqrt(variance)
                    maximum = max(lengths)
                else:
                    mean = std = maximum = 0.0
                by_channel[10].append(mean)
                by_channel[11].append(std)
                by_channel[12].append(maximum)
            matrix = tuple(tuple(row) for row in by_channel)
            extracted.append(
                Direct12CellMatrix(
                    cell_index=cell_index,
                    prefix8=canonical_prefixes[cell_index],
                    values=matrix,  # type: ignore[arg-type]
                )
            )
        return tuple(extracted), cnf_sha256

    def _slice(
        self,
        *,
        role: DatasetRole,
        attempt_id: str,
        schema_key: str,
        slice_id: str,
        low4: int | None,
        ledger: Mapping[str, object],
        metadata_member: str,
        metadata_sha256: str,
        expected_measurement_fields: Mapping[str, object] | None = None,
    ) -> Direct12Slice:
        measurement, compressed_sha, raw_sha, compressed_bytes, raw_bytes = (
            self._decode_measurement(ledger)
        )
        for field, expected in (expected_measurement_fields or {}).items():
            if measurement.get(field) != expected:
                raise Direct12Error(
                    f"{attempt_id} measurement field {field!r} differs from its freeze"
                )
        cells, cnf_sha256 = self._validate_run_and_extract(
            measurement,
            attempt_id=attempt_id,
            schema_key=schema_key,
            slice_id=slice_id,
            low4=low4,
        )
        matrix_sha256 = _canonical_sha256([cell.describe() for cell in cells])
        member = ledger.get("path")
        assert isinstance(member, str)
        return Direct12Slice(
            role=role,
            attempt_id=attempt_id,
            slice_id=slice_id,
            low4=low4,
            cells=cells,
            matrix_sha256=matrix_sha256,
            provenance=Direct12Provenance(
                metadata_member=metadata_member,
                metadata_sha256=metadata_sha256,
                measurement_member=member,
                measurement_compressed_sha256=compressed_sha,
                measurement_compressed_bytes=compressed_bytes,
                measurement_raw_sha256=raw_sha,
                measurement_raw_bytes=raw_bytes,
                cnf_sha256=cnf_sha256,
                source_manifest_sha256=self.source.manifest_sha256,
                snapshot_descriptor_sha256=self.snapshot_descriptor_sha256,
                source_ledger_sha256=self.source_ledger_sha256,
                zstd_binary=self.decoder.binary,
                zstd_version=self.decoder.version,
            ),
        )

    def load_a272(self) -> Direct12Partition:
        protocol, protocol_sha = self._read_json(A272_PROTOCOL)
        result, result_sha = self._read_json(A272_RESULT)
        _require_schema(protocol, "A272_PROTOCOL", "A272")
        _require_schema(result, "A272_RESULT", "A272")
        if result.get("protocol_sha256") != protocol_sha:
            raise Direct12Error("A272 result does not bind the copied protocol")
        design = _require_mapping(protocol.get("prospective_design"), "prospective_design")
        design_rows = tuple(
            _require_mapping(value, f"prospective_design.rows[{index}]")
            for index, value in enumerate(
                _require_list(design.get("rows"), "prospective_design.rows")
            )
        )
        if len(design_rows) != 20:
            raise Direct12Error("A272 must contain twenty frozen known-key rows")
        corpus = _require_mapping(result.get("prospective_corpus"), "prospective_corpus")
        expected = {
            "known_keys": 20,
            "candidate_measurements": 5120,
            "complete_candidate_covers": True,
            "early_stops": 0,
            "model_refits": 0,
        }
        for field, expected_value in expected.items():
            if corpus.get(field) != expected_value:
                raise Direct12Error(f"A272 prospective_corpus.{field} differs")
        ledger = self._validate_ledger(
            corpus.get("measurement_ledger"), expected=20, identity_field="label"
        )
        design_by_id = {row.get("label"): row for row in design_rows}
        if set(design_by_id) != {row.get("label") for row in ledger}:
            raise Direct12Error("A272 design and measurement ledgers differ")
        slices: list[Direct12Slice] = []
        for row in ledger:
            slice_id = row.get("label")
            if not isinstance(slice_id, str):
                raise Direct12Error("A272 ledger label must be text")
            item = self._slice(
                role=DatasetRole.TRAIN,
                attempt_id="A272",
                schema_key="A272_MEASUREMENT",
                slice_id=slice_id,
                low4=None,
                ledger=row,
                metadata_member=A272_RESULT,
                metadata_sha256=result_sha,
                expected_measurement_fields={
                    # The protocol row also carries the external slice ID and a
                    # redundant hexadecimal rendering.  The measurement binds
                    # the eight semantic design fields byte-for-value.
                    "known_key_design": {
                        field: design_by_id[slice_id][field]
                        for field in (
                            "low20",
                            "prefix8",
                            "prefix8_binary",
                            "prefix_index",
                            "prefix_split",
                            "suffix12",
                            "suffix_index",
                            "suffix_split",
                        )
                    },
                    "protocol_sha256": protocol_sha,
                },
            )
            slices.append(item)
        commitments = (
            Direct12Commitment("A272_protocol", protocol_sha),
            Direct12Commitment("A272_result", result_sha),
            Direct12Commitment(
                "A272_measurement_ledger",
                _require_sha256(
                    corpus.get("measurement_ledger_sha256"),
                    "measurement_ledger_sha256",
                ),
            ),
        )
        return Direct12Partition(
            role=DatasetRole.TRAIN,
            attempt_id="A272",
            slices=tuple(slices),
            commitments=commitments,
        )

    def load_a348(self) -> Direct12Partition:
        design, design_sha = self._read_json(A348_DESIGN)
        result, result_sha = self._read_json(A348_RESULT)
        _require_schema(design, "A348_DESIGN", "A348")
        _require_schema(result, "A348_RESULT", "A348")
        if result.get("design_sha256") != design_sha:
            raise Direct12Error("A348 result does not bind the copied design")
        contract = _require_mapping(design.get("measurement_contract"), "measurement_contract")
        expected_contract = {
            "complete_direct_prefix_bits": 12,
            "complete_direct_prefix_cells": 4096,
            "low4_slices": 16,
            "reader_refits": 0,
            "target_labels_used_during_measurement": 0,
        }
        for field, expected in expected_contract.items():
            if contract.get(field) != expected:
                raise Direct12Error(f"A348 measurement_contract.{field} differs")
        if tuple(contract.get("conflict_horizons", ())) != HORIZONS:
            raise Direct12Error("A348 design horizons differ")
        summary = _require_mapping(result.get("measurement_summary"), "measurement_summary")
        expected_summary = {
            "candidate_assignments_executed": 0,
            "complete_direct12_cells": 4096,
            "high8_cells_per_slice": 256,
            "low4_slices": 16,
            "solver_stages": 16384,
            "target_labels_used_during_measurement": 0,
            "status_counts": {"sat": 0, "unknown": 4096, "unsat": 0},
        }
        for field, expected in expected_summary.items():
            if summary.get(field) != expected:
                raise Direct12Error(f"A348 measurement_summary.{field} differs")
        boundary = _require_mapping(result.get("information_boundary"), "information_boundary")
        if (
            boundary.get("A325_candidate_or_prefix_used_to_construct_slice_CNF") is not False
            or boundary.get("A325_candidate_or_prefix_used_to_select_reader_views") is not False
            or boundary.get("measurement_completed_before_true_prefix_scoring") is not True
            or boundary.get("new_candidate_assignments_executed") != 0
        ):
            raise Direct12Error("A348 information boundary differs")
        ledger = self._validate_ledger(
            result.get("measurement_ledger"), expected=16, identity_field="low4"
        )
        slices = tuple(
            self._slice(
                role=DatasetRole.CALIBRATION,
                attempt_id="A348",
                schema_key="A348_MEASUREMENT",
                slice_id=f"slice_{low4:02x}",
                low4=low4,
                ledger=row,
                metadata_member=A348_RESULT,
                metadata_sha256=result_sha,
            )
            for low4, row in enumerate(ledger)
        )
        return Direct12Partition(
            role=DatasetRole.CALIBRATION,
            attempt_id="A348",
            slices=slices,
            commitments=(
                Direct12Commitment("A348_design", design_sha),
                Direct12Commitment("A348_result", result_sha),
                Direct12Commitment(
                    "A348_measurement",
                    _require_sha256(result.get("measurement_sha256"), "measurement_sha256"),
                ),
            ),
        )

    def load_a349(self) -> Direct12Partition:
        design, design_sha = self._read_json(A349_DESIGN)
        preflight, preflight_sha = self._read_json(A349_PREFLIGHT)
        order, order_sha = self._read_json(A349_ORDER)
        _require_schema(design, "A349_DESIGN", "A349")
        _require_schema(preflight, "A349_PREFLIGHT", "A349")
        _require_schema(order, "A349_ORDER", "A349")
        if order.get("design_sha256") != design_sha or order.get("preflight_sha256") != preflight_sha:
            raise Direct12Error("A349 order does not bind copied design/preflight")
        design_boundary = _require_mapping(design.get("information_boundary"), "information_boundary")
        if (
            design_boundary.get("A345_candidate_or_prefix_available_at_design_freeze") is not False
            or design_boundary.get("A345_progress_content_read_for_A349_design") is not False
            or design_boundary.get("A345_result_available_at_design_freeze") is not False
            or design_boundary.get("A349_reader_refits_on_A345") != 0
            or design_boundary.get("A349_target_labels_used") != 0
        ):
            raise Direct12Error("A349 design information boundary differs")
        if (
            preflight.get("A345_result_available_at_preflight") is not False
            or preflight.get("target_labels_used") != 0
            or preflight.get("reader_refits") != 0
        ):
            raise Direct12Error("A349 preflight information boundary differs")
        if (
            order.get("A345_candidate_or_prefix_read_before_order_freeze") is not False
            or order.get("A345_result_available_at_order_freeze") is not False
            or order.get("target_labels_used") != 0
            or order.get("reader_refits") != 0
            or order.get("complete_direct12_cells") != 4096
            or order.get("solver_stages") != 16384
        ):
            raise Direct12Error("A349 frozen order information boundary differs")
        if order.get("A345_protocol_sha256") != preflight.get("A345_protocol_sha256") or order.get(
            "A345_public_challenge_sha256"
        ) != preflight.get("A345_public_challenge_sha256"):
            raise Direct12Error("A349 preflight/order public commitments differ")
        cnf = _require_mapping(preflight.get("CNF"), "preflight.CNF")
        cnf_member = cnf.get("path")
        if not isinstance(cnf_member, str):
            raise Direct12Error("A349 preflight CNF path must be text")
        cnf_bytes = self._read_bytes(cnf_member)
        if hashlib.sha256(cnf_bytes).hexdigest() != _require_sha256(
            cnf.get("sha256"), "preflight.CNF.sha256"
        ):
            raise Direct12Error("A349 public-output CNF hash differs")
        try:
            first_line = cnf_bytes.splitlines()[0].decode("ascii")
        except (IndexError, UnicodeDecodeError) as exc:
            raise Direct12Error("A349 CNF has no ASCII header") from exc
        if first_line != preflight.get("CNF_header"):
            raise Direct12Error("A349 CNF header differs from preflight")
        ledger = self._validate_ledger(
            order.get("measurement_ledger"), expected=16, identity_field="low4"
        )
        slices = tuple(
            self._slice(
                role=DatasetRole.SEALED_DEPLOYMENT,
                attempt_id="A349",
                schema_key="A349_MEASUREMENT",
                slice_id=f"slice_{low4:02x}",
                low4=low4,
                ledger=row,
                metadata_member=A349_ORDER,
                metadata_sha256=order_sha,
            )
            for low4, row in enumerate(ledger)
        )
        raw_candidate_order = _require_list(order.get("selected_order"), "selected_order")
        candidate_order = tuple(
            _require_int(value, f"selected_order[{index}]")
            for index, value in enumerate(raw_candidate_order)
        )
        if len(candidate_order) != 4096 or set(candidate_order) != set(range(4096)):
            raise Direct12Error("A349 selected_order must permute 0..4095")
        encoded_order_sha = hashlib.sha256(
            b"".join(value.to_bytes(2, "big") for value in candidate_order)
        ).hexdigest()
        if encoded_order_sha != _require_sha256(
            order.get("selected_order_uint16be_sha256"),
            "selected_order_uint16be_sha256",
        ):
            raise Direct12Error("A349 selected order commitment differs")
        return Direct12Partition(
            role=DatasetRole.SEALED_DEPLOYMENT,
            attempt_id="A349",
            slices=slices,
            commitments=(
                Direct12Commitment("A349_design", design_sha),
                Direct12Commitment("A349_preflight", preflight_sha),
                Direct12Commitment("A349_order", order_sha),
                Direct12Commitment(
                    "A349_measurement",
                    _require_sha256(order.get("measurement_sha256"), "measurement_sha256"),
                ),
                Direct12Commitment(
                    "A349_score_field",
                    _require_sha256(order.get("score_field_sha256"), "score_field_sha256"),
                ),
            ),
            frozen_candidate_order=candidate_order,
        )

    def load_dataset(self) -> Direct12Dataset:
        return Direct12Dataset(
            partitions=(self.load_a272(), self.load_a348(), self.load_a349())
        )


@dataclass(frozen=True)
class A272TrainingTruth:
    slice_id: str
    correct_high8_cell: int
    source_member: str
    source_sha256: str


@dataclass(frozen=True)
class A348CalibrationTruth:
    correct_prefix12: int
    correct_high8_cell: int
    correct_low4_slice: int
    source_member: str
    source_sha256: str


class Direct12LabelRegistry:
    """Separate post-measurement truth API; A349 remains permanently sealed."""

    def __init__(self, adapter: Direct12Adapter) -> None:
        self._adapter = adapter

    def a272_training_truths(self) -> tuple[A272TrainingTruth, ...]:
        protocol, protocol_sha = self._adapter._read_json(A272_PROTOCOL)
        _require_schema(protocol, "A272_PROTOCOL", "A272")
        design = _require_mapping(protocol.get("prospective_design"), "prospective_design")
        rows = _require_list(design.get("rows"), "prospective_design.rows")
        truths: list[A272TrainingTruth] = []
        for index, raw_row in enumerate(rows):
            row = _require_mapping(raw_row, f"prospective_design.rows[{index}]")
            slice_id = row.get("label")
            if not isinstance(slice_id, str):
                raise Direct12Error("A272 truth slice ID must be text")
            correct = _require_int(row.get("prefix8"), "prefix8")
            if not 0 <= correct < 256 or row.get("prefix8_binary") != f"{correct:08b}":
                raise Direct12Error("A272 truth prefix is noncanonical")
            truths.append(
                A272TrainingTruth(
                    slice_id=slice_id,
                    correct_high8_cell=correct,
                    source_member=A272_PROTOCOL,
                    source_sha256=protocol_sha,
                )
            )
        if len(truths) != 20 or len({item.slice_id for item in truths}) != 20:
            raise Direct12Error("A272 truth registry must contain twenty unique rows")
        return tuple(truths)

    def a348_calibration_truth(self) -> A348CalibrationTruth:
        result, result_sha = self._adapter._read_json(A348_RESULT)
        _require_schema(result, "A348_RESULT", "A348")
        if result.get("confirmed_prefix_revealed_only_after_complete_measurement") is not True:
            raise Direct12Error("A348 prefix was not post-measurement")
        prefix = _require_int(result.get("confirmed_prefix12"), "confirmed_prefix12")
        if not 0 <= prefix < 4096 or result.get("confirmed_prefix12_hex") != f"{prefix:03x}":
            raise Direct12Error("A348 confirmed prefix is noncanonical")
        return A348CalibrationTruth(
            correct_prefix12=prefix,
            correct_high8_cell=prefix >> 4,
            correct_low4_slice=prefix & 0xF,
            source_member=A348_RESULT,
            source_sha256=result_sha,
        )

    def a349_truth(self) -> None:
        raise Direct12Error("A349 is SEALED_DEPLOYMENT; no truth API exists")


def finalized_direct12_adapter() -> Direct12Adapter:
    """Verify finalized O1C-0003 and return its strict snapshot adapter."""

    capsule = FINALIZED_CAPSULE.resolve()
    if not capsule.is_dir() or capsule.name != FINALIZED_CAPSULE.name:
        raise Direct12Error(f"finalized Direct12 capsule is missing: {capsule}")
    lab_root = capsule.parents[1]
    verification = RunCapsuleManager(lab_root).verify(capsule)
    if not verification.ok:
        raise Direct12Error(f"O1C-0003 capsule verification failed: {verification.describe()}")
    for path in (capsule, *capsule.rglob("*")):
        if path.is_symlink():
            raise Direct12Error(f"finalized capsule contains a symbolic link: {path}")
        if path.stat().st_mode & 0o222:
            raise Direct12Error(f"finalized capsule member is writable: {path}")

    source = ReadOnlyArtifactSource(capsule, capsule / "artifacts.sha256")
    report = source.verify()
    if not report.ok:
        raise Direct12Error(f"O1C-0003 source verification failed: {report.describe()}")
    descriptor_raw = source.read_bytes(SNAPSHOT_DESCRIPTOR)
    descriptor_sha = hashlib.sha256(descriptor_raw).hexdigest()
    try:
        descriptor = _require_mapping(json.loads(descriptor_raw), SNAPSHOT_DESCRIPTOR)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Direct12Error("O1C-0003 snapshot descriptor is invalid JSON") from exc
    if descriptor.get("schema") != "o1-crypto-direct12-source-snapshot-v1":
        raise Direct12Error("O1C-0003 snapshot descriptor schema differs")
    entries = _require_mapping(descriptor.get("entries"), "snapshot entries")
    parsed_entries = {
        str(member): _require_sha256(digest, f"entries[{member!r}]")
        for member, digest in entries.items()
    }
    outer_entries = {
        member[len(SNAPSHOT_PREFIX) :]: digest
        for member, digest in source.entries.items()
        if member.startswith(SNAPSHOT_PREFIX)
    }
    if parsed_entries != outer_entries:
        raise Direct12Error("copied snapshot ledger differs from capsule manifest")
    if descriptor.get("members") != len(parsed_entries) or descriptor.get("members") != 71:
        raise Direct12Error("O1C-0003 snapshot member count differs")
    expected_bytes = sum(
        (capsule / SNAPSHOT_PREFIX / member).stat().st_size for member in parsed_entries
    )
    if descriptor.get("bytes") != expected_bytes or expected_bytes != 9_882_690:
        raise Direct12Error("O1C-0003 snapshot byte count differs")
    if descriptor.get("denied_members_read") != 0:
        raise Direct12Error("O1C-0003 reports a denied source read")
    for member in parsed_entries:
        _require_allowed_member(member)
    return Direct12Adapter(
        source,
        member_prefix=SNAPSHOT_PREFIX,
        snapshot_descriptor_sha256=descriptor_sha,
        source_ledger_sha256=_require_sha256(
            descriptor.get("source_ledger_sha256"), "source_ledger_sha256"
        ),
    )


def finalized_direct12_label_registry() -> Direct12LabelRegistry:
    return Direct12LabelRegistry(finalized_direct12_adapter())


def load_finalized_direct12_dataset() -> Direct12Dataset:
    return finalized_direct12_adapter().load_dataset()
