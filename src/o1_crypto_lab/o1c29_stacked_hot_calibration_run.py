"""Conditional, source-frozen O1C-0029 real-packet capsule runner.

The module has two deliberately separate jobs.  Preflight resolves and verifies
the finalized O1C-0022 producer without reserving O1C-0029.  The protocol
lifecycle then persists the complete 4x4 state barrier, opens only the
calibration-label broker, freezes all fits and logits, and only then opens a
separate scoring capability.  Both label openings re-read the authoritative
artifact index and ``labels.bitpack``.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import resource
import stat
import subprocess
import sys
import time
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping, Protocol, Sequence, cast

from .living_inverse import canonical_json_bytes
from .o1c22_postresult_composer import UPSTREAM_ATTEMPT_ID
from .o1c22_postresult_composer_run import (
    EXPECTED_UPSTREAM_ARTIFACTS,
    O1C23RunConfig,
    UPSTREAM_ARTIFACT_INDEX_SCHEMA,
    load_o1c22_postresult_composer_run_config,
)
from .o1c23_selection_authority import verify_o1c22_producer_heldout_freeze
from .o1c29_packet_corpus import (
    VerifiedO1C22PacketCorpus,
    _discard_trusted_packet_corpus_transfer_nonce,
    _new_trusted_packet_corpus_transfer_nonce,
    deserialize_verified_o1c22_packet_corpus,
    load_trusted_verified_o1c22_packet_corpus,
    require_factory_minted_o1c22_packet_corpus,
    serialize_verified_o1c22_packet_corpus,
)
from .o1c29_real_protocol import (
    CANONICAL_FOLD_IDS,
    LABEL_BITPACK_BYTES,
    ManagerAuthorityCommitment,
    RealProtocolInputs,
    adapt_verified_o1c22_packet_corpus,
    bind_manager_authority_commitment,
    open_authoritative_calibration_broker_after_state_freeze,
    open_authoritative_labels_after_prediction_freeze,
    score_frozen_two_arm_predictions,
)
from .o1c29_stacked_hot_calibration import (
    PRIMARY_OPERATOR_ID,
    SECONDARY_OPERATOR_ID,
    GlobalStateFreeze,
    StackedHotCalibrationResult,
    freeze_all_owner_states,
    run_stacked_hot_calibration_from_freeze,
)
from .polyphase_sufficient_state_v2 import STATE_BYTES
from .run_capsule import ClaimLevel, FinalizedRun, RunCapsuleManager
from .o1c29_runtime_freeze import (
    RuntimeFreezeReceipt,
    verify_o1c29_runtime_freeze_fresh,
)


ATTEMPT_ID = "O1C-0029"
FORMAL_SLUG = "stacked-hot-calibration-real-v1"
RUN_CONFIG_SCHEMA = "o1-256-o1c29-stacked-hot-calibration-run-config-v1"
EXPERIMENT_SCHEMA = "o1-256-o1c29-stacked-hot-calibration-experiment-v1"
PREFLIGHT_SCHEMA = "o1-256-o1c29-stacked-hot-calibration-preflight-v1"
LABEL_COMMITMENT_SCHEMA = "o1-256-o1c29-label-index-commitment-v1"
SOURCE_ACCOUNTING_SCHEMA = "o1-256-o1c29-source-read-accounting-v1"
TRUSTED_PREFLIGHT_WIRE_SCHEMA = "o1-256-o1c29-trusted-preflight-wire-v1"
WORK_SCHEMA = "o1-256-o1c29-structural-work-v1"
RESULT_SCHEMA = "o1-256-o1c29-capsule-result-v1"
ARTIFACT_INDEX_SCHEMA = "o1-256-o1c29-artifact-index-v1"
SOURCE_INDEX_SCHEMA = "o1-256-o1c29-source-index-v1"
LABEL_PHASE = "POST_FREEZE_SCORED_RESULT"
TOP_K_LIMIT = 65_536
EXPECTED_SOURCE_LABELS = frozenset(
    {
        "runner",
        "stacked_hot_calibration",
        "real_protocol",
        "packet_corpus",
        "selection_authority",
        "run_capsule",
        "pyproject",
        "posterior_logit_frontier",
        "polyphase_sufficient_state_v2",
        "o1c22_polyphase_bridge",
        "o1c22_packet_codec",
        "living_inverse",
        "o1c22_postresult_composer",
        "o1c22_postresult_composer_run",
        "polyphase_sufficient_state",
        "chacha_trace",
    }
)
_HEX = frozenset("0123456789abcdef")


class O1C29RunError(ValueError):
    """A frozen config, source, phase boundary, or resource contract differs."""


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX for character in value)
    ):
        raise O1C29RunError(f"{field} must be lowercase SHA-256")
    return value


def _mapping(
    value: object,
    field: str,
    expected: set[str] | frozenset[str] | None = None,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise O1C29RunError(f"{field} must be an object")
    row = cast(Mapping[str, object], value)
    if expected is not None and set(row) != set(expected):
        raise O1C29RunError(f"{field} fields differ")
    return row


def _sequence(value: object, field: str) -> Sequence[object]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise O1C29RunError(f"{field} must be a sequence")
    return cast(Sequence[object], value)


def _integer(value: object, field: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise O1C29RunError(f"{field} must be an integer >= {minimum}")
    return value


def _safe_relative(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise O1C29RunError(f"{field} is not a safe relative path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise O1C29RunError(f"{field} is not a safe relative path")
    return value


def _read_json_payload(payload: bytes, field: str) -> Mapping[str, object]:
    try:
        decoded = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise O1C29RunError(f"{field} is invalid JSON") from exc
    return _mapping(decoded, field)


def _read_json(path: Path, field: str) -> tuple[Mapping[str, object], bytes]:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise O1C29RunError(f"{field} is unreadable") from exc
    return _read_json_payload(payload, field), payload


@dataclass(frozen=True, slots=True)
class O1C29Budgets:
    maximum_cpu_seconds: float
    maximum_wall_seconds: float
    maximum_resident_memory_mib: int
    maximum_persistent_artifact_bytes: int
    maximum_source_artifact_bytes_read: int
    required_state_count: int
    required_state_bytes: int
    required_lineage_verification_consumes: int
    required_label_artifact_opens: int
    required_trusted_manager_verification_count: int
    required_trusted_manager_label_payload_reads: int
    maximum_fresh_targets_consumed: int
    maximum_native_solver_branches: int
    maximum_scientific_entropy_calls: int
    maximum_sibling_reads: int
    maximum_sibling_writes: int
    maximum_mps_calls: int
    maximum_gpu_calls: int

    @classmethod
    def from_mapping(cls, value: object) -> "O1C29Budgets":
        fields = set(cls.__dataclass_fields__)
        row = _mapping(value, "budgets", fields)
        numeric = {
            "maximum_cpu_seconds": 180.0,
            "maximum_wall_seconds": 300.0,
        }
        numeric_values: dict[str, float] = {}
        for name, maximum in numeric.items():
            raw = row[name]
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                raise O1C29RunError(f"budgets.{name} must be numeric")
            parsed = float(raw)
            if not 0.0 < parsed <= maximum:
                raise O1C29RunError(f"budgets.{name} differs")
            numeric_values[name] = parsed
        integers = {
            name: _integer(row[name], f"budgets.{name}")
            for name in fields - set(numeric)
        }
        expected_exact = {
            "required_state_count": 16,
            "required_state_bytes": STATE_BYTES,
            "required_lineage_verification_consumes": 4,
            "required_label_artifact_opens": 2,
            "required_trusted_manager_verification_count": 1,
            "required_trusted_manager_label_payload_reads": 1,
            "maximum_fresh_targets_consumed": 0,
            "maximum_native_solver_branches": 0,
            "maximum_scientific_entropy_calls": 0,
            "maximum_sibling_reads": 0,
            "maximum_sibling_writes": 0,
            "maximum_mps_calls": 0,
            "maximum_gpu_calls": 0,
        }
        if any(integers[name] != expected for name, expected in expected_exact.items()):
            raise O1C29RunError("zero-authority or exact-work budget differs")
        if (
            integers["maximum_resident_memory_mib"] > 1024
            or integers["maximum_persistent_artifact_bytes"] > 4 * 1024 * 1024
            or integers["maximum_source_artifact_bytes_read"] > 256 * 1024 * 1024
        ):
            raise O1C29RunError("bounded resource budget differs")
        return cls(
            maximum_cpu_seconds=numeric_values["maximum_cpu_seconds"],
            maximum_wall_seconds=numeric_values["maximum_wall_seconds"],
            **integers,
        )


@dataclass(frozen=True, slots=True)
class O1C29RunConfig:
    top: Mapping[str, object]
    config_path: Path
    config_sha256: str
    root: Path
    budgets: O1C29Budgets
    source_paths: Mapping[str, Path]
    source_sha256: Mapping[str, str]
    source_freeze_commit: str
    o1c23_config_path: Path
    o1c23_config_sha256: str
    runtime_receipt: RuntimeFreezeReceipt


def _git_is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    completed = subprocess.run(
        ("git", "merge-base", "--is-ancestor", ancestor, descendant),
        cwd=root,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return completed.returncode == 0


def load_o1c29_stacked_hot_calibration_run_config(
    path: str | Path,
    *,
    root: str | Path | None = None,
) -> O1C29RunConfig:
    """Load the exact retrospective config and verify every pinned source byte."""

    config_path = Path(path).resolve(strict=True)
    lab_root = (
        Path(root).resolve(strict=True) if root is not None else config_path.parents[1]
    )
    if not config_path.is_relative_to(lab_root):
        raise O1C29RunError("config escapes lab root")
    top, payload = _read_json(config_path, "O1C-0029 config")
    _mapping(
        top,
        "O1C-0029 config",
        {
            "schema",
            "attempt_id",
            "slug",
            "claim_level",
            "hypothesis",
            "prediction",
            "controls",
            "budgets",
            "next_action",
            "experiment",
            "prerequisite",
            "source",
            "runtime",
        },
    )
    if (
        top.get("schema") != RUN_CONFIG_SCHEMA
        or top.get("attempt_id") != ATTEMPT_ID
        or top.get("slug") != FORMAL_SLUG
        or top.get("claim_level") != ClaimLevel.RETROSPECTIVE.value
        or any(
            not isinstance(top.get(name), str) or not str(top[name]).strip()
            for name in ("hypothesis", "prediction", "next_action")
        )
        or len(_sequence(top.get("controls"), "controls")) < 4
    ):
        raise O1C29RunError("top-level frozen config differs")
    budgets = O1C29Budgets.from_mapping(top["budgets"])
    runtime_receipt = verify_o1c29_runtime_freeze_fresh(top["runtime"], root=lab_root)
    experiment = _mapping(
        top["experiment"],
        "experiment",
        {
            "schema",
            "protocol",
            "fold_ids",
            "alpha",
            "confidence_temperature_grid",
            "state_inventory",
            "state_bytes",
            "arms",
            "top_k_limit",
            "label_artifact",
            "label_bitorder",
            "label_openings",
            "actual_o1c23_selection_role",
            "fresh_work_authority",
        },
    )
    if dict(experiment) != {
        "schema": EXPERIMENT_SCHEMA,
        "protocol": "OUTER_FOLD_STACKED_HOT_CALIBRATION",
        "fold_ids": list(CANONICAL_FOLD_IDS),
        "alpha": 1.0,
        "confidence_temperature_grid": [0.5, 1.0, 2.0, 4.0],
        "state_inventory": 16,
        "state_bytes": STATE_BYTES,
        "arms": [PRIMARY_OPERATOR_ID, SECONDARY_OPERATOR_ID],
        "top_k_limit": TOP_K_LIMIT,
        "label_artifact": "labels.bitpack",
        "label_bitorder": "little",
        "label_openings": [
            "CALIBRATION_AFTER_ALL_STATES_PERSISTED",
            "SCORING_AFTER_ALL_FITS_AND_LOGITS_PERSISTED",
        ],
        "actual_o1c23_selection_role": "OPTIONAL_METADATA_ONLY_NEVER_SELECTION",
        "fresh_work_authority": "ZERO",
    }:
        raise O1C29RunError("experiment differs")
    prerequisite = _mapping(
        top["prerequisite"],
        "prerequisite",
        {
            "attempt_id",
            "source_selection",
            "config_path",
            "config_sha256",
            "artifact_index_schema",
            "artifact_count",
            "label_phase",
        },
    )
    if (
        prerequisite.get("attempt_id") != UPSTREAM_ATTEMPT_ID
        or prerequisite.get("source_selection") != "reserved-finalized-attempt-only"
        or prerequisite.get("artifact_index_schema") != UPSTREAM_ARTIFACT_INDEX_SCHEMA
        or prerequisite.get("artifact_count") != EXPECTED_UPSTREAM_ARTIFACTS
        or prerequisite.get("label_phase") != LABEL_PHASE
    ):
        raise O1C29RunError("prerequisite identity differs")
    o1c23_relative = _safe_relative(prerequisite["config_path"], "prerequisite config")
    o1c23_config_path = (lab_root / o1c23_relative).resolve(strict=True)
    if not o1c23_config_path.is_relative_to(lab_root):
        raise O1C29RunError("prerequisite config escapes lab")
    o1c23_sha = _sha256(prerequisite["config_sha256"], "prerequisite config SHA")
    if _sha256_file(o1c23_config_path) != o1c23_sha:
        raise O1C29RunError("prerequisite config hash differs")
    source = _mapping(
        top["source"],
        "source",
        {"source_freeze_commit", "source_selection", "files"},
    )
    source_freeze = source.get("source_freeze_commit")
    if (
        not isinstance(source_freeze, str)
        or len(source_freeze) != 40
        or any(character not in _HEX for character in source_freeze)
        or source.get("source_selection") != "exact-hash-and-clean-descendant"
    ):
        raise O1C29RunError("source freeze differs")
    files = _mapping(source["files"], "source files")
    if set(files) != EXPECTED_SOURCE_LABELS:
        raise O1C29RunError("source file inventory differs")
    source_paths: dict[str, Path] = {}
    source_hashes: dict[str, str] = {}
    for label, raw in files.items():
        entry = _mapping(raw, f"source.{label}", {"path", "sha256"})
        relative = _safe_relative(entry["path"], f"source.{label}.path")
        candidate = (lab_root / relative).resolve(strict=True)
        if not candidate.is_relative_to(lab_root) or not candidate.is_file():
            raise O1C29RunError(f"source path differs: {label}")
        digest = _sha256(entry["sha256"], f"source.{label}.sha256")
        if _sha256_file(candidate) != digest:
            raise O1C29RunError(f"source bytes differ: {label}")
        source_paths[label] = candidate
        source_hashes[label] = digest
    head = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=lab_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not _git_is_ancestor(lab_root, source_freeze, head):
        raise O1C29RunError("HEAD does not descend from source freeze")
    return O1C29RunConfig(
        top=top,
        config_path=config_path,
        config_sha256=_sha256_bytes(payload),
        root=lab_root,
        budgets=budgets,
        source_paths=source_paths,
        source_sha256=source_hashes,
        source_freeze_commit=source_freeze,
        o1c23_config_path=o1c23_config_path,
        o1c23_config_sha256=o1c23_sha,
        runtime_receipt=runtime_receipt,
    )


@dataclass(frozen=True, slots=True)
class LabelArtifactCommitment:
    capsule_path: Path
    capsule_manifest_sha256: str
    artifact_index_sha256: str
    artifact_index_bytes: int
    labels_relative: str
    labels_sha256: str
    labels_bytes: int
    labels_phase: str

    def receipt_document(self) -> dict[str, object]:
        return {
            "schema": LABEL_COMMITMENT_SCHEMA,
            "source_attempt_id": UPSTREAM_ATTEMPT_ID,
            "source_capsule_manifest_sha256": self.capsule_manifest_sha256,
            "source_artifact_index_sha256": self.artifact_index_sha256,
            "source_artifact_index_bytes": self.artifact_index_bytes,
            "labels_relative": self.labels_relative,
            "labels_sha256": self.labels_sha256,
            "labels_bytes": self.labels_bytes,
            "labels_phase": self.labels_phase,
            "labels_payload_opened": False,
        }


@dataclass(frozen=True, slots=True)
class SourceReadAccounting:
    trusted_manager_verification_bytes: int
    authority_original_pass_bytes: int
    authority_projection_pass_bytes: int
    packet_projection_bytes: int
    accounting_probe_bytes: int
    label_index_bytes_per_open: int
    label_payload_bytes_per_open: int
    trusted_manager_verification_count: int = 1
    scientific_gated_label_open_count: int = 2

    @property
    def label_open_count(self) -> int:
        """Compatibility alias for the two scientific gated openings."""

        return self.scientific_gated_label_open_count

    @property
    def preflight_bytes(self) -> int:
        return (
            self.trusted_manager_verification_bytes
            + self.authority_original_pass_bytes
            + self.authority_projection_pass_bytes
            + self.packet_projection_bytes
            + self.accounting_probe_bytes
        )

    @property
    def label_open_bytes(self) -> int:
        return self.scientific_gated_label_open_count * (
            self.label_index_bytes_per_open + self.label_payload_bytes_per_open
        )

    @property
    def total_bytes(self) -> int:
        return self.preflight_bytes + self.label_open_bytes

    def receipt_document(self) -> dict[str, object]:
        return {
            "schema": SOURCE_ACCOUNTING_SCHEMA,
            "trusted_manager_verification_bytes": self.trusted_manager_verification_bytes,
            "authority_original_pass_bytes": self.authority_original_pass_bytes,
            "authority_disposable_projection_pass_bytes": (
                self.authority_projection_pass_bytes
            ),
            "packet_projection_bytes": self.packet_projection_bytes,
            "accounting_probe_bytes": self.accounting_probe_bytes,
            "label_index_bytes_per_open": self.label_index_bytes_per_open,
            "label_payload_bytes_per_open": self.label_payload_bytes_per_open,
            "trusted_manager_verification_count": self.trusted_manager_verification_count,
            "scientific_gated_label_open_count": self.scientific_gated_label_open_count,
            "label_open_count": self.scientific_gated_label_open_count,
            "preflight_source_artifact_bytes_read": self.preflight_bytes,
            "label_phase_source_artifact_bytes_read": self.label_open_bytes,
            "source_artifact_bytes_read": self.total_bytes,
            "trusted_manager_label_payload_reads": 1,
        }


def _validate_index(
    payload: bytes,
    *,
    expected_sha256: str,
) -> tuple[Mapping[str, object], Mapping[str, object]]:
    if _sha256_bytes(payload) != expected_sha256:
        raise O1C29RunError("authoritative O1C-0022 artifact-index SHA changed")
    index = _read_json_payload(payload, "O1C-0022 artifact index")
    if (
        index.get("schema") != UPSTREAM_ARTIFACT_INDEX_SCHEMA
        or index.get("attempt_id") != UPSTREAM_ATTEMPT_ID
    ):
        raise O1C29RunError("O1C-0022 artifact-index identity differs")
    artifacts = _mapping(index.get("artifacts"), "O1C-0022 artifact entries")
    indexed_bytes = sum(
        _integer(_mapping(entry, f"index entry {relative}").get("bytes"), "bytes")
        for relative, entry in artifacts.items()
    )
    if (
        len(artifacts) != EXPECTED_UPSTREAM_ARTIFACTS
        or index.get("indexed_artifact_count") != EXPECTED_UPSTREAM_ARTIFACTS
        or index.get("indexed_artifact_bytes") != indexed_bytes
    ):
        raise O1C29RunError("O1C-0022 artifact-index totals differ")
    return index, artifacts


def inspect_o1c22_label_commitment_and_accounting(
    finalized: FinalizedRun,
    *,
    expected_artifact_index_sha256: str,
    upstream_maximum_persistent_bytes: int,
) -> tuple[LabelArtifactCommitment, SourceReadAccounting]:
    """Read no label byte; derive exact original/projection/packet read billing."""

    if finalized.attempt_id != UPSTREAM_ATTEMPT_ID or not finalized.verification.ok:
        raise O1C29RunError("source is not a verified finalized O1C-0022 capsule")
    capsule = finalized.path.resolve(strict=True)
    artifacts_root = capsule / "artifacts"
    config_payload = (capsule / "config.json").read_bytes()
    metrics_payload = (capsule / "metrics.json").read_bytes()
    index_payload = (artifacts_root / "artifact_index.json").read_bytes()
    index, artifacts = _validate_index(
        index_payload, expected_sha256=expected_artifact_index_sha256
    )
    label_entry = _mapping(
        artifacts.get("labels.bitpack"),
        "labels.bitpack index entry",
        {"sha256", "bytes", "phase"},
    )
    label_sha = _sha256(label_entry.get("sha256"), "labels.bitpack SHA")
    if (
        label_entry.get("bytes") != LABEL_BITPACK_BYTES
        or label_entry.get("phase") != LABEL_PHASE
    ):
        raise O1C29RunError("labels.bitpack index authority differs")

    heldout_names = sorted(
        relative
        for relative in artifacts
        if relative.endswith("/heldout/prediction_freeze.json")
    )
    if len(heldout_names) != 4:
        raise O1C29RunError("producer heldout freeze inventory differs")
    projected_index = deepcopy(dict(index))
    projected_entries = _mapping(
        projected_index["artifacts"], "projected artifact entries"
    )
    heldout_payload_bytes = 0
    for fold_index, relative in enumerate(heldout_names):
        payload = (
            artifacts_root / _safe_relative(relative, "heldout freeze")
        ).read_bytes()
        heldout_payload_bytes += len(payload)
        entry = _mapping(artifacts[relative], f"heldout entry {fold_index}")
        if entry.get("sha256") != _sha256_bytes(payload) or entry.get("bytes") != len(
            payload
        ):
            raise O1C29RunError("producer heldout freeze index differs")
        producer = verify_o1c22_producer_heldout_freeze(
            _read_json_payload(payload, f"producer heldout freeze {fold_index}"),
            fold_index=fold_index,
        )
        unsigned = dict(producer)
        unsigned.pop("freeze_sha256", None)
        unsigned.pop("scientific_entropy_calls", None)
        projected_payload = canonical_json_bytes(
            {**unsigned, "freeze_sha256": _sha256_bytes(canonical_json_bytes(unsigned))}
        )
        projected_entry = cast(dict[str, object], projected_entries[relative])
        projected_entry["sha256"] = _sha256_bytes(projected_payload)
        projected_entry["bytes"] = len(projected_payload)
    projected_indexed_bytes = sum(
        _integer(_mapping(entry, "projected entry").get("bytes"), "projected bytes")
        for entry in projected_entries.values()
    )
    cast(dict[str, object], projected_index)["indexed_artifact_bytes"] = (
        projected_indexed_bytes
    )
    projected_index_payload = canonical_json_bytes(projected_index)
    metrics = deepcopy(dict(_read_json_payload(metrics_payload, "O1C-0022 metrics")))
    values = cast(dict[str, object], metrics.get("values"))
    projected_persistent_artifact_bytes = projected_indexed_bytes + len(
        projected_index_payload
    )
    values["persistent_artifact_bytes"] = projected_persistent_artifact_bytes
    checks = cast(dict[str, object], values.get("budget_checks"))
    checks["persistent_artifacts"] = (
        projected_persistent_artifact_bytes <= upstream_maximum_persistent_bytes
    )
    projected_metrics_payload = canonical_json_bytes(metrics)
    indexed_bytes = _integer(index.get("indexed_artifact_bytes"), "indexed bytes")
    original_pass = (
        len(config_payload)
        + len(metrics_payload)
        + len(index_payload)
        + indexed_bytes
        - LABEL_BITPACK_BYTES
    )
    projected_pass = (
        len(config_payload)
        + len(projected_metrics_payload)
        + len(projected_index_payload)
        + projected_indexed_bytes
    )
    packet_names = [
        relative
        for relative in artifacts
        if relative.endswith("/prediction_freeze.json")
        or relative.endswith("/quantizer.json")
        or relative.endswith("/packet_deltas.json")
    ]
    if len(packet_names) != 32:
        raise O1C29RunError("O1C-0029 packet projection inventory differs")
    packet_bytes = len(index_payload) + sum(
        _integer(_mapping(artifacts[name], "packet entry").get("bytes"), "packet bytes")
        for name in packet_names
    )
    commitment = LabelArtifactCommitment(
        capsule_path=capsule,
        capsule_manifest_sha256=_sha256(
            finalized.manifest_sha256, "O1C-0022 capsule manifest"
        ),
        artifact_index_sha256=expected_artifact_index_sha256,
        artifact_index_bytes=len(index_payload),
        labels_relative="labels.bitpack",
        labels_sha256=label_sha,
        labels_bytes=LABEL_BITPACK_BYTES,
        labels_phase=LABEL_PHASE,
    )
    accounting = SourceReadAccounting(
        trusted_manager_verification_bytes=sum(
            path.stat().st_size
            for path in capsule.rglob("*")
            if path.is_file() and not path.is_symlink()
        ),
        authority_original_pass_bytes=original_pass,
        authority_projection_pass_bytes=projected_pass,
        packet_projection_bytes=packet_bytes,
        accounting_probe_bytes=(
            len(config_payload)
            + len(metrics_payload)
            + len(index_payload)
            + heldout_payload_bytes
        ),
        label_index_bytes_per_open=len(index_payload),
        label_payload_bytes_per_open=LABEL_BITPACK_BYTES,
    )
    return commitment, accounting


def read_committed_o1c22_label_artifacts(
    commitment: LabelArtifactCommitment,
) -> tuple[bytes, bytes]:
    """Re-read and bind the exact index and label bytes for one gated opening."""

    artifacts_root = commitment.capsule_path / "artifacts"
    index_path = artifacts_root / "artifact_index.json"
    label_path = artifacts_root / commitment.labels_relative
    if index_path.is_symlink() or label_path.is_symlink():
        raise O1C29RunError("authoritative label path cannot be a symlink")
    index_payload = index_path.read_bytes()
    _index, artifacts = _validate_index(
        index_payload, expected_sha256=commitment.artifact_index_sha256
    )
    entry = _mapping(
        artifacts.get(commitment.labels_relative),
        "re-read labels entry",
        {"sha256", "bytes", "phase"},
    )
    if dict(entry) != {
        "sha256": commitment.labels_sha256,
        "bytes": commitment.labels_bytes,
        "phase": commitment.labels_phase,
    }:
        raise O1C29RunError("re-read labels index commitment differs")
    payload = label_path.read_bytes()
    if (
        type(payload) is not bytes
        or len(payload) != commitment.labels_bytes
        or _sha256_bytes(payload) != commitment.labels_sha256
    ):
        raise O1C29RunError("re-read labels.bitpack differs")
    return index_payload, payload


@dataclass(frozen=True, slots=True)
class TrustedO1C22PreflightProjection:
    """Parent-side result containing only validated label-free child output."""

    corpus: VerifiedO1C22PacketCorpus
    label_commitment: LabelArtifactCommitment
    source_accounting: SourceReadAccounting


def _trusted_preflight_document(
    config: O1C29RunConfig,
    manager: RunCapsuleManager,
    transfer_nonce: str,
) -> Mapping[str, object]:
    """Run inside the trusted child; perform the sole O1C-0022 manager pass."""

    upstream = manager.finalized_attempt(UPSTREAM_ATTEMPT_ID)
    if upstream is None:
        return {
            "schema": TRUSTED_PREFLIGHT_WIRE_SCHEMA,
            "status": "prerequisite-pending",
            "reason": "reserved finalized O1C-0022 capsule is not available",
        }
    o1c23_config = load_o1c22_postresult_composer_run_config(
        config.o1c23_config_path, root=config.root
    )
    corpus = load_trusted_verified_o1c22_packet_corpus(o1c23_config, upstream)
    authority = require_factory_minted_o1c22_packet_corpus(corpus)
    upstream_budgets = _mapping(
        o1c23_config.upstream_top.get("budgets"), "upstream budgets"
    )
    commitment, accounting = inspect_o1c22_label_commitment_and_accounting(
        upstream,
        expected_artifact_index_sha256=authority.artifact_index_sha256,
        upstream_maximum_persistent_bytes=_integer(
            upstream_budgets.get("maximum_persistent_artifact_bytes"),
            "upstream persistent budget",
        ),
    )
    if (
        commitment.capsule_manifest_sha256 != authority.capsule_manifest_sha256
        or commitment.artifact_index_sha256 != authority.artifact_index_sha256
        or commitment.artifact_index_bytes != authority.artifact_index_bytes
        or commitment.labels_relative != authority.labels_relative
        or commitment.labels_sha256 != authority.labels_sha256
        or commitment.labels_bytes != authority.labels_bytes
        or commitment.labels_phase != authority.labels_phase
        or accounting.trusted_manager_verification_count != 1
        or accounting.trusted_manager_verification_bytes
        != authority.trusted_manager_verification_bytes
        or accounting.scientific_gated_label_open_count != 2
    ):
        raise O1C29RunError("trusted manager authority projection differs")
    capsule = upstream.path.resolve(strict=True)
    if not capsule.is_relative_to(config.root):
        raise O1C29RunError("trusted capsule escapes lab root")
    relative = capsule.relative_to(config.root).as_posix()
    if len(PurePosixPath(relative).parts) != 2 or not relative.startswith("runs/"):
        raise O1C29RunError("trusted capsule locator differs")
    return {
        "schema": TRUSTED_PREFLIGHT_WIRE_SCHEMA,
        "status": "ready",
        "corpus": json.loads(
            serialize_verified_o1c22_packet_corpus(
                corpus, _trusted_nonce=transfer_nonce
            )
        ),
        "capsule_relative": relative,
        "authority": authority.receipt_document(),
        "source_accounting": accounting.receipt_document(),
    }


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        offset += os.write(descriptor, payload[offset:])


def _run_trusted_preflight_process(
    config: O1C29RunConfig,
    manager: RunCapsuleManager,
) -> tuple[Mapping[str, object], str]:
    """Fork exactly one trusted verifier and receive only its canonical wire."""

    transfer_nonce = _new_trusted_packet_corpus_transfer_nonce()
    read_fd, write_fd = os.pipe()
    process_id = os.fork()
    if process_id == 0:  # pragma: no cover - assertions occur in the parent.
        os.close(read_fd)
        try:
            document = _trusted_preflight_document(config, manager, transfer_nonce)
        except BaseException as exc:
            document = {
                "schema": TRUSTED_PREFLIGHT_WIRE_SCHEMA,
                "status": "prerequisite-invalid",
                "reason": f"{type(exc).__name__}: {exc}",
            }
        try:
            _write_all(write_fd, canonical_json_bytes(document))
        finally:
            os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = os.read(read_fd, 1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > 64 * 1024 * 1024:
                raise O1C29RunError("trusted preflight wire exceeds bound")
            chunks.append(chunk)
    finally:
        os.close(read_fd)
    _waited, wait_status = os.waitpid(process_id, 0)
    if not os.WIFEXITED(wait_status) or os.WEXITSTATUS(wait_status) != 0:
        raise O1C29RunError("trusted preflight process failed")
    return (
        _read_json_payload(b"".join(chunks), "trusted preflight wire"),
        transfer_nonce,
    )


def _decode_trusted_ready_projection(
    config: O1C29RunConfig,
    document: Mapping[str, object],
    transfer_nonce: str,
) -> TrustedO1C22PreflightProjection:
    if set(document) != {
        "schema",
        "status",
        "corpus",
        "capsule_relative",
        "authority",
        "source_accounting",
    }:
        raise O1C29RunError("trusted ready wire fields differ")
    corpus = deserialize_verified_o1c22_packet_corpus(
        canonical_json_bytes(document["corpus"]),
        _trusted_nonce=transfer_nonce,
    )
    authority = require_factory_minted_o1c22_packet_corpus(corpus)
    if (
        dict(_mapping(document["authority"], "trusted authority"))
        != authority.receipt_document()
    ):
        raise O1C29RunError("trusted authority wire differs")
    accounting_row = _mapping(document["source_accounting"], "source accounting")
    accounting = SourceReadAccounting(
        trusted_manager_verification_bytes=_integer(
            accounting_row.get("trusted_manager_verification_bytes"),
            "trusted manager verification bytes",
        ),
        authority_original_pass_bytes=_integer(
            accounting_row.get("authority_original_pass_bytes"), "original pass"
        ),
        authority_projection_pass_bytes=_integer(
            accounting_row.get("authority_disposable_projection_pass_bytes"),
            "projection pass",
        ),
        packet_projection_bytes=_integer(
            accounting_row.get("packet_projection_bytes"), "packet projection"
        ),
        accounting_probe_bytes=_integer(
            accounting_row.get("accounting_probe_bytes"), "accounting probe"
        ),
        label_index_bytes_per_open=_integer(
            accounting_row.get("label_index_bytes_per_open"), "label index bytes"
        ),
        label_payload_bytes_per_open=_integer(
            accounting_row.get("label_payload_bytes_per_open"), "label bytes"
        ),
    )
    if accounting.receipt_document() != dict(accounting_row):
        raise O1C29RunError("trusted source accounting wire differs")
    if (
        accounting.trusted_manager_verification_bytes
        != authority.trusted_manager_verification_bytes
    ):
        raise O1C29RunError("trusted manager verification byte accounting differs")
    relative = _safe_relative(document["capsule_relative"], "trusted capsule")
    capsule = (config.root / relative).resolve(strict=True)
    if not capsule.is_relative_to(config.root / "runs"):
        raise O1C29RunError("trusted capsule locator escapes runs")
    commitment = LabelArtifactCommitment(
        capsule_path=capsule,
        capsule_manifest_sha256=authority.capsule_manifest_sha256,
        artifact_index_sha256=authority.artifact_index_sha256,
        artifact_index_bytes=authority.artifact_index_bytes,
        labels_relative=authority.labels_relative,
        labels_sha256=authority.labels_sha256,
        labels_bytes=authority.labels_bytes,
        labels_phase=authority.labels_phase,
    )
    return TrustedO1C22PreflightProjection(corpus, commitment, accounting)


@dataclass(frozen=True, slots=True)
class O1C29Preflight:
    report: Mapping[str, object]
    config: O1C29RunConfig
    finalized: FinalizedRun | None = None
    o1c23_config: O1C23RunConfig | None = None
    corpus: VerifiedO1C22PacketCorpus | None = None
    inputs: RealProtocolInputs | None = None
    label_commitment: LabelArtifactCommitment | None = None
    source_accounting: SourceReadAccounting | None = None
    manager_authority: ManagerAuthorityCommitment | None = None
    optional_o1c23_metadata: Mapping[str, object] | None = None

    @property
    def ready(self) -> bool:
        return (
            self.report.get("status") == "ready"
            and self.inputs is not None
            and self.label_commitment is not None
            and self.source_accounting is not None
            and self.manager_authority is not None
        )


def preflight_o1c29_stacked_hot_calibration(
    path: str | Path,
    *,
    root: str | Path | None = None,
    manager: RunCapsuleManager | None = None,
) -> O1C29Preflight:
    """Verify readiness without calling ``RunCapsuleManager.start``."""

    config = load_o1c29_stacked_hot_calibration_run_config(path, root=root)
    selected_manager = manager or RunCapsuleManager(config.root)
    recoverable = selected_manager.recoverable_attempt_ids()
    existing = selected_manager.finalized_attempt(ATTEMPT_ID)
    base = {
        "schema": PREFLIGHT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "prerequisite_attempt_id": UPSTREAM_ATTEMPT_ID,
        "o1c29_reserved_by_this_preflight": False,
        "o1c29_existing_finalized": existing is not None,
        "o1c29_existing_recoverable": ATTEMPT_ID in recoverable,
        "o1c22_existing_recoverable": UPSTREAM_ATTEMPT_ID in recoverable,
    }
    trusted_document, transfer_nonce = _run_trusted_preflight_process(
        config, selected_manager
    )
    if trusted_document.get(
        "schema"
    ) != TRUSTED_PREFLIGHT_WIRE_SCHEMA or trusted_document.get("status") not in {
        "ready",
        "prerequisite-pending",
        "prerequisite-invalid",
    }:
        raise O1C29RunError("trusted preflight status wire differs")
    if trusted_document.get("status") == "prerequisite-pending":
        _discard_trusted_packet_corpus_transfer_nonce(transfer_nonce)
        return O1C29Preflight(
            report={
                **base,
                "status": "prerequisite-pending",
                "reason": trusted_document.get("reason"),
                "trusted_manager_verification_processes": 1,
            },
            config=config,
        )
    if trusted_document.get("status") == "prerequisite-invalid":
        _discard_trusted_packet_corpus_transfer_nonce(transfer_nonce)
        return O1C29Preflight(
            report={
                **base,
                "status": "prerequisite-invalid",
                "reason": trusted_document.get("reason"),
                "trusted_manager_verification_processes": 1,
            },
            config=config,
        )
    try:
        projection = _decode_trusted_ready_projection(
            config, trusted_document, transfer_nonce
        )
        corpus = projection.corpus
        inputs = adapt_verified_o1c22_packet_corpus(corpus)
        manager_authority = bind_manager_authority_commitment(inputs, corpus)
        commitment = projection.label_commitment
        accounting = projection.source_accounting
        if accounting.total_bytes > config.budgets.maximum_source_artifact_bytes_read:
            raise O1C29RunError("source-artifact read budget would be exceeded")
    except Exception as exc:
        return O1C29Preflight(
            report={
                **base,
                "status": "prerequisite-invalid",
                "reason": f"{type(exc).__name__}: {exc}",
                "trusted_manager_verification_processes": 1,
            },
            config=config,
        )
    # O1C-0023 is neither looked up nor opened.  Unknown availability is the
    # only sibling-read-free metadata state.
    optional = {
        "role": "OPTIONAL_METADATA_ONLY_NEVER_SELECTION",
        "available": None,
        "consumed": False,
        "selector_sha256": None,
        "scientific_selection_authority": False,
    }
    return O1C29Preflight(
        report={
            **base,
            "status": "ready",
            "o1c22_manifest_sha256": corpus.capsule_manifest_sha256,
            "o1c22_artifact_index_sha256": corpus.artifact_index_sha256,
            "packet_corpus_verified": True,
            "trusted_manager_verification_processes": 1,
            "trusted_manager_verification_count": 1,
            "scientific_gated_label_open_count": 2,
            "state_count": 16,
            "state_bytes": STATE_BYTES,
            "source_artifact_bytes_read": accounting.total_bytes,
            "actual_o1c23_selection_used_for_scientific_selection": False,
        },
        config=config,
        corpus=corpus,
        inputs=inputs,
        label_commitment=commitment,
        source_accounting=accounting,
        manager_authority=manager_authority,
        optional_o1c23_metadata=optional,
    )


class _Receipt(Protocol):
    def receipt_document(self) -> dict[str, object]: ...


PersistCallback = Callable[[str, bytes, str], None]
LabelReadCallback = Callable[[str], tuple[bytes, bytes]]
ScoreCallback = Callable[..., _Receipt]


@dataclass(frozen=True, slots=True)
class ProtocolExecution:
    freeze: GlobalStateFreeze
    result: StackedHotCalibrationResult
    score: _Receipt
    work: Mapping[str, object]
    manager_authority: ManagerAuthorityCommitment


def _json_bytes(value: object) -> bytes:
    return canonical_json_bytes(value)


def _persist_receipt(
    persist: PersistCallback,
    relative: str,
    receipt: _Receipt,
    phase: str,
) -> None:
    persist(relative, _json_bytes(receipt.receipt_document()), phase)


def execute_frozen_o1c29_protocol(
    inputs: RealProtocolInputs,
    *,
    manager_authority: ManagerAuthorityCommitment,
    persist: PersistCallback,
    read_label_artifacts: LabelReadCallback,
    actual_o1c23_selector_sha256: str | None = None,
    scorer: ScoreCallback = score_frozen_two_arm_predictions,
) -> ProtocolExecution:
    """Execute the exact two-opening lifecycle through public protocol APIs."""

    if actual_o1c23_selector_sha256 is not None:
        _sha256(actual_o1c23_selector_sha256, "optional O1C-0023 selector SHA")
    _persist_receipt(persist, "protocol/inputs.json", inputs, "INPUTS")
    persist(
        "protocol/experiment.json",
        _json_bytes(inputs.config.describe()),
        "INPUTS",
    )
    freeze = freeze_all_owner_states(inputs.config, inputs.owner_corpora)
    if len(freeze.states) != 16:
        raise O1C29RunError("global state inventory differs")
    for state in freeze.states:
        prefix = f"states/{state.owner_fold}/{state.episode_fold}"
        if len(state.state_bytes) != STATE_BYTES:
            raise O1C29RunError("persisted state width differs")
        persist(f"{prefix}/state.bin", state.state_bytes, "STATE_BARRIER")
        _persist_receipt(
            persist,
            f"{prefix}/freeze.json",
            state,
            "STATE_BARRIER",
        )
    _persist_receipt(
        persist,
        "states/global_freeze.json",
        freeze,
        "STATE_BARRIER",
    )

    calibration_index, calibration_labels = read_label_artifacts("CALIBRATION")
    broker = open_authoritative_calibration_broker_after_state_freeze(
        inputs,
        freeze,
        calibration_index,
        calibration_labels,
        manager_authority=manager_authority,
    )
    calibration_open = {
        "schema": "o1-256-o1c29-calibration-label-open-v1",
        "artifact_index_sha256": _sha256_bytes(calibration_index),
        "labels_sha256": _sha256_bytes(calibration_labels),
        "global_state_freeze_sha256": freeze.receipt_sha256,
        "opened_after_all_states_persisted": True,
        "heldout_label_grants": 0,
    }
    persist(
        "labels/calibration_open.json",
        _json_bytes(calibration_open),
        "CALIBRATION_LABEL_OPEN",
    )
    del calibration_labels, calibration_index
    result = run_stacked_hot_calibration_from_freeze(
        inputs.config,
        freeze,
        broker,
        actual_o1c23_selector_sha256=actual_o1c23_selector_sha256,
    )
    if result.global_freeze.receipt_sha256 != freeze.receipt_sha256:
        raise O1C29RunError("protocol reconstructed or changed the persisted freeze")
    if len(result.fits) != 4 or len(result.predictions) != 4:
        raise O1C29RunError("fit or prediction inventory differs")
    for fit, prediction in zip(result.fits, result.predictions, strict=True):
        prefix = f"folds/{fit.outer_fold}"
        _persist_receipt(persist, f"{prefix}/fit.json", fit, "FITS_AND_LOGITS")
        weights = fit.simplex_fit.slot_weights.astype("<f4", copy=False).tobytes(
            order="C"
        )
        persist(f"{prefix}/fit_slot_weights.f32le", weights, "FITS_AND_LOGITS")
        _persist_receipt(
            persist,
            f"{prefix}/prediction.json",
            prediction,
            "FITS_AND_LOGITS",
        )
        persist(
            f"{prefix}/primary_logits.f32le",
            prediction.primary_logits_bytes,
            "FITS_AND_LOGITS",
        )
        persist(
            f"{prefix}/secondary_logits.f32le",
            prediction.secondary_logits_bytes,
            "FITS_AND_LOGITS",
        )
    _persist_receipt(
        persist,
        "predictions/frozen_result.json",
        result,
        "FITS_AND_LOGITS",
    )

    scoring_index, scoring_labels = read_label_artifacts("SCORING")
    scoring_capability = open_authoritative_labels_after_prediction_freeze(
        inputs,
        result,
        scoring_index,
        scoring_labels,
        manager_authority=manager_authority,
    )
    _persist_receipt(
        persist,
        "labels/scoring_capability.json",
        scoring_capability,
        "SCORING_LABEL_OPEN",
    )
    score = scorer(result, scoring_capability, top_k_limit=TOP_K_LIMIT)
    score_document = score.receipt_document()
    if (
        score_document.get("top_k_limit") != TOP_K_LIMIT
        or score_document.get("arm_order") != ["primary", "secondary"]
        or score_document.get("label_dependent_arm_selection") is not False
    ):
        raise O1C29RunError("fixed two-arm score receipt differs")
    _persist_receipt(persist, "scores/two_arm_score.json", score, "SCORED")
    arms = tuple(getattr(score, "arms", ()))
    if len(arms) != 2:
        raise O1C29RunError("both precommitted arms were not scored")
    for arm in arms:
        arm_name = str(getattr(arm, "arm"))
        _persist_receipt(persist, f"scores/{arm_name}/arm_score.json", arm, "SCORED")
        for fold in tuple(getattr(arm, "folds", ())):
            _persist_receipt(
                persist,
                f"scores/{arm_name}/{getattr(fold, 'outer_fold')}.json",
                fold,
                "SCORED",
            )
    work = {
        "schema": WORK_SCHEMA,
        "state_constructions": 16,
        "state_stream_consumes": 16,
        "lineage_verification_consumes": 4,
        "hot_switch_replays": 0,
        "trusted_manager_verification_processes": 1,
        "trusted_manager_verification_count": 1,
        "trusted_manager_label_payload_reads": 1,
        "label_artifact_opens": 2,
        "scientific_gated_label_artifact_opens": 2,
        "fit_count": 4,
        "persisted_logit_vectors": 8,
        "scored_arms": [PRIMARY_OPERATOR_ID, SECONDARY_OPERATOR_ID],
        "top_k_limit": TOP_K_LIMIT,
        "fresh_targets_consumed": 0,
        "native_solver_branches": 0,
        "scientific_entropy_calls": 0,
        "sibling_reads": 0,
        "sibling_writes": 0,
        "mps_calls": 0,
        "gpu_calls": 0,
        "actual_o1c23_selector_used_for_scientific_selection": False,
    }
    persist("work/structural_work.json", _json_bytes(work), "WORK")
    return ProtocolExecution(
        freeze=freeze,
        result=result,
        score=score,
        work=work,
        manager_authority=manager_authority,
    )


def _peak_rss_bytes() -> int:
    raw = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return raw if sys.platform == "darwin" else raw * 1024


def _clean_commit(config: O1C29RunConfig) -> str:
    status = subprocess.run(
        ("git", "status", "--porcelain", "--untracked-files=all"),
        cwd=config.root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if status:
        raise O1C29RunError("source worktree must be exactly clean before reservation")
    commit = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=config.root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not _git_is_ancestor(config.root, config.source_freeze_commit, commit):
        raise O1C29RunError("clean execution commit does not descend source freeze")
    _verify_source_snapshot(config)
    return commit


def _verify_source_snapshot(config: O1C29RunConfig) -> None:
    if (
        any(
            _sha256_file(config.source_paths[label]) != digest
            for label, digest in config.source_sha256.items()
        )
        or _sha256_file(config.config_path) != config.config_sha256
    ):
        raise O1C29RunError("source snapshot changed")


def _read_capsule_status(finalized: FinalizedRun) -> object:
    document, _ = _read_json(finalized.path / "metrics.json", "capsule metrics")
    return document.get("status")


def _acquire_execution_lease(manager: RunCapsuleManager) -> int | None:
    """Acquire the attempt-spanning owner lease without following symlinks."""

    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    runs_fd = os.open(manager.output_root, directory_flags)
    try:
        attempts_fd = os.open(".attempt_ids", directory_flags, dir_fd=runs_fd)
    finally:
        os.close(runs_fd)
    try:
        lease_fd = os.open(
            f"{ATTEMPT_ID}.execution.lock",
            os.O_CREAT
            | os.O_RDWR
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=attempts_fd,
        )
    finally:
        os.close(attempts_fd)
    metadata = os.fstat(lease_fd)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        os.close(lease_fd)
        raise O1C29RunError("execution lease is not one regular owned file")
    try:
        fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lease_fd)
        return None
    return lease_fd


def run_capsule_from_config(path: str | Path) -> int:
    """Hold one execution lease across lookup, recovery, preflight and run."""

    config_path = Path(path).resolve(strict=True)
    root = config_path.parents[1]
    manager = RunCapsuleManager(root)
    lease_fd = _acquire_execution_lease(manager)
    if lease_fd is None:
        print(
            json.dumps(
                {
                    "attempt_id": ATTEMPT_ID,
                    "status": "active-execution-lease-held",
                    "reason": "another O1C-0029 lifecycle owner is active",
                },
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    try:
        return _run_capsule_from_config_under_lease(config_path, manager)
    finally:
        os.close(lease_fd)


def _run_capsule_from_config_under_lease(
    config_path: Path,
    manager: RunCapsuleManager,
) -> int:
    root = config_path.parents[1]
    published = manager.finalized_attempt(ATTEMPT_ID)
    if published is not None:
        status = _read_capsule_status(published)
        print(
            json.dumps(
                {
                    "attempt_id": ATTEMPT_ID,
                    "status": "already-finalized-no-replay",
                    "capsule_status": status,
                    "path": str(published.path),
                    "manifest_sha256": published.manifest_sha256,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if status == "completed" else 2
    if ATTEMPT_ID in manager.recoverable_attempt_ids():
        interrupted = manager.recover(ATTEMPT_ID)
        if interrupted.publication_prepared:
            finalized = interrupted.finalize(metrics={})
            return 0 if _read_capsule_status(finalized) == "completed" else 2
        finalized = interrupted.finalize(
            metrics={
                "schema": RESULT_SCHEMA,
                "hard_interruption_recovered": True,
                "scientific_result_claimed": False,
                "replay_performed": False,
            },
            status="stopped",
            next_action=(
                "Preserve the interrupted capsule and repeat only under a new "
                "attempt identity after diagnosing its final checkpoint."
            ),
        )
        print(f"stopped capsule without replay: {finalized.path}", file=sys.stderr)
        return 2

    cpu_started = time.process_time()
    wall_started = time.monotonic()
    preflight = preflight_o1c29_stacked_hot_calibration(config_path, root=root)
    if not preflight.ready:
        print(json.dumps(preflight.report, indent=2, sort_keys=True), file=sys.stderr)
        return 2
    assert preflight.inputs is not None
    assert preflight.label_commitment is not None
    assert preflight.source_accounting is not None
    assert preflight.manager_authority is not None
    config = preflight.config
    commit = _clean_commit(config)
    source_hashes = {
        **dict(config.source_sha256),
        "config": config.config_sha256,
        "o1c23_source_config": config.o1c23_config_sha256,
    }
    run = manager.start(
        attempt_id=ATTEMPT_ID,
        slug=FORMAL_SLUG,
        commit=commit,
        hypothesis=str(config.top["hypothesis"]),
        prediction=str(config.top["prediction"]),
        controls=tuple(
            str(item) for item in _sequence(config.top["controls"], "controls")
        ),
        budgets=dict(_mapping(config.top["budgets"], "budgets")),
        source_hashes=source_hashes,
        claim_level=ClaimLevel.RETROSPECTIVE,
        next_action=str(config.top["next_action"]),
        config=config.top,
        command=(
            sys.executable,
            "-m",
            "o1_crypto_lab.o1c29_stacked_hot_calibration_run",
            "--config",
            str(config.config_path),
        ),
        environment={
            "protocol": "OUTER_FOLD_STACKED_HOT_CALIBRATION",
            "accelerator": "none",
            "source_attempt_id": UPSTREAM_ATTEMPT_ID,
            "fresh_targets_consumed": 0,
            "native_solver_branches": 0,
            "scientific_entropy_calls": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "mps_calls": 0,
            "gpu_calls": 0,
            "hard_interruption_policy": "FINALIZE_STOPPED_AND_NEVER_REPLAY",
        },
    )
    persisted: dict[str, dict[str, object]] = {}
    persistent_bytes = 0

    def persist(relative: str, payload: bytes, phase: str) -> None:
        nonlocal persistent_bytes
        if relative in persisted or not payload:
            raise O1C29RunError("artifact inventory differs")
        if (
            persistent_bytes + len(payload)
            > config.budgets.maximum_persistent_artifact_bytes
        ):
            raise O1C29RunError("persistent artifact budget exceeded")
        output = run.write_artifact(relative, payload)
        digest = _sha256_bytes(payload)
        if _sha256_file(output) != digest:
            raise O1C29RunError("persisted artifact changed")
        persisted[relative] = {"sha256": digest, "bytes": len(payload), "phase": phase}
        persistent_bytes += len(payload)

    try:
        persist(
            "source/label_commitment.json",
            _json_bytes(preflight.label_commitment.receipt_document()),
            "SOURCE",
        )
        persist(
            "source/read_accounting.json",
            _json_bytes(preflight.source_accounting.receipt_document()),
            "SOURCE",
        )
        _persist_receipt(
            persist,
            "source/manager_authority.json",
            preflight.manager_authority,
            "SOURCE",
        )
        persist(
            "source/optional_o1c23_metadata.json",
            _json_bytes(dict(preflight.optional_o1c23_metadata or {})),
            "SOURCE",
        )
        run.checkpoint(
            {
                "phase": "RESERVED_AFTER_VERIFIED_O1C0022_PREFLIGHT",
                "source_artifact_bytes_read": preflight.source_accounting.preflight_bytes,
                "label_artifact_opens": 0,
            }
        )

        def read_labels(phase: str) -> tuple[bytes, bytes]:
            result = read_committed_o1c22_label_artifacts(
                cast(LabelArtifactCommitment, preflight.label_commitment)
            )
            run.checkpoint(
                {
                    "phase": f"{phase}_LABEL_INDEX_AND_PAYLOAD_REVALIDATED",
                    "label_artifact_opens": 1 if phase == "CALIBRATION" else 2,
                }
            )
            return result

        execution = execute_frozen_o1c29_protocol(
            preflight.inputs,
            manager_authority=preflight.manager_authority,
            persist=persist,
            read_label_artifacts=read_labels,
            actual_o1c23_selector_sha256=None,
        )
        cpu_seconds = time.process_time() - cpu_started
        wall_seconds = time.monotonic() - wall_started
        peak_rss = _peak_rss_bytes()
        _verify_source_snapshot(config)
        work = execution.work
        checks = {
            "cpu": cpu_seconds <= config.budgets.maximum_cpu_seconds,
            "wall": wall_seconds <= config.budgets.maximum_wall_seconds,
            "resident_memory": peak_rss
            <= config.budgets.maximum_resident_memory_mib * 1024 * 1024,
            "source_artifact_bytes_read": preflight.source_accounting.total_bytes
            <= config.budgets.maximum_source_artifact_bytes_read,
            "state_count": work["state_constructions"]
            == config.budgets.required_state_count,
            "state_bytes": all(
                len(row.state_bytes) == config.budgets.required_state_bytes
                for row in execution.freeze.states
            ),
            "lineage_verification": work["lineage_verification_consumes"]
            == config.budgets.required_lineage_verification_consumes,
            "trusted_manager_verification": work["trusted_manager_verification_count"]
            == config.budgets.required_trusted_manager_verification_count,
            "trusted_manager_label_payload_reads": work[
                "trusted_manager_label_payload_reads"
            ]
            == config.budgets.required_trusted_manager_label_payload_reads,
            "label_openings": work["label_artifact_opens"]
            == config.budgets.required_label_artifact_opens,
            "fresh_targets": work["fresh_targets_consumed"] == 0,
            "native_solver_branches": work["native_solver_branches"] == 0,
            "scientific_entropy": work["scientific_entropy_calls"] == 0,
            "sibling_reads": work["sibling_reads"] == 0,
            "sibling_writes": work["sibling_writes"] == 0,
            "mps": work["mps_calls"] == 0,
            "gpu": work["gpu_calls"] == 0,
        }
        failed = sorted(name for name, passed in checks.items() if not passed)
        source_index = {
            "schema": SOURCE_INDEX_SCHEMA,
            "source_attempt_id": UPSTREAM_ATTEMPT_ID,
            "source_capsule_manifest_sha256": preflight.inputs.source_capsule_manifest_sha256,
            "source_artifact_index_sha256": preflight.inputs.source_artifact_index_sha256,
            "source_artifact_bytes_read": preflight.source_accounting.total_bytes,
            "source_sha256": source_hashes,
        }
        persist("source/source_index.json", _json_bytes(source_index), "SOURCE_INDEX")
        arm_summaries = []
        for arm in tuple(getattr(execution.score, "arms", ())):
            folds = tuple(getattr(arm, "folds", ()))
            ranks = [getattr(fold, "true_key_rank", None) for fold in folds]
            arm_summaries.append(
                {
                    "arm": getattr(arm, "arm"),
                    "operator_id": getattr(arm, "operator_id"),
                    "total_compression_bits": getattr(arm, "total_compression_bits"),
                    "mean_compression_bits": getattr(arm, "mean_compression_bits"),
                    "positive_fold_count": getattr(arm, "positive_fold_count"),
                    "bit_accuracy": getattr(arm, "bit_accuracy"),
                    "byte_top1_count": getattr(arm, "byte_top1_count"),
                    "byte_top4_count": getattr(arm, "byte_top4_count"),
                    "byte_top16_count": getattr(arm, "byte_top16_count"),
                    "block16_top1_count": getattr(arm, "block16_top1_count"),
                    "block16_top4_count": getattr(arm, "block16_top4_count"),
                    "block16_top16_count": getattr(arm, "block16_top16_count"),
                    "full_key_rank_by_fold": ranks,
                    "full_key_top65536_hit_count": sum(
                        rank is not None and rank <= TOP_K_LIMIT for rank in ranks
                    ),
                }
            )
        result_document = {
            "schema": RESULT_SCHEMA,
            "classification": (
                "STACKED_HOT_CALIBRATION_RETROSPECTIVE_COMPLETE"
                if not failed
                else "STACKED_HOT_CALIBRATION_RESOURCE_FAILURE"
            ),
            "claim_level": ClaimLevel.RETROSPECTIVE.value,
            "prediction_result_receipt_sha256": execution.result.receipt_sha256,
            "score_receipt_sha256": getattr(execution.score, "receipt_sha256"),
            "arm_scientific_summaries": arm_summaries,
            "arm_selected_from_outcomes": None,
            "actual_o1c23_selector_used_for_scientific_selection": False,
            "work": dict(work),
            "source_read_accounting": preflight.source_accounting.receipt_document(),
            "cpu_seconds": cpu_seconds,
            "wall_seconds": wall_seconds,
            "peak_rss_bytes": peak_rss,
            "budget_checks": checks,
            "failed_budgets": failed,
        }
        persist("result.json", _json_bytes(result_document), "RESULT")
        index = {
            "schema": ARTIFACT_INDEX_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "source_capsule_manifest_sha256": preflight.inputs.source_capsule_manifest_sha256,
            "source_artifact_index_sha256": preflight.inputs.source_artifact_index_sha256,
            "artifacts": dict(sorted(persisted.items())),
            "indexed_artifact_count": len(persisted),
            "indexed_artifact_bytes": persistent_bytes,
        }
        index_payload = _json_bytes(index)
        if (
            persistent_bytes + len(index_payload)
            > config.budgets.maximum_persistent_artifact_bytes
        ):
            raise O1C29RunError("artifact index exceeds persistent budget")
        run.write_artifact("artifact_index.json", index_payload)
        persistent_total = persistent_bytes + len(index_payload)
        metrics = {
            **result_document,
            "artifact_index_sha256": _sha256_bytes(index_payload),
            "persistent_artifact_bytes": persistent_total,
            "operationally_complete": not failed,
        }
        finalized = run.finalize(
            metrics=metrics,
            status="completed" if not failed else "failed",
        )
        print(
            json.dumps(
                {
                    "attempt_id": ATTEMPT_ID,
                    "status": "completed" if not failed else "failed",
                    "path": str(finalized.path),
                    "manifest_sha256": finalized.manifest_sha256,
                    "classification": result_document["classification"],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if not failed else 2
    except Exception as exc:
        try:
            finalized = run.finalize(
                metrics={
                    "schema": RESULT_SCHEMA,
                    "classification": "OPERATIONAL_FAILURE_NO_SCIENTIFIC_CLAIM",
                    "error": f"{type(exc).__name__}: {exc}",
                    "persistent_artifact_bytes_before_failure": persistent_bytes,
                    "source_artifact_bytes_read": preflight.source_accounting.total_bytes,
                    "fresh_targets_consumed": 0,
                    "native_solver_branches": 0,
                    "scientific_entropy_calls": 0,
                    "sibling_reads": 0,
                    "sibling_writes": 0,
                    "mps_calls": 0,
                    "gpu_calls": 0,
                },
                status="failed",
            )
            print(f"failed capsule: {finalized.path}: {exc}", file=sys.stderr)
        except Exception:
            print(f"unfinalized O1C-0029 failure: {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        default="configs/o1c29_stacked_hot_calibration_v1.json",
    )
    parser.add_argument("--preflight", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.preflight:
        report = preflight_o1c29_stacked_hot_calibration(args.config).report
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report.get("status") in {"ready", "prerequisite-pending"} else 2
    return run_capsule_from_config(args.config)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "ATTEMPT_ID",
    "FORMAL_SLUG",
    "LabelArtifactCommitment",
    "O1C29Budgets",
    "O1C29Preflight",
    "O1C29RunConfig",
    "O1C29RunError",
    "ProtocolExecution",
    "SourceReadAccounting",
    "execute_frozen_o1c29_protocol",
    "inspect_o1c22_label_commitment_and_accounting",
    "load_o1c29_stacked_hot_calibration_run_config",
    "preflight_o1c29_stacked_hot_calibration",
    "read_committed_o1c22_label_artifacts",
    "run_capsule_from_config",
]
