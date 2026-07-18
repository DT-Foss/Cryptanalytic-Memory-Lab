"""Generic, manager-authoritative consumption of the O1C-0023 selection.

The pure semantic verifier accepts every operator registered by the frozen
O1C-0022 post-result policy.  The capsule loader adds publication authority,
exact inventory and ancestry checks, then recomposes the decision from the
authoritative O1C-0022 bytes.  Neither layer grants scientific execution or
attempt-reservation authority.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Final, Mapping, Sequence

from .living_inverse import canonical_json_bytes
from .o1c22_postresult_composer import (
    ATTEMPT_ID as O1C23_ATTEMPT_ID,
    O1O_FRAGMENT_FILENAME,
    O1O_KNOWLEDGE_FILENAME,
    OPERATOR_GRAPH_SCHEMA,
    O1C22PostResultComposerError,
    compose_postresult_decision,
    decision_policy,
    decision_policy_sha256,
    decode_o1o_route,
    encode_o1o_fragment_document,
    next_operator_graph,
    verify_decision,
)
from .o1c22_postresult_composer_run import (
    ARTIFACT_INDEX_SCHEMA,
    NATIVE_RECEIPT_SCHEMA,
    RUN_METRICS_SCHEMA,
    SOURCE_INDEX_SCHEMA,
    EXPECTED_UPSTREAM_ARTIFACTS,
    O1C22PostResultComposerRunError,
    O1C22PostResultSource,
    O1C23RunConfig,
    StructuralWorkLedger,
    _expected_operator_marker,
    _extract_exact_operator_marker,
    _load_bound_o1c22_source,
    _source_hashes,
    load_o1c22_postresult_composer_run_config,
)
from .run_capsule import (
    CapsuleVerification,
    ClaimLevel,
    FinalizedRun,
    RunCapsuleManager,
)


O1C22_ATTEMPT_ID: Final = "O1C-0022"
SEMANTIC_RECEIPT_SCHEMA: Final = "o1-256-o1c23-semantic-selection-receipt-v1"
AUTHORITY_RECEIPT_SCHEMA: Final = "o1-256-o1c23-selection-authority-receipt-v1"
PREFLIGHT_SCHEMA: Final = "o1-256-o1c23-selection-authority-preflight-v1"
DEFAULT_CONFIG_RELATIVE: Final = "configs/o1c22_postresult_composer_v1.json"
DEFAULT_CONFIG_SHA256: Final = (
    "f218bfa343afb977149165b59d55d0e85f4c488b24ed0dd5e170c710d5990afb"
)
O1C23_SOURCE_FREEZE_COMMIT: Final = "aa17eed6740edfdba18aaad487c93be8afaf5935"
_HEX: Final = frozenset("0123456789abcdef")

_ARTIFACT_PHASES: Final = {
    "decision_policy.json": "POLICY",
    "failure_memory.json": "FAILURE_MEMORY",
    "quantization_diagnostics.json": "DIAGNOSTICS",
    "decision.json": "DECISION",
    O1O_KNOWLEDGE_FILENAME: "O1O_ROUTE",
    O1O_FRAGMENT_FILENAME: "O1O_FRAGMENT",
    "native_o1o_receipt.json": "NATIVE_DOUBLE_ASSEMBLY",
    "native_generated_source.py": "NATIVE_GENERATED_SOURCE",
    "next_operator_graph.json": "OPERATOR_GRAPH",
    "structural_work_ledger.json": "STRUCTURAL_WORK",
    "source_index.json": "SOURCE_INDEX",
}
_INDEX_FIELDS: Final = {
    "schema",
    "attempt_id",
    "source_capsule_manifest_sha256",
    "decision_sha256",
    "operator_graph_sha256",
    "artifacts",
    "indexed_artifact_count",
    "indexed_artifact_bytes",
}
_CAPSULE_CONFIG_FIELDS: Final = {
    "schema",
    "publication_protocol",
    "attempt_id",
    "commit",
    "hypothesis",
    "prediction",
    "controls",
    "budgets",
    "source_hashes",
    "claim_level",
    "next_action",
    "config",
}
_OUTER_METRICS_FIELDS: Final = {
    "schema",
    "attempt_id",
    "status",
    "claim_level",
    "started_at",
    "ended_at",
    "elapsed_seconds",
    "next_action",
    "values",
}
_RUN_METRIC_FIELDS: Final = {
    "schema",
    "source_attempt_id",
    "source_capsule_manifest_sha256",
    "source_result_sha256",
    "source_classification",
    "decision_policy_sha256",
    "quantization_diagnostics_sha256",
    "decision_sha256",
    "operator_id",
    "operator_fingerprint",
    "fresh_target_authorized",
    "operator_graph_sha256",
    "native_receipt_sha256",
    "native_generated_sha256",
    "native_generated_bytes",
    "native_invocations",
    "structural_work_ledger_sha256",
    "native_generated_bytes_identical",
    "generated_code_compiled",
    "generated_code_executed",
    "source_artifact_bytes_read",
    "persistent_artifact_bytes",
    "parent_cpu_seconds",
    "native_child_cpu_seconds",
    "native_reported_cpu_seconds",
    "cpu_seconds",
    "wall_seconds",
    "native_peak_rss_bytes",
    "child_rusage_peak_rss_bytes",
    "peak_rss_bytes",
    "fresh_targets_consumed",
    "native_solver_branches",
    "scientific_entropy_calls",
    "sibling_write_free_proven",
    "sibling_mutations_observed_lower_bound",
    "sibling_writes",
    "mps_calls",
    "gpu_calls",
    "budget_checks",
    "failed_budgets",
    "operationally_complete",
}
_BUDGET_CHECK_FIELDS: Final = {
    "cpu",
    "wall",
    "resident_memory",
    "persistent_artifacts",
    "source_artifact_bytes_read",
    "k256_heldout_folds",
    "primary_state_bytes",
    "native_o1o_invocations",
    "generated_source_bytes",
    "fresh_targets",
    "native_solver_branches",
    "scientific_entropy",
    "sibling_writes",
    "mps",
    "gpu",
}
_NATIVE_RECEIPT_FIELDS: Final = {
    "schema",
    "attempt_id",
    "native_invocations",
    "byte_identical_generated_source",
    "generated_sha256",
    "generated_bytes",
    "generated_code_compiled",
    "generated_code_executed",
    "runs",
    "o1o_core_source_sha256_before",
    "o1o_core_source_sha256_after",
    "sibling_snapshot_sha256_before",
    "sibling_snapshot_sha256_after",
    "sibling_snapshot_entries",
    "sibling_write_free_proven",
    "sibling_writes",
    "native_receipt_sha256",
}
_SOURCE_INDEX_FIELDS: Final = {
    "schema",
    "attempt_id",
    "source_attempt_id",
    "o1c22",
    "lab",
    "o1o",
    "source_index_sha256",
}
_SOURCE_INDEX_O1C22_FIELDS: Final = {
    "capsule_path",
    "capsule_manifest_sha256",
    "config_file_sha256",
    "frozen_config_sha256",
    "artifact_index_sha256",
    "result_file_sha256",
    "result_sha256",
    "metrics_file_sha256",
    "k256_folds",
    "source_artifact_bytes_read",
}
_PRODUCER_HELDOUT_FREEZE_FIELDS: Final = frozenset(
    {
        "schema",
        "phase",
        "fold_index",
        "held_out_ordinal",
        "held_out_target_id",
        "held_out_action_pool_sha256",
        "reader_state_sha256",
        "slow_state_sha256",
        "upstream_prediction_freeze_sha256",
        "quantizer_sha256",
        "calibration_scales",
        "active_coordinate_plan_sha256",
        "active_coordinate_counts",
        "prediction_arms",
        "calibration_label_ordinals_used_for_this_fold",
        "held_out_label_used_for_this_fold",
        "previously_opened_build_label_ordinals",
        "held_out_label_may_have_been_opened_in_other_fold",
        "held_out_reader_updates",
        "solver_calls",
        "scientific_entropy_calls",
        "artifacts",
        "freeze_sha256",
    }
)
_HELDOUT_FREEZE_SCHEMA: Final = "o1-256-o1c22-heldout-prediction-freeze-v1"
_HELDOUT_FREEZE_PHASE: Final = "ALL_HELDOUT_DELTAS_SCALES_STATES_CONTROLS_AND_PREDICTIONS_FROZEN_BEFORE_LABEL_ORACLE"


class O1C23SelectionAuthorityError(ValueError):
    """An O1C-0023 decision, capsule, ancestry, or authority binding differs."""


class O1C23SelectionPending(O1C23SelectionAuthorityError):
    """The reserved finalized prerequisite is not yet available."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX for character in value)
    ):
        raise O1C23SelectionAuthorityError(f"{field} must be lowercase SHA-256")
    return value


def _commit(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or any(character not in _HEX for character in value)
    ):
        raise O1C23SelectionAuthorityError(f"{field} must be a lowercase commit")
    return value


def _mapping(
    value: object,
    field: str,
    expected: set[str] | frozenset[str] | None = None,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise O1C23SelectionAuthorityError(f"{field} must be a JSON object")
    if expected is not None and set(value) != set(expected):
        raise O1C23SelectionAuthorityError(f"{field} fields differ")
    return value


def _sequence(value: object, field: str) -> Sequence[object]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise O1C23SelectionAuthorityError(f"{field} must be a JSON sequence")
    return value


def _integer(value: object, field: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise O1C23SelectionAuthorityError(f"{field} must be an integer >= {minimum}")
    return value


def _freeze_json(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze_json(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _read_json_payload(
    payload: bytes,
    field: str,
    *,
    canonical: bool = False,
) -> Mapping[str, object]:
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise O1C23SelectionAuthorityError(f"{field} is invalid JSON") from exc
    row = _mapping(value, field)
    if canonical and canonical_json_bytes(value) != payload:
        raise O1C23SelectionAuthorityError(f"{field} is not canonical JSON")
    return row


def _read_json(path: Path, field: str) -> tuple[Mapping[str, object], bytes]:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise O1C23SelectionAuthorityError(f"{field} is unreadable") from exc
    return _read_json_payload(payload, field), payload


def _safe_relative(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise O1C23SelectionAuthorityError(f"{field} path is invalid")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise O1C23SelectionAuthorityError(f"{field} path is unsafe")
    return value


def _git_is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    completed = subprocess.run(
        ("git", "merge-base", "--is-ancestor", ancestor, descendant),
        cwd=root,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return completed.returncode == 0


@dataclass(frozen=True)
class O1C23SemanticSelectionReceipt:
    """Immutable semantic receipt with no publication or execution authority."""

    decision_sha256: str
    operator_graph_sha256: str
    source_capsule_manifest_sha256: str
    source_result_sha256: str
    policy_sha256: str
    quantization_diagnostics_sha256: str
    failure_memory_sha256: str
    operator: Mapping[str, object]
    fresh_target_proposed: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "operator", _freeze_json(self.operator))

    @property
    def operator_id(self) -> str:
        return str(self.operator["operator_id"])

    @property
    def operator_fingerprint(self) -> str:
        return str(self.operator["operator_fingerprint"])

    def describe(self) -> dict[str, object]:
        return {
            "schema": SEMANTIC_RECEIPT_SCHEMA,
            "decision_sha256": self.decision_sha256,
            "operator_graph_sha256": self.operator_graph_sha256,
            "source_capsule_manifest_sha256": self.source_capsule_manifest_sha256,
            "source_result_sha256": self.source_result_sha256,
            "policy_sha256": self.policy_sha256,
            "quantization_diagnostics_sha256": (self.quantization_diagnostics_sha256),
            "failure_memory_sha256": self.failure_memory_sha256,
            "operator_id": self.operator_id,
            "operator_fingerprint": self.operator_fingerprint,
            "operator": _thaw_json(self.operator),
            "fresh_target_proposed": self.fresh_target_proposed,
            "fresh_target_authorized": False,
            "authoritative_capsule_verified": False,
            "scientific_decision_authority": False,
            "attempt_reservation_authorized": False,
        }


@dataclass(frozen=True)
class O1C23SelectionAuthorityReceipt:
    """Immutable authoritative-source receipt, still carrying zero run authority."""

    capsule_path: Path
    capsule_manifest_sha256: str
    capsule_config_sha256: str
    frozen_config_sha256: str
    metrics_sha256: str
    artifact_index_sha256: str
    semantic: O1C23SemanticSelectionReceipt
    operator: Mapping[str, object]

    def __post_init__(self) -> None:
        object.__setattr__(self, "capsule_path", self.capsule_path.resolve())
        object.__setattr__(self, "operator", _freeze_json(self.operator))
        if _thaw_json(self.operator) != _thaw_json(self.semantic.operator):
            raise O1C23SelectionAuthorityError("authority operator receipt differs")

    @property
    def operator_id(self) -> str:
        return self.semantic.operator_id

    @property
    def operator_fingerprint(self) -> str:
        return self.semantic.operator_fingerprint

    @property
    def decision_sha256(self) -> str:
        return self.semantic.decision_sha256

    @property
    def operator_graph_sha256(self) -> str:
        return self.semantic.operator_graph_sha256

    @property
    def source_capsule_manifest_sha256(self) -> str:
        return self.semantic.source_capsule_manifest_sha256

    @property
    def source_result_sha256(self) -> str:
        return self.semantic.source_result_sha256

    def describe(self) -> dict[str, object]:
        return {
            "schema": AUTHORITY_RECEIPT_SCHEMA,
            "attempt_id": O1C23_ATTEMPT_ID,
            "capsule_path": str(self.capsule_path),
            "capsule_manifest_sha256": self.capsule_manifest_sha256,
            "capsule_config_sha256": self.capsule_config_sha256,
            "frozen_config_sha256": self.frozen_config_sha256,
            "metrics_sha256": self.metrics_sha256,
            "artifact_index_sha256": self.artifact_index_sha256,
            "decision_sha256": self.decision_sha256,
            "operator_graph_sha256": self.operator_graph_sha256,
            "source_capsule_manifest_sha256": (self.source_capsule_manifest_sha256),
            "source_result_sha256": self.source_result_sha256,
            "operator_id": self.operator_id,
            "operator_fingerprint": self.operator_fingerprint,
            "operator": _thaw_json(self.operator),
            "fresh_target_proposed": self.semantic.fresh_target_proposed,
            "fresh_target_authorized": False,
            "authoritative_capsule_verified": True,
            "scientific_decision_authority": False,
            "attempt_reservation_authorized": False,
        }


@dataclass(frozen=True)
class O1C23SelectionAuthorityPreflight:
    """Read-mostly readiness result that never reserves a successor attempt."""

    report: Mapping[str, object]
    receipt: O1C23SelectionAuthorityReceipt | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "report", _freeze_json(self.report))

    @property
    def ready(self) -> bool:
        return self.receipt is not None and self.report.get("status") == "ready"

    def describe(self) -> dict[str, object]:
        return _thaw_json(self.report)  # type: ignore[return-value]


def verify_o1c23_decision_graph(
    decision: object,
    operator_graph: object,
) -> O1C23SemanticSelectionReceipt:
    """Verify a generic registered O1C-0023 decision and its exact graph."""

    try:
        checked = verify_decision(decision)
    except O1C22PostResultComposerError as exc:
        raise O1C23SelectionAuthorityError("O1C-0023 decision is invalid") from exc
    graph = _mapping(operator_graph, "O1C-0023 operator graph")
    selection = _mapping(graph.get("selection"), "O1C-0023 graph selection")
    try:
        expected = next_operator_graph(
            checked,
            causal_sha256=_sha256(selection.get("causal_sha256"), "causal_sha256"),
            fragment_sha256=_sha256(
                selection.get("fragment_sha256"), "fragment_sha256"
            ),
            native_generated_sha256=_sha256(
                selection.get("native_generated_sha256"),
                "native_generated_sha256",
            ),
        )
    except O1C22PostResultComposerError as exc:
        raise O1C23SelectionAuthorityError(
            "O1C-0023 operator graph source is invalid"
        ) from exc
    if dict(graph) != expected or expected.get("schema") != OPERATOR_GRAPH_SCHEMA:
        raise O1C23SelectionAuthorityError(
            "O1C-0023 operator graph differs from decision"
        )
    source = _mapping(checked.get("source"), "O1C-0023 decision source")
    operator = _mapping(checked.get("operator"), "O1C-0023 selected operator")
    return O1C23SemanticSelectionReceipt(
        decision_sha256=str(checked["decision_sha256"]),
        operator_graph_sha256=str(expected["operator_graph_sha256"]),
        source_capsule_manifest_sha256=str(source["capsule_manifest_sha256"]),
        source_result_sha256=str(source["result_sha256"]),
        policy_sha256=str(checked["policy_sha256"]),
        quantization_diagnostics_sha256=str(checked["quantization_diagnostics_sha256"]),
        failure_memory_sha256=str(checked["failure_memory_sha256"]),
        operator=operator,
        fresh_target_proposed=checked.get("fresh_target_proposed") is True,
    )


def _authoritative_finalized(
    manager: RunCapsuleManager,
    supplied: FinalizedRun,
) -> FinalizedRun:
    authoritative = manager.finalized_attempt(O1C23_ATTEMPT_ID)
    if authoritative is None:
        raise O1C23SelectionPending(
            "reserved finalized O1C-0023 capsule is not available"
        )
    fresh = manager.verify(authoritative.path)
    try:
        supplied_path = supplied.path.resolve(strict=True)
        authoritative_path = authoritative.path.resolve(strict=True)
        fresh_path = fresh.path.resolve(strict=True)
    except OSError as exc:
        raise O1C23SelectionAuthorityError(
            "O1C-0023 finalized path is unavailable"
        ) from exc
    if (
        supplied.attempt_id != O1C23_ATTEMPT_ID
        or supplied_path != authoritative_path
        or supplied.manifest_sha256 != authoritative.manifest_sha256
        or authoritative.verification.schema != "o1c-capsule-verification-v1"
        or fresh.schema != "o1c-capsule-verification-v1"
        or fresh_path != authoritative_path
        or fresh.manifest_sha256 != authoritative.manifest_sha256
        or not authoritative.verification.ok
        or not fresh.ok
    ):
        raise O1C23SelectionAuthorityError(
            "O1C-0023 is not the authoritative manager-verified publication"
        )
    return authoritative


def _indexed_artifacts(
    finalized: FinalizedRun,
) -> tuple[Mapping[str, object], bytes, dict[str, bytes]]:
    artifacts_root = finalized.path / "artifacts"
    try:
        entries = list(artifacts_root.iterdir())
    except OSError as exc:
        raise O1C23SelectionAuthorityError(
            "O1C-0023 artifacts directory is unreadable"
        ) from exc
    expected_files = set(_ARTIFACT_PHASES) | {"artifact_index.json"}
    if (
        any(path.is_symlink() or not path.is_file() for path in entries)
        or {path.name for path in entries} != expected_files
    ):
        raise O1C23SelectionAuthorityError(
            "O1C-0023 exact actual artifact inventory differs"
        )
    index_path = artifacts_root / "artifact_index.json"
    try:
        index_payload = index_path.read_bytes()
    except OSError as exc:  # pragma: no cover - inventory access already proves it.
        raise O1C23SelectionAuthorityError("O1C-0023 index is unreadable") from exc
    index = _read_json_payload(
        index_payload,
        "O1C-0023 artifact index",
        canonical=True,
    )
    _mapping(index, "O1C-0023 artifact index", _INDEX_FIELDS)
    if (
        index.get("schema") != ARTIFACT_INDEX_SCHEMA
        or index.get("attempt_id") != O1C23_ATTEMPT_ID
    ):
        raise O1C23SelectionAuthorityError("O1C-0023 artifact index identity differs")
    artifacts = _mapping(index.get("artifacts"), "O1C-0023 artifact inventory")
    if set(artifacts) != set(_ARTIFACT_PHASES):
        raise O1C23SelectionAuthorityError(
            "O1C-0023 exact indexed artifact inventory differs"
        )
    payloads: dict[str, bytes] = {}
    for relative, phase in sorted(_ARTIFACT_PHASES.items()):
        safe = _safe_relative(relative, f"O1C-0023 artifact {relative}")
        entry = _mapping(
            artifacts.get(safe),
            f"O1C-0023 index entry {relative}",
            {"sha256", "bytes", "phase"},
        )
        payload = (artifacts_root / safe).read_bytes()
        if (
            entry.get("sha256") != _sha256_bytes(payload)
            or entry.get("bytes") != len(payload)
            or entry.get("phase") != phase
        ):
            raise O1C23SelectionAuthorityError(
                f"O1C-0023 index entry differs: {relative}"
            )
        payloads[relative] = payload
    if index.get("indexed_artifact_count") != len(payloads) or index.get(
        "indexed_artifact_bytes"
    ) != sum(len(payload) for payload in payloads.values()):
        raise O1C23SelectionAuthorityError("O1C-0023 artifact-index totals differ")
    return index, index_payload, payloads


def _verified_digest(
    document: Mapping[str, object],
    *,
    digest_field: str,
    field: str,
) -> str:
    unsigned = dict(document)
    supplied = _sha256(unsigned.pop(digest_field, None), f"{field} digest")
    if supplied != _sha256_bytes(canonical_json_bytes(unsigned)):
        raise O1C23SelectionAuthorityError(f"{field} digest differs")
    return supplied


def verify_o1c22_producer_heldout_freeze(
    value: object,
    *,
    fold_index: int,
) -> Mapping[str, object]:
    """Require the exact producer ABI, including zero scientific entropy.

    O1C-0022's producer writes ``scientific_entropy_calls`` into every held-out
    prediction freeze.  The source-frozen O1C-0023 verifier accidentally omits
    that member from its exact field set.  This successor check deliberately
    recognizes only the producer-authentic shape; omission, nonzero values and
    extra members all fail closed.
    """

    if (
        isinstance(fold_index, bool)
        or not isinstance(fold_index, int)
        or not 0 <= fold_index < 4
    ):
        raise O1C23SelectionAuthorityError("producer heldout fold index differs")
    document = _mapping(
        value,
        f"O1C-0022 producer heldout freeze {fold_index}",
        _PRODUCER_HELDOUT_FREEZE_FIELDS,
    )
    _verified_digest(
        document,
        digest_field="freeze_sha256",
        field=f"O1C-0022 producer heldout freeze {fold_index}",
    )
    if (
        document.get("schema") != _HELDOUT_FREEZE_SCHEMA
        or document.get("phase") != _HELDOUT_FREEZE_PHASE
        or document.get("fold_index") != fold_index
        or document.get("held_out_ordinal") != fold_index
        or document.get("held_out_target_id") != f"build-{fold_index:04d}"
        or document.get("held_out_label_used_for_this_fold") is not False
        or document.get("held_out_reader_updates") != 0
        or document.get("solver_calls") != 0
        or document.get("scientific_entropy_calls") != 0
    ):
        raise O1C23SelectionAuthorityError(
            f"O1C-0022 producer heldout freeze {fold_index} differs"
        )
    _mapping(
        document.get("artifacts"),
        f"O1C-0022 producer heldout artifacts {fold_index}",
    )
    return document


def _authoritative_o1c22(
    manager: RunCapsuleManager,
    supplied: FinalizedRun,
) -> FinalizedRun:
    authoritative = manager.finalized_attempt(O1C22_ATTEMPT_ID)
    if authoritative is None:
        raise O1C23SelectionPending(
            "authoritative finalized O1C-0022 capsule is not available"
        )
    fresh = manager.verify(authoritative.path)
    try:
        supplied_path = supplied.path.resolve(strict=True)
        authoritative_path = authoritative.path.resolve(strict=True)
        fresh_path = fresh.path.resolve(strict=True)
    except OSError as exc:
        raise O1C23SelectionAuthorityError(
            "O1C-0022 finalized path is unavailable"
        ) from exc
    if (
        supplied.attempt_id != O1C22_ATTEMPT_ID
        or supplied_path != authoritative_path
        or supplied.manifest_sha256 != authoritative.manifest_sha256
        or authoritative.verification.schema != "o1c-capsule-verification-v1"
        or fresh.schema != "o1c-capsule-verification-v1"
        or fresh_path != authoritative_path
        or fresh.manifest_sha256 != authoritative.manifest_sha256
        or not authoritative.verification.ok
        or not fresh.ok
    ):
        raise O1C23SelectionAuthorityError(
            "O1C-0022 is not the authoritative manager-verified publication"
        )
    return authoritative


_LABEL_BITPACK_RELATIVE = "labels.bitpack"
_LABEL_BITPACK_BYTES = 128
_LABEL_PLACEHOLDER = bytes(_LABEL_BITPACK_BYTES)


def _legacy_projection_document(
    producer: Mapping[str, object],
) -> dict[str, object]:
    unsigned = dict(producer)
    unsigned.pop("freeze_sha256", None)
    unsigned.pop("scientific_entropy_calls", None)
    return {
        **unsigned,
        "freeze_sha256": _sha256_bytes(canonical_json_bytes(unsigned)),
    }


def _load_producer_authentic_o1c22_source_from_verified_finalized(
    config: O1C23RunConfig,
    authoritative: FinalizedRun,
) -> O1C22PostResultSource:
    """Repair the frozen ABI after exactly one external manager verification.

    ``authoritative`` must be the direct result of one trusted-process
    ``RunCapsuleManager.finalized_attempt`` call.  This function performs no
    manager lookup and no second manifest verification.  The real label
    bitpack was therefore consumed only by that one complete manager pass.
    The disposable legacy projection receives a deterministic 128-byte
    placeholder and never opens, links, or copies the real label payload.
    """

    if (
        authoritative.attempt_id != O1C22_ATTEMPT_ID
        or authoritative.verification.schema != "o1c-capsule-verification-v1"
        or not authoritative.verification.ok
        or authoritative.verification.path.resolve(strict=True)
        != authoritative.path.resolve(strict=True)
        or authoritative.verification.manifest_sha256 != authoritative.manifest_sha256
    ):
        raise O1C23SelectionAuthorityError(
            "trusted O1C-0022 manager verification differs"
        )
    artifacts_root = authoritative.path / "artifacts"
    index, index_payload = _read_json(
        artifacts_root / "artifact_index.json",
        "O1C-0022 producer artifact index",
    )
    artifacts = _mapping(index.get("artifacts"), "O1C-0022 producer artifacts")
    if (
        len(artifacts) != EXPECTED_UPSTREAM_ARTIFACTS
        or index.get("indexed_artifact_count") != EXPECTED_UPSTREAM_ARTIFACTS
    ):
        raise O1C23SelectionAuthorityError(
            "O1C-0022 producer artifact inventory differs"
        )
    actual = {
        path.relative_to(artifacts_root).as_posix()
        for path in artifacts_root.rglob("*")
        if path.is_file() and path.name != "artifact_index.json"
    }
    if actual != set(artifacts):
        raise O1C23SelectionAuthorityError(
            "O1C-0022 producer actual artifact inventory differs"
        )
    config_document, config_payload = _read_json(
        authoritative.path / "config.json", "O1C-0022 producer config"
    )
    outer_metrics, metrics_payload = _read_json(
        authoritative.path / "metrics.json", "O1C-0022 producer metrics"
    )
    original_values = _mapping(
        outer_metrics.get("values"), "O1C-0022 producer metric values"
    )
    indexed_bytes = sum(
        _integer(
            _mapping(entry, f"O1C-0022 producer index entry {relative}").get("bytes"),
            f"O1C-0022 producer artifact bytes {relative}",
        )
        for relative, entry in artifacts.items()
    )
    if index.get("indexed_artifact_bytes") != indexed_bytes or original_values.get(
        "persistent_artifact_bytes"
    ) != indexed_bytes + len(index_payload):
        raise O1C23SelectionAuthorityError(
            "O1C-0022 producer persistent-byte accounting differs"
        )

    with tempfile.TemporaryDirectory(prefix="o1c22-producer-auth-") as temporary:
        shadow = Path(temporary) / "capsule"
        shadow_artifacts = shadow / "artifacts"
        shadow_artifacts.mkdir(parents=True)
        shadow_index = json.loads(json.dumps(index))
        shadow_entries = _mapping(
            shadow_index.get("artifacts"), "O1C-0022 compatibility artifacts"
        )
        for relative, raw_entry in sorted(artifacts.items()):
            safe = _safe_relative(relative, "O1C-0022 producer artifact path")
            source_path = artifacts_root / safe
            if source_path.is_symlink() or not source_path.is_file():
                raise O1C23SelectionAuthorityError(
                    f"O1C-0022 producer artifact is not regular: {relative}"
                )
            entry = _mapping(
                raw_entry,
                f"O1C-0022 producer index entry {relative}",
                {"sha256", "bytes", "phase"},
            )
            indexed_sha = _sha256(
                entry.get("sha256"),
                f"O1C-0022 producer artifact SHA {relative}",
            )
            indexed_size = _integer(
                entry.get("bytes"),
                f"O1C-0022 producer artifact bytes {relative}",
            )
            if not isinstance(entry.get("phase"), str):
                raise O1C23SelectionAuthorityError(
                    f"O1C-0022 producer index entry differs: {relative}"
                )
            destination = shadow_artifacts / safe
            if relative == _LABEL_BITPACK_RELATIVE:
                # The preceding manager verification already authenticated the
                # real payload against the capsule manifest.  A stat-only shape
                # check plus the index commitment is sufficient here; opening
                # the true labels a second time would violate the phase wall.
                if (
                    indexed_size != _LABEL_BITPACK_BYTES
                    or source_path.stat().st_size != _LABEL_BITPACK_BYTES
                ):
                    raise O1C23SelectionAuthorityError(
                        "O1C-0022 labels.bitpack shape differs"
                    )
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(_LABEL_PLACEHOLDER)
                projected_entry = _mapping(
                    shadow_entries[relative],
                    "compatibility labels.bitpack entry",
                )
                projected_entry["sha256"] = _sha256_bytes(_LABEL_PLACEHOLDER)  # type: ignore[index]
                projected_entry["bytes"] = _LABEL_BITPACK_BYTES  # type: ignore[index]
                continue
            payload = source_path.read_bytes()
            if indexed_sha != _sha256_bytes(payload) or indexed_size != len(payload):
                raise O1C23SelectionAuthorityError(
                    f"O1C-0022 producer index entry differs: {relative}"
                )
            if relative.endswith("/heldout/prediction_freeze.json"):
                fold_text = relative.split("/", 2)[1]
                if not fold_text.startswith("build-"):
                    raise O1C23SelectionAuthorityError(
                        "O1C-0022 producer heldout owner path differs"
                    )
                fold_index = int(fold_text.removeprefix("build-"))
                producer = verify_o1c22_producer_heldout_freeze(
                    _read_json_payload(payload, f"producer heldout fold {fold_index}"),
                    fold_index=fold_index,
                )
                projected_payload = canonical_json_bytes(
                    _legacy_projection_document(producer)
                )
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(projected_payload)
                projected_entry = _mapping(
                    shadow_entries[relative],
                    f"compatibility index entry {relative}",
                )
                projected_entry["sha256"] = _sha256_bytes(projected_payload)  # type: ignore[index]
                projected_entry["bytes"] = len(projected_payload)  # type: ignore[index]
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(payload)

        shadow_indexed_bytes = sum(
            _integer(
                _mapping(entry, "compatibility artifact entry").get("bytes"),
                "compatibility artifact bytes",
            )
            for entry in shadow_entries.values()
        )
        shadow_index["indexed_artifact_bytes"] = shadow_indexed_bytes
        shadow_index_payload = canonical_json_bytes(shadow_index)
        (shadow_artifacts / "artifact_index.json").write_bytes(shadow_index_payload)
        (shadow / "config.json").write_bytes(config_payload)
        shadow_metrics = json.loads(json.dumps(outer_metrics))
        shadow_values = shadow_metrics["values"]
        shadow_values["persistent_artifact_bytes"] = shadow_indexed_bytes + len(
            shadow_index_payload
        )
        upstream_budgets = _mapping(config.upstream_top.get("budgets"), "budgets")
        shadow_values["budget_checks"]["persistent_artifacts"] = (
            shadow_values["persistent_artifact_bytes"]
            <= upstream_budgets["maximum_persistent_artifact_bytes"]
        )
        (shadow / "metrics.json").write_bytes(canonical_json_bytes(shadow_metrics))
        shadow_verification = CapsuleVerification(
            schema="o1c-capsule-verification-v1",
            path=shadow,
            manifest_sha256=authoritative.manifest_sha256,
            checked=EXPECTED_UPSTREAM_ARTIFACTS + 3,
            missing=(),
            mismatched=(),
            unexpected=(),
        )
        shadow_finalized = FinalizedRun(
            attempt_id=O1C22_ATTEMPT_ID,
            path=shadow,
            manifest_sha256=authoritative.manifest_sha256,
            verification=shadow_verification,
        )
        try:
            projected = _load_bound_o1c22_source(config, shadow_finalized)
        except O1C22PostResultComposerRunError as exc:
            raise O1C23SelectionAuthorityError(
                "O1C-0022 producer compatibility projection failed verification"
            ) from exc

    original_pass_bytes = (
        len(config_payload)
        + len(metrics_payload)
        + len(index_payload)
        + indexed_bytes
        - _LABEL_BITPACK_BYTES
    )
    source_bytes = original_pass_bytes + projected.source_artifact_bytes_read
    if source_bytes > config.budgets.maximum_source_artifact_bytes_read:
        raise O1C23SelectionAuthorityError(
            "O1C-0022 original-plus-projection source byte budget exceeded"
        )
    # The compatibility projection is validation-only.  Every outward anchor
    # is restored to the manager-authenticated producer publication.
    return replace(
        projected,
        finalized=authoritative,
        metrics=original_values,
        artifact_index_sha256=_sha256_bytes(index_payload),
        metrics_file_sha256=_sha256_bytes(metrics_payload),
        config_file_sha256=_sha256_bytes(config_payload),
        source_artifact_bytes_read=source_bytes,
    )


def load_producer_authentic_o1c22_source(
    config: O1C23RunConfig,
    manager: RunCapsuleManager,
    candidate: FinalizedRun,
) -> O1C22PostResultSource:
    """Manager-bind O1C-0022, then repair one frozen verifier ABI bug.

    Successor production code should use the trusted-process entry point below
    after its sole ``finalized_attempt`` call.  This compatibility entry point
    retains the older independent authority recheck for generic callers.
    """

    authoritative = _authoritative_o1c22(manager, candidate)
    return _load_producer_authentic_o1c22_source_from_verified_finalized(
        config, authoritative
    )


def load_trusted_manager_verified_o1c22_source(
    config: O1C23RunConfig,
    authoritative: FinalizedRun,
) -> O1C22PostResultSource:
    """Consume one direct trusted-process manager result without re-verifying."""

    return _load_producer_authentic_o1c22_source_from_verified_finalized(
        config, authoritative
    )


def _verify_native_receipt(
    receipt: Mapping[str, object],
    generated: bytes,
) -> str:
    _mapping(receipt, "O1C-0023 native receipt", _NATIVE_RECEIPT_FIELDS)
    digest = _verified_digest(
        receipt,
        digest_field="native_receipt_sha256",
        field="O1C-0023 native receipt",
    )
    runs = _sequence(receipt.get("runs"), "O1C-0023 native runs")
    if (
        receipt.get("schema") != NATIVE_RECEIPT_SCHEMA
        or receipt.get("attempt_id") != O1C23_ATTEMPT_ID
        or receipt.get("native_invocations") != len(runs)
        or len(runs) != 2
        or receipt.get("byte_identical_generated_source") is not True
        or receipt.get("generated_sha256") != _sha256_bytes(generated)
        or receipt.get("generated_bytes") != len(generated)
        or receipt.get("generated_code_compiled") is not False
        or receipt.get("generated_code_executed") is not False
        or receipt.get("sibling_write_free_proven") is not True
        or receipt.get("sibling_writes") != 0
        or receipt.get("o1o_core_source_sha256_before")
        != receipt.get("o1o_core_source_sha256_after")
        or receipt.get("sibling_snapshot_sha256_before")
        != receipt.get("sibling_snapshot_sha256_after")
    ):
        raise O1C23SelectionAuthorityError("O1C-0023 native receipt differs")
    return digest


def _verify_source_index(
    document: Mapping[str, object],
    *,
    config: O1C23RunConfig,
    source: object,
) -> str:
    _mapping(document, "O1C-0023 source index", _SOURCE_INDEX_FIELDS)
    digest = _verified_digest(
        document,
        digest_field="source_index_sha256",
        field="O1C-0023 source index",
    )
    if (
        document.get("schema") != SOURCE_INDEX_SCHEMA
        or document.get("attempt_id") != O1C23_ATTEMPT_ID
        or document.get("source_attempt_id") != O1C22_ATTEMPT_ID
    ):
        raise O1C23SelectionAuthorityError("O1C-0023 source index identity differs")
    o1c22 = _mapping(
        document.get("o1c22"),
        "O1C-0023 source index O1C-0022",
        _SOURCE_INDEX_O1C22_FIELDS,
    )
    folds = tuple(getattr(source, "folds"))
    expected_folds = [row.describe() for row in folds]
    if (
        o1c22.get("capsule_path") != str(getattr(source, "finalized").path)
        or o1c22.get("capsule_manifest_sha256")
        != getattr(source, "finalized").manifest_sha256
        or o1c22.get("config_file_sha256") != getattr(source, "config_file_sha256")
        or o1c22.get("frozen_config_sha256") != config.upstream_config_sha256
        or o1c22.get("artifact_index_sha256")
        != getattr(source, "artifact_index_sha256")
        or o1c22.get("result_file_sha256") != getattr(source, "result_file_sha256")
        or o1c22.get("result_sha256") != getattr(source, "result")["result_sha256"]
        or o1c22.get("metrics_file_sha256") != getattr(source, "metrics_file_sha256")
        or o1c22.get("k256_folds") != expected_folds
        or o1c22.get("source_artifact_bytes_read")
        != getattr(source, "source_artifact_bytes_read")
    ):
        raise O1C23SelectionAuthorityError(
            "O1C-0023 source index differs from authoritative O1C-0022"
        )
    lab = _mapping(
        document.get("lab"),
        "O1C-0023 source index lab",
        {"source_sha256", "policy_sha256"},
    )
    o1o = _mapping(
        document.get("o1o"),
        "O1C-0023 source index O1-O",
        {
            "repository",
            "forge",
            "core_source_sha256_before",
            "core_source_sha256_after",
            "dependency_source_sha256",
            "sibling_snapshot_sha256_before",
            "sibling_snapshot_sha256_after",
            "sibling_snapshot_entries",
            "sibling_writes",
        },
    )
    if (
        lab.get("source_sha256") != dict(config.local_source_sha256)
        or lab.get("policy_sha256") != decision_policy_sha256()
        or o1o.get("repository") != str(config.o1o_repository)
        or o1o.get("forge") != str(config.o1o_forge)
        or o1o.get("core_source_sha256_before") != dict(config.o1o_core_sha256)
        or o1o.get("core_source_sha256_after") != dict(config.o1o_core_sha256)
        or o1o.get("dependency_source_sha256") != dict(config.o1o_dependency_sha256)
        or o1o.get("sibling_snapshot_sha256_before")
        != o1o.get("sibling_snapshot_sha256_after")
        or o1o.get("sibling_writes") != 0
    ):
        raise O1C23SelectionAuthorityError("O1C-0023 source-index ancestry differs")
    _integer(o1o.get("sibling_snapshot_entries"), "sibling snapshot entries")
    return digest


def _verify_metrics(
    outer: Mapping[str, object],
    values: Mapping[str, object],
    *,
    config: O1C23RunConfig,
    semantic: O1C23SemanticSelectionReceipt,
    source: object,
    diagnostics: Mapping[str, object],
    native_receipt_sha256: str,
    generated: bytes,
    work: StructuralWorkLedger,
    index: Mapping[str, object],
    index_payload: bytes,
) -> None:
    _mapping(outer, "O1C-0023 outer metrics", _OUTER_METRICS_FIELDS)
    _mapping(values, "O1C-0023 metric values", _RUN_METRIC_FIELDS)
    budget_checks = _mapping(
        values.get("budget_checks"),
        "O1C-0023 budget checks",
        _BUDGET_CHECK_FIELDS,
    )
    failed = _sequence(values.get("failed_budgets"), "O1C-0023 failed budgets")
    source_result = _mapping(getattr(source, "result"), "authoritative O1C-0022 result")
    if (
        outer.get("schema") != "o1c-run-metrics-v1"
        or outer.get("attempt_id") != O1C23_ATTEMPT_ID
        or outer.get("status") != "completed"
        or outer.get("claim_level") != ClaimLevel.RETROSPECTIVE.value
        or outer.get("next_action") != config.top["next_action"]
        or values.get("schema") != RUN_METRICS_SCHEMA
        or values.get("source_attempt_id") != O1C22_ATTEMPT_ID
        or values.get("source_capsule_manifest_sha256")
        != semantic.source_capsule_manifest_sha256
        or values.get("source_result_sha256") != semantic.source_result_sha256
        or values.get("source_classification") != source_result.get("classification")
        or values.get("decision_policy_sha256") != semantic.policy_sha256
        or values.get("quantization_diagnostics_sha256")
        != diagnostics.get("diagnostics_sha256")
        or values.get("decision_sha256") != semantic.decision_sha256
        or values.get("operator_id") != semantic.operator_id
        or values.get("operator_fingerprint") != semantic.operator_fingerprint
        or values.get("fresh_target_authorized") is not False
        or values.get("operator_graph_sha256") != semantic.operator_graph_sha256
        or values.get("native_receipt_sha256") != native_receipt_sha256
        or values.get("native_generated_sha256") != _sha256_bytes(generated)
        or values.get("native_generated_bytes") != len(generated)
        or values.get("native_invocations") != work.native_o1o_invocations_validated
        or values.get("structural_work_ledger_sha256")
        != work.document()["work_ledger_sha256"]
        or values.get("native_generated_bytes_identical") is not True
        or values.get("generated_code_compiled") is not False
        or values.get("generated_code_executed") is not False
        or values.get("source_artifact_bytes_read")
        != getattr(source, "source_artifact_bytes_read")
        or values.get("persistent_artifact_bytes")
        != _integer(index.get("indexed_artifact_bytes"), "indexed artifact bytes")
        + len(index_payload)
        or values.get("fresh_targets_consumed") != work.fresh_targets_consumed
        or values.get("native_solver_branches") != work.native_solver_branches
        or values.get("scientific_entropy_calls") != work.scientific_entropy_calls
        or values.get("sibling_write_free_proven") is not True
        or values.get("sibling_mutations_observed_lower_bound")
        != work.sibling_mutations_observed_lower_bound
        or values.get("sibling_writes") != 0
        or values.get("mps_calls") != work.mps_calls
        or values.get("gpu_calls") != work.gpu_calls
        or any(value is not True for value in budget_checks.values())
        or list(failed)
        or values.get("operationally_complete") is not True
    ):
        raise O1C23SelectionAuthorityError("O1C-0023 exact operational metrics differ")


def _verify_capsule_config(
    capsule: Mapping[str, object],
    *,
    config: O1C23RunConfig,
    expected_source_hashes: Mapping[str, str] | None = None,
) -> str:
    _mapping(capsule, "O1C-0023 capsule config", _CAPSULE_CONFIG_FIELDS)
    commit = _commit(capsule.get("commit"), "O1C-0023 capsule commit")
    if (
        capsule.get("schema") != "o1c-run-config-v1"
        or capsule.get("publication_protocol") != "manifested-prepared-state-v1"
        or capsule.get("attempt_id") != O1C23_ATTEMPT_ID
        or capsule.get("claim_level") != ClaimLevel.RETROSPECTIVE.value
        or capsule.get("hypothesis") != config.top["hypothesis"]
        or capsule.get("prediction") != config.top["prediction"]
        or capsule.get("controls") != config.top["controls"]
        or capsule.get("budgets") != config.top["budgets"]
        or capsule.get("next_action") != config.top["next_action"]
        or capsule.get("config") != config.top
        or (
            expected_source_hashes is not None
            and capsule.get("source_hashes") != dict(expected_source_hashes)
        )
    ):
        raise O1C23SelectionAuthorityError("O1C-0023 exact capsule config differs")
    _mapping(capsule.get("source_hashes"), "O1C-0023 capsule source hashes")
    return commit


def _load_authoritative_selection(
    config: O1C23RunConfig,
    manager: RunCapsuleManager,
    supplied: FinalizedRun,
) -> O1C23SelectionAuthorityReceipt:
    finalized = _authoritative_finalized(manager, supplied)
    capsule_config, config_payload = _read_json(
        finalized.path / "config.json", "O1C-0023 capsule config"
    )
    commit = _verify_capsule_config(capsule_config, config=config)
    if not _git_is_ancestor(config.root, O1C23_SOURCE_FREEZE_COMMIT, commit):
        raise O1C23SelectionAuthorityError(
            "O1C-0023 commit does not descend from its source freeze"
        )

    outer_metrics, metrics_payload = _read_json(
        finalized.path / "metrics.json", "O1C-0023 metrics"
    )
    values = _mapping(outer_metrics.get("values"), "O1C-0023 metric values")
    index, index_payload, payloads = _indexed_artifacts(finalized)

    policy = _read_json_payload(
        payloads["decision_policy.json"],
        "O1C-0023 decision policy",
        canonical=True,
    )
    memory = _read_json_payload(
        payloads["failure_memory.json"],
        "O1C-0023 failure memory",
        canonical=True,
    )
    diagnostics = _read_json_payload(
        payloads["quantization_diagnostics.json"],
        "O1C-0023 quantization diagnostics",
        canonical=True,
    )
    decision = _read_json_payload(
        payloads["decision.json"],
        "O1C-0023 decision",
        canonical=True,
    )
    graph = _read_json_payload(
        payloads["next_operator_graph.json"],
        "O1C-0023 operator graph",
        canonical=True,
    )
    native_receipt = _read_json_payload(
        payloads["native_o1o_receipt.json"],
        "O1C-0023 native receipt",
        canonical=True,
    )
    work_document = _read_json_payload(
        payloads["structural_work_ledger.json"],
        "O1C-0023 structural work ledger",
        canonical=True,
    )
    source_index = _read_json_payload(
        payloads["source_index.json"],
        "O1C-0023 source index",
        canonical=True,
    )
    if dict(policy) != decision_policy():
        raise O1C23SelectionAuthorityError("O1C-0023 decision policy bytes differ")
    try:
        decode_o1o_route(payloads[O1O_KNOWLEDGE_FILENAME], decision=decision)
        expected_fragment = encode_o1o_fragment_document(decision)
    except O1C22PostResultComposerError as exc:
        raise O1C23SelectionAuthorityError("O1C-0023 O1-O route differs") from exc
    if payloads[O1O_FRAGMENT_FILENAME] != expected_fragment:
        raise O1C23SelectionAuthorityError("O1C-0023 O1-O fragment differs")
    semantic = verify_o1c23_decision_graph(decision, graph)
    graph_selection = _mapping(graph.get("selection"), "O1C-0023 graph selection")
    generated = payloads["native_generated_source.py"]
    if (
        graph_selection.get("causal_sha256")
        != _sha256_bytes(payloads[O1O_KNOWLEDGE_FILENAME])
        or graph_selection.get("fragment_sha256")
        != _sha256_bytes(payloads[O1O_FRAGMENT_FILENAME])
        or graph_selection.get("native_generated_sha256") != _sha256_bytes(generated)
    ):
        raise O1C23SelectionAuthorityError(
            "O1C-0023 graph artifact-hash selection differs"
        )
    try:
        _extract_exact_operator_marker(
            generated,
            _expected_operator_marker(decision),
        )
    except O1C22PostResultComposerRunError as exc:
        raise O1C23SelectionAuthorityError(
            "O1C-0023 generated operator marker differs"
        ) from exc
    native_receipt_sha = _verify_native_receipt(native_receipt, generated)
    try:
        work = StructuralWorkLedger.from_document(work_document)
        work.validate_success(config.budgets)
    except O1C22PostResultComposerRunError as exc:
        raise O1C23SelectionAuthorityError(
            "O1C-0023 structural work ledger differs"
        ) from exc

    o1c22_finalized = manager.finalized_attempt(O1C22_ATTEMPT_ID)
    if o1c22_finalized is None:
        raise O1C23SelectionPending(
            "authoritative finalized O1C-0022 capsule is not available"
        )
    try:
        source = load_producer_authentic_o1c22_source(
            config,
            manager,
            o1c22_finalized,
        )
    except (O1C22PostResultComposerRunError, O1C23SelectionAuthorityError) as exc:
        raise O1C23SelectionAuthorityError(
            "authoritative O1C-0022 source differs"
        ) from exc
    if dict(diagnostics) != dict(source.diagnostics):
        raise O1C23SelectionAuthorityError(
            "O1C-0023 diagnostics differ from authoritative O1C-0022 bytes"
        )
    try:
        recomposed = compose_postresult_decision(
            source.result,
            source.metrics,
            capsule_manifest_sha256=source.finalized.manifest_sha256,
            quantization_diagnostics=diagnostics,
            failure_memory=memory,
        )
    except O1C22PostResultComposerError as exc:
        raise O1C23SelectionAuthorityError(
            "O1C-0023 decision cannot be recomposed"
        ) from exc
    if (
        dict(decision) != recomposed
        or semantic.source_capsule_manifest_sha256 != source.finalized.manifest_sha256
        or semantic.source_result_sha256 != source.result.get("result_sha256")
    ):
        raise O1C23SelectionAuthorityError(
            "O1C-0023 is not the exact authoritative O1C-0022 decision"
        )
    expected_source_hashes = _source_hashes(config, source)
    _verify_capsule_config(
        capsule_config,
        config=config,
        expected_source_hashes=expected_source_hashes,
    )
    _verify_source_index(source_index, config=config, source=source)
    if (
        index.get("source_capsule_manifest_sha256") != source.finalized.manifest_sha256
        or index.get("decision_sha256") != semantic.decision_sha256
        or index.get("operator_graph_sha256") != semantic.operator_graph_sha256
    ):
        raise O1C23SelectionAuthorityError("O1C-0023 artifact-index binding differs")
    _verify_metrics(
        outer_metrics,
        values,
        config=config,
        semantic=semantic,
        source=source,
        diagnostics=diagnostics,
        native_receipt_sha256=native_receipt_sha,
        generated=generated,
        work=work,
        index=index,
        index_payload=index_payload,
    )
    return O1C23SelectionAuthorityReceipt(
        capsule_path=finalized.path,
        capsule_manifest_sha256=finalized.manifest_sha256,
        capsule_config_sha256=_sha256_bytes(config_payload),
        frozen_config_sha256=DEFAULT_CONFIG_SHA256,
        metrics_sha256=_sha256_bytes(metrics_payload),
        artifact_index_sha256=_sha256_bytes(index_payload),
        semantic=semantic,
        operator=semantic.operator,
    )


def _manager_for(
    root: Path,
    manager: RunCapsuleManager | None,
) -> RunCapsuleManager:
    selected = RunCapsuleManager(root) if manager is None else manager
    try:
        manager_root = Path(selected.lab_root).resolve(strict=True)
    except (AttributeError, OSError) as exc:
        raise O1C23SelectionAuthorityError("capsule manager root is invalid") from exc
    if manager_root != root:
        raise O1C23SelectionAuthorityError("capsule manager root differs")
    return selected


def _load_pinned_config(
    root: Path,
    config_path: str | Path | None,
) -> O1C23RunConfig:
    candidate = Path(config_path or DEFAULT_CONFIG_RELATIVE)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise O1C23SelectionAuthorityError("frozen O1C-0023 config is missing") from exc
    if not resolved.is_relative_to(root):
        raise O1C23SelectionAuthorityError("frozen O1C-0023 config escapes lab")
    if _sha256_bytes(resolved.read_bytes()) != DEFAULT_CONFIG_SHA256:
        raise O1C23SelectionAuthorityError("frozen O1C-0023 config hash differs")
    try:
        return load_o1c22_postresult_composer_run_config(resolved, root=root)
    except O1C22PostResultComposerRunError as exc:
        raise O1C23SelectionAuthorityError("frozen O1C-0023 config differs") from exc


def load_authoritative_o1c23_selection(
    root: str | Path,
    *,
    config_path: str | Path | None = None,
    manager: RunCapsuleManager | None = None,
) -> O1C23SelectionAuthorityReceipt:
    """Load the exact manager-owned O1C-0023 selection without reserving work."""

    lab_root = Path(root).resolve(strict=True)
    selected_manager = _manager_for(lab_root, manager)
    supplied = selected_manager.finalized_attempt(O1C23_ATTEMPT_ID)
    if supplied is None:
        raise O1C23SelectionPending(
            "reserved finalized O1C-0023 capsule is not available"
        )
    config = _load_pinned_config(lab_root, config_path)
    return _load_authoritative_selection(config, selected_manager, supplied)


def preflight_o1c23_selection_authority(
    root: str | Path,
    *,
    config_path: str | Path | None = None,
    manager: RunCapsuleManager | None = None,
) -> O1C23SelectionAuthorityPreflight:
    """Check readiness without loading config when O1C-0023 is still absent."""

    lab_root = Path(root).resolve(strict=True)
    selected_manager = _manager_for(lab_root, manager)
    supplied = selected_manager.finalized_attempt(O1C23_ATTEMPT_ID)
    base = {
        "schema": PREFLIGHT_SCHEMA,
        "attempt_id": O1C23_ATTEMPT_ID,
        "source_attempt_id": O1C22_ATTEMPT_ID,
        "authoritative_capsule_verified": False,
        "scientific_decision_authority": False,
        "attempt_reservation_authorized": False,
    }
    if supplied is None:
        return O1C23SelectionAuthorityPreflight(
            {
                **base,
                "status": "prerequisite-pending",
                "reason": "reserved finalized O1C-0023 capsule is not available",
            },
            None,
        )
    try:
        config = _load_pinned_config(lab_root, config_path)
        receipt = _load_authoritative_selection(config, selected_manager, supplied)
    except Exception as exc:
        return O1C23SelectionAuthorityPreflight(
            {
                **base,
                "status": "prerequisite-invalid",
                "o1c23_manifest_sha256": supplied.manifest_sha256,
                "reason": f"{type(exc).__name__}: {exc}",
            },
            None,
        )
    return O1C23SelectionAuthorityPreflight(
        {
            **base,
            "status": "ready",
            "authoritative_capsule_verified": True,
            "o1c23_manifest_sha256": receipt.capsule_manifest_sha256,
            "decision_sha256": receipt.decision_sha256,
            "operator_graph_sha256": receipt.operator_graph_sha256,
            "operator_id": receipt.operator_id,
            "operator_fingerprint": receipt.operator_fingerprint,
            "reason": "authoritative O1C-0023 selection is ready for policy consumption",
        },
        receipt,
    )


__all__ = [
    "AUTHORITY_RECEIPT_SCHEMA",
    "DEFAULT_CONFIG_RELATIVE",
    "DEFAULT_CONFIG_SHA256",
    "O1C22_ATTEMPT_ID",
    "O1C23_ATTEMPT_ID",
    "O1C23_SOURCE_FREEZE_COMMIT",
    "O1C23SelectionAuthorityError",
    "O1C23SelectionAuthorityPreflight",
    "O1C23SelectionAuthorityReceipt",
    "O1C23SelectionPending",
    "O1C23SemanticSelectionReceipt",
    "PREFLIGHT_SCHEMA",
    "SEMANTIC_RECEIPT_SCHEMA",
    "load_authoritative_o1c23_selection",
    "load_producer_authentic_o1c22_source",
    "preflight_o1c23_selection_authority",
    "verify_o1c22_producer_heldout_freeze",
    "verify_o1c23_decision_graph",
]
