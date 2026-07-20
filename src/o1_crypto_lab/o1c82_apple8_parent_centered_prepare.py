"""Zero-call Page-8/lineage-21 preparation for O1C-0082.

This module consumes only sealed, public O1C-0080/O1C-0081 evidence.  It
does not persist anything and has no solver, target, truth, reveal, or model
interface.  Its one public operation returns the exact bytes a later runner
may choose to publish after a separate authorization step.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence, cast

from .causal_attic_v1 import (
    CausalAtticError,
    canonical_json_bytes,
    parse_vault_telemetry,
    sha256_bytes,
)
from .causal_residency_v1 import (
    CausalResidencyError,
    CausalResidencyState,
    advance_causal_residency,
    validate_activation_replay,
)
from .o1c80_apple8_bound_crossing_prepare import (
    ACTIVATION_LEDGER_NAME as PAGE7_ACTIVATION_LEDGER_NAME,
)
from .o1c80_apple8_bound_crossing_prepare import (
    EXPECTED_PREPARED_MANIFEST_SHA256 as PAGE7_PREPARATION_MANIFEST_SHA256,
)
from .o1c80_apple8_bound_crossing_prepare import (
    PAGE7_ACTIVATION_LEDGER_SHA256,
    PAGE7_SHA256,
    PAGE7_STATE_DOCUMENT_SHA256,
    PreparedBoundCrossing,
    load_prepared_bound_crossing,
)
from .o1c82_parent_centered_seed import (
    BANK_BYTES,
    EXPECTED_BANK_SHA256,
    MANIFEST_SCHEMA as SEED_MANIFEST_SCHEMA,
    compile_parent_centered_seed,
    parse_seed_bank,
)
from .threshold_no_good_vault_v1 import ThresholdNoGoodVault


ATTEMPT_ID = "O1C-0082"
PARENT_ATTEMPT_ID = "O1C-0080"
PREPARATION_SCHEMA = "o1-256-o1c82-page8-parent-centered-preparation-v1"

DEFAULT_PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260720_124516_O1C-0080_apple8-bound-crossing-v1"
)
DEFAULT_PARENT_RESULT_RELATIVE = Path(
    "research/O1C0080_APPLE8_BOUND_CROSSING_RESULT_20260720.json"
)
DEFAULT_SEED_MANIFEST_RELATIVE = Path(
    "research/O1C0082_PARENT_CENTERED_SEED_MANIFEST_20260720.json"
)

PARENT_CAPSULE_MANIFEST_SHA256 = (
    "400b79b01ed54addbd99db53b2cf5ad36afd388a18d1435dcd7ef850c8532c44"
)
PARENT_CAPSULE_ENTRY_COUNT = 43
PARENT_RESULT_SHA256 = (
    "e2ceb375c2fb83469db8eb537459b223d8e7f63e4bb58882882f8cdd8bdb22a5"
)
PARENT_INVOCATION_SHA256 = (
    "a178c251b34a500c3c6f9f786021586911bb6a9c4e89d53e94792442348968be"
)
PARENT_EPISODE_SHA256 = (
    "968a97c4dd0b7f5b396a1d361303bb7bc5bc8f5be9b9247be74e2a9685b5e6af"
)
PARENT_CONCLUSION_SHA256 = (
    "0a6082c2102ae9ac218e20e1c79ffa1e1d4b682a69676568b92d71f2ed6195a6"
)
PARENT_TELEMETRY_GZIP_SHA256 = (
    "25d58d3dd170feb83d72368ef53f60cc38e74e5173d2798c0b1534e0820bc7de"
)
PARENT_TELEMETRY_GZIP_BYTES = 1_096
PARENT_TELEMETRY_RAW_SHA256 = (
    "b1159bb36cf2c40cba28a025897283ee7dc4913656a1158d0c1cc4dd190ff3b9"
)
PARENT_TELEMETRY_RAW_BYTES = 2_564
SEED_MANIFEST_SHA256 = (
    "ce288800e6a41ef6c5e0fabebeb700dd35adcc21b8140126f1ae298256310431"
)
SEED_MANIFEST_BYTES = 3_669
EMPTY_ROLLOVER_SHA256 = (
    "43377d8b5c116f2e3deac2064a16bbc526ae2c31bb2999c074084b81faa4ce94"
)
EMPTY_ROLLOVER_BYTES = 191
PAGE8_SHA256 = "89e085e7323ea9aaaa31ad1430c3f20ac03f9c21a49c6404374b75ddf59330f4"
PAGE8_SERIALIZED_BYTES = 2_769_351
PAGE8_SELECTION_ORDER_SHA256 = (
    "19e9cecc7d3ae2c6d5ef30fcf1dcee44958d5c059c47ff26c4a5a51bbf57e2c4"
)
PAGE8_RESIDENCY_BYTES = 31_983
PAGE8_ACTIVATION_LEDGER_BYTES = 15_007

ACTIVE_PROJECTION_NAME = "page-08-active.bin"
RESIDENCY_NAME = "residency.json"
ACTIVATION_LEDGER_NAME = "activation-ledger.json"
EMPTY_ROLLOVER_NAME = "lineage-21-empty-rollover.vault"
SEED_BANK_NAME = "parent-centered-priority-seed.bin"
SEED_MANIFEST_NAME = "parent-centered-priority-seed-manifest.json"
PREPARATION_MANIFEST_NAME = "parent-centered-preparation-manifest.json"


class O1C82PreparationError(RuntimeError):
    """A source seal, replay boundary, or deterministic artifact differs."""


@dataclass(frozen=True)
class PreparedParentCenteredArtifacts:
    """In-memory Page-8 preparation; no path has been written."""

    state: CausalResidencyState
    artifacts: Mapping[str, bytes]
    manifest: Mapping[str, object]


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _canonical_path(value: str | Path, label: str, *, directory: bool) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise O1C82PreparationError(f"{label} path is not canonical")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise O1C82PreparationError(f"{label} is unreadable") from exc
    expected = (
        stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    )
    if stat.S_ISLNK(metadata.st_mode) or not expected or path != resolved:
        raise O1C82PreparationError(f"{label} path is not canonical")
    return path


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise O1C82PreparationError(f"{label} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise O1C82PreparationError(f"{label} differs")
    return cast(Sequence[object], value)


def _canonical_document(payload: bytes, label: str) -> Mapping[str, object]:
    try:
        document = _mapping(json.loads(payload), label)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C82PreparationError(f"{label} differs") from exc
    if canonical_json_bytes(document) != payload:
        raise O1C82PreparationError(f"{label} is not canonical JSON")
    return document


def _parse_capsule_manifest(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise O1C82PreparationError("parent capsule manifest differs") from exc
    entries: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise O1C82PreparationError("parent capsule manifest row differs")
        digest, relative = line[:64], line[66:]
        parts = Path(relative).parts
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not relative
            or relative.startswith("/")
            or ".." in parts
            or relative in entries
        ):
            raise O1C82PreparationError("parent capsule manifest row differs")
        entries[relative] = digest
    if len(entries) != PARENT_CAPSULE_ENTRY_COUNT:
        raise O1C82PreparationError("parent capsule manifest inventory differs")
    return entries


def _validate_capsule_inventory(capsule: Path) -> dict[str, str]:
    manifest_path = capsule / "artifacts.sha256"
    try:
        manifest_metadata = manifest_path.lstat()
    except OSError as exc:
        raise O1C82PreparationError("parent capsule manifest is unreadable") from exc
    if stat.S_ISLNK(manifest_metadata.st_mode) or not stat.S_ISREG(
        manifest_metadata.st_mode
    ):
        raise O1C82PreparationError("parent capsule manifest is not sealed")
    payload = manifest_path.read_bytes()
    if sha256_bytes(payload) != PARENT_CAPSULE_MANIFEST_SHA256:
        raise O1C82PreparationError("parent capsule manifest differs")
    entries = _parse_capsule_manifest(payload)
    observed: dict[str, str] = {}
    for candidate in capsule.rglob("*"):
        metadata = candidate.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise O1C82PreparationError("parent capsule contains a symlink")
        if stat.S_ISREG(metadata.st_mode):
            relative = candidate.relative_to(capsule).as_posix()
            if relative != "artifacts.sha256":
                observed[relative] = hashlib.sha256(candidate.read_bytes()).hexdigest()
        elif not stat.S_ISDIR(metadata.st_mode):
            raise O1C82PreparationError("parent capsule contains a special file")
    if observed != entries:
        raise O1C82PreparationError("parent capsule inventory or digest differs")
    required = {
        "result.json": PARENT_RESULT_SHA256,
        "invocation.json": PARENT_INVOCATION_SHA256,
        "episodes/00/episode.json": PARENT_EPISODE_SHA256,
        "episodes/00/three-axis-conclusion.json": PARENT_CONCLUSION_SHA256,
        "episodes/00/vault-telemetry.json.gz": PARENT_TELEMETRY_GZIP_SHA256,
        "initial/page-07-active.bin": PAGE7_SHA256,
        "initial/residency.json": PAGE7_STATE_DOCUMENT_SHA256,
        f"initial/{PAGE7_ACTIVATION_LEDGER_NAME}": PAGE7_ACTIVATION_LEDGER_SHA256,
    }
    if any(entries.get(name) != digest for name, digest in required.items()):
        raise O1C82PreparationError("parent capsule required seal differs")
    return entries


def _validate_parent(
    capsule_dir: str | Path, parent_result_path: str | Path
) -> PreparedBoundCrossing:
    capsule = _canonical_path(capsule_dir, "parent capsule", directory=True)
    result_path = _canonical_path(parent_result_path, "parent result", directory=False)
    _validate_capsule_inventory(capsule)
    result_payload = result_path.read_bytes()
    if (
        sha256_bytes(result_payload) != PARENT_RESULT_SHA256
        or result_payload != (capsule / "result.json").read_bytes()
    ):
        raise O1C82PreparationError("parent result binding differs")
    result = _canonical_document(result_payload, "parent result")
    episodes = _sequence(result.get("episodes"), "parent result episodes")
    episode_payload = (capsule / "episodes/00/episode.json").read_bytes()
    episode = _canonical_document(episode_payload, "parent episode")
    conclusion = _canonical_document(
        (capsule / "episodes/00/three-axis-conclusion.json").read_bytes(),
        "parent conclusion",
    )
    if (
        result.get("schema") != "o1-256-apple8-bound-crossing-result-v1"
        or result.get("attempt_id") != PARENT_ATTEMPT_ID
        or result.get("classification") != "BOUND_PROBE_OPERATION_ONLY"
        or result.get("stop_reason")
        != "exact-probes-operated-without-crossing-or-science"
        or len(episodes) != 1
        or episodes[0] != episode
        or episode.get("completed") is not True
        or episode.get("native_call_issued") is not True
        or episode.get("native_calls_consumed") != 1
        or episode.get("lineage_call_ordinal") != 20
        or episode.get("page7_burned") is not True
        or episode.get("lineage20_burned") is not True
        or episode.get("retry_authorized") is not False
        or episode.get("replay_authorized") is not False
        or episode.get("globally_novel_clause_count") != 0
        or episode.get("science_gain") is not False
        or _mapping(conclusion.get("exact_probe_operation"), "probe axis").get(
            "exact_probe_operation"
        )
        is not True
        or _mapping(conclusion.get("crossing_activation"), "crossing axis").get(
            "crossing_activation"
        )
        is not False
        or _mapping(conclusion.get("science"), "science axis").get("science_gain")
        is not False
    ):
        raise O1C82PreparationError("parent completed-call contract differs")

    telemetry_gzip = (capsule / "episodes/00/vault-telemetry.json.gz").read_bytes()
    if (
        len(telemetry_gzip) != PARENT_TELEMETRY_GZIP_BYTES
        or sha256_bytes(telemetry_gzip) != PARENT_TELEMETRY_GZIP_SHA256
    ):
        raise O1C82PreparationError("parent telemetry gzip differs")
    try:
        telemetry_raw = gzip.decompress(telemetry_gzip)
    except (OSError, EOFError) as exc:
        raise O1C82PreparationError("parent telemetry gzip differs") from exc
    if (
        len(telemetry_raw) != PARENT_TELEMETRY_RAW_BYTES
        or sha256_bytes(telemetry_raw) != PARENT_TELEMETRY_RAW_SHA256
    ):
        raise O1C82PreparationError("parent telemetry raw seal differs")
    try:
        telemetry = parse_vault_telemetry(
            telemetry_raw,
            stream_id="o1c80-episode-00",
            expected_sha256=PARENT_TELEMETRY_RAW_SHA256,
        )
        prepared = load_prepared_bound_crossing(
            capsule / "initial",
            expected_manifest_sha256=PAGE7_PREPARATION_MANIFEST_SHA256,
        )
    except (CausalAtticError, CausalResidencyError, RuntimeError) as exc:
        raise O1C82PreparationError("parent Page-7 replay differs") from exc
    state = prepared.state
    if (
        telemetry.occurrences != ()
        or telemetry.input_vault_sha256 != PAGE7_SHA256
        or state.current_projection.lineage_ordinal != 20
        or state.active_projection.sha256 != PAGE7_SHA256
        or sha256_bytes(canonical_json_bytes(state.describe()))
        != PAGE7_STATE_DOCUMENT_SHA256
        or sha256_bytes(canonical_json_bytes(state.activation_ledger_document()))
        != PAGE7_ACTIVATION_LEDGER_SHA256
        or state.used_active_sha256[-1] != PAGE7_SHA256
    ):
        raise O1C82PreparationError("parent Page-7 state differs")
    return prepared


def _advance_page8(
    previous: CausalResidencyState,
) -> tuple[CausalResidencyState, bytes]:
    if (
        previous.current_projection.lineage_ordinal != 20
        or previous.active_projection.sha256 != PAGE7_SHA256
    ):
        raise O1C82PreparationError("Page-8 source is a replay or mutation")
    rollover = ThresholdNoGoodVault(
        previous.active_projection.identity,
        previous.active_projection.observed_variables,
        (),
    )
    if (
        rollover.sha256 != EMPTY_ROLLOVER_SHA256
        or rollover.serialized_bytes != EMPTY_ROLLOVER_BYTES
        or rollover.clause_count != 0
    ):
        raise O1C82PreparationError("identity-bound empty rollover differs")
    try:
        state = advance_causal_residency(
            previous,
            chunk=rollover,
            occurrences=(),
            next_lineage_ordinal=21,
        )
        validate_activation_replay(state)
    except CausalResidencyError as exc:
        raise O1C82PreparationError("Page-8 causal-residency advance differs") from exc
    residency_payload = canonical_json_bytes(state.describe())
    ledger_payload = canonical_json_bytes(state.activation_ledger_document())
    if (
        state.current_projection.lineage_ordinal != 21
        or state.active_projection.sha256 != PAGE8_SHA256
        or state.active_projection.serialized_bytes != PAGE8_SERIALIZED_BYTES
        or state.current_projection.describe().get("selection_order_sha256")
        != PAGE8_SELECTION_ORDER_SHA256
        or len(residency_payload) != PAGE8_RESIDENCY_BYTES
        or len(ledger_payload) != PAGE8_ACTIVATION_LEDGER_BYTES
        or state.active_projection.sha256 in previous.used_active_sha256
        or state.used_active_sha256[:-1] != previous.used_active_sha256
        or state.activation_ledger[:-1] != previous.activation_ledger
        or state.attic.chunks[:-1] != previous.attic.chunks
        or state.attic.chunks[-1] != rollover
        or state.attic.union_vault != previous.attic.union_vault
        or state.attic.occurrences != previous.attic.occurrences
        or state.attic.relations != previous.attic.relations
    ):
        raise O1C82PreparationError("Page-8 advance rewrote or reused evidence")
    return state, rollover.serialized


def _load_seed(seed_manifest_path: str | Path) -> tuple[bytes, bytes]:
    path = _canonical_path(seed_manifest_path, "seed manifest", directory=False)
    manifest_payload = path.read_bytes()
    if (
        len(manifest_payload) != SEED_MANIFEST_BYTES
        or sha256_bytes(manifest_payload) != SEED_MANIFEST_SHA256
    ):
        raise O1C82PreparationError("seed manifest seal differs")
    manifest = _canonical_document(manifest_payload, "seed manifest")
    lineage = _mapping(manifest.get("lineage"), "seed lineage")
    bank_contract = _mapping(manifest.get("bank"), "seed bank contract")
    if (
        manifest.get("schema") != SEED_MANIFEST_SCHEMA
        or manifest.get("attempt_id") != ATTEMPT_ID
        or lineage
        != {
            "parent_attempt_id": "O1C-0081",
            "seed_role": "target-free-preload-for-fresh-lineage-21",
            "source_attempt_id": PARENT_ATTEMPT_ID,
            "source_lineage_call_ordinal": 20,
        }
        or bank_contract.get("sha256") != EXPECTED_BANK_SHA256
        or bank_contract.get("serialized_bytes") != BANK_BYTES
    ):
        raise O1C82PreparationError("seed manifest lineage or bank differs")
    try:
        bank = compile_parent_centered_seed(lab_root(), verify_fresh=True)
        parse_seed_bank(bank, expected_sha256=EXPECTED_BANK_SHA256)
    except (ValueError, RuntimeError) as exc:
        raise O1C82PreparationError("fresh seed compilation differs") from exc
    if len(bank) != BANK_BYTES or sha256_bytes(bank) != EXPECTED_BANK_SHA256:
        raise O1C82PreparationError("compiled seed bank differs")
    return bank, manifest_payload


def _artifact_row(payload: bytes) -> dict[str, object]:
    return {"serialized_bytes": len(payload), "sha256": sha256_bytes(payload)}


def prepare_o1c82_parent_centered(
    *,
    capsule_dir: str | Path,
    parent_result_path: str | Path,
    seed_manifest_path: str | Path,
) -> PreparedParentCenteredArtifacts:
    """Return a complete deterministic Page-8 artifact mapping in memory."""

    parent = _validate_parent(capsule_dir, parent_result_path)
    state, rollover = _advance_page8(parent.state)
    seed_bank, seed_manifest = _load_seed(seed_manifest_path)
    artifacts: dict[str, bytes] = {
        ACTIVE_PROJECTION_NAME: state.active_projection.serialized,
        RESIDENCY_NAME: canonical_json_bytes(state.describe()),
        ACTIVATION_LEDGER_NAME: canonical_json_bytes(
            state.activation_ledger_document()
        ),
        EMPTY_ROLLOVER_NAME: rollover,
        SEED_BANK_NAME: seed_bank,
        SEED_MANIFEST_NAME: seed_manifest,
    }
    manifest: dict[str, object] = {
        "schema": PREPARATION_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "zero_call": {
            "native_solver_calls": 0,
            "science_calls": 0,
            "target_bytes_read": False,
            "truth_key_bytes_read": False,
            "reveal_calls": 0,
            "refits": 0,
        },
        "authorization": {
            "science_call_authorized": False,
            "intent_created": False,
            "page8_burned": False,
            "lineage21_burned": False,
            "page7_replay_authorized": False,
        },
        "parent": {
            "attempt_id": PARENT_ATTEMPT_ID,
            "capsule_manifest_sha256": PARENT_CAPSULE_MANIFEST_SHA256,
            "result_sha256": PARENT_RESULT_SHA256,
            "source_lineage_ordinal": 20,
            "source_active_sha256": PAGE7_SHA256,
            "fully_emitted_union_indices": [],
        },
        "page8": {
            "lineage_ordinal": 21,
            "active_sha256": state.active_projection.sha256,
            "active_clause_count": state.active_projection.clause_count,
            "selection_order_sha256": state.current_projection.describe()[
                "selection_order_sha256"
            ],
            "fresh_identity": state.active_projection.sha256
            not in parent.state.used_active_sha256,
            "advance_api": "advance_causal_residency",
            "rollover_clause_count": 0,
            "rollover_occurrence_count": 0,
        },
        "seed": {
            "manifest_sha256": SEED_MANIFEST_SHA256,
            "bank_sha256": EXPECTED_BANK_SHA256,
            "bank_bytes": BANK_BYTES,
            "orientation": "priority-only-not-key-bit-belief",
        },
        "artifacts": {
            name: _artifact_row(payload) for name, payload in sorted(artifacts.items())
        },
    }
    manifest_payload = canonical_json_bytes(manifest)
    artifacts[PREPARATION_MANIFEST_NAME] = manifest_payload
    return PreparedParentCenteredArtifacts(
        state=state,
        artifacts=artifacts,
        manifest=manifest,
    )


__all__ = [
    "ACTIVE_PROJECTION_NAME",
    "ACTIVATION_LEDGER_NAME",
    "ATTEMPT_ID",
    "DEFAULT_PARENT_CAPSULE_RELATIVE",
    "DEFAULT_PARENT_RESULT_RELATIVE",
    "DEFAULT_SEED_MANIFEST_RELATIVE",
    "EMPTY_ROLLOVER_NAME",
    "O1C82PreparationError",
    "PREPARATION_MANIFEST_NAME",
    "PreparedParentCenteredArtifacts",
    "RESIDENCY_NAME",
    "SEED_BANK_NAME",
    "SEED_MANIFEST_NAME",
    "prepare_o1c82_parent_centered",
]
