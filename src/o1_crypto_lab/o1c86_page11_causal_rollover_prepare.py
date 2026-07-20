"""Zero-call O1C-0086 Page-11 causal-rollover preparation.

The only new scientific evidence consumed here is O1C-0085's sealed set of
23 fully emitted, globally novel threshold no-good clauses.  The clauses are
appended to the immutable 807-clause Page-10 attic, the exact evolved live
priority bank and its state receipt are carried forward, and lineage 24 is
projected at the mechanically safe 254-clause residency limit.

The module has no native, solver, target, truth-key, model, or reveal
interface.  Preparation is in-memory; publication is a separate atomic
operation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import stat
import struct
import sys
from pathlib import Path
from typing import Mapping, Sequence, cast

from . import o1c85_page10_transport_recovery_prepare as _o1c85
from .causal_attic_v1 import (
    CausalAtticError,
    ParsedVaultTelemetry,
    canonical_json_bytes,
    parse_vault_telemetry,
    sha256_bytes,
)
from .causal_residency_v1 import (
    CausalResidencyError,
    CausalResidencyState,
    advance_causal_residency,
    replay_causal_residency,
    validate_activation_replay,
)
from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultError,
    parse_threshold_no_good_vault,
)


ATTEMPT_ID = "O1C-0086"
PARENT_ATTEMPT_ID = "O1C-0085"
PREPARATION_SCHEMA = "o1-256-o1c86-page11-causal-rollover-preparation-v1"

DEFAULT_PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260720_170426_298664_O1C-0085_apple8-parent-centered-continuation-v1"
)
DEFAULT_PARENT_RESULT_RELATIVE = Path(
    "research/O1C0085_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json"
)

PARENT_CAPSULE_MANIFEST_SHA256 = (
    "c6f4cb50ab5e7b0e57afbe5bbaccf53106008094be824c35bb7f849a8d4be492"
)
PARENT_CAPSULE_MANIFEST_BYTES = 2_780
PARENT_CAPSULE_ENTRY_COUNT = 29
PARENT_RESULT_SHA256 = (
    "d65fcaa76caa50905b5061b99cdf3ea10841449bdec6e9d20344e17bbe1e2ca4"
)
PARENT_RESULT_BYTES = 10_555
PARENT_EPISODE_SHA256 = (
    "80cdad4b1cd89e4d90bf82325ee205a2b5c7f9b9f0cfaa140540df011dc43569"
)
PARENT_EPISODE_BYTES = 3_507
PARENT_INTENT_SHA256 = (
    "18607add506d55a3b3286b3954415a5d6a65c3760aa0fe0dedd82ec10cea3114"
)
PARENT_INTENT_BYTES = 1_114
PARENT_VAULT_TELEMETRY_SHA256 = (
    "899d3ac156cff2de6e31b4c736d037ca13ac57c044cbf52bb3fae21835c0cc40"
)
PARENT_VAULT_TELEMETRY_BYTES = 467_841
PARENT_PREPARATION_MANIFEST_SHA256 = (
    "d512f675d7076ecc650ce93052d60b8db1d1ed206d5b8d119118bdcec310c42c"
)
PARENT_PREPARATION_MANIFEST_BYTES = 4_594
PARENT_CLASSIFICATION = "PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN"
PARENT_STOP_REASON = "globally-novel-clause"
PARENT_REQUESTED_CONFLICTS = 128
GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT = 807

PAGE10_SHA256 = _o1c85.PAGE10_SHA256
PAGE10_CLAUSE_COUNT = _o1c85.PAGE10_CLAUSE_COUNT
PAGE10_LITERAL_COUNT = _o1c85.PAGE10_LITERAL_COUNT
PAGE10_SERIALIZED_BYTES = _o1c85.PAGE10_SERIALIZED_BYTES
PAGE10_CLAUSE_AGGREGATE_SHA256 = (
    "6a909a71030eefcdb8b5e5dd4fc9694b9a413645e856382d834cc3c4c88349f3"
)
PARENT_INITIAL_ARTIFACT_COUNT = 10

NEW_CHUNK_SHA256 = "7689d51af4a51ea2539bf7f84ae52a97ae625229aa464f9056733b7147fd12df"
NEW_CHUNK_CLAUSE_COUNT = 23
NEW_CHUNK_LITERAL_COUNT = 67_130
NEW_CHUNK_SERIALIZED_BYTES = 268_803
NEW_CHUNK_CLAUSE_AGGREGATE_SHA256 = (
    "8a3b21b76f8d4c441c13c516e167b52356144c4a3e114267099c254f977c572e"
)

ATTIC_CHUNK_COUNT = 14
ATTIC_UNION_SHA256 = "78f7dce532f06b6c276168b3bec75066fc9c13ec5fcc62defc35e290dc715b30"
ATTIC_UNION_CLAUSE_COUNT = 830
ATTIC_UNION_LITERAL_COUNT = 2_298_483
ATTIC_UNION_SERIALIZED_BYTES = 9_197_443
ATTIC_UNION_CLAUSE_AGGREGATE_SHA256 = (
    "9333a02ed7ad9d32c38ab7d344e6bbd87190d4007fe473eb985a938bad34e415"
)
ATTIC_OCCURRENCE_COUNT = 838
ATTIC_DUPLICATE_OCCURRENCE_COUNT = 8
ATTIC_SUBSUMPTION_RELATION_COUNT = 10
ATTIC_UNDOMINATED_CLAUSE_COUNT = 823
OCCURRENCE_DOCUMENT_SHA256 = (
    "24c8d37eaea70abdc8b59b35b4a7915385d5ee645c206ec51d6563ab255e9e3c"
)
OCCURRENCE_DOCUMENT_BYTES = 296_668
RELATION_DOCUMENT_SHA256 = (
    "69a9f0bd25ea515af120773b1eabaeb20f2861d424c9b5c38844e716ae8914a7"
)
RELATION_DOCUMENT_BYTES = 6_415

PAGE11_SHA256 = "9853f06bc882bfbb6312207bc8c20e0e9ca1500e49aad14594f6d7c66b62a04d"
PAGE11_CLAUSE_COUNT = 254
PAGE11_LITERAL_COUNT = 718_881
PAGE11_SERIALIZED_BYTES = 2_876_731
PAGE11_CLAUSE_AGGREGATE_SHA256 = (
    "78fd7063d4049cf136143a10c011a1626676babc8d2ee026db5d56c9b218e7a6"
)
PAGE11_ACTIVE_LIMIT = 254
PAGE11_LINEAGE_ORDINAL = 24
PAGE11_CATEGORY_COUNTS = {
    "structural_root": 5,
    "pinned_core": 43,
    "inherited_debt": 0,
    "new_debt": 21,
    "hot_event": 0,
    "recycled": 185,
}
PAGE11_HEADROOM = {
    "clauses": 258,
    "literals": 881_119,
    "serialized_bytes": 5_511_877,
}
PAGE11_RESIDENCY_DOCUMENT_SHA256 = (
    "cc96585dab190c220f0b22e901138f1ef7c33a41e9e9afd96f5bf96f4027b7ee"
)
PAGE11_RESIDENCY_DOCUMENT_BYTES = 39_207
PAGE11_ACTIVATION_DOCUMENT_SHA256 = (
    "d360d3dc6e1988519c828c14e6dc31400b5644c8c8ceea33ec283f3a9cbf39e9"
)
PAGE11_ACTIVATION_DOCUMENT_BYTES = 20_578
PAGE11_ACTIVATION_COUNT = 12

NATIVE_VAULT_CAPS = {
    "maximum_clauses": 512,
    "maximum_literals": 1_600_000,
    "maximum_serialized_bytes": 8_388_608,
}
PARENT_CENTERED_ACTION_CAPACITY = 256

FINAL_BANK_SHA256 = "2c0c4ccba476bc642778b68234cc497c1776d144092ea9f1aead367559f59b07"
FINAL_BANK_BYTES = 24_576
PRIORITY_RECEIPT_SHA256 = (
    "288d91298200ae69f84e6616c9a445c87b092ff56ac8671033ae3c3b4dd8b0a9"
)
PRIORITY_RECEIPT_BYTES = 51_273
CONTINUATION_RECORD_FORMAT = "<QddQQddQQddd"
CONTINUATION_RECORD = struct.Struct(CONTINUATION_RECORD_FORMAT)
CONTINUATION_RECORD_BYTES = 96
CONTINUATION_CANDIDATE_ORDER_SHA256 = (
    "8198e3662f8ea2647c85982585b51ef46154007397bdc67533615778d8741a44"
)

NEW_CHUNK_NAME = "lineage-24-new-chunk.vault"
ACTIVE_PROJECTION_NAME = "page-11-active.bin"
RESIDENCY_NAME = _o1c85.RESIDENCY_NAME
ACTIVATION_LEDGER_NAME = _o1c85.ACTIVATION_LEDGER_NAME
OCCURRENCES_NAME = _o1c85.OCCURRENCES_NAME
RELATIONS_NAME = _o1c85.RELATIONS_NAME
COMMON_CORE_AUDIT_NAME = _o1c85.COMMON_CORE_AUDIT_NAME
COMMON_CORE_AUDIT_SHA256 = (
    "2a14bc7382f90bb038223852fd8c5fcfb2c99145338800efead72cb6c1dbb83c"
)
COMMON_CORE_AUDIT_BYTES = 20_115
FINAL_BANK_NAME = _o1c85.FINAL_BANK_NAME
PRIORITY_RECEIPT_NAME = "o1c85-priority-state-receipt.json"
PREPARATION_MANIFEST_NAME = "causal-rollover-preparation-manifest.json"
PREPARATION_MANIFEST_SHA256 = (
    "2e9f30aa193f1f640523e333bbb7990db6cdf32e3f54ebee19600ab307366116"
)
PREPARATION_MANIFEST_BYTES = 6_893

PreparedCausalRolloverArtifacts = _o1c85.PreparedCausalRolloverArtifacts


class O1C86PreparationError(RuntimeError):
    """An O1C-0085 seal or deterministic Page-11 invariant differs."""


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise O1C86PreparationError(f"{label} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise O1C86PreparationError(f"{label} differs")
    return cast(Sequence[object], value)


def _canonical_path(value: str | Path, label: str, *, directory: bool) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise O1C86PreparationError(f"{label} path is not canonical")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise O1C86PreparationError(f"{label} is unreadable") from exc
    expected = (
        stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    )
    if stat.S_ISLNK(metadata.st_mode) or not expected or path != resolved:
        raise O1C86PreparationError(f"{label} path is not canonical")
    return path


def _canonical_document(payload: bytes, label: str) -> Mapping[str, object]:
    try:
        value = _mapping(json.loads(payload), label)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C86PreparationError(f"{label} differs") from exc
    if canonical_json_bytes(value) != payload:
        raise O1C86PreparationError(f"{label} is not canonical JSON")
    return value


def _parse_capsule_manifest(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise O1C86PreparationError("parent capsule manifest differs") from exc
    entries: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise O1C86PreparationError("parent capsule manifest row differs")
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
            raise O1C86PreparationError("parent capsule manifest row differs")
        entries[relative] = digest
    if len(entries) != PARENT_CAPSULE_ENTRY_COUNT:
        raise O1C86PreparationError("parent capsule manifest inventory differs")
    return entries


def _validate_capsule_inventory(capsule: Path) -> dict[str, str]:
    manifest_path = capsule / "artifacts.sha256"
    try:
        metadata = manifest_path.lstat()
        payload = manifest_path.read_bytes()
    except OSError as exc:
        raise O1C86PreparationError("parent capsule manifest is unreadable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or len(payload) != PARENT_CAPSULE_MANIFEST_BYTES
        or sha256_bytes(payload) != PARENT_CAPSULE_MANIFEST_SHA256
    ):
        raise O1C86PreparationError("parent capsule manifest differs")
    entries = _parse_capsule_manifest(payload)
    observed: dict[str, str] = {}
    for candidate in capsule.rglob("*"):
        candidate_metadata = candidate.lstat()
        if stat.S_ISLNK(candidate_metadata.st_mode):
            raise O1C86PreparationError("parent capsule contains a symlink")
        if stat.S_ISREG(candidate_metadata.st_mode):
            relative = candidate.relative_to(capsule).as_posix()
            if relative != "artifacts.sha256":
                observed[relative] = hashlib.sha256(candidate.read_bytes()).hexdigest()
        elif not stat.S_ISDIR(candidate_metadata.st_mode):
            raise O1C86PreparationError("parent capsule contains a special file")
    if observed != entries:
        raise O1C86PreparationError("parent capsule inventory or digest differs")
    required = {
        "result.json": PARENT_RESULT_SHA256,
        "episodes/00/episode.json": PARENT_EPISODE_SHA256,
        "episodes/00/intent.json": PARENT_INTENT_SHA256,
        "episodes/00/vault.json": PARENT_VAULT_TELEMETRY_SHA256,
        "episodes/00/final-parent-centered-priority-bank.bin": FINAL_BANK_SHA256,
        "episodes/00/priority-state.json": PRIORITY_RECEIPT_SHA256,
        f"initial/{_o1c85.ACTIVE_PROJECTION_NAME}": PAGE10_SHA256,
        f"initial/{_o1c85.PREPARATION_MANIFEST_NAME}": (
            PARENT_PREPARATION_MANIFEST_SHA256
        ),
        f"initial/{_o1c85.OCCURRENCES_NAME}": (
            "b011f4c7bbda808fc78827353fe39ddec334b067f4744bd89f1a3bc31dcacb1f"
        ),
        f"initial/{_o1c85.RELATIONS_NAME}": (
            "c599e44573e5c1be1740d1bd6fe40970cf562746e9e77ee927d7021030b58e43"
        ),
    }
    if any(entries.get(name) != digest for name, digest in required.items()):
        raise O1C86PreparationError("parent capsule required seal differs")
    if "episodes/00/terminal-failure.json" in entries:
        raise O1C86PreparationError("parent successful episode boundary differs")
    return entries


def _validate_parent_result(capsule: Path, result_path: Path) -> Mapping[str, object]:
    try:
        payload = result_path.read_bytes()
        capsule_payload = (capsule / "result.json").read_bytes()
        episode_payload = (capsule / "episodes/00/episode.json").read_bytes()
        intent_payload = (capsule / "episodes/00/intent.json").read_bytes()
    except OSError as exc:
        raise O1C86PreparationError("parent result boundary is unreadable") from exc
    if (
        len(payload) != PARENT_RESULT_BYTES
        or sha256_bytes(payload) != PARENT_RESULT_SHA256
        or capsule_payload != payload
        or len(episode_payload) != PARENT_EPISODE_BYTES
        or sha256_bytes(episode_payload) != PARENT_EPISODE_SHA256
        or len(intent_payload) != PARENT_INTENT_BYTES
        or sha256_bytes(intent_payload) != PARENT_INTENT_SHA256
    ):
        raise O1C86PreparationError("parent result binding differs")

    result = _canonical_document(payload, "parent result")
    episode_document = _canonical_document(episode_payload, "parent episode")
    intent = _canonical_document(intent_payload, "parent intent")
    episodes = _sequence(result.get("episodes"), "parent result episodes")
    if len(episodes) != 1:
        raise O1C86PreparationError("parent completed-call contract differs")
    episode = _mapping(episodes[0], "parent episode")
    claim = _mapping(result.get("claim_boundary"), "parent claim boundary")
    science = _mapping(episode.get("science"), "parent science")
    final_bank = _mapping(episode.get("final_priority_bank"), "parent final bank")
    archived = _mapping(
        episode.get("archived_native_components"), "parent archived components"
    )
    archived_vault = _mapping(archived.get("vault.json"), "parent archived vault")
    archived_bank = _mapping(
        archived.get("final-parent-centered-priority-bank.bin"),
        "parent archived bank",
    )
    archived_state = _mapping(
        archived.get("priority-state.json"), "parent archived priority state"
    )
    resources = _mapping(result.get("resources"), "parent resources")
    expected_science = {
        "active_page10_new_clauses": NEW_CHUNK_CLAUSE_COUNT,
        "actual_certified_prunes": 0,
        "attacker_valid_domain_reduction": 0,
        "attacker_valid_entropy_gain_bits": 0.0,
        "certified_closure": False,
        "certified_model_or_key": False,
        "failure_first_action_alone_is_science_gain": False,
        "fully_emitted_clauses": NEW_CHUNK_CLAUSE_COUNT,
        "globally_novel_clauses": NEW_CHUNK_CLAUSE_COUNT,
        "priority_or_differential_alone_is_science_gain": False,
        "science_gain": True,
        "threshold_prunes": NEW_CHUNK_CLAUSE_COUNT,
        "unconfirmed_crossing_alone_is_science_gain": False,
    }
    if (
        episode_document != episode
        or result.get("schema")
        != "o1-256-apple8-parent-centered-continuation-result-v1"
        or result.get("attempt_id") != PARENT_ATTEMPT_ID
        or result.get("capsule") != DEFAULT_PARENT_CAPSULE_RELATIVE.as_posix()
        or result.get("classification") != PARENT_CLASSIFICATION
        or result.get("stop_reason") != PARENT_STOP_REASON
        or result.get("science_gain") is not True
        or result.get("operational_activation") is not True
        or claim.get("global_novelty_baseline_clause_count")
        != GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT
        or claim.get("page10_sha256") != PAGE10_SHA256
        or claim.get("page10_burned") is not True
        or claim.get("lineage23_only") is not True
        or claim.get("retry_or_replay") is not False
        or claim.get("target_bytes_read") is not False
        or claim.get("truth_key_bytes_read") is not False
        or claim.get("fresh_reveal_calls") != 0
        or claim.get("refits") != 0
        or claim.get("rollover_manifest_sha256") != PARENT_PREPARATION_MANIFEST_SHA256
        or episode.get("schema")
        != "o1-256-apple8-parent-centered-continuation-episode-v1"
        or episode.get("classification") != PARENT_CLASSIFICATION
        or episode.get("stop_reason") != PARENT_STOP_REASON
        or episode.get("completed") is not True
        or episode.get("status") != 0
        or episode.get("lineage_call_ordinal") != 23
        or episode.get("local_episode_ordinal") != 0
        or episode.get("page10_burned") is not True
        or episode.get("lineage23_burned") is not True
        or episode.get("native_call_issued") is not True
        or episode.get("native_calls_consumed") != 1
        or episode.get("native_result_returned") is not True
        or episode.get("retry_authorized") is not False
        or episode.get("replay_authorized") is not False
        or episode.get("requested_conflicts") != PARENT_REQUESTED_CONFLICTS
        or episode.get("actual_conflicts") != PARENT_REQUESTED_CONFLICTS
        or episode.get("billed_conflicts") != PARENT_REQUESTED_CONFLICTS
        or episode.get("terminal_failure") is not None
        or science != expected_science
        or final_bank
        != {
            "path": "final-parent-centered-priority-bank.bin",
            "serialized_bytes": FINAL_BANK_BYTES,
            "sha256": FINAL_BANK_SHA256,
        }
        or archived_vault
        != {
            "path": "vault.json",
            "serialized_bytes": PARENT_VAULT_TELEMETRY_BYTES,
            "sha256": PARENT_VAULT_TELEMETRY_SHA256,
        }
        or archived_bank != final_bank
        or archived_state
        != {
            "path": "priority-state.json",
            "serialized_bytes": PRIORITY_RECEIPT_BYTES,
            "sha256": PRIORITY_RECEIPT_SHA256,
        }
        or resources.get("native_solver_calls") != 1
        or resources.get("requested_conflicts") != PARENT_REQUESTED_CONFLICTS
        or resources.get("actual_conflicts") != PARENT_REQUESTED_CONFLICTS
        or resources.get("billed_conflicts") != PARENT_REQUESTED_CONFLICTS
    ):
        raise O1C86PreparationError("parent completed-call contract differs")

    if (
        intent.get("schema") != "o1-256-apple8-parent-centered-continuation-intent-v1"
        or intent.get("attempt_id") != PARENT_ATTEMPT_ID
        or intent.get("lineage_call_ordinal") != 23
        or intent.get("local_episode_ordinal") != 0
        or intent.get("page10_sha256") != PAGE10_SHA256
        or intent.get("page10_burned") is not True
        or intent.get("lineage23_burned") is not True
        or intent.get("burn_on_persisted_intent") is not True
        or intent.get("retry_authorized") is not False
        or intent.get("replay_authorized") is not False
        or intent.get("target_bytes_read") is not False
        or intent.get("truth_key_bytes_read") is not False
        or intent.get("rollover_manifest_sha256") != PARENT_PREPARATION_MANIFEST_SHA256
        or intent.get("requested_conflicts") != PARENT_REQUESTED_CONFLICTS
        or episode.get("intent_sha256") != PARENT_INTENT_SHA256
        or intent.get("invocation_sha256") != episode.get("invocation_sha256")
    ):
        raise O1C86PreparationError("parent persisted intent contract differs")
    return result


def _regenerate_page10_and_validate_initial(
    capsule: Path,
) -> PreparedCausalRolloverArtifacts:
    try:
        previous = _o1c85.prepare_o1c85_page10_transport_recovery()
    except (OSError, RuntimeError, CausalAtticError, CausalResidencyError) as exc:
        raise O1C86PreparationError("O1C-0085 Page-10 regeneration differs") from exc
    expected_names = set(previous.artifacts)
    if expected_names != {
        _o1c85.ACTIVE_PROJECTION_NAME,
        _o1c85.RESIDENCY_NAME,
        _o1c85.ACTIVATION_LEDGER_NAME,
        _o1c85.OCCURRENCES_NAME,
        _o1c85.RELATIONS_NAME,
        _o1c85.COMMON_CORE_AUDIT_NAME,
        _o1c85.FINAL_BANK_NAME,
        _o1c85.FAILURE_RECEIPT_NAME,
        _o1c85.PREPARATION_MANIFEST_NAME,
    }:
        raise O1C86PreparationError("O1C-0085 Page-10 inventory differs")
    initial = capsule / "initial"
    try:
        initial_children = tuple(initial.iterdir())
    except OSError as exc:
        raise O1C86PreparationError("parent initial inventory is unreadable") from exc
    expected_initial_names = expected_names | {_o1c85.PRIORITY_RECEIPT_NAME}
    if (
        len(expected_initial_names) != PARENT_INITIAL_ARTIFACT_COUNT
        or {path.name for path in initial_children} != expected_initial_names
    ):
        raise O1C86PreparationError("parent initial inventory differs")
    for name, expected in previous.artifacts.items():
        path = initial / name
        try:
            metadata = path.lstat()
            observed = path.read_bytes()
        except OSError as exc:
            raise O1C86PreparationError("parent initial artifact differs") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or observed != expected
        ):
            raise O1C86PreparationError("parent initial artifact differs")
    state = previous.state
    if (
        state.current_projection.lineage_ordinal != 23
        or state.active_limit != _o1c85.PAGE10_ACTIVE_LIMIT
        or state.active_projection.sha256 != PAGE10_SHA256
        or state.active_projection.clause_count != PAGE10_CLAUSE_COUNT
        or state.active_projection.literal_count != PAGE10_LITERAL_COUNT
        or state.active_projection.serialized_bytes != PAGE10_SERIALIZED_BYTES
        or state.attic.union_vault.clause_count != GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT
        or len(state.activation_ledger) != 11
    ):
        raise O1C86PreparationError("parent Page-10 state differs")
    try:
        validate_activation_replay(state)
    except CausalResidencyError as exc:
        raise O1C86PreparationError("parent Page-10 replay differs") from exc
    return previous


def _parse_parent_telemetry(
    capsule: Path, previous: CausalResidencyState
) -> ParsedVaultTelemetry:
    path = capsule / "episodes/00/vault.json"
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise O1C86PreparationError("parent vault telemetry is unreadable") from exc
    if len(payload) != PARENT_VAULT_TELEMETRY_BYTES:
        raise O1C86PreparationError("parent vault telemetry size differs")
    raw = _canonical_document(payload, "parent vault telemetry")
    try:
        telemetry = parse_vault_telemetry(
            payload,
            stream_id="o1c85-episode-00",
            expected_sha256=PARENT_VAULT_TELEMETRY_SHA256,
        )
    except CausalAtticError as exc:
        raise O1C86PreparationError("parent vault telemetry differs") from exc
    active = previous.active_projection
    aggregate = sha256_bytes(b"".join(clause.serialized for clause in active.clauses))
    occurrences = telemetry.occurrences
    known_sha256 = {clause.sha256 for clause in previous.attic.union_vault.clauses}
    occurrence_sha256 = {occurrence.clause_sha256 for occurrence in occurrences}
    expected_raw = {
        "input_sha256": PAGE10_SHA256,
        "input_clause_count": PAGE10_CLAUSE_COUNT,
        "input_literal_count": PAGE10_LITERAL_COUNT,
        "input_serialized_bytes": PAGE10_SERIALIZED_BYTES,
        "input_clause_aggregate_sha256": PAGE10_CLAUSE_AGGREGATE_SHA256,
        "validated_input_clause_count": PAGE10_CLAUSE_COUNT,
        "validated_input_literal_count": PAGE10_LITERAL_COUNT,
        "fully_emitted_clause_count": NEW_CHUNK_CLAUSE_COUNT,
        "fully_emitted_literal_count": NEW_CHUNK_LITERAL_COUNT,
        "fully_emitted_aggregate_sha256": NEW_CHUNK_CLAUSE_AGGREGATE_SHA256,
        "emitted_new_clause_count": NEW_CHUNK_CLAUSE_COUNT,
        "emitted_new_literal_count": NEW_CHUNK_LITERAL_COUNT,
        "emitted_current_duplicate_clause_count": 0,
        "emitted_current_duplicate_literal_count": 0,
        "emitted_input_duplicate_clause_count": 0,
        "emitted_input_duplicate_literal_count": 0,
        "preloaded_clause_count": PAGE10_CLAUSE_COUNT,
        "preloaded_literal_count": PAGE10_LITERAL_COUNT,
        "next_vault_available": True,
        "next_vault_sha256": (
            "21c53865d86d6b9168c0260ccbf8eaa3de7a900d9577f2817ab23b9e7f4037d4"
        ),
        "next_clause_count": 277,
        "next_literal_count": 785_425,
        "next_serialized_bytes": 3_142_999,
        "next_vault_terminal_reason": None,
        "maximum_clause_count": NATIVE_VAULT_CAPS["maximum_clauses"],
        "maximum_literal_count": NATIVE_VAULT_CAPS["maximum_literals"],
        "maximum_payload_bytes": NATIVE_VAULT_CAPS["maximum_serialized_bytes"],
        "pending_clause_exported": False,
        "terminal_empty_clause_count": 0,
    }
    if (
        any(raw.get(name) != value for name, value in expected_raw.items())
        or telemetry.input_identity != active.identity
        or telemetry.input_vault_sha256 != PAGE10_SHA256
        or telemetry.input_clause_count != PAGE10_CLAUSE_COUNT
        or telemetry.input_literal_count != PAGE10_LITERAL_COUNT
        or telemetry.input_serialized_bytes != PAGE10_SERIALIZED_BYTES
        or telemetry.input_clause_aggregate_sha256 != PAGE10_CLAUSE_AGGREGATE_SHA256
        or aggregate != PAGE10_CLAUSE_AGGREGATE_SHA256
        or len(occurrences) != NEW_CHUNK_CLAUSE_COUNT
        or telemetry.new_occurrences != occurrences
        or any(occurrence.classification != "new" for occurrence in occurrences)
        or any(occurrence.source != "trail_upper_bound" for occurrence in occurrences)
        or len(occurrence_sha256) != NEW_CHUNK_CLAUSE_COUNT
        or occurrence_sha256 & known_sha256
        or len({occurrence.clause.serialized for occurrence in occurrences})
        != NEW_CHUNK_CLAUSE_COUNT
    ):
        raise O1C86PreparationError("Page-10 telemetry novelty binding differs")
    return telemetry


def _new_chunk(
    previous: CausalResidencyState, telemetry: ParsedVaultTelemetry
) -> ThresholdNoGoodVault:
    try:
        chunk = ThresholdNoGoodVault(
            telemetry.input_identity,
            previous.active_projection.observed_variables,
            tuple(occurrence.clause for occurrence in telemetry.occurrences),
        )
        roundtrip = parse_threshold_no_good_vault(
            chunk.serialized,
            observed_variables=chunk.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1C86PreparationError("new immutable chunk differs") from exc
    if (
        roundtrip != chunk
        or chunk.sha256 != NEW_CHUNK_SHA256
        or chunk.clause_count != NEW_CHUNK_CLAUSE_COUNT
        or chunk.literal_count != NEW_CHUNK_LITERAL_COUNT
        or chunk.serialized_bytes != NEW_CHUNK_SERIALIZED_BYTES
        or chunk.describe().get("clause_aggregate_sha256")
        != NEW_CHUNK_CLAUSE_AGGREGATE_SHA256
    ):
        raise O1C86PreparationError("new immutable chunk seal differs")
    return chunk


def _advance_page11(
    previous: CausalResidencyState,
    chunk: ThresholdNoGoodVault,
    telemetry: ParsedVaultTelemetry,
) -> CausalResidencyState:
    try:
        state = advance_causal_residency(
            previous,
            chunk=chunk,
            occurrences=telemetry.occurrences,
            next_lineage_ordinal=PAGE11_LINEAGE_ORDINAL,
            next_active_limit=PAGE11_ACTIVE_LIMIT,
        )
        validate_activation_replay(state)
        replayed = replay_causal_residency(state.attic, state.describe())
        page_roundtrip = parse_threshold_no_good_vault(
            state.active_projection.serialized,
            observed_variables=state.active_projection.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
    except (CausalResidencyError, ThresholdNoGoodVaultError) as exc:
        raise O1C86PreparationError("Page-11 causal rollover differs") from exc
    attic = state.attic
    page = state.active_projection
    occurrence_payload = canonical_json_bytes(attic.occurrence_document())
    relation_payload = canonical_json_bytes(attic.relation_document())
    residency_payload = canonical_json_bytes(state.describe())
    activation_payload = canonical_json_bytes(state.activation_ledger_document())
    headroom = {
        "clauses": O1C66_VAULT_CAPS.maximum_clauses - page.clause_count,
        "literals": O1C66_VAULT_CAPS.maximum_literals - page.literal_count,
        "serialized_bytes": O1C66_VAULT_CAPS.maximum_serialized_bytes
        - page.serialized_bytes,
    }
    union = attic.union_vault
    new_indices = tuple(
        range(GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT, ATTIC_UNION_CLAUSE_COUNT)
    )
    if (
        page_roundtrip != page
        or replayed != state
        or state.current_projection.lineage_ordinal != PAGE11_LINEAGE_ORDINAL
        or state.active_limit != PAGE11_ACTIVE_LIMIT
        or attic.active_limit != PAGE11_ACTIVE_LIMIT
        or page.sha256 != PAGE11_SHA256
        or page.clause_count != PAGE11_CLAUSE_COUNT
        or page.literal_count != PAGE11_LITERAL_COUNT
        or page.serialized_bytes != PAGE11_SERIALIZED_BYTES
        or page.describe().get("clause_aggregate_sha256")
        != PAGE11_CLAUSE_AGGREGATE_SHA256
        or state.current_projection.category_counts != PAGE11_CATEGORY_COUNTS
        or headroom != PAGE11_HEADROOM
        # This proves the current projection is inside every cap and the 258
        # clause slots cover all 256 action records.  Literal/byte residuals
        # are accounting only, not a future-emission safety guarantee.
        or O1C66_VAULT_CAPS.describe() != NATIVE_VAULT_CAPS
        or page.clause_count + headroom["clauses"] != O1C66_VAULT_CAPS.maximum_clauses
        or headroom["clauses"] < PARENT_CENTERED_ACTION_CAPACITY
        or len(attic.chunks) != ATTIC_CHUNK_COUNT
        or attic.chunks[:-1] != previous.attic.chunks
        or attic.chunks[-1] != chunk
        or attic.chunk_clause_union_indices[-1] != new_indices
        or union.clauses[: previous.attic.union_vault.clause_count]
        != previous.attic.union_vault.clauses
        or union.sha256 != ATTIC_UNION_SHA256
        or union.clause_count != ATTIC_UNION_CLAUSE_COUNT
        or union.literal_count != ATTIC_UNION_LITERAL_COUNT
        or union.serialized_bytes != ATTIC_UNION_SERIALIZED_BYTES
        or union.describe().get("clause_aggregate_sha256")
        != ATTIC_UNION_CLAUSE_AGGREGATE_SHA256
        or attic.occurrences[: len(previous.attic.occurrences)]
        != previous.attic.occurrences
        or attic.occurrences[-NEW_CHUNK_CLAUSE_COUNT:] != telemetry.occurrences
        or attic.occurrence_union_indices[-NEW_CHUNK_CLAUSE_COUNT:] != new_indices
        or len(attic.occurrences) != ATTIC_OCCURRENCE_COUNT
        or attic.duplicate_occurrence_count != ATTIC_DUPLICATE_OCCURRENCE_COUNT
        or not set(previous.attic.relations).issubset(attic.relations)
        or len(attic.relations) != ATTIC_SUBSUMPTION_RELATION_COUNT
        or len(attic.undominated_indices) != ATTIC_UNDOMINATED_CLAUSE_COUNT
        or len(occurrence_payload) != OCCURRENCE_DOCUMENT_BYTES
        or sha256_bytes(occurrence_payload) != OCCURRENCE_DOCUMENT_SHA256
        or len(relation_payload) != RELATION_DOCUMENT_BYTES
        or sha256_bytes(relation_payload) != RELATION_DOCUMENT_SHA256
        or len(residency_payload) != PAGE11_RESIDENCY_DOCUMENT_BYTES
        or sha256_bytes(residency_payload) != PAGE11_RESIDENCY_DOCUMENT_SHA256
        or len(activation_payload) != PAGE11_ACTIVATION_DOCUMENT_BYTES
        or sha256_bytes(activation_payload) != PAGE11_ACTIVATION_DOCUMENT_SHA256
        or len(state.activation_ledger) != PAGE11_ACTIVATION_COUNT
        or state.activation_ledger[:-1] != previous.activation_ledger
        or state.used_active_sha256[:-1] != previous.used_active_sha256
        or page.sha256 in previous.used_active_sha256
        or state.never_resident_undominated_indices
    ):
        raise O1C86PreparationError("Page-11 rollover contract differs")
    return state


def _validate_evolved_continuation_bank(
    capsule: Path, bank: bytes
) -> tuple[bytes, dict[str, object]]:
    receipt_path = capsule / "episodes/00/priority-state.json"
    try:
        receipt_payload = receipt_path.read_bytes()
    except OSError as exc:
        raise O1C86PreparationError("priority-state receipt is unreadable") from exc
    if (
        len(bank) != FINAL_BANK_BYTES
        or sha256_bytes(bank) != FINAL_BANK_SHA256
        or len(receipt_payload) != PRIORITY_RECEIPT_BYTES
        or sha256_bytes(receipt_payload) != PRIORITY_RECEIPT_SHA256
    ):
        raise O1C86PreparationError("evolved continuation state differs")
    receipt = _canonical_document(receipt_payload, "evolved priority-state receipt")
    operator = _mapping(receipt.get("operator"), "evolved priority operator")
    operator_accounting = _mapping(
        operator.get("state_accounting"), "evolved priority operator accounting"
    )
    accounting = _mapping(
        receipt.get("state_accounting"), "evolved priority state accounting"
    )
    probe_counters = _mapping(
        receipt.get("probe_counters"), "evolved priority probe counters"
    )
    probe_trace = _mapping(receipt.get("probe_trace"), "evolved priority probe trace")
    hexadecimal = receipt.get("bank_hex")
    if not isinstance(hexadecimal, str):
        raise O1C86PreparationError("evolved continuation bank hex differs")
    try:
        receipt_bank = bytes.fromhex(hexadecimal)
    except ValueError as exc:
        raise O1C86PreparationError("evolved continuation bank hex differs") from exc
    if (
        receipt.get("schema")
        != "o1-256-o1c85-live-parent-centered-continuation-priority-state-v1"
        or receipt.get("bank_encoding")
        != "256-variable-ordered-96-byte-records-little-endian"
        or receipt.get("bank_bytes") != FINAL_BANK_BYTES
        or receipt.get("current_bank_sha256") != FINAL_BANK_SHA256
        or receipt_bank != bank
        or receipt.get("candidate_population") != 255
        or receipt.get("candidate_order_rule")
        != "observed-key-variables-ascending;currently-unassigned-and-no-live-token"
        or receipt.get("candidate_order_sha256") != CONTINUATION_CANDIDATE_ORDER_SHA256
        or receipt.get("one_shot_rule")
        != "coordinate-consumed-on-first-return;release-does-not-rearm"
        or receipt.get("consumed_coordinate_count") != 255
        or receipt.get("assignment_literals_observed") != 10_281
        or receipt.get("parent_scans") != 430
        or receipt.get("callback_calls") != 430
        or receipt.get("nonzero_returns") != 255
        or receipt.get("zero_returns") != 175
        or receipt.get("last_parent_candidate_count") != 0
        or operator.get("schema")
        != "o1-256-o1c82-parent-centered-priority-telemetry-v1"
        or operator.get("action_semantics") != "current-lower-upper-bound-proof-mining"
        or operator.get("belief_orientation_authorized") is not False
        or operator.get("proof_mining_action_only") is not True
        or operator.get("coordinate_capacity") != PARENT_CENTERED_ACTION_CAPACITY
        or operator.get("eligible_coordinate_count") != 255
        or operator.get("minimum_eligible_count") != 37
        or operator.get("current_parent_candidate_count") != 0
        or operator_accounting
        != {
            "packed_bytes_per_coordinate": 96,
            "coordinate_state_bytes": 24_576,
            "parent_scratch_bytes": 4_096,
            "live_packed_state_bytes": 28_672,
        }
        or accounting
        != {
            "priority_bank_bytes": 24_576,
            "parent_scratch_bytes": 4_096,
            "priority_live_state_bytes": 28_672,
            "consumed_mask_bytes": 256,
            "action_capacity": 256,
            "action_record_bytes": 176,
            "action_state_bytes": 45_056,
            "growing_parent_history_bytes": 0,
        }
        or probe_counters
        != {
            "BOTH_PRUNABLE": 4,
            "NEITHER_PRUNABLE": 32_836,
            "ONE_PRUNABLE": 0,
            "ZERO_PRUNABLE": 0,
            "child_bound_evaluations": 65_680,
        }
        or probe_trace
        != {
            "bytes": 1_871_880,
            "count": 32_840,
            "encoding": (
                "u64le-call;u64le-probe;u32le-candidate-index;"
                "u32le-parent-level;i32le-variable;f64le-U0;f64le-U1;"
                "f64le-tau;u8-selection;i32le-certified-literal"
            ),
            "record_bytes": 57,
            "sha256": (
                "bb0a0e24ee5cba474efe7f37d698e72e4c46523307acad44b85104786f4186f5"
            ),
        }
    ):
        raise O1C86PreparationError("evolved continuation bank receipt differs")

    records: list[tuple[object, ...]] = []
    for variable in range(1, 257):
        offset = (variable - 1) * CONTINUATION_RECORD_BYTES
        values = CONTINUATION_RECORD.unpack_from(bank, offset)
        count = cast(int, values[0])
        raw_positive = cast(int, values[3])
        raw_zero = cast(int, values[4])
        centered_positive = cast(int, values[7])
        centered_zero = cast(int, values[8])
        floats = tuple(
            cast(float, value) for value in (*values[1:3], *values[5:7], *values[9:12])
        )
        if (
            any(not math.isfinite(value) for value in floats)
            or cast(float, values[2]) < 0.0
            or cast(float, values[6]) < 0.0
            or raw_positive + raw_zero > count
            or centered_positive + centered_zero > count
            or cast(float, values[10]) < abs(cast(float, values[9]))
            or cast(float, values[11]) < cast(float, values[10])
        ):
            raise O1C86PreparationError("evolved continuation bank record differs")
        records.append(values)
    counts = tuple(cast(int, record[0]) for record in records)
    nonzero_counts = tuple(count for count in counts if count)
    if (
        bank[240 * CONTINUATION_RECORD_BYTES : 241 * CONTINUATION_RECORD_BYTES]
        != bytes(CONTINUATION_RECORD_BYTES)
        or tuple(index + 1 for index, count in enumerate(counts) if not count) != (241,)
        or len(nonzero_counts) != 255
        or min(nonzero_counts) != 38
        or max(nonzero_counts) != 829
        or tuple(index + 1 for index, count in enumerate(counts) if count == 829)
        != (21,)
        or sum(counts) != 82_330
        or sum(count >= 37 for count in counts) != 255
    ):
        raise O1C86PreparationError("evolved continuation bank population differs")
    continuation = {
        "validation_contract": "o1c85-live-continuation-bank-with-state-receipt",
        "receipt_sha256": PRIORITY_RECEIPT_SHA256,
        "receipt_serialized_bytes": PRIORITY_RECEIPT_BYTES,
        "receipt_artifact": PRIORITY_RECEIPT_NAME,
        "encoding": receipt["bank_encoding"],
        "coordinate_record_count": len(records),
        "record_bytes": CONTINUATION_RECORD_BYTES,
        "eligible_coordinate_count": 255,
        "zero_coordinate_variables": [241],
        "minimum_nonzero_evolved_count": min(nonzero_counts),
        "maximum_evolved_count": max(nonzero_counts),
        "maximum_evolved_count_variables": [21],
        "aggregate_evolved_count": sum(counts),
        "receipt_bank_hex_byte_equal": True,
        "fresh_seed_parser_compatible": False,
        "next_action_parser_gate": (
            "require-live-continuation-parser;do-not-use-fresh-seed-parser"
        ),
    }
    return receipt_payload, continuation


def _artifact_row(payload: bytes, role: str) -> dict[str, object]:
    return {
        "role": role,
        "serialized_bytes": len(payload),
        "sha256": sha256_bytes(payload),
    }


def prepare_o1c86_page11_causal_rollover(
    *,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Validate O1C-0085 and return the exact Page-11 bundle in memory."""

    root = lab_root()
    capsule_value = (
        (root / DEFAULT_PARENT_CAPSULE_RELATIVE).resolve()
        if capsule_dir is None
        else capsule_dir
    )
    result_value = (
        (root / DEFAULT_PARENT_RESULT_RELATIVE).resolve()
        if parent_result_path is None
        else parent_result_path
    )
    capsule = _canonical_path(capsule_value, "parent capsule", directory=True)
    result_path = _canonical_path(result_value, "parent result", directory=False)
    entries = _validate_capsule_inventory(capsule)
    _validate_parent_result(capsule, result_path)
    previous = _regenerate_page10_and_validate_initial(capsule)
    telemetry = _parse_parent_telemetry(capsule, previous.state)
    chunk = _new_chunk(previous.state, telemetry)
    state = _advance_page11(previous.state, chunk, telemetry)

    bank_path = capsule / "episodes/00/final-parent-centered-priority-bank.bin"
    try:
        bank = bank_path.read_bytes()
    except OSError as exc:
        raise O1C86PreparationError(
            "evolved final priority bank is unreadable"
        ) from exc
    priority_receipt, continuation = _validate_evolved_continuation_bank(capsule, bank)
    audit_payload = previous.artifacts[_o1c85.COMMON_CORE_AUDIT_NAME]
    if (
        len(audit_payload) != COMMON_CORE_AUDIT_BYTES
        or sha256_bytes(audit_payload) != COMMON_CORE_AUDIT_SHA256
        or audit_payload
        != (capsule / "initial" / _o1c85.COMMON_CORE_AUDIT_NAME).read_bytes()
    ):
        raise O1C86PreparationError("historical common-core audit differs")

    artifacts: dict[str, bytes] = {
        NEW_CHUNK_NAME: chunk.serialized,
        ACTIVE_PROJECTION_NAME: state.active_projection.serialized,
        RESIDENCY_NAME: canonical_json_bytes(state.describe()),
        ACTIVATION_LEDGER_NAME: canonical_json_bytes(
            state.activation_ledger_document()
        ),
        OCCURRENCES_NAME: canonical_json_bytes(state.attic.occurrence_document()),
        RELATIONS_NAME: canonical_json_bytes(state.attic.relation_document()),
        COMMON_CORE_AUDIT_NAME: audit_payload,
        FINAL_BANK_NAME: bank,
        PRIORITY_RECEIPT_NAME: priority_receipt,
    }
    roles = {
        NEW_CHUNK_NAME: "immutable-all-new-lineage-23-evidence-chunk",
        ACTIVE_PROJECTION_NAME: "fresh-lineage-24-page11-science-input",
        RESIDENCY_NAME: "complete-updated-causal-residency-state",
        ACTIVATION_LEDGER_NAME: "complete-updated-replayable-activation-ledger",
        OCCURRENCES_NAME: "complete-updated-compact-witness-occurrence-ledger",
        RELATIONS_NAME: "complete-updated-strict-subsumption-closure",
        COMMON_CORE_AUDIT_NAME: "unchanged-historical-public-common-core-audit",
        FINAL_BANK_NAME: "sealed-evolved-live-continuation-bank-bytes",
        PRIORITY_RECEIPT_NAME: "canonical-o1c85-evolved-priority-state-receipt",
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
            "page11_burned": False,
            "lineage24_burned": False,
            "page10_replay_authorized": False,
            "lineage23_replay_authorized": False,
            "page9_retry_or_replay_authorized": False,
        },
        "parent": {
            "attempt_id": PARENT_ATTEMPT_ID,
            "capsule_manifest_sha256": PARENT_CAPSULE_MANIFEST_SHA256,
            "capsule_manifest_serialized_bytes": PARENT_CAPSULE_MANIFEST_BYTES,
            "capsule_entry_count": len(entries),
            "result_sha256": PARENT_RESULT_SHA256,
            "result_serialized_bytes": PARENT_RESULT_BYTES,
            "episode_sha256": PARENT_EPISODE_SHA256,
            "intent_sha256": PARENT_INTENT_SHA256,
            "preparation_manifest_sha256": PARENT_PREPARATION_MANIFEST_SHA256,
            "classification": PARENT_CLASSIFICATION,
            "stop_reason": PARENT_STOP_REASON,
            "source_lineage_ordinal": 23,
            "source_active_sha256": PAGE10_SHA256,
            "page10_burned": True,
            "lineage23_burned": True,
            "retry_or_replay_authorized": False,
            "global_novelty_baseline_clause_count": (
                GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT
            ),
            "initial_artifact_count": PARENT_INITIAL_ARTIFACT_COUNT,
            "initial_artifacts_byte_equal_to_fresh_page10_regeneration": True,
            "activation_ledger_prefix_preserved": True,
        },
        "science_boundary": {
            "imported_science_attempt_id": PARENT_ATTEMPT_ID,
            "imported_science_kind": "fully-emitted-globally-novel-clauses",
            "imported_fully_emitted_clause_count": NEW_CHUNK_CLAUSE_COUNT,
            "imported_globally_novel_clause_count": NEW_CHUNK_CLAUSE_COUNT,
            "imported_literal_count": NEW_CHUNK_LITERAL_COUNT,
            "all_sources": ["trail_upper_bound"],
            "all_classifications": ["new"],
            "page9_retry_imported": False,
            "o1c84_terminal_failure_imported_as_science": False,
            "priority_magnitude_imported_as_science": False,
        },
        "rollover": {
            "stream_id": telemetry.stream_id,
            "telemetry_sha256": telemetry.artifact_sha256,
            "telemetry_serialized_bytes": PARENT_VAULT_TELEMETRY_BYTES,
            "source_active_sha256": PAGE10_SHA256,
            "chunk_sha256": chunk.sha256,
            "clause_count": chunk.clause_count,
            "literal_count": chunk.literal_count,
            "serialized_bytes": chunk.serialized_bytes,
            "all_occurrences_new": True,
            "all_occurrences_unique": True,
            "all_occurrences_globally_novel_against_807_clause_attic": True,
            "source_counts": {"trail_upper_bound": NEW_CHUNK_CLAUSE_COUNT},
            "classification_counts": {"new": NEW_CHUNK_CLAUSE_COUNT},
            "api": (
                "advance_causal_residency(next_lineage_ordinal=24,"
                "next_active_limit=254)"
            ),
        },
        "attic": {
            "chunk_count": len(state.attic.chunks),
            "union_sha256": state.attic.union_vault.sha256,
            "union_clause_count": state.attic.union_vault.clause_count,
            "union_literal_count": state.attic.union_vault.literal_count,
            "union_serialized_bytes": state.attic.union_vault.serialized_bytes,
            "occurrence_count": len(state.attic.occurrences),
            "duplicate_occurrence_count": state.attic.duplicate_occurrence_count,
            "strict_subsumption_pair_count": len(state.attic.relations),
            "undominated_clause_count": len(state.attic.undominated_indices),
            "prior_807_clause_union_is_exact_prefix": True,
        },
        "page11": {
            "lineage_ordinal": PAGE11_LINEAGE_ORDINAL,
            "active_limit": state.active_limit,
            "active_sha256": state.active_projection.sha256,
            "clause_count": state.active_projection.clause_count,
            "literal_count": state.active_projection.literal_count,
            "serialized_bytes": state.active_projection.serialized_bytes,
            "category_counts": state.current_projection.category_counts,
            "headroom": PAGE11_HEADROOM,
            "fresh_identity": state.active_projection.sha256
            not in previous.state.used_active_sha256,
            "native_capacity_proof": {
                "caps": NATIVE_VAULT_CAPS,
                "clause_headroom_guarantee": {
                    "native_vault_maximum_clauses": NATIVE_VAULT_CAPS[
                        "maximum_clauses"
                    ],
                    "page11_input_clauses": PAGE11_CLAUSE_COUNT,
                    "maximum_additional_clauses_before_capacity_terminal": (
                        PAGE11_HEADROOM["clauses"]
                    ),
                    "parent_centered_action_capacity": (
                        PARENT_CENTERED_ACTION_CAPACITY
                    ),
                    "spare_clause_slots_beyond_action_capacity": (
                        PAGE11_HEADROOM["clauses"] - PARENT_CENTERED_ACTION_CAPACITY
                    ),
                    "proved_sufficient": True,
                },
                "recorded_residual_headroom": {
                    "literals": PAGE11_HEADROOM["literals"],
                    "serialized_bytes": PAGE11_HEADROOM["serialized_bytes"],
                },
                "literal_future_emission_safety_claimed": False,
                "serialized_byte_future_emission_safety_claimed": False,
            },
        },
        "carried_context": {
            "common_core_audit_artifact": COMMON_CORE_AUDIT_NAME,
            "common_core_audit_sha256": COMMON_CORE_AUDIT_SHA256,
            "common_core_audit_serialized_bytes": COMMON_CORE_AUDIT_BYTES,
            "common_core_audit_unchanged": True,
            "historical_failure_receipt_carried_forward": False,
        },
        "final_priority_bank": {
            "sha256": FINAL_BANK_SHA256,
            "serialized_bytes": FINAL_BANK_BYTES,
            "priority_is_key_bit_belief": False,
            "semantic_role": "sealed-evolved-live-continuation-bytes",
            **continuation,
        },
        "artifacts": {
            name: _artifact_row(payload, roles[name])
            for name, payload in sorted(artifacts.items())
        },
    }
    manifest_payload = canonical_json_bytes(manifest)
    if (
        _canonical_document(manifest_payload, "causal rollover manifest") != manifest
        or len(manifest_payload) != PREPARATION_MANIFEST_BYTES
        or sha256_bytes(manifest_payload) != PREPARATION_MANIFEST_SHA256
    ):
        raise O1C86PreparationError("causal rollover manifest differs")
    artifacts[PREPARATION_MANIFEST_NAME] = manifest_payload
    return PreparedCausalRolloverArtifacts(
        state=state,
        artifacts=artifacts,
        manifest=manifest,
    )


def preflight_o1c86_page11_causal_rollover(
    *,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Run the complete zero-call validation without publishing a directory."""

    return prepare_o1c86_page11_causal_rollover(
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )


def _validate_prepared_bundle_for_publication(
    prepared: PreparedCausalRolloverArtifacts,
) -> None:
    if not isinstance(prepared, PreparedCausalRolloverArtifacts):
        raise O1C86PreparationError("prepared Page-11 bundle differs")
    expected_names = {
        NEW_CHUNK_NAME,
        ACTIVE_PROJECTION_NAME,
        RESIDENCY_NAME,
        ACTIVATION_LEDGER_NAME,
        OCCURRENCES_NAME,
        RELATIONS_NAME,
        COMMON_CORE_AUDIT_NAME,
        FINAL_BANK_NAME,
        PRIORITY_RECEIPT_NAME,
        PREPARATION_MANIFEST_NAME,
    }
    manifest = _mapping(prepared.manifest, "prepared Page-11 manifest")
    rows = _mapping(manifest.get("artifacts"), "prepared Page-11 artifact rows")
    manifest_payload = prepared.artifacts.get(PREPARATION_MANIFEST_NAME)
    exact_artifact_seals = {
        NEW_CHUNK_NAME: (NEW_CHUNK_SERIALIZED_BYTES, NEW_CHUNK_SHA256),
        ACTIVE_PROJECTION_NAME: (PAGE11_SERIALIZED_BYTES, PAGE11_SHA256),
        RESIDENCY_NAME: (
            PAGE11_RESIDENCY_DOCUMENT_BYTES,
            PAGE11_RESIDENCY_DOCUMENT_SHA256,
        ),
        ACTIVATION_LEDGER_NAME: (
            PAGE11_ACTIVATION_DOCUMENT_BYTES,
            PAGE11_ACTIVATION_DOCUMENT_SHA256,
        ),
        OCCURRENCES_NAME: (OCCURRENCE_DOCUMENT_BYTES, OCCURRENCE_DOCUMENT_SHA256),
        RELATIONS_NAME: (RELATION_DOCUMENT_BYTES, RELATION_DOCUMENT_SHA256),
        COMMON_CORE_AUDIT_NAME: (COMMON_CORE_AUDIT_BYTES, COMMON_CORE_AUDIT_SHA256),
        FINAL_BANK_NAME: (FINAL_BANK_BYTES, FINAL_BANK_SHA256),
        PRIORITY_RECEIPT_NAME: (PRIORITY_RECEIPT_BYTES, PRIORITY_RECEIPT_SHA256),
    }
    if (
        set(prepared.artifacts) != expected_names
        or manifest.get("schema") != PREPARATION_SCHEMA
        or manifest.get("attempt_id") != ATTEMPT_ID
        or manifest_payload != canonical_json_bytes(manifest)
        or not isinstance(manifest_payload, bytes)
        or len(manifest_payload) != PREPARATION_MANIFEST_BYTES
        or sha256_bytes(manifest_payload) != PREPARATION_MANIFEST_SHA256
        or set(rows) != expected_names - {PREPARATION_MANIFEST_NAME}
        or prepared.state.active_projection.sha256 != PAGE11_SHA256
        or prepared.artifacts.get(ACTIVE_PROJECTION_NAME)
        != prepared.state.active_projection.serialized
        or prepared.artifacts.get(RESIDENCY_NAME)
        != canonical_json_bytes(prepared.state.describe())
        or prepared.artifacts.get(ACTIVATION_LEDGER_NAME)
        != canonical_json_bytes(prepared.state.activation_ledger_document())
        or prepared.artifacts.get(OCCURRENCES_NAME)
        != canonical_json_bytes(prepared.state.attic.occurrence_document())
        or prepared.artifacts.get(RELATIONS_NAME)
        != canonical_json_bytes(prepared.state.attic.relation_document())
    ):
        raise O1C86PreparationError("prepared Page-11 publication bundle differs")
    for name, (expected_bytes, expected_sha256) in exact_artifact_seals.items():
        payload = prepared.artifacts[name]
        if len(payload) != expected_bytes or sha256_bytes(payload) != expected_sha256:
            raise O1C86PreparationError("prepared Page-11 exact artifact seal differs")
    for name, row_value in rows.items():
        row = _mapping(row_value, f"prepared Page-11 artifact row {name}")
        payload = prepared.artifacts[name]
        role = row.get("role")
        if not isinstance(role, str) or not role or row != _artifact_row(payload, role):
            raise O1C86PreparationError("prepared Page-11 artifact seal differs")


def write_prepared_o1c86_page11_causal_rollover(
    prepared: PreparedCausalRolloverArtifacts, output_dir: str | Path
) -> None:
    """Atomically publish a validated Page-11 bundle to a fresh directory."""

    _validate_prepared_bundle_for_publication(prepared)
    try:
        _o1c85.write_prepared_o1c85_page10_transport_recovery(prepared, output_dir)
    except _o1c85.O1C85PreparationError as exc:
        raise O1C86PreparationError("Page-11 publication failed") from exc


def prepare_and_write_o1c86_page11_causal_rollover(
    *,
    output_dir: str | Path,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Prepare, validate, and atomically publish the Page-11 bundle."""

    prepared = prepare_o1c86_page11_causal_rollover(
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )
    write_prepared_o1c86_page11_causal_rollover(prepared, output_dir)
    return prepared


def _parser() -> argparse.ArgumentParser:
    root = lab_root()
    parser = argparse.ArgumentParser(
        description="Preflight or prepare O1C-0086's zero-call Page-11 rollover"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("preflight", "prepare"):
        child = subparsers.add_parser(command)
        child.add_argument(
            "--capsule", default=(root / DEFAULT_PARENT_CAPSULE_RELATIVE).as_posix()
        )
        child.add_argument(
            "--parent-result",
            default=(root / DEFAULT_PARENT_RESULT_RELATIVE).as_posix(),
        )
        if command == "prepare":
            child.add_argument("--output-dir", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        prepared = prepare_o1c86_page11_causal_rollover(
            capsule_dir=args.capsule,
            parent_result_path=args.parent_result,
        )
        if args.command == "prepare":
            write_prepared_o1c86_page11_causal_rollover(prepared, args.output_dir)
    except (
        O1C86PreparationError,
        CausalAtticError,
        CausalResidencyError,
    ) as exc:
        print(f"{ATTEMPT_ID}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(prepared.manifest, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ACTIVE_PROJECTION_NAME",
    "ACTIVATION_LEDGER_NAME",
    "ATTEMPT_ID",
    "ATTIC_CHUNK_COUNT",
    "ATTIC_OCCURRENCE_COUNT",
    "ATTIC_SUBSUMPTION_RELATION_COUNT",
    "ATTIC_UNDOMINATED_CLAUSE_COUNT",
    "ATTIC_UNION_CLAUSE_COUNT",
    "ATTIC_UNION_LITERAL_COUNT",
    "ATTIC_UNION_SERIALIZED_BYTES",
    "ATTIC_UNION_SHA256",
    "COMMON_CORE_AUDIT_NAME",
    "DEFAULT_PARENT_CAPSULE_RELATIVE",
    "DEFAULT_PARENT_RESULT_RELATIVE",
    "FINAL_BANK_BYTES",
    "FINAL_BANK_NAME",
    "FINAL_BANK_SHA256",
    "NEW_CHUNK_CLAUSE_COUNT",
    "NEW_CHUNK_LITERAL_COUNT",
    "NEW_CHUNK_NAME",
    "NEW_CHUNK_SERIALIZED_BYTES",
    "NEW_CHUNK_SHA256",
    "O1C86PreparationError",
    "OCCURRENCES_NAME",
    "PAGE11_ACTIVE_LIMIT",
    "PAGE11_CATEGORY_COUNTS",
    "PAGE11_CLAUSE_COUNT",
    "PAGE11_HEADROOM",
    "PAGE11_LITERAL_COUNT",
    "PAGE11_SERIALIZED_BYTES",
    "PAGE11_SHA256",
    "PARENT_CAPSULE_MANIFEST_SHA256",
    "PARENT_RESULT_SHA256",
    "PREPARATION_MANIFEST_BYTES",
    "PREPARATION_MANIFEST_NAME",
    "PREPARATION_MANIFEST_SHA256",
    "PREPARATION_SCHEMA",
    "PRIORITY_RECEIPT_BYTES",
    "PRIORITY_RECEIPT_NAME",
    "PRIORITY_RECEIPT_SHA256",
    "PreparedCausalRolloverArtifacts",
    "RELATIONS_NAME",
    "RESIDENCY_NAME",
    "main",
    "preflight_o1c86_page11_causal_rollover",
    "prepare_and_write_o1c86_page11_causal_rollover",
    "prepare_o1c86_page11_causal_rollover",
    "write_prepared_o1c86_page11_causal_rollover",
]
