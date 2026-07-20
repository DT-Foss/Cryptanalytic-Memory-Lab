"""Zero-call O1C-0079 successor preparation from O1C-0078's terminal.

O1C-0078 consumed fresh Page 5 but returned no native result.  This module
therefore imports no solver output and appends no synthetic attic chunk.  It
validates the complete sealed terminal capsule, reconstructs the Page-5 state
once, and rotates the unchanged causal attic to fresh Page 6 / lineage 19.
"""

from __future__ import annotations

import argparse
import gzip
import json
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence, cast

from .causal_attic_v1 import (
    CAUSAL_ATTIC_OCCURRENCE_SCHEMA,
    CausalAtticError,
    ClauseOccurrence,
    canonical_json_bytes,
    reproject_causal_attic,
    sha256_bytes,
)
from .causal_residency_v1 import (
    CausalResidencyError,
    CausalResidencyState,
    replay_causal_residency,
    reproject_causal_residency,
    validate_activation_replay,
)
from .o1c78_apple8_rescue_prefix_preemption_prepare import (
    O1C78PreparationError,
    _derive_rank_decision as _o1c78_derive_rank_decision,
    _publish_directory as _o1c78_publish_directory,
)
from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodClause,
    ThresholdNoGoodVaultError,
    parse_threshold_no_good_vault,
)
from .causal_attic_v1 import parse_self_scoping_vault
from .causal_frontier_v1 import (
    CAUSAL_FRONTIER_PLAN_SCHEMA,
    CausalFrontierError,
    CausalFrontierPlan,
    derive_causal_frontier_plan,
    parse_causal_frontier_plan,
    serialize_causal_frontier_plan,
    validate_causal_frontier_plan,
)
from .rescue_prefix_preemption_v1 import (
    O1C78_BASELINE_TRACE_SHA256,
    O1C78_PREFIX_LITERALS,
    RescuePrefixPreemptionError,
    RescuePrefixPreemptionPlan,
    derive_rescue_prefix_preemption_plan,
    parse_rescue_prefix_preemption_plan,
    serialize_rescue_prefix_preemption_plan,
    validate_rescue_prefix_preemption_evidence,
    validate_rescue_prefix_preemption_plan,
)
from .residual_polarity_staging_v1 import (
    RESIDUAL_POLARITY_STAGING_PLAN_SCHEMA,
    ResidualPolarityStagingError,
    ResidualPolarityStagingPlan,
    derive_residual_polarity_staging_plan,
    parse_residual_polarity_staging_plan,
    serialize_residual_polarity_staging_plan,
    validate_residual_polarity_staging_plan,
)
from .vault_ranked_decision_v1 import VaultRankedDecision


ATTEMPT_ID = "O1C-0079"
PARENT_ATTEMPT_ID = "O1C-0078"
PREPARATION_SCHEMA = "o1-256-apple8-decision-ownership-preparation-v1"
MANIFEST_SCHEMA = "o1-256-apple8-decision-ownership-manifest-v1"
ARTIFACT_SET_SCHEMA = "o1-256-apple8-decision-ownership-artifact-set-v1"
TERMINAL_RECEIPT_SCHEMA = "o1-256-o1c78-terminal-consumption-receipt-v1"
SCIENCE_HISTORY_SCHEMA = "o1-256-science-input-history-v1"
SCIENCE_INPUT_SCHEMA = "o1-256-apple8-decision-ownership-science-input-v1"
FRONTIER_PLAN_DOCUMENT_SCHEMA = (
    "o1-256-apple8-decision-ownership-frontier-plan-document-v1"
)
STAGING_PLAN_DOCUMENT_SCHEMA = (
    "o1-256-apple8-decision-ownership-staging-plan-document-v1"
)
PREFIX_PLAN_DOCUMENT_SCHEMA = "o1-256-apple8-decision-ownership-prefix-plan-document-v1"

DEFAULT_PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260720_065505_O1C-0078_apple8-rescue-prefix-preemption-v1"
)
DEFAULT_PARENT_RESULT_RELATIVE = Path(
    "research/O1C0078_APPLE8_RESCUE_PREFIX_PREEMPTION_RESULT_20260720.json"
)

CHUNK_NAMES = tuple(f"chunk-{index:02d}.vault" for index in range(10))
ACTIVE_PROJECTION_NAME = "page-06-active.bin"
OCCURRENCES_NAME = "witness-occurrences.json"
RELATIONS_NAME = "subsumption-relations.json"
ACTIVATION_LEDGER_NAME = "activation-ledger.json"
RESIDENCY_NAME = "residency.json"
TERMINAL_RECEIPT_NAME = "o1c78-terminal-receipt.json"
SCIENCE_HISTORY_NAME = "science-input-history.json"
SCIENCE_INPUT_NAME = "science-input.json"
FRONTIER_PLAN_NAME = "frontier-plan.json"
FRONTIER_PLAN_BINARY_NAME = "frontier-plan.bin"
STAGING_PLAN_NAME = "staging-plan.json"
STAGING_PLAN_BINARY_NAME = "staging-plan.bin"
PREFIX_PLAN_NAME = "prefix-plan.json"
PREFIX_PLAN_BINARY_NAME = "prefix-plan.bin"
MANIFEST_NAME = "decision-ownership-preparation-manifest.json"

FRONTIER_SOURCE_NATIVE_GZIP_RELATIVE = Path(
    "runs/20260720_013632_O1C-0076_apple8-causal-frontier-v1/"
    "episodes/00/native-result.json.gz"
)
PREFIX_SOURCE_NATIVE_GZIP_RELATIVE = Path(
    "runs/20260720_025550_O1C-0077_apple8-residual-polarity-staging-v1/"
    "episodes/00/native-result.json.gz"
)
FRONTIER_SOURCE_NATIVE_GZIP_SHA256 = (
    "0ca67f629bfc62f62d3705c74f3fef44aff3d5e4646048798a7006c722d02658"
)
FRONTIER_SOURCE_NATIVE_RAW_SHA256 = (
    "5cee812cc99b824b43b345f20b2eed253a09090a69866de2f3c4fa074c95e198"
)
FRONTIER_SOURCE_NATIVE_RAW_BYTES = 252_812
PREFIX_SOURCE_NATIVE_GZIP_SHA256 = (
    "e13e98d14af49978a8afaeebb36d4d854f21f92ffa29efcbec323e7a20ec5a15"
)
PREFIX_SOURCE_NATIVE_RAW_SHA256 = (
    "8980046510cd80417260436d73fdbe3cb24da6d233e136aff616972f92aadfd0"
)
PREFIX_SOURCE_NATIVE_RAW_BYTES = 361_499

PARENT_RESULT_SHA256 = (
    "f72821443ed7e7dd80698a39288ff31f9c8f52a120bb745e713e3b23b1822fed"
)
PARENT_CAPSULE_MANIFEST_SHA256 = (
    "5d358863162a64f27d215fc4b91258c73194d2458f89d9dd7495bb1e05e50a69"
)
PARENT_INVOCATION_SHA256 = (
    "06d74e30bcefeb97bbf631c4631353375022198dac615ae02fa69b0033f9e588"
)
PARENT_INTENT_SHA256 = (
    "50a29a3f1d5882b15981acd962c91c1efb9ab2ab90209f13f1b400860bc60853"
)
PARENT_EPISODE_SHA256 = (
    "8607130a7fc0389c21175a5a81da0de2c3327877fa8dfc7c7e10cf3166302446"
)
PARENT_TERMINAL_FAILURE_SHA256 = (
    "a84fbdf7eeea4b5195a187eb357c711ab5a6a399bf24bd14a19214c1742574bc"
)
PARENT_PREPARED_MANIFEST_SHA256 = (
    "ee1a2144b2eb30ac3f69012f4e5085de1c6f668625f85b31e73c0aa188cfd30d"
)
PARENT_SOURCE_COMMIT = "2840824b2aa482f30dfbd39060c200994fc09957"
PARENT_CLASSIFICATION = "RESCUE_PREFIX_PREEMPTION_OPERATIONAL_TERMINAL"
PARENT_STOP_REASON = "native-call-or-resource-terminal"
PARENT_FAILURE_MESSAGE = (
    "joint-score-sieve-v19 execution failed: "
    "cadical_o1_joint_score_sieve_v16: backtrack-release guided assignment "
    "sign differs"
)
PARENT_CAPSULE_ENTRY_COUNT = 33

PAGE5_SHA256 = "07c73013705898e228a05b0578b0f8090a6f094c427dbd8f32d856467b08e208"
PAGE6_SHA256 = "69bde6adc23e9e89f97581175ecb85dc9f1d94cddc6d162dfb2f93f9d60f3846"
PAGE6_CLAUSE_COUNT = 256
PAGE6_LITERAL_COUNT = 723_864
PAGE6_SERIALIZED_BYTES = 2_896_671
PAGE6_SELECTION_ORDER_SHA256 = (
    "f257f2e3c7b236434121f4f5157f0dbd21242687c0cce62868648abc5c0e4a6a"
)
PAGE6_STATE_DOCUMENT_SHA256 = (
    "71d22c10280e4afcb51a9739d58aa8d9839bc4512cbbc6a5d98bcb5a902f0caf"
)
PAGE6_ACTIVATION_LEDGER_SHA256 = (
    "2e1f346a627cd3bdace0c4171436b047af530ea4359293c51e2de4de5a5d3323"
)
UNCHANGED_UNION_SHA256 = (
    "e99682c4d0c1cfb53a2b51284d810e5a0a07dd7023672549b8435a920d688307"
)
UNCHANGED_UNION_CLAUSES = 550
UNCHANGED_UNION_LITERALS = 1_488_224
UNCHANGED_UNION_SERIALIZED_BYTES = 5_955_287
EXPECTED_CHUNK_CLAUSE_COUNTS = (202, 311, 0, 37, 0, 0, 0, 0, 0, 0)

FRONTIER_PLAN_BINARY_SHA256 = (
    "785cae9e32912e1d45858d046b36a7c7b9e4cf51799f233a7b3246aa6756ad65"
)
FRONTIER_PLAN_BINARY_BYTES = 4_479
STAGING_PLAN_BINARY_SHA256 = (
    "c536a94483467ee1197d52e0e3f81ad2f728a36ad3982124e1b9966e0011f927"
)
STAGING_PLAN_BINARY_BYTES = 4_477
PREFIX_PLAN_BINARY_SHA256 = (
    "b5debc5f55f7cbc1e728d00ce1d14d0c437249793f8c10e8b80e614a00ed155c"
)
PREFIX_PLAN_BINARY_BYTES = 44

INHERITED_SCIENCE_INPUT_SHA256 = (
    "fb7528bf1cccf76e57dfa34dd8d5b13a9c96b331dad9ebf4443e7caa45d6f2b7",
    "ccfad8b31582baf0b29506387daac84e34998848851ce37e6c072666992022e1",
    "78696f2b662beda4b371aa547350cc66b2105bc4dcaf0b982af2d1279e3012ed",
    "82b1512a393f9d595a1207253e2b623ee8ece9bd2f5b92f8283857c3dd9b2911",
    "db3acd5e6b7eb27529fd141a99865623530258f3aa2f7db6e84f03f16ecf4f0f",
    "5b459ea4a10bcb8183e5aaf1e93a91e0e7e4bfc89c58b3e65efaf8d4838c8d91",
    "b57e3091df7eca20137f4c63e3bc125aa8978c2ff183a7396de3a2a4a79acf33",
)
SCIENCE_INPUT_SHA256_HISTORY = (*INHERITED_SCIENCE_INPUT_SHA256, PAGE5_SHA256)
PARENT_USED_ACTIVE_SHA256 = (
    "78696f2b662beda4b371aa547350cc66b2105bc4dcaf0b982af2d1279e3012ed",
    "82b1512a393f9d595a1207253e2b623ee8ece9bd2f5b92f8283857c3dd9b2911",
    "db3acd5e6b7eb27529fd141a99865623530258f3aa2f7db6e84f03f16ecf4f0f",
    "5b459ea4a10bcb8183e5aaf1e93a91e0e7e4bfc89c58b3e65efaf8d4838c8d91",
    "b57e3091df7eca20137f4c63e3bc125aa8978c2ff183a7396de3a2a4a79acf33",
    PAGE5_SHA256,
)

# Frozen after the deterministic real-capsule preparation is constructed.
EXPECTED_TERMINAL_RECEIPT_SHA256 = (
    "25e89ad493f3422cc5d89998a96ee1828e3f3bde27cf485c50e695eeff601b9a"
)
EXPECTED_SCIENCE_HISTORY_SHA256 = (
    "93e9e03b2a4baa6bff87bb8e7fe0dcaa24515be76956cef0e3c18e271ba7cb72"
)
EXPECTED_FRONTIER_PLAN_DOCUMENT_SHA256 = (
    "e5c9474b5105e3c6eb38f026ba43f087c14e320f566e9efd2c8f732b80bc8e84"
)
EXPECTED_STAGING_PLAN_DOCUMENT_SHA256 = (
    "c9408efbc9880da9beb25437524288e3c1deee883e4384aff93202d90cfb629b"
)
EXPECTED_PREFIX_PLAN_DOCUMENT_SHA256 = (
    "6ad85e96e257e281469993ce9af6f750c3b9d67163f0291d114bfd3a6856408e"
)
EXPECTED_SCIENCE_INPUT_SHA256 = (
    "2c9cb3879d50d104e9c6e8d2ad64f78631f8bc1a69728b8eec93849f9ccefa2a"
)
EXPECTED_PREPARED_MANIFEST_SHA256 = (
    "17ce7568ca16fb6af01d842b9f875176ca3df11ff1ec7496d2d76ab5d2d57b4b"
)

_PARENT_RECEIPT_RELATIVE_SHA256 = {
    "result.json": PARENT_RESULT_SHA256,
    "invocation.json": PARENT_INVOCATION_SHA256,
    "episodes/00/intent.json": PARENT_INTENT_SHA256,
    "episodes/00/episode.json": PARENT_EPISODE_SHA256,
    "episodes/00/terminal-failure.json": PARENT_TERMINAL_FAILURE_SHA256,
    "initial/prepared-manifest.json": PARENT_PREPARED_MANIFEST_SHA256,
}


class O1C79PreparationError(RuntimeError):
    """A terminal receipt, residency rotation, or publication differs."""


@dataclass(frozen=True)
class PreparedDecisionOwnership:
    directory: Path
    manifest: Mapping[str, object]
    manifest_bytes: bytes
    manifest_sha256: str
    state: CausalResidencyState
    terminal_receipt: Mapping[str, object]
    science_input_history: Mapping[str, object]
    science_input: Mapping[str, object]
    frontier_plan: CausalFrontierPlan
    frontier_plan_document: Mapping[str, object]
    frontier_plan_binary: bytes
    staging_plan: ResidualPolarityStagingPlan
    staging_plan_document: Mapping[str, object]
    staging_plan_binary: bytes
    prefix_plan: RescuePrefixPreemptionPlan
    prefix_plan_document: Mapping[str, object]
    prefix_plan_binary: bytes
    rank_decision: VaultRankedDecision

    @property
    def active_projection(self):  # type: ignore[no-untyped-def]
        return self.state.active_projection


@dataclass(frozen=True)
class _SealedTerminal:
    result: Mapping[str, object]
    invocation: Mapping[str, object]
    intent: Mapping[str, object]
    episode: Mapping[str, object]
    failure: Mapping[str, object]
    prepared_manifest: Mapping[str, object]
    receipt: Mapping[str, object]


@dataclass(frozen=True)
class _PlanBundle:
    rank_decision: VaultRankedDecision
    frontier_plan: CausalFrontierPlan
    frontier_document: Mapping[str, object]
    frontier_binary: bytes
    staging_plan: ResidualPolarityStagingPlan
    staging_document: Mapping[str, object]
    staging_binary: bytes
    prefix_plan: RescuePrefixPreemptionPlan
    prefix_document: Mapping[str, object]
    prefix_binary: bytes


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise O1C79PreparationError(f"{field} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise O1C79PreparationError(f"{field} differs")
    return cast(Sequence[object], value)


def _nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise O1C79PreparationError(f"{field} differs")
    return value


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C79PreparationError(f"{field} differs")
    return value


def _regular_file(path: Path, field: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise O1C79PreparationError(f"{field} is unreadable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise O1C79PreparationError(f"{field} is not a sealed regular file")
    return path


def _sealed_directory(path: Path, field: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise O1C79PreparationError(f"{field} is unreadable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise O1C79PreparationError(f"{field} is not a sealed directory")
    try:
        return path.resolve(strict=True)
    except OSError as exc:
        raise O1C79PreparationError(f"{field} is unreadable") from exc


def _read_json_bytes(payload: bytes, field: str) -> Mapping[str, object]:
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C79PreparationError(f"{field} JSON differs") from exc
    document = _mapping(value, field)
    if canonical_json_bytes(document) != payload:
        raise O1C79PreparationError(f"{field} is not canonical")
    return document


def _parse_capsule_manifest(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise O1C79PreparationError("parent capsule manifest differs") from exc
    entries: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise O1C79PreparationError("parent capsule manifest row differs")
        digest, relative = line[:64], line[66:]
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not relative
            or relative.startswith("/")
            or ".." in Path(relative).parts
            or relative in entries
        ):
            raise O1C79PreparationError("parent capsule manifest row differs")
        entries[relative] = digest
    if len(entries) != PARENT_CAPSULE_ENTRY_COUNT:
        raise O1C79PreparationError("parent capsule manifest inventory differs")
    return entries


def _validate_capsule_inventory(capsule: Path) -> dict[str, str]:
    manifest_path = _regular_file(
        capsule / "artifacts.sha256", "parent capsule manifest"
    )
    payload = manifest_path.read_bytes()
    if sha256_bytes(payload) != PARENT_CAPSULE_MANIFEST_SHA256:
        raise O1C79PreparationError("parent capsule manifest differs")
    entries = _parse_capsule_manifest(payload)
    observed: dict[str, str] = {}
    for path in capsule.rglob("*"):
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise O1C79PreparationError("parent capsule inventory differs") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise O1C79PreparationError("parent capsule contains a symlink")
        if stat.S_ISREG(metadata.st_mode):
            relative = path.relative_to(capsule).as_posix()
            if relative != "artifacts.sha256":
                observed[relative] = sha256_bytes(path.read_bytes())
        elif not stat.S_ISDIR(metadata.st_mode):
            raise O1C79PreparationError("parent capsule contains a special file")
    if observed != entries:
        raise O1C79PreparationError("parent capsule inventory or digest differs")
    if any(
        entries.get(path) != digest
        for path, digest in _PARENT_RECEIPT_RELATIVE_SHA256.items()
    ):
        raise O1C79PreparationError("parent terminal receipt inventory differs")
    if "episodes/00/native-result.json.gz" in entries:
        raise O1C79PreparationError(
            "parent terminal unexpectedly returned native output"
        )
    return entries


def _projection_identity(value: object, field: str) -> tuple[int, str]:
    state = _mapping(value, field)
    projection = _mapping(state.get("current_projection"), f"{field} projection")
    encoding = _mapping(projection.get("encoding_only"), f"{field} projection encoding")
    return (
        _nonnegative_int(projection.get("lineage_ordinal"), f"{field} lineage"),
        _sha256(encoding.get("sha256"), f"{field} active SHA-256"),
    )


def _validate_parent_terminal(
    capsule: Path, parent_result_path: Path
) -> _SealedTerminal:
    entries = _validate_capsule_inventory(capsule)
    external_result = _regular_file(
        parent_result_path, "parent result root"
    ).read_bytes()
    capsule_result = _regular_file(
        capsule / "result.json", "parent capsule result"
    ).read_bytes()
    if (
        sha256_bytes(external_result) != PARENT_RESULT_SHA256
        or external_result != capsule_result
        or entries.get("result.json") != PARENT_RESULT_SHA256
    ):
        raise O1C79PreparationError("parent result binding differs")

    payloads = {
        "result": external_result,
        "invocation": _regular_file(
            capsule / "invocation.json", "parent invocation"
        ).read_bytes(),
        "intent": _regular_file(
            capsule / "episodes/00/intent.json", "parent intent"
        ).read_bytes(),
        "episode": _regular_file(
            capsule / "episodes/00/episode.json", "parent episode"
        ).read_bytes(),
        "failure": _regular_file(
            capsule / "episodes/00/terminal-failure.json",
            "parent terminal failure",
        ).read_bytes(),
        "prepared_manifest": _regular_file(
            capsule / "initial/prepared-manifest.json",
            "parent prepared manifest",
        ).read_bytes(),
    }
    expected_payload_sha = {
        "result": PARENT_RESULT_SHA256,
        "invocation": PARENT_INVOCATION_SHA256,
        "intent": PARENT_INTENT_SHA256,
        "episode": PARENT_EPISODE_SHA256,
        "failure": PARENT_TERMINAL_FAILURE_SHA256,
        "prepared_manifest": PARENT_PREPARED_MANIFEST_SHA256,
    }
    if any(
        sha256_bytes(payloads[name]) != digest
        for name, digest in expected_payload_sha.items()
    ):
        raise O1C79PreparationError("parent terminal receipt digest differs")
    result = _read_json_bytes(payloads["result"], "parent result")
    invocation = _read_json_bytes(payloads["invocation"], "parent invocation")
    intent = _read_json_bytes(payloads["intent"], "parent intent")
    episode = _read_json_bytes(payloads["episode"], "parent episode")
    failure = _read_json_bytes(payloads["failure"], "parent terminal failure")
    prepared_manifest = _read_json_bytes(
        payloads["prepared_manifest"], "parent prepared manifest"
    )

    bindings = _mapping(invocation.get("bindings"), "parent invocation bindings")
    resources = _mapping(result.get("resources"), "parent result resources")
    result_episodes = _sequence(result.get("episodes"), "parent result episodes")
    initial_residency = _mapping(
        invocation.get("initial_residency"), "parent initial residency"
    )
    intent_residency = _mapping(
        intent.get("residency_before"), "parent intent residency"
    )
    episode_before = _mapping(
        episode.get("residency_before"), "parent episode residency before"
    )
    episode_after = _mapping(
        episode.get("residency_after"), "parent episode residency after"
    )
    final_residency = _mapping(result.get("final_residency"), "parent final residency")
    prepared_residency = _mapping(
        prepared_manifest.get("residency"), "parent prepared residency"
    )
    terminal_from_episode = _mapping(
        episode.get("terminal_failure"), "parent episode terminal failure"
    )
    if (
        result.get("schema") != "o1-256-apple8-rescue-prefix-preemption-result-v1"
        or result.get("attempt_id") != PARENT_ATTEMPT_ID
        or result.get("source_commit") != PARENT_SOURCE_COMMIT
        or result.get("classification") != PARENT_CLASSIFICATION
        or result.get("stop_reason") != PARENT_STOP_REASON
        or result.get("publication_recovery") is not None
        or len(result_episodes) != 1
        or result_episodes[0] != episode
        or result.get("operational_failure") != failure
        or invocation.get("schema")
        != "o1-256-apple8-rescue-prefix-preemption-invocation-v1"
        or invocation.get("attempt_id") != PARENT_ATTEMPT_ID
        or bindings.get("execution_commit") != PARENT_SOURCE_COMMIT
        or bindings.get("prepared_manifest_sha256") != PARENT_PREPARED_MANIFEST_SHA256
        or invocation.get("maximum_native_solver_calls") != 1
        or invocation.get("maximum_total_requested_conflicts") != 128
        or invocation.get("requested_conflicts_per_episode") != 128
        or invocation.get("local_episode_ordinals") != [0]
        or invocation.get("lineage_call_ordinals") != [18]
        or invocation.get("retry_authorized") is not False
        or invocation.get("truth_key_bytes_read") is not False
        or intent.get("schema") != "o1-256-apple8-rescue-prefix-preemption-intent-v1"
        or intent.get("attempt_id") != PARENT_ATTEMPT_ID
        or intent.get("invocation_sha256") != PARENT_INVOCATION_SHA256
        or intent.get("local_episode_ordinal") != 0
        or intent.get("lineage_call_ordinal") != 18
        or intent.get("requested_conflicts") != 128
        or intent.get("prior_science_input_sha256")
        != sorted(INHERITED_SCIENCE_INPUT_SHA256)
        or intent.get("retry_authorized") is not False
        or intent.get("truth_key_bytes_read") is not False
        or episode.get("schema") != "o1-256-apple8-rescue-prefix-preemption-episode-v1"
        or episode.get("invocation_sha256") != PARENT_INVOCATION_SHA256
        or episode.get("intent_sha256") != PARENT_INTENT_SHA256
        or episode.get("local_episode_ordinal") != 0
        or episode.get("lineage_call_ordinal") != 18
        or episode.get("requested_conflicts") != 128
        or episode.get("completed") is not False
        or episode.get("native_call_issued") is not True
        or episode.get("native_calls_consumed") != 1
        or episode.get("billed_conflicts") is not None
        or episode.get("retry_authorized") is not False
        or terminal_from_episode != failure
        or failure.get("classification") != PARENT_CLASSIFICATION
        or failure.get("error_type") != "JointScoreSieveExecutionError"
        or failure.get("error_message") != PARENT_FAILURE_MESSAGE
        or failure.get("invocation_sha256") != PARENT_INVOCATION_SHA256
        or failure.get("intent_sha256") != PARENT_INTENT_SHA256
        or failure.get("local_episode_ordinal") != 0
        or failure.get("lineage_call_ordinal") != 18
        or failure.get("native_call_issued") is not True
        or failure.get("native_calls_consumed") != 1
        or failure.get("native_result_returned") is not False
        or failure.get("requested_conflicts_consumed") != 128
        or failure.get("fully_emitted_occurrences_retained") is not False
        or failure.get("retry_authorized") is not False
        or failure.get("truth_key_bytes_read") is not False
        or resources.get("native_solver_calls") != 1
        or resources.get("requested_conflicts") != 128
        or resources.get("billed_conflicts") is not None
        or resources.get("maximum_native_solver_calls") != 1
        or resources.get("maximum_total_requested_conflicts") != 128
        or prepared_manifest.get("attempt_id") != PARENT_ATTEMPT_ID
        or initial_residency != intent_residency
        or initial_residency != episode_before
        or initial_residency != episode_after
        or initial_residency != final_residency
        or initial_residency != prepared_residency
        or _projection_identity(initial_residency, "parent initial residency")
        != (18, PAGE5_SHA256)
    ):
        raise O1C79PreparationError("parent terminal contract differs")

    intent_active = _mapping(
        intent.get("active_input_vault"), "parent intent active input"
    )
    intent_active_artifact = _mapping(
        intent.get("active_input_artifact"), "parent intent active artifact"
    )
    episode_active = _mapping(
        episode.get("input_active_vault"), "parent episode active input"
    )
    if (
        intent_active.get("sha256") != PAGE5_SHA256
        or intent_active_artifact.get("sha256") != PAGE5_SHA256
        or intent_active_artifact.get("path") != "active-input.bin"
        or episode_active.get("sha256") != PAGE5_SHA256
        or entries.get("episodes/00/active-input.bin") != PAGE5_SHA256
        or PAGE5_SHA256 in INHERITED_SCIENCE_INPUT_SHA256
        or len(set(SCIENCE_INPUT_SHA256_HISTORY)) != len(SCIENCE_INPUT_SHA256_HISTORY)
    ):
        raise O1C79PreparationError("parent science-input consumption differs")

    receipt: dict[str, object] = {
        "schema": TERMINAL_RECEIPT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "parent_attempt_id": PARENT_ATTEMPT_ID,
        "parent_classification": PARENT_CLASSIFICATION,
        "parent_stop_reason": PARENT_STOP_REASON,
        "parent_source_commit": PARENT_SOURCE_COMMIT,
        "receipt_sha256": {
            "capsule_manifest": PARENT_CAPSULE_MANIFEST_SHA256,
            "result": PARENT_RESULT_SHA256,
            "invocation": PARENT_INVOCATION_SHA256,
            "intent": PARENT_INTENT_SHA256,
            "episode": PARENT_EPISODE_SHA256,
            "terminal_failure": PARENT_TERMINAL_FAILURE_SHA256,
            "prepared_manifest": PARENT_PREPARED_MANIFEST_SHA256,
        },
        "consumption": {
            "local_episode_ordinal": 0,
            "lineage_call_ordinal": 18,
            "science_input_sha256": PAGE5_SHA256,
            "native_call_issued": True,
            "native_calls_consumed": 1,
            "native_result_returned": False,
            "requested_conflicts": 128,
            "billed_conflicts": None,
            "retry_authorized": False,
        },
        "evidence_import": {
            "native_result_imported": False,
            "fully_emitted_occurrences_retained": False,
            "synthetic_output_created": False,
            "synthetic_chunk_created": False,
            "attic_mutated": False,
        },
        "failure": {
            "classification": PARENT_CLASSIFICATION,
            "error_type": "JointScoreSieveExecutionError",
            "error_message": PARENT_FAILURE_MESSAGE,
        },
        "retry_authorized": False,
        "truth_key_bytes_read": False,
    }
    return _SealedTerminal(
        result=result,
        invocation=invocation,
        intent=intent,
        episode=episode,
        failure=failure,
        prepared_manifest=prepared_manifest,
        receipt=receipt,
    )


def _recover_parent_state(
    capsule: Path, terminal: _SealedTerminal
) -> CausalResidencyState:
    """Reconstruct the sealed Page-5 residency exactly once."""

    from . import o1c78_apple8_rescue_prefix_preemption_run as parent_runner

    try:
        state = parent_runner._rebuild_initial_from_capsule(
            capsule,
            _mapping(
                terminal.invocation.get("initial_artifacts"),
                "parent initial artifacts",
            ),
            _mapping(
                terminal.invocation.get("initial_residency"),
                "parent initial residency",
            ),
        )
        validate_activation_replay(state)
    except Exception as exc:
        if isinstance(exc, O1C79PreparationError):
            raise
        raise O1C79PreparationError("parent Page-5 reconstruction differs") from exc
    if (
        state.describe() != terminal.invocation.get("initial_residency")
        or state.describe() != terminal.result.get("final_residency")
        or state.attic.describe() != terminal.result.get("final_attic")
        or state.active_projection.describe()
        != terminal.result.get("final_active_vault")
        or state.describe() != terminal.prepared_manifest.get("residency")
        or state.current_projection.lineage_ordinal != 18
        or state.active_projection.sha256 != PAGE5_SHA256
        or state.attic.union_vault.sha256 != UNCHANGED_UNION_SHA256
        or state.used_active_sha256 != PARENT_USED_ACTIVE_SHA256
        or tuple(chunk.clause_count for chunk in state.attic.chunks)
        != EXPECTED_CHUNK_CLAUSE_COUNTS
    ):
        raise O1C79PreparationError("parent Page-5 state differs")
    return state


def _validate_successor_state(
    state: CausalResidencyState,
    *,
    previous_state: CausalResidencyState | None = None,
) -> None:
    projection = state.current_projection.describe()
    state_payload = canonical_json_bytes(state.describe())
    ledger_payload = canonical_json_bytes(state.activation_ledger_document())
    union = state.attic.union_vault
    if (
        state.current_projection.lineage_ordinal != 19
        or state.active_projection.sha256 != PAGE6_SHA256
        or state.active_projection.clause_count != PAGE6_CLAUSE_COUNT
        or state.active_projection.literal_count != PAGE6_LITERAL_COUNT
        or state.active_projection.serialized_bytes != PAGE6_SERIALIZED_BYTES
        or projection.get("selection_order_sha256") != PAGE6_SELECTION_ORDER_SHA256
        or sha256_bytes(state_payload) != PAGE6_STATE_DOCUMENT_SHA256
        or sha256_bytes(ledger_payload) != PAGE6_ACTIVATION_LEDGER_SHA256
        or union.sha256 != UNCHANGED_UNION_SHA256
        or union.clause_count != UNCHANGED_UNION_CLAUSES
        or union.literal_count != UNCHANGED_UNION_LITERALS
        or union.serialized_bytes != UNCHANGED_UNION_SERIALIZED_BYTES
        or tuple(chunk.clause_count for chunk in state.attic.chunks)
        != EXPECTED_CHUNK_CLAUSE_COUNTS
        or state.used_active_sha256 != (*PARENT_USED_ACTIVE_SHA256, PAGE6_SHA256)
        or PAGE6_SHA256 in SCIENCE_INPUT_SHA256_HISTORY
        or PAGE5_SHA256 not in SCIENCE_INPUT_SHA256_HISTORY
        or any(
            digest not in SCIENCE_INPUT_SHA256_HISTORY
            for digest in PARENT_USED_ACTIVE_SHA256
        )
    ):
        raise O1C79PreparationError("frozen Page-6 successor differs")
    if previous_state is not None and (
        state.attic != previous_state.attic
        or state.attic.chunks != previous_state.attic.chunks
        or state.attic.occurrences != previous_state.attic.occurrences
        or state.attic.relations != previous_state.attic.relations
        or len(state.activation_ledger) != len(previous_state.activation_ledger) + 1
        or state.activation_ledger[:-1] != previous_state.activation_ledger
    ):
        raise O1C79PreparationError("successor altered immutable attic evidence")
    validate_activation_replay(state)


def _reproject_successor(
    previous_state: CausalResidencyState, *, next_lineage_ordinal: int = 19
) -> CausalResidencyState:
    if (
        not isinstance(previous_state, CausalResidencyState)
        or previous_state.current_projection.lineage_ordinal != 18
        or previous_state.active_projection.sha256 != PAGE5_SHA256
        or next_lineage_ordinal != 19
    ):
        raise O1C79PreparationError("Page-6 lineage schedule differs")
    try:
        state = reproject_causal_residency(
            previous_state.attic,
            previous_state=previous_state,
            fully_emitted_union_indices=(),
            next_lineage_ordinal=next_lineage_ordinal,
        )
    except CausalResidencyError as exc:
        raise O1C79PreparationError("Page-6 reprojection differs") from exc
    if state.active_projection.sha256 == PAGE5_SHA256:
        raise O1C79PreparationError("Page 5 cannot be reused")
    _validate_successor_state(state, previous_state=previous_state)
    return state


def _science_history_document() -> dict[str, object]:
    return {
        "schema": SCIENCE_HISTORY_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "history_order": "chronological-consumption-order",
        "science_input_count": len(SCIENCE_INPUT_SHA256_HISTORY),
        "science_input_sha256": list(SCIENCE_INPUT_SHA256_HISTORY),
        "prior_to_o1c78_sha256": list(INHERITED_SCIENCE_INPUT_SHA256),
        "o1c78_consumed_sha256": PAGE5_SHA256,
        "o1c78_consumed_lineage_ordinal": 18,
        "next_active_sha256": PAGE6_SHA256,
        "next_lineage_ordinal": 19,
        "next_active_absent_from_history": True,
        "all_history_entries_unique": True,
        "page5_replay_authorized": False,
        "retry_authorized": False,
        "truth_key_bytes_read": False,
    }


def _read_native_source(
    path: Path,
    *,
    field: str,
    expected_gzip_sha256: str,
    expected_raw_sha256: str,
    expected_raw_bytes: int,
) -> bytes:
    compressed = _regular_file(path, field).read_bytes()
    if sha256_bytes(compressed) != expected_gzip_sha256:
        raise O1C79PreparationError(f"{field} gzip differs")
    try:
        raw = gzip.decompress(compressed)
    except (OSError, EOFError) as exc:
        raise O1C79PreparationError(f"{field} gzip differs") from exc
    if len(raw) != expected_raw_bytes or sha256_bytes(raw) != expected_raw_sha256:
        raise O1C79PreparationError(f"{field} raw result differs")
    _read_json_bytes(raw, field)
    return raw


def _frontier_plan_document(plan: CausalFrontierPlan) -> dict[str, object]:
    return {
        "schema": FRONTIER_PLAN_DOCUMENT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "generic_plan_schema": CAUSAL_FRONTIER_PLAN_SCHEMA,
        "lineage_ordinal": 19,
        "plan": plan.describe(),
        "derivation": "deterministic-closest-unsatisfied-clause-on-page6",
        "source_native_gzip_sha256": FRONTIER_SOURCE_NATIVE_GZIP_SHA256,
        "source_result_sha256": FRONTIER_SOURCE_NATIVE_RAW_SHA256,
        "active_vault_sha256": PAGE6_SHA256,
        "page5_plan_bytes_copied": False,
        "native_solver_calls": 0,
        "truth_key_bytes_read": False,
    }


def _staging_plan_document(
    plan: ResidualPolarityStagingPlan,
    *,
    frontier_plan: CausalFrontierPlan,
) -> dict[str, object]:
    return {
        "schema": STAGING_PLAN_DOCUMENT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "generic_plan_schema": RESIDUAL_POLARITY_STAGING_PLAN_SCHEMA,
        "lineage_ordinal": 19,
        "plan": plan.describe(),
        "derivation": "deterministic-page6-residual-polarity-overlay",
        "source_native_gzip_sha256": FRONTIER_SOURCE_NATIVE_GZIP_SHA256,
        "source_result_sha256": FRONTIER_SOURCE_NATIVE_RAW_SHA256,
        "active_vault_sha256": PAGE6_SHA256,
        "parent_frontier_plan_sha256": frontier_plan.sha256,
        "overlay_rank_indices_zero_based": [224, 226],
        "page5_plan_bytes_copied": False,
        "native_solver_calls": 0,
        "truth_key_bytes_read": False,
    }


def _prefix_plan_document(
    plan: RescuePrefixPreemptionPlan,
    *,
    staging_plan: ResidualPolarityStagingPlan,
) -> dict[str, object]:
    return {
        "schema": PREFIX_PLAN_DOCUMENT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "generic_plan_schema": plan.describe().get("schema"),
        "lineage_ordinal": 19,
        "plan": plan.describe(),
        "derivation": "deterministic-signed-i32le-rows-with-page6-bindings",
        "source_native_gzip_sha256": PREFIX_SOURCE_NATIVE_GZIP_SHA256,
        "source_result_sha256": PREFIX_SOURCE_NATIVE_RAW_SHA256,
        "active_vault_sha256": PAGE6_SHA256,
        "parent_staging_plan_sha256": staging_plan.sha256,
        "baseline_trace_sha256": O1C78_BASELINE_TRACE_SHA256,
        "prefix_rows_content_preserved": True,
        "binary_rederived_from_rows": True,
        "page5_plan_document_copied": False,
        "retry_of_page5_authorized": False,
        "native_solver_calls": 0,
        "truth_key_bytes_read": False,
    }


def _validate_plan_bundle(state: CausalResidencyState, bundle: _PlanBundle) -> None:
    try:
        validate_causal_frontier_plan(
            bundle.frontier_plan, active_vault=state.active_projection
        )
        validate_residual_polarity_staging_plan(
            bundle.staging_plan,
            active_vault=state.active_projection,
            rank_decision=bundle.rank_decision,
        )
        validate_rescue_prefix_preemption_plan(
            bundle.prefix_plan,
            active_vault=state.active_projection,
            parent_staging_plan_sha256=bundle.staging_plan.sha256,
            baseline_trace_sha256=O1C78_BASELINE_TRACE_SHA256,
            required_prefix_literals=O1C78_PREFIX_LITERALS,
            source_result_sha256=PREFIX_SOURCE_NATIVE_RAW_SHA256,
        )
        parsed_frontier = parse_causal_frontier_plan(
            bundle.frontier_binary, active_vault=state.active_projection
        )
        parsed_staging = parse_residual_polarity_staging_plan(
            bundle.staging_binary,
            active_vault=state.active_projection,
            rank_decision=bundle.rank_decision,
        )
        parsed_prefix = parse_rescue_prefix_preemption_plan(
            bundle.prefix_binary, active_vault=state.active_projection
        )
    except (
        CausalFrontierError,
        ResidualPolarityStagingError,
        RescuePrefixPreemptionError,
    ) as exc:
        raise O1C79PreparationError("Page-6 plan validation differs") from exc
    if (
        state.active_projection.sha256 != PAGE6_SHA256
        or parsed_frontier != bundle.frontier_plan
        or parsed_staging != bundle.staging_plan
        or parsed_prefix != bundle.prefix_plan
        or bundle.frontier_plan.active_vault_sha256 != PAGE6_SHA256
        or bundle.frontier_plan.selected_active_index != 232
        or bundle.frontier_plan.selected_union_index != 526
        or bundle.frontier_plan.sha256 != FRONTIER_PLAN_BINARY_SHA256
        or bundle.frontier_plan.serialized_bytes != FRONTIER_PLAN_BINARY_BYTES
        or sha256_bytes(bundle.frontier_binary) != FRONTIER_PLAN_BINARY_SHA256
        or len(bundle.frontier_binary) != FRONTIER_PLAN_BINARY_BYTES
        or bundle.staging_plan.active_vault_sha256 != PAGE6_SHA256
        or bundle.staging_plan.parent_frontier_plan_sha256
        != bundle.frontier_plan.sha256
        or bundle.staging_plan.sha256 != STAGING_PLAN_BINARY_SHA256
        or bundle.staging_plan.serialized_bytes != STAGING_PLAN_BINARY_BYTES
        or sha256_bytes(bundle.staging_binary) != STAGING_PLAN_BINARY_SHA256
        or len(bundle.staging_binary) != STAGING_PLAN_BINARY_BYTES
        or tuple(row.rank_index for row in bundle.staging_plan.overlays) != (224, 226)
        or bundle.prefix_plan.prefix_literals != O1C78_PREFIX_LITERALS
        or bundle.prefix_plan.sha256 != PREFIX_PLAN_BINARY_SHA256
        or bundle.prefix_plan.serialized_bytes != PREFIX_PLAN_BINARY_BYTES
        or sha256_bytes(bundle.prefix_binary) != PREFIX_PLAN_BINARY_SHA256
        or len(bundle.prefix_binary) != PREFIX_PLAN_BINARY_BYTES
        or bundle.frontier_document != _frontier_plan_document(bundle.frontier_plan)
        or sha256_bytes(canonical_json_bytes(bundle.frontier_document))
        != EXPECTED_FRONTIER_PLAN_DOCUMENT_SHA256
        or bundle.staging_document
        != _staging_plan_document(
            bundle.staging_plan, frontier_plan=bundle.frontier_plan
        )
        or sha256_bytes(canonical_json_bytes(bundle.staging_document))
        != EXPECTED_STAGING_PLAN_DOCUMENT_SHA256
        or bundle.prefix_document
        != _prefix_plan_document(bundle.prefix_plan, staging_plan=bundle.staging_plan)
        or sha256_bytes(canonical_json_bytes(bundle.prefix_document))
        != EXPECTED_PREFIX_PLAN_DOCUMENT_SHA256
    ):
        raise O1C79PreparationError("frozen Page-6 plan bundle differs")


def _derive_plan_bundle(
    state: CausalResidencyState,
    *,
    frontier_source_path: Path,
    prefix_source_path: Path,
) -> _PlanBundle:
    frontier_source = _read_native_source(
        frontier_source_path,
        field="frontier/staging source",
        expected_gzip_sha256=FRONTIER_SOURCE_NATIVE_GZIP_SHA256,
        expected_raw_sha256=FRONTIER_SOURCE_NATIVE_RAW_SHA256,
        expected_raw_bytes=FRONTIER_SOURCE_NATIVE_RAW_BYTES,
    )
    prefix_source = _read_native_source(
        prefix_source_path,
        field="prefix source",
        expected_gzip_sha256=PREFIX_SOURCE_NATIVE_GZIP_SHA256,
        expected_raw_sha256=PREFIX_SOURCE_NATIVE_RAW_SHA256,
        expected_raw_bytes=PREFIX_SOURCE_NATIVE_RAW_BYTES,
    )
    try:
        rank_decision = _o1c78_derive_rank_decision(state)
        frontier_plan = derive_causal_frontier_plan(
            source_result=frontier_source,
            source_result_sha256=FRONTIER_SOURCE_NATIVE_RAW_SHA256,
            active_vault=state.active_projection,
            selected_union_indices=state.current_projection.selected_union_indices,
        )
        frontier_binary = serialize_causal_frontier_plan(frontier_plan)
        staging_plan = derive_residual_polarity_staging_plan(
            source_result=frontier_source,
            source_result_sha256=FRONTIER_SOURCE_NATIVE_RAW_SHA256,
            active_vault=state.active_projection,
            rank_decision=rank_decision,
            parent_frontier_plan_sha256=frontier_plan.sha256,
            selected_active_index=frontier_plan.selected_active_index,
            selected_union_index=frontier_plan.selected_union_index,
            overlay_rank_indices=(224, 226),
        )
        staging_binary = serialize_residual_polarity_staging_plan(staging_plan)
        prefix_plan = derive_rescue_prefix_preemption_plan(
            prefix_literals=O1C78_PREFIX_LITERALS,
            source_result=prefix_source,
            source_result_sha256=PREFIX_SOURCE_NATIVE_RAW_SHA256,
            active_vault=state.active_projection,
            parent_staging_plan_sha256=staging_plan.sha256,
            baseline_trace_sha256=O1C78_BASELINE_TRACE_SHA256,
        )
        validate_rescue_prefix_preemption_evidence(
            prefix_plan,
            source_result=prefix_source,
            source_result_sha256=PREFIX_SOURCE_NATIVE_RAW_SHA256,
            active_vault=state.active_projection,
            parent_staging_plan_sha256=staging_plan.sha256,
            baseline_trace_sha256=O1C78_BASELINE_TRACE_SHA256,
        )
        prefix_binary = serialize_rescue_prefix_preemption_plan(prefix_plan)
    except (
        O1C78PreparationError,
        CausalFrontierError,
        ResidualPolarityStagingError,
        RescuePrefixPreemptionError,
    ) as exc:
        raise O1C79PreparationError("Page-6 plan derivation differs") from exc
    bundle = _PlanBundle(
        rank_decision=rank_decision,
        frontier_plan=frontier_plan,
        frontier_document=_frontier_plan_document(frontier_plan),
        frontier_binary=frontier_binary,
        staging_plan=staging_plan,
        staging_document=_staging_plan_document(
            staging_plan, frontier_plan=frontier_plan
        ),
        staging_binary=staging_binary,
        prefix_plan=prefix_plan,
        prefix_document=_prefix_plan_document(prefix_plan, staging_plan=staging_plan),
        prefix_binary=prefix_binary,
    )
    _validate_plan_bundle(state, bundle)
    return bundle


def _science_input_document(
    *,
    state: CausalResidencyState,
    bundle: _PlanBundle,
    terminal_receipt_sha256: str,
    science_history_sha256: str,
) -> dict[str, object]:
    return {
        "schema": SCIENCE_INPUT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "lineage_call_ordinal": 19,
        "active_vault_sha256": state.active_projection.sha256,
        "rank_source_sha256": state.attic.chunks[0].sha256,
        "frontier_plan_sha256": bundle.frontier_plan.sha256,
        "frontier_plan_document_sha256": sha256_bytes(
            canonical_json_bytes(bundle.frontier_document)
        ),
        "staging_plan_sha256": bundle.staging_plan.sha256,
        "staging_plan_document_sha256": sha256_bytes(
            canonical_json_bytes(bundle.staging_document)
        ),
        "prefix_plan_sha256": bundle.prefix_plan.sha256,
        "prefix_plan_document_sha256": sha256_bytes(
            canonical_json_bytes(bundle.prefix_document)
        ),
        "prefix_order_sha256": bundle.prefix_plan.prefix_order_sha256,
        "terminal_receipt_sha256": terminal_receipt_sha256,
        "science_history_sha256": science_history_sha256,
        "page5_plan_bytes_reused": False,
        "page5_science_input_reused": False,
        "native_solver_calls": 0,
        "truth_key_bytes_read": False,
    }


def _artifact_row(payload: bytes, role: str) -> dict[str, object]:
    return {
        "role": role,
        "serialized_bytes": len(payload),
        "sha256": sha256_bytes(payload),
    }


def _publish_directory(output_dir: Path, files: Mapping[str, bytes]) -> None:
    """Reuse O1C-0078's fsync + atomic-rename publisher."""

    try:
        _o1c78_publish_directory(output_dir, files)
    except O1C78PreparationError as exc:
        raise O1C79PreparationError(str(exc)) from exc


def _build_successor(
    *,
    capsule_dir: str | Path,
    parent_result_path: str | Path,
    frontier_source_path: str | Path | None = None,
    prefix_source_path: str | Path | None = None,
) -> tuple[
    dict[str, object],
    dict[str, bytes],
    CausalResidencyState,
    _PlanBundle,
]:
    capsule = _sealed_directory(Path(capsule_dir), "parent capsule")
    parent_result = _regular_file(
        Path(parent_result_path), "parent result root"
    ).resolve(strict=True)
    terminal = _validate_parent_terminal(capsule, parent_result)
    previous_state = _recover_parent_state(capsule, terminal)
    state = _reproject_successor(previous_state)
    root = lab_root()
    bundle = _derive_plan_bundle(
        state,
        frontier_source_path=_regular_file(
            Path(frontier_source_path)
            if frontier_source_path is not None
            else root / FRONTIER_SOURCE_NATIVE_GZIP_RELATIVE,
            "frontier/staging source root",
        ).resolve(strict=True),
        prefix_source_path=_regular_file(
            Path(prefix_source_path)
            if prefix_source_path is not None
            else root / PREFIX_SOURCE_NATIVE_GZIP_RELATIVE,
            "prefix source root",
        ).resolve(strict=True),
    )

    receipt_payload = canonical_json_bytes(terminal.receipt)
    science_history = _science_history_document()
    science_history_payload = canonical_json_bytes(science_history)
    science_input = _science_input_document(
        state=state,
        bundle=bundle,
        terminal_receipt_sha256=sha256_bytes(receipt_payload),
        science_history_sha256=sha256_bytes(science_history_payload),
    )
    science_input_payload = canonical_json_bytes(science_input)
    artifacts: dict[str, bytes] = {
        **{
            name: chunk.serialized
            for name, chunk in zip(CHUNK_NAMES, state.attic.chunks, strict=True)
        },
        ACTIVE_PROJECTION_NAME: state.active_projection.serialized,
        OCCURRENCES_NAME: canonical_json_bytes(state.attic.occurrence_document()),
        RELATIONS_NAME: canonical_json_bytes(state.attic.relation_document()),
        ACTIVATION_LEDGER_NAME: canonical_json_bytes(
            state.activation_ledger_document()
        ),
        RESIDENCY_NAME: canonical_json_bytes(state.describe()),
        TERMINAL_RECEIPT_NAME: receipt_payload,
        SCIENCE_HISTORY_NAME: science_history_payload,
        SCIENCE_INPUT_NAME: science_input_payload,
        FRONTIER_PLAN_NAME: canonical_json_bytes(bundle.frontier_document),
        FRONTIER_PLAN_BINARY_NAME: bundle.frontier_binary,
        STAGING_PLAN_NAME: canonical_json_bytes(bundle.staging_document),
        STAGING_PLAN_BINARY_NAME: bundle.staging_binary,
        PREFIX_PLAN_NAME: canonical_json_bytes(bundle.prefix_document),
        PREFIX_PLAN_BINARY_NAME: bundle.prefix_binary,
    }
    roles = {
        **{name: "unchanged-immutable-causal-attic-chunk" for name in CHUNK_NAMES},
        ACTIVE_PROJECTION_NAME: "fresh-unused-page6-science-input",
        OCCURRENCES_NAME: "unchanged-complete-witness-occurrence-ledger",
        RELATIONS_NAME: "unchanged-complete-strict-subsumption-closure",
        ACTIVATION_LEDGER_NAME: "lineage19-causal-residency-ledger",
        RESIDENCY_NAME: "lineage19-complete-causal-residency-state",
        TERMINAL_RECEIPT_NAME: "sealed-o1c78-operational-terminal-receipt",
        SCIENCE_HISTORY_NAME: "complete-eight-input-consumption-history",
        SCIENCE_INPUT_NAME: "page6-cross-bound-science-input",
        FRONTIER_PLAN_NAME: "page6-derived-frontier-plan-document",
        FRONTIER_PLAN_BINARY_NAME: "page6-derived-native-frontier-plan",
        STAGING_PLAN_NAME: "page6-derived-staging-plan-document",
        STAGING_PLAN_BINARY_NAME: "page6-derived-native-staging-plan",
        PREFIX_PLAN_NAME: "page6-bound-prefix-plan-document",
        PREFIX_PLAN_BINARY_NAME: "rederived-signed-i32le-prefix-rows",
    }
    rows = {
        name: _artifact_row(payload, roles[name])
        for name, payload in sorted(artifacts.items())
    }
    projection = state.current_projection.describe()
    manifest: dict[str, object] = {
        "schema": MANIFEST_SCHEMA,
        "preparation_schema": PREPARATION_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "zero_call": {
            "native_solver_calls": 0,
            "science_calls": 0,
            "public_verification_calls": 0,
            "truth_key_bytes_read": False,
            "reveal_calls": 0,
        },
        "parent_terminal": dict(terminal.receipt),
        "projection_contract": {
            "source_lineage_ordinal": 18,
            "source_active_sha256": PAGE5_SHA256,
            "next_lineage_ordinal": 19,
            "next_active_sha256": PAGE6_SHA256,
            "next_selection_order_sha256": projection.get("selection_order_sha256"),
            "fully_emitted_union_indices": [],
            "unchanged_union_sha256": state.attic.union_vault.sha256,
            "native_result_imported": False,
            "synthetic_output_created": False,
            "synthetic_chunk_created": False,
            "same_attic_reprojected": True,
            "page5_replay_authorized": False,
            "retry_authorized": False,
        },
        "science_input_history": science_history,
        "science_input": science_input,
        "frontier_plan": dict(bundle.frontier_document),
        "staging_plan": dict(bundle.staging_document),
        "prefix_plan": dict(bundle.prefix_document),
        "residency": state.describe(),
        "artifact_set": {
            "schema": ARTIFACT_SET_SCHEMA,
            "artifact_count": len(rows),
            "artifacts": rows,
        },
    }
    return manifest, artifacts, state, bundle


def _validate_frozen_manifest_payload(payload: bytes) -> None:
    if sha256_bytes(payload) != EXPECTED_PREPARED_MANIFEST_SHA256:
        raise O1C79PreparationError(
            "frozen decision-ownership manifest identity differs"
        )


def prepare_o1c79_decision_ownership(
    *,
    capsule_dir: str | Path,
    parent_result_path: str | Path,
    output_dir: str | Path,
    frontier_source_path: str | Path | None = None,
    prefix_source_path: str | Path | None = None,
    enforce_release_contract: bool = True,
) -> dict[str, object]:
    """Publish the exact zero-call Page-6 successor from O1C-0078."""

    if enforce_release_contract is not True:
        raise O1C79PreparationError("release-contract flag must remain true")
    manifest, artifacts, _, _ = _build_successor(
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
        frontier_source_path=frontier_source_path,
        prefix_source_path=prefix_source_path,
    )
    payload = canonical_json_bytes(manifest)
    _validate_frozen_manifest_payload(payload)
    _publish_directory(Path(output_dir), {**artifacts, MANIFEST_NAME: payload})
    return manifest


def _parse_occurrence_document(
    value: object, *, clauses: tuple[ThresholdNoGoodClause, ...]
) -> tuple[ClauseOccurrence, ...]:
    document = _mapping(value, "prepared occurrence document")
    if document.get("schema") != CAUSAL_ATTIC_OCCURRENCE_SCHEMA:
        raise O1C79PreparationError("prepared occurrence schema differs")
    records = _sequence(document.get("records"), "prepared occurrence records")
    occurrences: list[ClauseOccurrence] = []
    for ordinal, raw in enumerate(records):
        row = _mapping(raw, "prepared occurrence record")
        union_index = _nonnegative_int(
            row.get("union_clause_index"), "prepared occurrence union index"
        )
        if row.get("ordinal") != ordinal or union_index >= len(clauses):
            raise O1C79PreparationError("prepared occurrence ordinal differs")
        try:
            occurrence = ClauseOccurrence(
                stream_id=cast(str, row.get("stream_id")),
                source_index=_nonnegative_int(
                    row.get("source_index"), "prepared occurrence source index"
                ),
                classification=cast(str, row.get("classification")),
                source=cast(str, row.get("source")),
                witness_score_f64le_hex=cast(str, row.get("witness_score_f64le_hex")),
                clause=clauses[union_index],
                clause_sha256=cast(str, row.get("clause_sha256")),
                witness_sha256=cast(str, row.get("witness_sha256")),
            )
        except (CausalAtticError, TypeError) as exc:
            raise O1C79PreparationError("prepared occurrence record differs") from exc
        if occurrence.describe(ordinal=ordinal, union_clause_index=union_index) != dict(
            row
        ):
            raise O1C79PreparationError("prepared occurrence record differs")
        occurrences.append(occurrence)
    if document.get("occurrence_count") != len(occurrences) or document.get(
        "unique_clause_count"
    ) != len(clauses):
        raise O1C79PreparationError("prepared occurrence ledger differs")
    return tuple(occurrences)


def _validate_embedded_documents(
    *,
    terminal_receipt: Mapping[str, object],
    science_history: Mapping[str, object],
) -> None:
    consumption = _mapping(
        terminal_receipt.get("consumption"), "prepared terminal consumption"
    )
    evidence_import = _mapping(
        terminal_receipt.get("evidence_import"), "prepared evidence import"
    )
    if (
        terminal_receipt.get("schema") != TERMINAL_RECEIPT_SCHEMA
        or terminal_receipt.get("attempt_id") != ATTEMPT_ID
        or terminal_receipt.get("parent_attempt_id") != PARENT_ATTEMPT_ID
        or terminal_receipt.get("parent_classification") != PARENT_CLASSIFICATION
        or terminal_receipt.get("parent_stop_reason") != PARENT_STOP_REASON
        or terminal_receipt.get("parent_source_commit") != PARENT_SOURCE_COMMIT
        or terminal_receipt.get("receipt_sha256")
        != {
            "capsule_manifest": PARENT_CAPSULE_MANIFEST_SHA256,
            "result": PARENT_RESULT_SHA256,
            "invocation": PARENT_INVOCATION_SHA256,
            "intent": PARENT_INTENT_SHA256,
            "episode": PARENT_EPISODE_SHA256,
            "terminal_failure": PARENT_TERMINAL_FAILURE_SHA256,
            "prepared_manifest": PARENT_PREPARED_MANIFEST_SHA256,
        }
        or consumption
        != {
            "local_episode_ordinal": 0,
            "lineage_call_ordinal": 18,
            "science_input_sha256": PAGE5_SHA256,
            "native_call_issued": True,
            "native_calls_consumed": 1,
            "native_result_returned": False,
            "requested_conflicts": 128,
            "billed_conflicts": None,
            "retry_authorized": False,
        }
        or evidence_import
        != {
            "native_result_imported": False,
            "fully_emitted_occurrences_retained": False,
            "synthetic_output_created": False,
            "synthetic_chunk_created": False,
            "attic_mutated": False,
        }
        or terminal_receipt.get("retry_authorized") is not False
        or terminal_receipt.get("truth_key_bytes_read") is not False
        or science_history != _science_history_document()
        or sha256_bytes(canonical_json_bytes(terminal_receipt))
        != EXPECTED_TERMINAL_RECEIPT_SHA256
        or sha256_bytes(canonical_json_bytes(science_history))
        != EXPECTED_SCIENCE_HISTORY_SHA256
    ):
        raise O1C79PreparationError("prepared terminal/history contract differs")


def load_prepared_decision_ownership(
    directory: str | Path, *, expected_manifest_sha256: str
) -> PreparedDecisionOwnership:
    """Validate and independently reconstruct the published Page-6 seed."""

    prepared = _sealed_directory(Path(directory), "prepared decision-ownership root")
    expected = _sha256(expected_manifest_sha256, "prepared manifest SHA-256")
    if expected != EXPECTED_PREPARED_MANIFEST_SHA256:
        raise O1C79PreparationError("prepared manifest freeze differs")
    manifest_payload = _regular_file(
        prepared / MANIFEST_NAME, "prepared manifest"
    ).read_bytes()
    if sha256_bytes(manifest_payload) != expected:
        raise O1C79PreparationError("prepared decision-ownership manifest differs")
    manifest = _read_json_bytes(manifest_payload, "prepared manifest")
    if (
        manifest.get("schema") != MANIFEST_SCHEMA
        or manifest.get("preparation_schema") != PREPARATION_SCHEMA
        or manifest.get("attempt_id") != ATTEMPT_ID
    ):
        raise O1C79PreparationError("prepared manifest contract differs")
    artifact_set = _mapping(manifest.get("artifact_set"), "prepared artifact set")
    rows = _mapping(artifact_set.get("artifacts"), "prepared artifacts")
    expected_names = set(CHUNK_NAMES) | {
        ACTIVE_PROJECTION_NAME,
        OCCURRENCES_NAME,
        RELATIONS_NAME,
        ACTIVATION_LEDGER_NAME,
        RESIDENCY_NAME,
        TERMINAL_RECEIPT_NAME,
        SCIENCE_HISTORY_NAME,
        SCIENCE_INPUT_NAME,
        FRONTIER_PLAN_NAME,
        FRONTIER_PLAN_BINARY_NAME,
        STAGING_PLAN_NAME,
        STAGING_PLAN_BINARY_NAME,
        PREFIX_PLAN_NAME,
        PREFIX_PLAN_BINARY_NAME,
    }
    actual = tuple(prepared.iterdir())
    if (
        set(rows) != expected_names
        or artifact_set.get("schema") != ARTIFACT_SET_SCHEMA
        or artifact_set.get("artifact_count") != len(expected_names)
        or {path.name for path in actual} != expected_names | {MANIFEST_NAME}
        or any(path.is_symlink() or not path.is_file() for path in actual)
    ):
        raise O1C79PreparationError("prepared directory inventory differs")
    payloads: dict[str, bytes] = {}
    for name in sorted(expected_names):
        row = _mapping(rows[name], f"prepared artifact {name}")
        payload = _regular_file(
            prepared / name, f"prepared artifact {name}"
        ).read_bytes()
        if row.get("sha256") != sha256_bytes(payload) or row.get(
            "serialized_bytes"
        ) != len(payload):
            raise O1C79PreparationError(f"prepared artifact {name} differs")
        payloads[name] = payload

    try:
        rank = parse_self_scoping_vault(payloads[CHUNK_NAMES[0]])
        chunks = [rank]
        for name in CHUNK_NAMES[1:]:
            chunks.append(
                parse_threshold_no_good_vault(
                    payloads[name],
                    observed_variables=rank.observed_variables,
                    caps=O1C66_VAULT_CAPS,
                )
            )
        union_clauses: list[ThresholdNoGoodClause] = []
        known: set[bytes] = set()
        for chunk in chunks:
            for clause in chunk.clauses:
                if clause.serialized not in known:
                    known.add(clause.serialized)
                    union_clauses.append(clause)
        occurrence_document = _read_json_bytes(
            payloads[OCCURRENCES_NAME], "prepared occurrences"
        )
        occurrences = _parse_occurrence_document(
            occurrence_document, clauses=tuple(union_clauses)
        )
        attic = reproject_causal_attic(tuple(chunks), occurrences, active_limit=256)
        residency_document = _read_json_bytes(
            payloads[RESIDENCY_NAME], "prepared residency"
        )
        state = replay_causal_residency(attic, residency_document)
        validate_activation_replay(state)
        active = parse_threshold_no_good_vault(
            payloads[ACTIVE_PROJECTION_NAME],
            observed_variables=rank.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
    except (
        CausalAtticError,
        CausalResidencyError,
        ThresholdNoGoodVaultError,
        O1C79PreparationError,
    ) as exc:
        raise O1C79PreparationError(
            "prepared decision-ownership reconstruction differs"
        ) from exc

    terminal_receipt = _read_json_bytes(
        payloads[TERMINAL_RECEIPT_NAME], "prepared terminal receipt"
    )
    science_history = _read_json_bytes(
        payloads[SCIENCE_HISTORY_NAME], "prepared science-input history"
    )
    science_input = _read_json_bytes(
        payloads[SCIENCE_INPUT_NAME], "prepared science input"
    )
    _validate_embedded_documents(
        terminal_receipt=terminal_receipt, science_history=science_history
    )
    frontier_document = _read_json_bytes(
        payloads[FRONTIER_PLAN_NAME], "prepared frontier plan"
    )
    staging_document = _read_json_bytes(
        payloads[STAGING_PLAN_NAME], "prepared staging plan"
    )
    prefix_document = _read_json_bytes(
        payloads[PREFIX_PLAN_NAME], "prepared prefix plan"
    )
    try:
        rank_decision = _o1c78_derive_rank_decision(state)
        frontier_plan = parse_causal_frontier_plan(
            payloads[FRONTIER_PLAN_BINARY_NAME],
            active_vault=state.active_projection,
        )
        staging_plan = parse_residual_polarity_staging_plan(
            payloads[STAGING_PLAN_BINARY_NAME],
            active_vault=state.active_projection,
            rank_decision=rank_decision,
        )
        prefix_plan = parse_rescue_prefix_preemption_plan(
            payloads[PREFIX_PLAN_BINARY_NAME],
            active_vault=state.active_projection,
        )
    except (
        O1C78PreparationError,
        CausalFrontierError,
        ResidualPolarityStagingError,
        RescuePrefixPreemptionError,
    ) as exc:
        raise O1C79PreparationError("prepared Page-6 plan parsing differs") from exc
    bundle = _PlanBundle(
        rank_decision=rank_decision,
        frontier_plan=frontier_plan,
        frontier_document=frontier_document,
        frontier_binary=payloads[FRONTIER_PLAN_BINARY_NAME],
        staging_plan=staging_plan,
        staging_document=staging_document,
        staging_binary=payloads[STAGING_PLAN_BINARY_NAME],
        prefix_plan=prefix_plan,
        prefix_document=prefix_document,
        prefix_binary=payloads[PREFIX_PLAN_BINARY_NAME],
    )
    _validate_plan_bundle(state, bundle)
    expected_science_input = _science_input_document(
        state=state,
        bundle=bundle,
        terminal_receipt_sha256=sha256_bytes(payloads[TERMINAL_RECEIPT_NAME]),
        science_history_sha256=sha256_bytes(payloads[SCIENCE_HISTORY_NAME]),
    )
    projection_contract = _mapping(
        manifest.get("projection_contract"), "prepared projection contract"
    )
    if (
        state.active_projection.serialized != active.serialized
        or state.describe() != residency_document
        or state.describe() != manifest.get("residency")
        or state.attic.occurrence_document() != occurrence_document
        or canonical_json_bytes(state.attic.relation_document())
        != payloads[RELATIONS_NAME]
        or canonical_json_bytes(state.activation_ledger_document())
        != payloads[ACTIVATION_LEDGER_NAME]
        or terminal_receipt != manifest.get("parent_terminal")
        or science_history != manifest.get("science_input_history")
        or science_input != expected_science_input
        or science_input != manifest.get("science_input")
        or sha256_bytes(payloads[SCIENCE_INPUT_NAME]) != EXPECTED_SCIENCE_INPUT_SHA256
        or frontier_document != manifest.get("frontier_plan")
        or staging_document != manifest.get("staging_plan")
        or prefix_document != manifest.get("prefix_plan")
        or projection_contract
        != {
            "source_lineage_ordinal": 18,
            "source_active_sha256": PAGE5_SHA256,
            "next_lineage_ordinal": 19,
            "next_active_sha256": PAGE6_SHA256,
            "next_selection_order_sha256": PAGE6_SELECTION_ORDER_SHA256,
            "fully_emitted_union_indices": [],
            "unchanged_union_sha256": UNCHANGED_UNION_SHA256,
            "native_result_imported": False,
            "synthetic_output_created": False,
            "synthetic_chunk_created": False,
            "same_attic_reprojected": True,
            "page5_replay_authorized": False,
            "retry_authorized": False,
        }
        or manifest.get("zero_call")
        != {
            "native_solver_calls": 0,
            "science_calls": 0,
            "public_verification_calls": 0,
            "truth_key_bytes_read": False,
            "reveal_calls": 0,
        }
    ):
        raise O1C79PreparationError("prepared Page-6 projection differs")
    _validate_successor_state(state)
    return PreparedDecisionOwnership(
        directory=prepared,
        manifest=dict(manifest),
        manifest_bytes=manifest_payload,
        manifest_sha256=expected,
        state=state,
        terminal_receipt=dict(terminal_receipt),
        science_input_history=dict(science_history),
        science_input=dict(science_input),
        frontier_plan=frontier_plan,
        frontier_plan_document=dict(frontier_document),
        frontier_plan_binary=payloads[FRONTIER_PLAN_BINARY_NAME],
        staging_plan=staging_plan,
        staging_plan_document=dict(staging_document),
        staging_plan_binary=payloads[STAGING_PLAN_BINARY_NAME],
        prefix_plan=prefix_plan,
        prefix_plan_document=dict(prefix_document),
        prefix_plan_binary=payloads[PREFIX_PLAN_BINARY_NAME],
        rank_decision=rank_decision,
    )


def _parser() -> argparse.ArgumentParser:
    root = lab_root()
    parser = argparse.ArgumentParser(
        description="Prepare O1C-0079's zero-call Page-6 decision-ownership seed"
    )
    parser.add_argument(
        "--capsule", default=(root / DEFAULT_PARENT_CAPSULE_RELATIVE).as_posix()
    )
    parser.add_argument(
        "--parent-result",
        default=(root / DEFAULT_PARENT_RESULT_RELATIVE).as_posix(),
    )
    parser.add_argument(
        "--frontier-source",
        default=(root / FRONTIER_SOURCE_NATIVE_GZIP_RELATIVE).as_posix(),
    )
    parser.add_argument(
        "--prefix-source",
        default=(root / PREFIX_SOURCE_NATIVE_GZIP_RELATIVE).as_posix(),
    )
    parser.add_argument("--output-dir", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        manifest = prepare_o1c79_decision_ownership(
            capsule_dir=args.capsule,
            parent_result_path=args.parent_result,
            output_dir=args.output_dir,
            frontier_source_path=args.frontier_source,
            prefix_source_path=args.prefix_source,
        )
    except (O1C79PreparationError, CausalResidencyError) as exc:
        print(f"{ATTEMPT_ID}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(manifest, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ACTIVE_PROJECTION_NAME",
    "ACTIVATION_LEDGER_NAME",
    "ATTEMPT_ID",
    "CHUNK_NAMES",
    "DEFAULT_PARENT_CAPSULE_RELATIVE",
    "DEFAULT_PARENT_RESULT_RELATIVE",
    "EXPECTED_PREPARED_MANIFEST_SHA256",
    "EXPECTED_FRONTIER_PLAN_DOCUMENT_SHA256",
    "EXPECTED_PREFIX_PLAN_DOCUMENT_SHA256",
    "EXPECTED_SCIENCE_HISTORY_SHA256",
    "EXPECTED_SCIENCE_INPUT_SHA256",
    "EXPECTED_STAGING_PLAN_DOCUMENT_SHA256",
    "EXPECTED_TERMINAL_RECEIPT_SHA256",
    "FRONTIER_PLAN_BINARY_BYTES",
    "FRONTIER_PLAN_BINARY_NAME",
    "FRONTIER_PLAN_BINARY_SHA256",
    "FRONTIER_PLAN_NAME",
    "FRONTIER_SOURCE_NATIVE_GZIP_RELATIVE",
    "INHERITED_SCIENCE_INPUT_SHA256",
    "MANIFEST_NAME",
    "O1C79PreparationError",
    "OCCURRENCES_NAME",
    "PAGE5_SHA256",
    "PAGE6_ACTIVATION_LEDGER_SHA256",
    "PAGE6_CLAUSE_COUNT",
    "PAGE6_LITERAL_COUNT",
    "PAGE6_SELECTION_ORDER_SHA256",
    "PAGE6_SERIALIZED_BYTES",
    "PAGE6_SHA256",
    "PAGE6_STATE_DOCUMENT_SHA256",
    "PARENT_CAPSULE_MANIFEST_SHA256",
    "PARENT_EPISODE_SHA256",
    "PARENT_INTENT_SHA256",
    "PARENT_INVOCATION_SHA256",
    "PARENT_PREPARED_MANIFEST_SHA256",
    "PARENT_RESULT_SHA256",
    "PARENT_TERMINAL_FAILURE_SHA256",
    "PREFIX_PLAN_BINARY_BYTES",
    "PREFIX_PLAN_BINARY_NAME",
    "PREFIX_PLAN_BINARY_SHA256",
    "PREFIX_PLAN_NAME",
    "PREFIX_SOURCE_NATIVE_GZIP_RELATIVE",
    "PreparedDecisionOwnership",
    "RELATIONS_NAME",
    "RESIDENCY_NAME",
    "SCIENCE_HISTORY_NAME",
    "SCIENCE_INPUT_NAME",
    "SCIENCE_INPUT_SHA256_HISTORY",
    "STAGING_PLAN_BINARY_BYTES",
    "STAGING_PLAN_BINARY_NAME",
    "STAGING_PLAN_BINARY_SHA256",
    "STAGING_PLAN_NAME",
    "TERMINAL_RECEIPT_NAME",
    "UNCHANGED_UNION_SHA256",
    "lab_root",
    "load_prepared_decision_ownership",
    "main",
    "prepare_o1c79_decision_ownership",
]
