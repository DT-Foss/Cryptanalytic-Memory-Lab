"""O1C-0073: one released-literal complement contrast from O1C-0072.

The target-free reader ranks 255 key variables by absolute vault vote, then by
the exact singleton grouped-upper-bound gap, then by variable number.  Its
signed literal is the sign of the vault vote; tied variable 241 is omitted.
The original stage preserves O1C-0072's immutable consume-once rank and release
policy.  Only after that rank is exhausted, every genuinely released original
literal may authorize its hard complement once, if still unassigned. O1C-0073
imports O1C-0072's sealed 202-clause vault, journals local ordinal 0 / lineage
ordinal 9, and authorizes one fresh native-v12 process with no retry, replay,
sweep, phase call, truth read, reveal, refit, MPS, or GPU work.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import resource
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Mapping, Protocol, Sequence, cast

from . import joint_score_sieve_v15 as _native_v15
from . import o1c72_apple8_vault_backtrack_release_run as _o1c72
from . import o1c71_apple8_vault_ranked_decision_run as _o1c71
from . import o1c70_apple8_vault_phase_reader_run as _o1c70
from . import vault_ranked_decision_v1 as _rank_v1
from .joint_score_grouping_v1 import COMPATIBILITY_GROUPING_BOUND_RULE
from .o1_relational_search import NativeGuidedSearchBuild, sha256_file
from .o1c37_relational_guided_search_run import _git_commit, lab_root
from .o1c59_multiblock_joint_score_sieve_run import (
    _atomic_bytes,
    _atomic_json,
    _canonical_json_bytes,
    _commit_bound_bytes,
    _memory_free_percent,
    _replace_owned_json,
)


_o1c68 = _o1c70._o1c68
_o1c67 = _o1c70._o1c67
_o1c65 = _o1c70._o1c65
_o1c66 = _o1c70._o1c66
_vault_v1 = _o1c70._vault_v1

ATTEMPT_ID = "O1C-0073"
CONFIG_SCHEMA = "o1-256-apple8-vault-release-contrast-config-v1"
PREFLIGHT_SCHEMA = "o1-256-apple8-vault-release-contrast-preflight-v1"
INVOCATION_SCHEMA = "o1-256-apple8-vault-release-contrast-invocation-v1"
INTENT_SCHEMA = "o1-256-apple8-vault-release-contrast-intent-v1"
EPISODE_SCHEMA = "o1-256-apple8-vault-release-contrast-episode-v1"
RESULT_SCHEMA = "o1-256-apple8-vault-release-contrast-result-v1"
FAILURE_EVIDENCE_SCHEMA = "o1-256-o1c73-native-failure-evidence-v1"
PUBLICATION_RECOVERY_SCHEMA = "o1-256-o1c73-publication-recovery-v1"

INVOCATION_ID = "O1C-0073-apple8-vault-release-contrast-v1-call-0009"
CAPSULE_SUFFIX = "O1C-0073_apple8-vault-release-contrast-v1"
PUBLICATION_SOURCE_NAME = "publication_source.json"
RESULT_RELATIVE = Path(
    "research/O1C0073_APPLE8_VAULT_RELEASE_CONTRAST_RESULT_20260719.json"
)
DESIGN_RELATIVE = Path(
    "research/O1C0073_APPLE8_VAULT_RELEASE_CONTRAST_DESIGN_20260719.md"
)
CONFIG_RELATIVE = Path("configs/o1c73_apple8_vault_release_contrast_v1.json")

PARENT_RESULT_RELATIVE = Path(
    "research/O1C0072_APPLE8_VAULT_BACKTRACK_RELEASE_RESULT_20260719.json"
)
PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260719_204421_O1C-0072_apple8-vault-backtrack-release-v1"
)
PARENT_RESULT_SHA256 = (
    "e441a32de808ee33e2245ea69af4e6ad6f246311e5a410b0cbab4a63dbd165d8"
)
PARENT_MANIFEST_SHA256 = (
    "83bbc2438fc33e3a61fdf5b23b589574c6a12cfaefd9fc2f0e7c4c4e84b521f8"
)
PARENT_SOURCE_COMMIT = "bf1ffaad30ac276c2fcc3b332207c5933bf96443"
PARENT_RETAINED_VAULT_RELATIVE = Path("episodes/00/vault-output.bin")
PARENT_RETAINED_VAULT_SHA256 = (
    "cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858"
)
PARENT_RETAINED_VAULT_BYTES = 2_399_911
PARENT_RETAINED_VAULT_CLAUSES = 202
PARENT_RETAINED_VAULT_LITERALS = 599_728
PARENT_RETAINED_VAULT_AGGREGATE_SHA256 = (
    "72d788d52064f4d67ea4355069df0420ecfb100656a985691ff82000794dd0e9"
)
PARENT_ATTEMPT_NATIVE_CALLS = 1
PARENT_LINEAGE_CALLS = 9
PARENT_COMPLETED_EPISODES = 1
PARENT_LAST_CONSUMED_ORDINAL = 8
PARENT_LAST_COMPLETED_ORDINAL = 8
PARENT_FAILED_ORDINAL = 2
PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS = 4_104
PARENT_FAILED_CALL_BILLED_CONFLICTS: None = None
PARENT_LINEAGE_ACTUAL_BILLED_CONFLICTS: None = None
PARENT_LAST_DECISIONS = 1_155
PARENT_LAST_PROPAGATIONS = 5_763_035
PARENT_LAST_MINIMUM_UPPER_BOUND = 19.57599384995442
PARENT_LAST_REDECISIONS = 0
MAXIMUM_COMPLEMENT_DECISIONS = 255

LOCAL_EPISODE_ORDINAL = 0
LINEAGE_CALL_ORDINAL = 9
MAXIMUM_NATIVE_SOLVER_CALLS = 1
REQUESTED_CONFLICTS = 512
TIMEOUT_SECONDS = 45.0
MEMORY_LIMIT_BYTES = 536_870_912
MAXIMUM_FAILURE_STREAM_BYTES = 1_048_576
MAXIMUM_PERSISTENT_ARTIFACT_BYTES = 67_108_864
MINIMUM_DISK_FREE_BYTES = 1_073_741_824
MINIMUM_MEMORY_FREE_PERCENT = 25
MAXIMUM_NORMALIZED_LOAD_1M = 0.75
PLANNING_RESERVED_CLAUSES = 397
PLANNING_RESERVED_LITERALS = 1_179_254
PLANNING_RESERVED_BYTES = 4_718_795
THRESHOLD = _o1c66.THRESHOLD
SEED = 0

APPLE8_CNF_SHA256 = _o1c66.APPLE8_CNF_SHA256
APPLE8_POTENTIAL_SHA256 = _o1c66.APPLE8_POTENTIAL_SHA256
GROUPING_SHA256 = _o1c66.GROUPING_SHA256

RANKED_VARIABLE_COUNT = 255
RANKED_OMITTED_VARIABLES = (241,)
RANKED_ORDER_ENCODING = _rank_v1.VAULT_RANKED_DECISION_ORDER_ENCODING
RANKED_ORDER_BYTES = 1_020
RANKED_ORDER_SHA256 = "26c0063f4eed586ef67535cccabacc07d945587a603cbb56dbb3b2225a32a2f5"
RANKED_TABLE_ENCODING = _rank_v1.VAULT_RANKED_DECISION_TABLE_ENCODING
RANKED_TABLE_BYTES = 9_180
RANKED_TABLE_SHA256 = "d3a007ebee7c515289d33be30757f769b2c1fde618fb5c6c312ea9f3509380ae"
RANK_RULE = _rank_v1.VAULT_RANKED_DECISION_SORT_RULE
SIGN_RULE = _rank_v1.VAULT_RANKED_DECISION_LITERAL_RULE
TARGET_FREE_PREFLIGHT_RELATIVE = Path(
    "research/O1C0073_TARGET_FREE_VAULT_RELEASE_CONTRAST_PREFLIGHT_20260719.json"
)
TARGET_FREE_PREFLIGHT_SCHEMA = (
    "o1-256-o1c73-target-free-vault-release-contrast-preflight-v1"
)
TARGET_FREE_PREFLIGHT_CLASSIFICATION = (
    "O1C73_TARGET_FREE_VAULT_RELEASE_CONTRAST_PREFLIGHT_PASS"
)
PUBLIC_FIXTURE_ORDER_SHA256 = (
    "74304fb799ce8ce1d8e355bb244b4c18fadec0722a4b0c4e36fcafbf69377f30"
)
PUBLIC_FIXTURE_RANK_TABLE_SHA256 = (
    "ad0656f1968a47f2cb4eb9229a8ee034bf5690b7f93224f2d19e4ef57678e6e6"
)
PUBLIC_FIXTURE_NATIVE_STABLE_BYTES = 16_356
PUBLIC_FIXTURE_NATIVE_STABLE_SHA256 = (
    "e856105aab55758924f9cdd22c9e1607b9e0f79a67f438061f6ba9c9d7bde961"
)
PUBLIC_FIXTURE_CALLBACK_SHA256 = (
    "142448052b524afe08a51ac6ccc0b6053ecd3ab64c593bdfbf22e41175731315"
)
PUBLIC_FIXTURE_DEFERRED_ASSIGNED_STATE_HEX = (
    "0500000000000000000000000000000000000000000000000000000000000000"
)
PUBLIC_FIXTURE_DEFERRED_ASSIGNED_STATE_SHA256 = (
    "aae761377f3b4f1f07d982783b902314b61a9cbe6ccfdfa96559039f07e332ed"
)
CAPACITY_RESERVATION: dict[str, object] = {
    "schema": "o1-256-o1c73-observed-envelope-capacity-reservation-v1",
    "basis_attempt": "O1C-0068",
    "basis": "one-observed-o1c68-envelope-not-formal-maximum",
    "planning_only": True,
    "formal_maximum": False,
    "input_clause_count": PARENT_RETAINED_VAULT_CLAUSES,
    "input_literal_count": PARENT_RETAINED_VAULT_LITERALS,
    "input_serialized_bytes": PARENT_RETAINED_VAULT_BYTES,
    "observed_envelope_clause_count": 195,
    "observed_envelope_literal_count": 579_526,
    "observed_envelope_serialized_bytes": 2_318_884,
    "projected_clause_count": PLANNING_RESERVED_CLAUSES,
    "projected_literal_count": PLANNING_RESERVED_LITERALS,
    "projected_serialized_bytes": PLANNING_RESERVED_BYTES,
    "maximum_clause_count": _o1c66.VAULT_MAXIMUM_CLAUSES,
    "maximum_literal_count": _o1c66.VAULT_MAXIMUM_LITERALS,
    "maximum_serialized_bytes": _o1c66.VAULT_MAXIMUM_SERIALIZED_BYTES,
    "hard_caps_fail_closed": True,
}

RANK_SOURCE_BINDING: dict[str, object] = {
    "schema": "o1-256-o1c73-vault-release-contrast-source-v1",
    "source_vault_sha256": PARENT_RETAINED_VAULT_SHA256,
    "source_vault_clause_count": PARENT_RETAINED_VAULT_CLAUSES,
    "source_vault_literal_count": PARENT_RETAINED_VAULT_LITERALS,
    "source_vault_serialized_bytes": PARENT_RETAINED_VAULT_BYTES,
    "source_vault_aggregate_clause_sha256": PARENT_RETAINED_VAULT_AGGREGATE_SHA256,
    "potential_sha256": APPLE8_POTENTIAL_SHA256,
    "grouping_sha256": GROUPING_SHA256,
    "candidate_variables": 256,
    "ranked_variable_count": RANKED_VARIABLE_COUNT,
    "omitted_zero_delta_variables": list(RANKED_OMITTED_VARIABLES),
    "rank_rule": RANK_RULE,
    "sign_rule": SIGN_RULE,
    "ranked_order_encoding": RANKED_ORDER_ENCODING,
    "ranked_order_bytes": RANKED_ORDER_BYTES,
    "ranked_order_sha256": RANKED_ORDER_SHA256,
    "ranked_table_encoding": RANKED_TABLE_ENCODING,
    "ranked_table_bytes": RANKED_TABLE_BYTES,
    "ranked_table_sha256": RANKED_TABLE_SHA256,
    "phase_calls": 0,
}

RANK_SOURCE_READER_SCHEMA = _rank_v1.VAULT_RANKED_DECISION_READER_SCHEMA
READER_SCHEMA = _native_v15.VAULT_RANKED_DECISION_READER_SCHEMA
READER_OPERATOR = "vault-ranked-once-then-released-opposite-once"
READER_SPEC_SHA256 = _rank_v1.VAULT_RANKED_DECISION_SPEC_SHA256
CONTRAST_POLICY_SPEC_BYTES = _native_v15.VAULT_RELEASE_CONTRAST_POLICY_SPEC_BYTES
CONTRAST_POLICY_SPEC_SHA256 = (
    _native_v15.VAULT_RELEASE_CONTRAST_POLICY_SPEC_SHA256
)

NATIVE_RESULT_SCHEMA = _native_v15.JOINT_SCORE_SIEVE_RESULT_SCHEMA
NATIVE_IMPLEMENTATION_PARENT_SCHEMA = (
    _native_v15.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
)
NATIVE_ADAPTER_SCHEMA = _native_v15.JOINT_SCORE_SIEVE_ADAPTER_SCHEMA
NATIVE_LEDGER_SCHEMA = _native_v15.O1C67_VAULT_SOFT_CONFLICT_LEDGER_SCHEMA
NATIVE_VAULT_TELEMETRY_SCHEMA = _o1c67.NATIVE_VAULT_TELEMETRY_SCHEMA
NATIVE_DECISION_TELEMETRY_SCHEMA = (
    "o1-256-cadical-vault-release-contrast-ranked-decision-telemetry-v1"
)

PUBLIC_EXACT_RECOVERY = "PUBLIC_EXACT_RECOVERY"
VAULT_RELEASE_CONTRAST_NOVEL_CLAUSE_GAIN = (
    "EPISODIC_VAULT_ACTIVE_RELEASE_CONTRAST_NOVEL_EXCLUSION_GAIN"
)
VAULT_RELEASE_CONTRAST_NO_GAIN = (
    "EPISODIC_VAULT_ACTIVE_RELEASE_CONTRAST_NO_GAIN"
)
THRESHOLD_REGION_EXHAUSTED = "EPISODIC_VAULT_THRESHOLD_REGION_EXHAUSTED"
CAPACITY_TERMINAL = "EPISODIC_VAULT_CAPACITY_TERMINAL"
OPERATIONAL_TERMINAL = "EPISODIC_VAULT_RELEASE_CONTRAST_OPERATIONAL_TERMINAL"
INVALID_RESULT_TERMINAL = "EPISODIC_VAULT_RELEASE_CONTRAST_INVALID_RESULT"

SOURCE_RELATIVES = {
    "runner": "src/o1_crypto_lab/o1c73_apple8_vault_release_contrast_run.py",
    "joint_score_sieve_v15": "src/o1_crypto_lab/joint_score_sieve_v15.py",
    "joint_score_sieve_v14": "src/o1_crypto_lab/joint_score_sieve_v14.py",
    "joint_score_sieve_v13": "src/o1_crypto_lab/joint_score_sieve_v13.py",
    "vault_ranked_decision_v1": "src/o1_crypto_lab/vault_ranked_decision_v1.py",
    "native_source": "native/cadical_o1_joint_score_sieve_v12.cpp",
    "native_release_predecessor_source": "native/cadical_o1_joint_score_sieve_v11.cpp",
    "native_rank_predecessor_source": "native/cadical_o1_joint_score_sieve_v10.cpp",
    "native_parent_source": "native/cadical_o1_joint_score_sieve_v6.cpp",
    "o1c72_runner": "src/o1_crypto_lab/o1c72_apple8_vault_backtrack_release_run.py",
    "o1c71_runner": "src/o1_crypto_lab/o1c71_apple8_vault_ranked_decision_run.py",
    "o1c70_runner": "src/o1_crypto_lab/o1c70_apple8_vault_phase_reader_run.py",
    "o1c67_runner": (
        "src/o1_crypto_lab/o1c67_apple8_episodic_vault_continuation_run.py"
    ),
    "o1c66_runner": "src/o1_crypto_lab/o1c66_apple8_episodic_vault_run.py",
    "o1c65_runner": "src/o1_crypto_lab/o1c65_apple8_width6_grouped_run.py",
    "joint_score_grouping_v1": "src/o1_crypto_lab/joint_score_grouping_v1.py",
    "threshold_no_good_vault_v1": ("src/o1_crypto_lab/threshold_no_good_vault_v1.py"),
    "lifecycle_helpers": "src/o1_crypto_lab/o1c59_multiblock_joint_score_sieve_run.py",
    "chacha_trace": "src/o1_crypto_lab/chacha_trace.py",
    "full256_broker": "src/o1_crypto_lab/full256_broker.py",
    "design": DESIGN_RELATIVE.as_posix(),
}
SOURCE_NAMES = tuple(SOURCE_RELATIVES)
CONFIG_FIELDS = {
    "schema",
    "attempt_id",
    "slug",
    "claim_level",
    "hypothesis",
    "prediction",
    "source",
    "apple8_baseline_attempt_id",
    "apple8_baseline_sha256",
    "grouping_provenance",
    "input",
    "parent",
    "retained_vault",
    "release_contrast",
    "invocation",
    "native",
    "budgets",
    "capacity_reservation",
    "rank_source",
    "target_free_gates",
    "next_action",
}


class O1C73RunError(RuntimeError):
    """O1C-0073 provenance, protocol, reader, or result differs."""


class O1C73ParentError(O1C73RunError):
    """The sealed O1C-0072 parent or retained vault differs."""


class EpisodeInvoker(Protocol):
    def __call__(
        self, local_ordinal: int, lineage_ordinal: int, vault: Path, /
    ) -> object:
        """Make the one authorized fresh native-v12 process call."""


@dataclass(frozen=True)
class ImportedParentVault:
    source_path: Path
    payload: bytes
    independent: _o1c66.ClauseVault
    adapter: _vault_v1.ThresholdNoGoodVault
    ranked_decision: _rank_v1.VaultRankedDecision


@dataclass(frozen=True)
class SingleContinuationOutcome:
    classification: str
    stop_reason: str
    episode: Mapping[str, object]
    final_vault: _o1c66.ClauseVault
    native_calls: int
    requested_conflicts: int
    billed_conflicts: int | None
    operational_failure: Mapping[str, object] | None


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise O1C73RunError(f"{field} must be an object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise O1C73RunError(f"{field} must be an array")
    return cast(Sequence[object], value)


def _nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise O1C73RunError(f"{field} differs")
    return value


def _finite_float(value: object, field: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        raise O1C73RunError(f"{field} differs")
    return float(value)


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C73RunError(f"{field} differs")
    return value


def _digest_or_pending(value: object, field: str) -> str:
    if value == "PENDING":
        return "PENDING"
    return _sha256(value, field)


def _relative(root: Path, value: object, field: str) -> Path:
    if not isinstance(value, str):
        raise O1C73RunError(f"{field} differs")
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise O1C73RunError(f"{field} escapes the lab")
    try:
        path = (root / candidate).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise O1C73RunError(f"{field} cannot be resolved") from exc
    if not path.is_relative_to(root):
        raise O1C73RunError(f"{field} escapes the lab")
    return path


def _read_json(path: Path, field: str) -> Mapping[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise O1C73RunError(f"{field} cannot be read") from exc
    return _mapping(value, field)


def _validate_reader(value: object, field: str = "reader") -> dict[str, object]:
    """Validate the exact production rank plus release-contrast binding."""

    reader = _mapping(value, field)
    expected_fields = {
        "schema",
        "operator",
        "implementation_release_parent_schema",
        "source_vault_sha256",
        "suffix_canonical_records_sha256",
        "vote_field_sha256",
        "potential_sha256",
        "potential_source_sha256",
        "grouping_sha256",
        "grouping_width_cap",
        "key_variable_count",
        "observed_variable_count",
        "candidate_count",
        "vote_rule",
        "bound_rule",
        "gap_rule",
        "sort_rule",
        "literal_rule",
        "reader_spec_bytes",
        "reader_spec_sha256",
        "contrast_policy_spec_bytes",
        "contrast_policy_spec_sha256",
        "order_encoding",
        "ranked_literals",
        "order_bytes",
        "order_sha256",
        "rank_table_encoding",
        "rank_table_rows",
        "rank_table_bytes",
        "rank_table_sha256",
    }
    literals_raw = reader.get("ranked_literals")
    literals = (
        tuple(literals_raw)
        if isinstance(literals_raw, list)
        and all(type(literal) is int for literal in literals_raw)
        else ()
    )
    packed = b"".join(struct.pack("<i", literal) for literal in literals)
    if (
        set(reader) != expected_fields
        or reader.get("schema") != READER_SCHEMA
        or reader.get("operator") != READER_OPERATOR
        or reader.get("implementation_release_parent_schema")
        != _native_v15.JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
        or reader.get("source_vault_sha256") != PARENT_RETAINED_VAULT_SHA256
        or reader.get("suffix_canonical_records_sha256")
        != _rank_v1.PRODUCTION_SUFFIX_CANONICAL_RECORDS_SHA256
        or reader.get("vote_field_sha256") != _rank_v1.PRODUCTION_VOTE_FIELD_SHA256
        or reader.get("potential_sha256") != APPLE8_POTENTIAL_SHA256
        or reader.get("potential_source_sha256")
        != _rank_v1.PRODUCTION_POTENTIAL_SOURCE_SHA256
        or reader.get("grouping_sha256") != GROUPING_SHA256
        or reader.get("grouping_width_cap") != 6
        or reader.get("key_variable_count") != 256
        or reader.get("observed_variable_count") != 2_981
        or reader.get("candidate_count") != RANKED_VARIABLE_COUNT
        or reader.get("vote_rule") != _rank_v1.VAULT_RANKED_DECISION_VOTE_RULE
        or reader.get("bound_rule") != _rank_v1.VAULT_RANKED_DECISION_BOUND_RULE
        or reader.get("gap_rule") != _rank_v1.VAULT_RANKED_DECISION_GAP_RULE
        or reader.get("sort_rule") != RANK_RULE
        or reader.get("literal_rule") != SIGN_RULE
        or reader.get("reader_spec_bytes")
        != len(_rank_v1.vault_ranked_decision_spec_bytes())
        or reader.get("reader_spec_sha256") != READER_SPEC_SHA256
        or reader.get("contrast_policy_spec_bytes") != CONTRAST_POLICY_SPEC_BYTES
        or reader.get("contrast_policy_spec_sha256")
        != CONTRAST_POLICY_SPEC_SHA256
        or reader.get("order_encoding") != RANKED_ORDER_ENCODING
        or len(literals) != RANKED_VARIABLE_COUNT
        or len({abs(literal) for literal in literals}) != RANKED_VARIABLE_COUNT
        or any(literal == 0 or abs(literal) > 256 for literal in literals)
        or abs(241) in {abs(literal) for literal in literals}
        or reader.get("order_bytes") != RANKED_ORDER_BYTES
        or len(packed) != RANKED_ORDER_BYTES
        or hashlib.sha256(packed).hexdigest() != RANKED_ORDER_SHA256
        or reader.get("order_sha256") != RANKED_ORDER_SHA256
        or reader.get("rank_table_encoding") != RANKED_TABLE_ENCODING
        or reader.get("rank_table_rows") != RANKED_VARIABLE_COUNT
        or reader.get("rank_table_bytes") != RANKED_TABLE_BYTES
        or reader.get("rank_table_sha256") != RANKED_TABLE_SHA256
    ):
        raise O1C73RunError(f"{field} release-contrast binding differs")
    return dict(reader)


def _release_reader_binding(
    decision: _rank_v1.VaultRankedDecision,
    field: str = "reader",
) -> dict[str, object]:
    """Promote the frozen rank binding to v12's release-contrast schema."""

    try:
        source = decision.reader_binding()
        _o1c71._validate_reader(source, f"{field}.rank_source")
    except Exception as exc:
        raise O1C73RunError(f"{field} rank source differs") from exc
    promoted = dict(source)
    promoted.pop("zero_delta_count")
    promoted.pop("unobserved_nonzero_count")
    promoted["schema"] = READER_SCHEMA
    promoted["operator"] = READER_OPERATOR
    promoted["implementation_release_parent_schema"] = (
        _native_v15.JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
    )
    promoted["contrast_policy_spec_bytes"] = CONTRAST_POLICY_SPEC_BYTES
    promoted["contrast_policy_spec_sha256"] = CONTRAST_POLICY_SPEC_SHA256
    return _validate_reader(promoted, field)


APPLE8_BASELINE_SHA256 = dict(_o1c70.FROZEN_APPLE8_SHA256)


def _baseline_compat_config(config: Mapping[str, object]) -> dict[str, object]:
    """Return a nonmutating legacy-key view for inherited APPLE8 validators."""

    if "frozen_sha256" in config:
        raise O1C73RunError("legacy frozen_sha256 is forbidden in O1C-0073")
    baseline = _mapping(config.get("apple8_baseline_sha256"), "apple8_baseline_sha256")
    if config.get("apple8_baseline_attempt_id") != "APPLE-VIEW-0008-MATCHED":
        raise O1C73RunError("APPLE8 baseline attempt differs")
    compatibility = dict(config)
    compatibility.pop("apple8_baseline_attempt_id", None)
    compatibility.pop("apple8_baseline_sha256", None)
    compatibility["frozen_sha256"] = dict(baseline)
    return compatibility


def validate_apple8_baseline(root: Path, config: Mapping[str, object]) -> object:
    """Call the inherited validator through an isolated compatibility mapping."""

    compatibility = _baseline_compat_config(config)
    try:
        return _o1c65.validate_apple8_baseline(root, compatibility)
    except Exception as exc:
        raise O1C73RunError("frozen positive APPLE8 input differs") from exc


def validate_grouping_provenance(
    root: Path, config: Mapping[str, object]
) -> Mapping[str, object]:
    compatibility = _baseline_compat_config(config)
    try:
        return _o1c65.validate_grouping_provenance(root, compatibility)
    except Exception as exc:
        raise O1C73RunError("APPLE-VIEW-0009 grouping provenance differs") from exc


def _validate_release_config(value: object) -> dict[str, object]:
    row = _mapping(value, "release_contrast")
    expected_fields = {
        "schema",
        "operator",
        "reader_spec_sha256",
        "contrast_policy_spec_bytes",
        "contrast_policy_spec_sha256",
        "ranked_order_sha256",
        "ranked_table_sha256",
        "ranked_variable_count",
        "omitted_zero_delta_variables",
        "rank_rule",
        "sign_rule",
        "phase_calls",
        "rank_sweep_authorized",
        "original_rank_monotone_cursor",
        "original_assigned_before_opportunity_consumed",
        "original_return_each_candidate_at_most_once",
        "original_released_literal_reasserted",
        "original_rank_exhausted_before_contrast",
        "contrast_requires_genuine_original_release",
        "contrast_literal_rule",
        "contrast_requires_unassigned_variable",
        "assigned_contrast_policy",
        "contrast_return_each_released_candidate_at_most_once",
        "maximum_original_decisions",
        "maximum_complement_decisions",
        "same_signed_redecision_authorized",
    }
    spec = _digest_or_pending(
        row.get("reader_spec_sha256"), "release_contrast.reader_spec_sha256"
    )
    contrast_spec = _digest_or_pending(
        row.get("contrast_policy_spec_sha256"),
        "release_contrast.contrast_policy_spec_sha256",
    )
    contrast_bytes = row.get("contrast_policy_spec_bytes")
    if (
        set(row) != expected_fields
        or row.get("schema") != READER_SCHEMA
        or row.get("operator") != READER_OPERATOR
        or (spec != "PENDING" and spec != READER_SPEC_SHA256)
        or (
            contrast_bytes != "PENDING"
            and contrast_bytes != CONTRAST_POLICY_SPEC_BYTES
        )
        or (
            contrast_spec != "PENDING"
            and contrast_spec != CONTRAST_POLICY_SPEC_SHA256
        )
        or row.get("ranked_order_sha256") != RANKED_ORDER_SHA256
        or row.get("ranked_table_sha256") != RANKED_TABLE_SHA256
        or row.get("ranked_variable_count") != RANKED_VARIABLE_COUNT
        or row.get("omitted_zero_delta_variables") != list(RANKED_OMITTED_VARIABLES)
        or row.get("rank_rule") != RANK_RULE
        or row.get("sign_rule") != SIGN_RULE
        or row.get("phase_calls") != 0
        or row.get("rank_sweep_authorized") is not False
        or row.get("original_rank_monotone_cursor") is not True
        or row.get("original_assigned_before_opportunity_consumed") is not True
        or row.get("original_return_each_candidate_at_most_once") is not True
        or row.get("original_released_literal_reasserted") is not False
        or row.get("original_rank_exhausted_before_contrast") is not True
        or row.get("contrast_requires_genuine_original_release") is not True
        or row.get("contrast_literal_rule")
        != "hard-complement=-released-original-literal"
        or row.get("contrast_requires_unassigned_variable") is not True
        or row.get("assigned_contrast_policy")
        != "bounded-scan-skip-and-retain-pending"
        or row.get("contrast_return_each_released_candidate_at_most_once")
        is not True
        or row.get("maximum_original_decisions") != RANKED_VARIABLE_COUNT
        or row.get("maximum_complement_decisions")
        != MAXIMUM_COMPLEMENT_DECISIONS
        or row.get("same_signed_redecision_authorized") is not False
    ):
        raise O1C73RunError("release-contrast config differs")
    return dict(row)


def load_config(path: str | Path) -> dict[str, object]:
    """Load the exact O1C-0073 protocol without a call or filesystem write."""

    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C73RunError("config escapes the lab")
    config = dict(_read_json(config_path, "O1C73 config"))
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "source.expected_sha256")
    baseline = _mapping(config.get("apple8_baseline_sha256"), "apple8_baseline_sha256")
    grouping = _mapping(config.get("grouping_provenance"), "grouping_provenance")
    input_row = _mapping(config.get("input"), "input")
    parent = _mapping(config.get("parent"), "parent")
    retained = _mapping(config.get("retained_vault"), "retained_vault")
    rank_source = _mapping(config.get("rank_source"), "rank_source")
    invocation = _mapping(config.get("invocation"), "invocation")
    native = _mapping(config.get("native"), "native")
    budgets = _mapping(config.get("budgets"), "budgets")
    target_free = _mapping(config.get("target_free_gates"), "target_free_gates")
    validate_capacity_reservation(config.get("capacity_reservation"))
    _validate_release_config(config.get("release_contrast"))
    if (
        set(config) != CONFIG_FIELDS
        or config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "apple8-vault-release-contrast-v1"
        or config.get("claim_level") != "TEST"
        or not isinstance(config.get("hypothesis"), str)
        or not isinstance(config.get("prediction"), str)
        or not isinstance(config.get("next_action"), str)
        or set(source) != {*SOURCE_NAMES, "expected_sha256"}
        or set(expected) != set(SOURCE_NAMES)
        or any(
            source.get(name) != relative for name, relative in SOURCE_RELATIVES.items()
        )
        or config.get("apple8_baseline_attempt_id") != "APPLE-VIEW-0008-MATCHED"
        or dict(baseline) != APPLE8_BASELINE_SHA256
        or "frozen_sha256" in config
        or grouping.get("source_attempt") != "APPLE-VIEW-0009"
        or grouping.get("result")
        != "research/APPLE_VIEW_0009_EXACT_GROUPED_BOUND_RESULT_20260719.json"
        or grouping.get("result_sha256")
        != "ebbe9e308f3e3dfa00685a9c10eba6554c85e453459178a26a03b9fc6b2b3728"
        or grouping.get("classification")
        != "PUBLIC_EXACT_GROUPED_BOUND_STRICTLY_DOMINATES_PAIR_RELAXATION_NO_SEARCH_CLAIM"
        or grouping.get("native_solver_calls") != 0
        or grouping.get("truth_bytes_read") is not False
        or grouping.get("native_integration_validated") is not False
        or input_row.get("apple8_result")
        != "research/apple_view_8/apple_view_8_matched_result.json"
        or input_row.get("apple8_capsule")
        != "runs/20260719_095509_APPLE-VIEW-0008-MATCHED_crossblock-consequence-sieve-v1"
        or input_row.get("cnf_relative")
        != "artifacts/cnf/full256-eight-block-apple-view-0008.cnf"
        or input_row.get("potential_relative")
        != "artifacts/potential/primary-eight-block.potential"
        or input_row.get("cnf_sha256") != APPLE8_CNF_SHA256
        or input_row.get("potential_sha256") != APPLE8_POTENTIAL_SHA256
        or input_row.get("threshold") != THRESHOLD
        or input_row.get("seed") != SEED
        or any(
            input_row.get(name) != 0
            for name in (
                "fresh_targets",
                "scientific_entropy_calls",
                "fresh_reveal_calls",
                "refits",
            )
        )
        or parent.get("attempt_id") != "O1C-0072"
        or parent.get("result") != PARENT_RESULT_RELATIVE.as_posix()
        or parent.get("result_sha256") != PARENT_RESULT_SHA256
        or parent.get("capsule") != PARENT_CAPSULE_RELATIVE.as_posix()
        or parent.get("manifest_sha256") != PARENT_MANIFEST_SHA256
        or parent.get("source_commit") != PARENT_SOURCE_COMMIT
        or parent.get("classification")
        != _o1c72.VAULT_BACKTRACK_RELEASE_MECHANISM_WORK_GAIN
        or parent.get("native_calls_consumed") != PARENT_ATTEMPT_NATIVE_CALLS
        or parent.get("lineage_calls_consumed") != PARENT_LINEAGE_CALLS
        or parent.get("completed_episodes") != PARENT_COMPLETED_EPISODES
        or parent.get("last_consumed_ordinal") != PARENT_LAST_CONSUMED_ORDINAL
        or parent.get("last_completed_ordinal") != PARENT_LAST_COMPLETED_ORDINAL
        or parent.get("failed_ordinal") != PARENT_FAILED_ORDINAL
        or parent.get("known_completed_billed_conflicts")
        != PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS
        or parent.get("failed_call_billed_conflicts") is not None
        or parent.get("lineage_actual_billed_conflicts") is not None
        or parent.get("decisions") != PARENT_LAST_DECISIONS
        or parent.get("propagations") != PARENT_LAST_PROPAGATIONS
        or parent.get("minimum_upper_bound") != PARENT_LAST_MINIMUM_UPPER_BOUND
        or parent.get("redecisions") != PARENT_LAST_REDECISIONS
        or parent.get("retry_authorized") is not False
        or parent.get("truth_key_bytes_read") is not False
        or retained.get("path") != PARENT_RETAINED_VAULT_RELATIVE.as_posix()
        or retained.get("sha256") != PARENT_RETAINED_VAULT_SHA256
        or retained.get("serialized_bytes") != PARENT_RETAINED_VAULT_BYTES
        or retained.get("clause_count") != PARENT_RETAINED_VAULT_CLAUSES
        or retained.get("literal_count") != PARENT_RETAINED_VAULT_LITERALS
        or retained.get("aggregate_clause_sha256")
        != PARENT_RETAINED_VAULT_AGGREGATE_SHA256
        or retained.get("copy_into_capsule_as") != "vault-imported.bin"
        or retained.get("dual_parse_required") is not True
        or dict(rank_source) != RANK_SOURCE_BINDING
        or invocation.get("invocation_id") != INVOCATION_ID
        or invocation.get("local_episode_ordinal") != LOCAL_EPISODE_ORDINAL
        or invocation.get("lineage_call_ordinal") != LINEAGE_CALL_ORDINAL
        or invocation.get("continuation_calls_before") != 0
        or invocation.get("lineage_calls_before") != PARENT_LINEAGE_CALLS
        or invocation.get("parent_last_consumed_ordinal")
        != PARENT_LAST_CONSUMED_ORDINAL
        or invocation.get("parent_ordinal_replay_authorized") is not False
        or invocation.get("episode_is_retry") is not False
        or invocation.get("shortcut_authorized") is not False
        or invocation.get("rank_sweep_authorized") is not False
        or invocation.get("horizon_sweep_authorized") is not False
        or native.get("maximum_native_solver_calls") != MAXIMUM_NATIVE_SOLVER_CALLS
        or native.get("requested_conflicts") != REQUESTED_CONFLICTS
        or native.get("billing_rule") != "actual-nonnegative-solve-conflicts"
        or native.get("timeout_seconds") != TIMEOUT_SECONDS
        or native.get("memory_limit_bytes") != MEMORY_LIMIT_BYTES
        or native.get("seed") != SEED
        or native.get("result_schema") != NATIVE_RESULT_SCHEMA
        or native.get("implementation_parent_schema")
        != NATIVE_IMPLEMENTATION_PARENT_SCHEMA
        or native.get("adapter_schema") != NATIVE_ADAPTER_SCHEMA
        or native.get("ledger_schema") != NATIVE_LEDGER_SCHEMA
        or native.get("vault_telemetry_schema") != NATIVE_VAULT_TELEMETRY_SCHEMA
        or native.get("decision_telemetry_schema") != NATIVE_DECISION_TELEMETRY_SCHEMA
        or (
            native.get("contrast_policy_spec_bytes") != "PENDING"
            and native.get("contrast_policy_spec_bytes")
            != CONTRAST_POLICY_SPEC_BYTES
        )
        or native.get("maximum_complement_decisions")
        != MAXIMUM_COMPLEMENT_DECISIONS
        or native.get("precommitted_frontier_gain_rule")
        != "status-20-frozen-threshold-region-exhaustion-only"
        or native.get("pair_count_or_low_work_alone_is_gain") is not False
        or native.get("ranked_order_sha256") != RANKED_ORDER_SHA256
        or native.get("ranked_table_sha256") != RANKED_TABLE_SHA256
        or native.get("fresh_process") is not True
        or "maximum_billed_conflicts" in native
        or "maximum_conflict_limit_overshoot" in native
        or budgets.get("maximum_native_solver_calls") != MAXIMUM_NATIVE_SOLVER_CALLS
        or budgets.get("maximum_requested_conflicts") != REQUESTED_CONFLICTS
        or budgets.get("maximum_failure_stream_bytes") != MAXIMUM_FAILURE_STREAM_BYTES
        or budgets.get("maximum_persistent_artifact_bytes")
        != MAXIMUM_PERSISTENT_ARTIFACT_BYTES
        or budgets.get("minimum_disk_free_bytes") != MINIMUM_DISK_FREE_BYTES
        or budgets.get("minimum_memory_free_percent") != MINIMUM_MEMORY_FREE_PERCENT
        or budgets.get("maximum_normalized_load_1m") != MAXIMUM_NORMALIZED_LOAD_1M
        or any(
            budgets.get(name) != 0
            for name in (
                "maximum_fresh_targets",
                "maximum_scientific_entropy_calls",
                "maximum_fresh_reveal_calls",
                "maximum_refits",
                "maximum_mps_calls",
                "maximum_gpu_calls",
            )
        )
        or target_free.get("final_preflight")
        != TARGET_FREE_PREFLIGHT_RELATIVE.as_posix()
        or target_free.get("final_preflight_schema") != TARGET_FREE_PREFLIGHT_SCHEMA
        or target_free.get("required_before_science") is not True
        or target_free.get("public_fixture_required") is not True
        or target_free.get("release_contrast_fixture_required") is not True
        or target_free.get("deterministic_native_repeats_required") is not True
        or target_free.get("deterministic_adapter_repeats_required") is not True
        or target_free.get("rank_source_identity_required") is not True
        or target_free.get("one_call_no_sweep_required") is not True
    ):
        raise O1C73RunError("frozen O1C-0073 config differs")
    for name in SOURCE_NAMES:
        _digest_or_pending(expected[name], f"source.expected_sha256.{name}")
    for name in (
        "final_preflight_sha256",
        "reader_spec_sha256",
        "contrast_policy_spec_sha256",
        "public_fixture_sha256",
        "deterministic_native_repeat_sha256",
        "deterministic_adapter_repeat_sha256",
    ):
        _digest_or_pending(target_free.get(name), f"target_free_gates.{name}")
    configured_spec = _digest_or_pending(
        native.get("reader_spec_sha256"), "native.reader_spec_sha256"
    )
    if configured_spec != "PENDING" and configured_spec != READER_SPEC_SHA256:
        raise O1C73RunError("native reader specification differs")
    configured_contrast_spec = _digest_or_pending(
        native.get("contrast_policy_spec_sha256"),
        "native.contrast_policy_spec_sha256",
    )
    if (
        configured_contrast_spec != "PENDING"
        and configured_contrast_spec != CONTRAST_POLICY_SPEC_SHA256
    ):
        raise O1C73RunError("native release-contrast policy specification differs")
    source_native = _digest_or_pending(
        native.get("expected_source_sha256"), "native.expected_source_sha256"
    )
    executable = _digest_or_pending(
        native.get("expected_executable_sha256"),
        "native.expected_executable_sha256",
    )
    if source_native != expected["native_source"] or executable == "":
        raise O1C73RunError("native source/executable binding differs")
    return config


def validate_capacity_reservation(value: object) -> dict[str, object]:
    """Validate the conservative observed-envelope reservation before a call."""

    capacity = _mapping(value, "capacity_reservation")
    if dict(capacity) != CAPACITY_RESERVATION:
        raise O1C73RunError("capacity reservation differs")
    projected_clauses = _nonnegative_int(
        capacity["projected_clause_count"], "projected clause count"
    )
    projected_literals = _nonnegative_int(
        capacity["projected_literal_count"], "projected literal count"
    )
    projected_bytes = _nonnegative_int(
        capacity["projected_serialized_bytes"], "projected serialized bytes"
    )
    maximum_clauses = _nonnegative_int(
        capacity["maximum_clause_count"], "maximum clause count"
    )
    maximum_literals = _nonnegative_int(
        capacity["maximum_literal_count"], "maximum literal count"
    )
    maximum_bytes = _nonnegative_int(
        capacity["maximum_serialized_bytes"], "maximum serialized bytes"
    )
    if (
        projected_clauses > maximum_clauses
        or projected_literals > maximum_literals
        or projected_bytes > maximum_bytes
    ):
        raise O1C73RunError("capacity reservation exceeds a hard vault cap")
    return dict(capacity)


def _manifest_inventory(capsule: Path) -> dict[str, str]:
    manifest = capsule / "artifacts.sha256"
    if sha256_file(manifest) != PARENT_MANIFEST_SHA256:
        raise O1C73ParentError("O1C-0072 manifest identity differs")
    inventory: dict[str, str] = {}
    try:
        for line in manifest.read_text(encoding="ascii").splitlines():
            digest, separator, relative = line.partition("  ")
            if separator != "  " or relative in inventory:
                raise O1C73ParentError("O1C-0072 manifest syntax differs")
            _sha256(digest, "O1C-0072 manifest digest")
            path = Path(relative)
            if path.is_absolute() or ".." in path.parts:
                raise O1C73ParentError("O1C-0072 manifest path escapes")
            inventory[relative] = digest
    except (OSError, UnicodeError, ValueError) as exc:
        raise O1C73ParentError("O1C-0072 manifest cannot be read") from exc
    return inventory


def _parse_bound_vault(
    payload: bytes,
    *,
    frozen: object,
    expected_sha256: str,
    expected_clauses: int,
    expected_literals: int,
    expected_aggregate_sha256: str,
    field: str,
) -> tuple[_o1c66.ClauseVault, _vault_v1.ThresholdNoGoodVault]:
    """Parse one frozen vault through both independent implementations."""

    frozen_field = cast(object, getattr(frozen, "field"))
    observed_tuple = tuple(
        cast(Sequence[int], getattr(frozen_field, "observed_variables"))
    )
    observed = frozenset(observed_tuple)
    try:
        independent = _o1c66.ClauseVault.from_bytes(
            payload,
            expected_identity=_o1c66.frozen_vault_identity(frozen_field),  # type: ignore[arg-type]
            observed_variables=observed,
        )
        adapter = _vault_v1.parse_threshold_no_good_vault(
            payload,
            observed_variables=observed_tuple,
            caps=_vault_v1.O1C66_VAULT_CAPS,
        )
        expected_identity = _vault_v1.vault_identity_from_sources(
            cnf_sha256=APPLE8_CNF_SHA256,
            potential_sha256=APPLE8_POTENTIAL_SHA256,
            grouping_sha256=GROUPING_SHA256,
            observed_variables=observed_tuple,
            bound_rule=COMPATIBILITY_GROUPING_BOUND_RULE,
            threshold=THRESHOLD,
        )
        _vault_v1.validate_threshold_no_good_vault_identity(
            adapter, expected=expected_identity
        )
    except Exception as exc:
        raise O1C73ParentError(f"{field} dual parse differs") from exc
    if (
        independent.to_bytes() != payload
        or adapter.serialized != payload
        or independent.sha256 != adapter.sha256
        or independent.sha256 != expected_sha256
        or len(independent.clauses) != expected_clauses
        or independent.literal_count != expected_literals
        or independent.aggregate_clause_sha256 != expected_aggregate_sha256
    ):
        raise O1C73ParentError(f"{field} parsers disagree")
    return independent, adapter


def _derive_ranked_decision(
    *, root: Path, vault_payload: bytes, frozen: object
) -> _rank_v1.VaultRankedDecision:
    """Reproduce the exact production rank from frozen target-free inputs."""

    del root
    try:
        frozen_grouping = cast(_o1c65.FrozenGrouping, frozen)
        potential_payload = frozen_grouping.field.to_bytes()
        grouping_payload = frozen_grouping.grouping.serialized
        decision = _rank_v1.derive_production_vault_ranked_decision(
            vault_payload,
            potential_payload,
            grouping_payload,
        )
        _rank_v1.validate_production_vault_ranked_decision(decision)
        rank_reader = decision.reader_binding()
    except Exception as exc:
        raise O1C73ParentError("production vault-ranked decision differs") from exc
    rows = decision.rows
    literals = decision.ranked_literals
    omitted = decision.zero_delta_variables + decision.unobserved_nonzero_variables
    if (
        hashlib.sha256(potential_payload).hexdigest() != APPLE8_POTENTIAL_SHA256
        or len(rows) != RANKED_VARIABLE_COUNT
        or len(literals) != RANKED_VARIABLE_COUNT
        or omitted != RANKED_OMITTED_VARIABLES
        or decision.order_sha256 != RANKED_ORDER_SHA256
        or len(decision.order_bytes) != RANKED_ORDER_BYTES
        or decision.rank_table_sha256 != RANKED_TABLE_SHA256
        or len(decision.rank_table_bytes) != RANKED_TABLE_BYTES
        or decision.spec_sha256 != READER_SPEC_SHA256
        or _o1c71._validate_reader(rank_reader, "derived O1C71 rank binding")
        != dict(rank_reader)
        or _release_reader_binding(decision, "derived release reader").get(
            "contrast_policy_spec_sha256"
        )
        != CONTRAST_POLICY_SPEC_SHA256
        or any(getattr(row, "delta") == 0 for row in rows)
        or any(
            literal
            != (
                getattr(row, "variable")
                if getattr(row, "delta") > 0
                else -getattr(row, "variable")
            )
            for literal, row in zip(literals, rows)
        )
    ):
        raise O1C73ParentError("production vault-ranked decision seal differs")
    return decision


def validate_parent_and_import_vault(
    root: Path, config: Mapping[str, object], frozen: object
) -> ImportedParentVault:
    """Verify O1C-0072 and import its exact retained 202-clause vault."""

    del config
    result_path = root / PARENT_RESULT_RELATIVE
    capsule = root / PARENT_CAPSULE_RELATIVE
    if (
        sha256_file(result_path) != PARENT_RESULT_SHA256
        or not capsule.is_dir()
        or capsule.is_symlink()
    ):
        raise O1C73ParentError("O1C-0072 parent identity differs")
    result = _read_json(result_path, "O1C-0072 result")
    episode = _mapping(result.get("episode"), "O1C-0072 episode")
    final_vault = _mapping(result.get("final_vault"), "O1C-0072 final vault")
    resources = _mapping(result.get("resources"), "O1C-0072 resources")
    parent = _mapping(result.get("parent"), "O1C-0072 lineage parent")
    claim = _mapping(result.get("claim_boundary"), "O1C-0072 claim boundary")
    eligible = _mapping(episode.get("eligible_emitted"), "O1C-0072 eligible emitted")
    work = _mapping(episode.get("work_and_resources"), "O1C-0072 work")
    decision = _mapping(episode.get("decision_telemetry"), "O1C-0072 decision")
    if (
        result.get("attempt_id") != "O1C-0072"
        or result.get("classification")
        != _o1c72.VAULT_BACKTRACK_RELEASE_MECHANISM_WORK_GAIN
        or result.get("source_commit") != PARENT_SOURCE_COMMIT
        or result.get("capsule") != PARENT_CAPSULE_RELATIVE.as_posix()
        or result.get("local_episode_ordinal") != 0
        or result.get("lineage_call_ordinal") != 8
        or episode.get("completed") is not True
        or episode.get("native_calls_consumed") != 1
        or episode.get("billed_conflicts") != 512
        or episode.get("output_vault_archived") is not True
        or episode.get("output_vault_sidecar")
        != PARENT_RETAINED_VAULT_RELATIVE.as_posix()
        or eligible.get("novel_clause_count") != 0
        or episode.get("retry_authorized") is not False
        or work.get("decisions") != PARENT_LAST_DECISIONS
        or work.get("propagations") != PARENT_LAST_PROPAGATIONS
        or work.get("minimum_upper_bound") != PARENT_LAST_MINIMUM_UPPER_BOUND
        or decision.get("redecisions") != PARENT_LAST_REDECISIONS
        or decision.get("cursor") != RANKED_VARIABLE_COUNT
        or decision.get("rows_consumed") != RANKED_VARIABLE_COUNT
        or decision.get("once_returns") != RANKED_VARIABLE_COUNT
        or decision.get("released_guided") != RANKED_VARIABLE_COUNT
        or decision.get("skipped_preassigned") != 0
        or decision.get("mechanism_validated") is not True
        or decision.get("guided_release_observed") is not True
        or decision.get("solver_phase_calls") != 0
        or resources.get("native_solver_calls") != 1
        or resources.get("billed_conflicts") != 512
        or resources.get("lineage_known_completed_billed_conflicts")
        != PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS
        or resources.get("lineage_actual_billed_conflicts") is not None
        or resources.get("parent_known_completed_billed_conflicts") != 3_592
        or parent.get("known_completed_billed_conflicts") != 3_592
        or parent.get("failed_call_billed_conflicts") is not None
        or claim.get("truth_key_bytes_read") is not False
        or final_vault.get("sha256") != PARENT_RETAINED_VAULT_SHA256
        or final_vault.get("serialized_bytes") != PARENT_RETAINED_VAULT_BYTES
        or final_vault.get("clause_count") != PARENT_RETAINED_VAULT_CLAUSES
        or final_vault.get("literal_count") != PARENT_RETAINED_VAULT_LITERALS
        or final_vault.get("aggregate_clause_sha256")
        != PARENT_RETAINED_VAULT_AGGREGATE_SHA256
    ):
        raise O1C73ParentError("O1C-0072 terminal evidence differs")
    inventory = _manifest_inventory(capsule)
    required = {
        PARENT_RETAINED_VAULT_RELATIVE.as_posix(): PARENT_RETAINED_VAULT_SHA256,
        "result.json": PARENT_RESULT_SHA256,
    }
    if any(inventory.get(name) != digest for name, digest in required.items()):
        raise O1C73ParentError("O1C-0072 manifest inventory differs")
    for relative, digest in required.items():
        if sha256_file(capsule / relative) != digest:
            raise O1C73ParentError("O1C-0072 capsule artifact differs")

    source = capsule / PARENT_RETAINED_VAULT_RELATIVE
    try:
        status = source.stat(follow_symlinks=False)
        if (
            source.is_symlink()
            or not stat.S_ISREG(status.st_mode)
            or status.st_size != PARENT_RETAINED_VAULT_BYTES
        ):
            raise O1C73ParentError("retained vault file identity differs")
        payload = source.read_bytes()
    except O1C73ParentError:
        raise
    except OSError as exc:
        raise O1C73ParentError("retained vault cannot be read") from exc
    if hashlib.sha256(payload).hexdigest() != PARENT_RETAINED_VAULT_SHA256:
        raise O1C73ParentError("retained vault hash differs")

    independent, adapter = _parse_bound_vault(
        payload,
        frozen=frozen,
        expected_sha256=PARENT_RETAINED_VAULT_SHA256,
        expected_clauses=PARENT_RETAINED_VAULT_CLAUSES,
        expected_literals=PARENT_RETAINED_VAULT_LITERALS,
        expected_aggregate_sha256=PARENT_RETAINED_VAULT_AGGREGATE_SHA256,
        field="retained vault",
    )
    ranked_decision = _derive_ranked_decision(
        root=root, vault_payload=payload, frozen=frozen
    )
    return ImportedParentVault(
        source_path=source,
        payload=payload,
        independent=independent,
        adapter=adapter,
        ranked_decision=ranked_decision,
    )


def _source_hashes(root: Path, config: Mapping[str, object]) -> dict[str, str]:
    source = _mapping(config["source"], "source")
    return {
        name: sha256_file(_relative(root, source[name], f"source.{name}"))
        for name in SOURCE_NAMES
    }


def _selected_sources_clean(
    root: Path, config_path: Path, config: Mapping[str, object]
) -> bool:
    source = _mapping(config["source"], "source")
    paths = [
        config_path,
        *(_relative(root, source[name], name) for name in SOURCE_NAMES),
    ]
    final_gate = root / TARGET_FREE_PREFLIGHT_RELATIVE
    if final_gate.exists():
        paths.append(final_gate)
    relatives = [path.relative_to(root).as_posix() for path in paths]
    completed = subprocess.run(
        ["git", "status", "--porcelain", "--", *relatives],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.returncode == 0 and not completed.stdout.strip()


def _validate_final_target_free_preflight(
    value: Mapping[str, object], config: Mapping[str, object]
) -> dict[str, object]:
    """Validate fixture, repeatability, identity, and one-call/no-sweep gates."""

    reader = _validate_reader(value.get("reader_binding"), "gate reader binding")
    rank_source = _mapping(value.get("rank_source"), "gate rank source")
    fixture = _mapping(value.get("public_fixture"), "gate public fixture")
    native_repeat = _mapping(
        value.get("deterministic_native_repeats"), "gate native repeats"
    )
    adapter_repeat = _mapping(
        value.get("deterministic_adapter_repeats"), "gate adapter repeats"
    )
    protocol = _mapping(value.get("protocol"), "gate protocol")
    truth = _mapping(value.get("truth_boundary"), "gate truth boundary")
    gates = _mapping(config.get("target_free_gates"), "target_free_gates")
    source = _mapping(config.get("source"), "source")
    expected_sources = _mapping(
        source.get("expected_sha256"), "source.expected_sha256"
    )
    native_config = _mapping(config.get("native"), "native")

    def compact_sha256(item: Mapping[str, object]) -> str:
        return hashlib.sha256(
            json.dumps(
                item,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
        ).hexdigest()

    native_repeat_count = _nonnegative_int(
        native_repeat.get("repeat_count"), "native repeat count"
    )
    adapter_repeat_count = _nonnegative_int(
        adapter_repeat.get("repeat_count"), "adapter repeat count"
    )
    native_stable_hashes = native_repeat.get("all_stable_payload_sha256")
    native_public_builds = native_repeat.get("public_executable_sha256")
    adapter_stable_hashes = adapter_repeat.get("all_stable_projection_sha256")
    stable_native_sha = _sha256(
        native_repeat.get("stable_payload_sha256"), "native stable payload"
    )
    stable_adapter_sha = _sha256(
        adapter_repeat.get("stable_projection_sha256"),
        "adapter stable projection",
    )
    native_hashes_valid = (
        isinstance(native_stable_hashes, list)
        and len(native_stable_hashes) == native_repeat_count
        and all(item == stable_native_sha for item in native_stable_hashes)
    )
    public_builds_valid = (
        isinstance(native_public_builds, list)
        and len(native_public_builds) == 2
        and all(item == native_config.get("expected_executable_sha256") for item in native_public_builds)
        and len(set(native_public_builds)) == 1
    )
    adapter_hashes_valid = (
        isinstance(adapter_stable_hashes, list)
        and len(adapter_stable_hashes) == adapter_repeat_count
        and all(item == stable_adapter_sha for item in adapter_stable_hashes)
    )
    public_fixture_sha256 = compact_sha256(fixture)
    deterministic_native_repeat_sha256 = compact_sha256(native_repeat)
    deterministic_adapter_repeat_sha256 = compact_sha256(adapter_repeat)
    fixture_fields = {
        "passed",
        "target_free",
        "production_target_or_vault_used",
        "reader_spec_sha256",
        "contrast_policy_spec_sha256",
        "fixture_order_sha256",
        "fixture_rank_table_sha256",
        "fixture_ranked_literals",
        "original_return_sequence",
        "original_release_sequence",
        "contrast_return_sequence",
        "original_releases_finalized_after_call",
        "first_contrast_call",
        "cb_decide_calls",
        "cb_decide_nonzero",
        "cb_decide_zero",
        "contrast_returns",
        "contrast_releases",
        "queue_size",
        "maximum_queue_size",
        "bounded_guidance_state_bytes",
        "actual_callback_return_sha256",
        "same_signed_redecisions",
        "solver_phase_calls",
        "original_rank_exhausted_before_contrast",
        "assigned_contrasts_deferred",
        "contrast_deferred_assigned",
        "contrast_deferred_assigned_state_bits",
        "contrast_deferred_assigned_state_bytes",
        "contrast_deferred_assigned_state_encoding",
        "contrast_deferred_assigned_state_hex",
        "contrast_deferred_assigned_state_sha256",
        "contrasts_are_hard_opposites",
        "adapter_strict_validation_passed",
        "base_cb_decide_nonzero",
        "base_outer_cb_decide_calls_equal",
        "native_payload_sha256",
        "adapter_projection_sha256",
    }
    native_repeat_fields = {
        "passed",
        "repeat_count",
        "byte_deterministic",
        "byte_deterministic_scope",
        "independent_source_builds",
        "stable_payload_bytes",
        "stable_payload_sha256",
        "all_stable_payload_sha256",
        "public_executable_sha256",
    }
    adapter_repeat_fields = {
        "passed",
        "repeat_count",
        "byte_deterministic",
        "byte_deterministic_scope",
        "actual_native_payloads_parsed",
        "monkeypatches_used",
        "stable_projection_bytes",
        "stable_projection_sha256",
        "all_stable_projection_sha256",
    }
    protocol_fields = {
        "maximum_native_solver_calls",
        "local_episode_ordinal",
        "lineage_call_ordinal",
        "retry_authorized",
        "parent_ordinal_replay_authorized",
        "rank_sweep_authorized",
        "horizon_sweep_authorized",
        "phase_calls",
        "maximum_complement_decisions",
        "pair_count_or_low_work_alone_is_gain",
    }
    truth_fields = {
        "truth_key_bytes_read",
        "fresh_targets",
        "fresh_reveal_calls",
        "refits",
        "scientific_entropy_calls",
        "MPS_or_GPU",
    }
    sources_final = all(
        _digest_or_pending(expected_sources.get(name), f"gate source {name}")
        != "PENDING"
        for name in SOURCE_NAMES
    )
    if (
        set(value)
        != {
            "schema",
            "attempt_id",
            "classification",
            "all_gates_passed",
            "target_free",
            "reader_binding",
            "rank_source",
            "public_fixture",
            "deterministic_native_repeats",
            "deterministic_adapter_repeats",
            "protocol",
            "truth_boundary",
            "source_sha256",
            "native_source_sha256",
            "adapter_source_sha256",
            "deterministic_executable_sha256",
            "science_native_calls",
            "production_native_solver_calls",
            "ready_for_full256_science",
            "public_fixture_sha256",
            "deterministic_native_repeat_sha256",
            "deterministic_adapter_repeat_sha256",
        }
        or set(fixture) != fixture_fields
        or set(native_repeat) != native_repeat_fields
        or set(adapter_repeat) != adapter_repeat_fields
        or set(protocol) != protocol_fields
        or set(truth) != truth_fields
        or not sources_final
        or value.get("schema") != TARGET_FREE_PREFLIGHT_SCHEMA
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("classification") != TARGET_FREE_PREFLIGHT_CLASSIFICATION
        or value.get("all_gates_passed") is not True
        or value.get("target_free") is not True
        or dict(rank_source) != RANK_SOURCE_BINDING
        or reader.get("reader_spec_sha256") != READER_SPEC_SHA256
        or reader.get("contrast_policy_spec_sha256")
        != CONTRAST_POLICY_SPEC_SHA256
        or fixture.get("passed") is not True
        or fixture.get("reader_spec_sha256") != READER_SPEC_SHA256
        or fixture.get("contrast_policy_spec_sha256")
        != CONTRAST_POLICY_SPEC_SHA256
        or fixture.get("fixture_order_sha256") != PUBLIC_FIXTURE_ORDER_SHA256
        or fixture.get("fixture_rank_table_sha256")
        != PUBLIC_FIXTURE_RANK_TABLE_SHA256
        or fixture.get("target_free") is not True
        or fixture.get("production_target_or_vault_used") is not False
        or fixture.get("fixture_ranked_literals") != [3, -1, -2, -6]
        or fixture.get("original_return_sequence") != [3, -1, -2]
        or fixture.get("original_release_sequence") != [-2, 3, -1]
        or fixture.get("contrast_return_sequence") != [1]
        or fixture.get("original_releases_finalized_after_call") != 254
        or fixture.get("first_contrast_call") != 255
        or fixture.get("cb_decide_calls") != 507
        or fixture.get("cb_decide_nonzero") != 4
        or fixture.get("cb_decide_zero") != 503
        or fixture.get("contrast_returns") != 1
        or fixture.get("contrast_releases") != 1
        or fixture.get("queue_size") != 2
        or fixture.get("maximum_queue_size") != 3
        or fixture.get("bounded_guidance_state_bytes") != 706
        or fixture.get("actual_callback_return_sha256")
        != PUBLIC_FIXTURE_CALLBACK_SHA256
        or fixture.get("same_signed_redecisions") != 0
        or fixture.get("solver_phase_calls") != 0
        or fixture.get("original_rank_exhausted_before_contrast") is not True
        or fixture.get("assigned_contrasts_deferred") is not True
        or fixture.get("contrast_deferred_assigned") != 2
        or fixture.get("contrast_deferred_assigned_state_bits") != 256
        or fixture.get("contrast_deferred_assigned_state_bytes") != 32
        or fixture.get("contrast_deferred_assigned_state_encoding")
        != _native_v15.VAULT_RANKED_DECISION_STATE_ENCODING
        or fixture.get("contrast_deferred_assigned_state_hex")
        != PUBLIC_FIXTURE_DEFERRED_ASSIGNED_STATE_HEX
        or fixture.get("contrast_deferred_assigned_state_sha256")
        != PUBLIC_FIXTURE_DEFERRED_ASSIGNED_STATE_SHA256
        or fixture.get("contrasts_are_hard_opposites") is not True
        or fixture.get("adapter_strict_validation_passed") is not True
        or fixture.get("base_cb_decide_nonzero") != 0
        or fixture.get("base_outer_cb_decide_calls_equal") is not True
        or _sha256(fixture.get("native_payload_sha256"), "fixture native payload")
        != stable_native_sha
        or _sha256(
            fixture.get("adapter_projection_sha256"),
            "fixture adapter projection",
        )
        != stable_adapter_sha
        or native_repeat.get("passed") is not True
        or native_repeat_count != 3
        or native_repeat.get("byte_deterministic") is not True
        or native_repeat.get("byte_deterministic_scope")
        != "canonical-native-v12-result-json-with-resources-field-removed"
        or native_repeat.get("independent_source_builds") != 2
        or _nonnegative_int(
            native_repeat.get("stable_payload_bytes"), "native stable payload bytes"
        )
        != PUBLIC_FIXTURE_NATIVE_STABLE_BYTES
        or stable_native_sha != PUBLIC_FIXTURE_NATIVE_STABLE_SHA256
        or not native_hashes_valid
        or not public_builds_valid
        or adapter_repeat.get("passed") is not True
        or adapter_repeat_count != 3
        or adapter_repeat.get("byte_deterministic") is not True
        or adapter_repeat.get("byte_deterministic_scope")
        != (
            "canonical-v15-normalized-projection-with-runtime-resources-"
            "excluded-and-raw-bound-by-stable-sha256"
        )
        or adapter_repeat.get("actual_native_payloads_parsed") != 3
        or adapter_repeat.get("monkeypatches_used") is not False
        or _nonnegative_int(
            adapter_repeat.get("stable_projection_bytes"),
            "adapter stable projection bytes",
        )
        == 0
        or not adapter_hashes_valid
        or protocol.get("maximum_native_solver_calls") != 1
        or protocol.get("local_episode_ordinal") != LOCAL_EPISODE_ORDINAL
        or protocol.get("lineage_call_ordinal") != LINEAGE_CALL_ORDINAL
        or protocol.get("retry_authorized") is not False
        or protocol.get("parent_ordinal_replay_authorized") is not False
        or protocol.get("rank_sweep_authorized") is not False
        or protocol.get("horizon_sweep_authorized") is not False
        or protocol.get("phase_calls") != 0
        or protocol.get("maximum_complement_decisions")
        != MAXIMUM_COMPLEMENT_DECISIONS
        or protocol.get("pair_count_or_low_work_alone_is_gain") is not False
        or truth.get("truth_key_bytes_read") is not False
        or truth.get("fresh_targets") != 0
        or truth.get("fresh_reveal_calls") != 0
        or truth.get("refits") != 0
        or truth.get("scientific_entropy_calls") != 0
        or truth.get("MPS_or_GPU") is not False
        or value.get("science_native_calls") != 0
        or value.get("production_native_solver_calls") != 0
        or value.get("ready_for_full256_science") is not True
        or value.get("source_sha256") != expected_sources
        or value.get("native_source_sha256") != expected_sources.get("native_source")
        or value.get("adapter_source_sha256")
        != expected_sources.get("joint_score_sieve_v15")
        or value.get("deterministic_executable_sha256")
        != native_config.get("expected_executable_sha256")
        or value.get("public_fixture_sha256") != public_fixture_sha256
        or public_fixture_sha256 != gates.get("public_fixture_sha256")
        or value.get("deterministic_native_repeat_sha256")
        != deterministic_native_repeat_sha256
        or deterministic_native_repeat_sha256
        != gates.get("deterministic_native_repeat_sha256")
        or value.get("deterministic_adapter_repeat_sha256")
        != deterministic_adapter_repeat_sha256
        or deterministic_adapter_repeat_sha256
        != gates.get("deterministic_adapter_repeat_sha256")
    ):
        raise O1C73RunError("final target-free release-contrast preflight differs")
    return dict(value)


def validate_final_target_free_preflight(
    root: Path,
    config: Mapping[str, object],
    *,
    required: bool,
) -> tuple[dict[str, object] | None, str | None, bool]:
    """Permit PENDING integration fields for drafts and fail closed for science."""

    gates = _mapping(config["target_free_gates"], "target_free_gates")
    digest_names = (
        "final_preflight_sha256",
        "reader_spec_sha256",
        "contrast_policy_spec_sha256",
        "public_fixture_sha256",
        "deterministic_native_repeat_sha256",
        "deterministic_adapter_repeat_sha256",
    )
    unresolved = tuple(
        name
        for name in digest_names
        if _digest_or_pending(gates.get(name), f"target_free_gates.{name}") == "PENDING"
    )
    if unresolved:
        if required:
            raise O1C73RunError("target-free final preflight fields remain PENDING")
        return None, None, False
    if gates.get("reader_spec_sha256") != READER_SPEC_SHA256:
        raise O1C73RunError("target-free reader specification differs")
    if gates.get("contrast_policy_spec_sha256") != CONTRAST_POLICY_SPEC_SHA256:
        raise O1C73RunError("target-free contrast-policy specification differs")
    path = root / TARGET_FREE_PREFLIGHT_RELATIVE
    try:
        status = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise O1C73RunError("final target-free preflight cannot be read") from exc
    if path.is_symlink() or not stat.S_ISREG(status.st_mode):
        raise O1C73RunError("final target-free preflight identity differs")
    observed = sha256_file(path)
    if observed != gates.get("final_preflight_sha256"):
        raise O1C73RunError("final target-free preflight hash differs")
    validated = _validate_final_target_free_preflight(
        _read_json(path, "final target-free ranked-decision preflight"), config
    )
    return validated, observed, True


def preflight(
    config_path: str | Path, *, require_commit_binding: bool = False
) -> dict[str, object]:
    """Read-only authorization with zero writes, calls, targets, or truth reads."""

    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    source = _mapping(config["source"], "source")
    expected = _mapping(source["expected_sha256"], "source.expected_sha256")
    observed = _source_hashes(root, config)
    unresolved = tuple(name for name in SOURCE_NAMES if expected[name] == "PENDING")
    for name in SOURCE_NAMES:
        if expected[name] != "PENDING" and observed[name] != expected[name]:
            raise O1C73RunError(f"source hash differs for {name}")
    if require_commit_binding and unresolved:
        raise O1C73RunError("science source hashes remain PENDING")
    if (
        getattr(_native_v15, "JOINT_SCORE_SIEVE_ADAPTER_SCHEMA", None)
        != NATIVE_ADAPTER_SCHEMA
        or getattr(_native_v15, "JOINT_SCORE_SIEVE_RESULT_SCHEMA", None)
        != NATIVE_RESULT_SCHEMA
        or getattr(_native_v15, "JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA", None)
        != NATIVE_IMPLEMENTATION_PARENT_SCHEMA
        or getattr(_native_v15, "VAULT_RANKED_DECISION_READER_SCHEMA", None)
        != READER_SCHEMA
        or len(_native_v15.vault_release_contrast_policy_spec_bytes())
        != CONTRAST_POLICY_SPEC_BYTES
        or hashlib.sha256(
            _native_v15.vault_release_contrast_policy_spec_bytes()
        ).hexdigest()
        != CONTRAST_POLICY_SPEC_SHA256
        or _rank_v1.VAULT_RANKED_DECISION_SPEC_SHA256 != READER_SPEC_SHA256
        or _rank_v1.PRODUCTION_ORDER_SHA256 != RANKED_ORDER_SHA256
        or _rank_v1.PRODUCTION_RANK_TABLE_SHA256 != RANKED_TABLE_SHA256
        or _rank_v1.PRODUCTION_ZERO_DELTA_VARIABLES != RANKED_OMITTED_VARIABLES
    ):
        raise O1C73RunError("adapter-v15/release-contrast schema binding differs")

    baseline = validate_apple8_baseline(root, config)
    validate_grouping_provenance(root, config)
    potential = cast(Path, getattr(baseline, "potential"))
    cnf = cast(Path, getattr(baseline, "cnf"))
    frozen = _o1c65.build_frozen_grouping(potential, config)
    imported = validate_parent_and_import_vault(root, config, frozen)
    reader = _release_reader_binding(imported.ranked_decision, "derived reader")
    final_gate, final_gate_sha, final_gate_frozen = (
        validate_final_target_free_preflight(
            root, config, required=require_commit_binding
        )
    )
    capacity = validate_capacity_reservation(config["capacity_reservation"])
    source_commit = _git_commit(root)
    clean = _selected_sources_clean(root, config_file, config)
    if require_commit_binding:
        if not clean:
            raise O1C73RunError("science sources/config are not clean")
        for name in SOURCE_NAMES:
            _commit_bound_bytes(
                root, source_commit, _relative(root, source[name], name), name
            )
        _commit_bound_bytes(root, source_commit, config_file, "config")
        _commit_bound_bytes(
            root,
            source_commit,
            root / TARGET_FREE_PREFLIGHT_RELATIVE,
            "final target-free ranked-decision preflight",
        )

    memory_free = _memory_free_percent()
    disk_free = shutil.disk_usage(root).free
    cpu_count = max(os.cpu_count() or 1, 1)
    load_1m = os.getloadavg()[0]
    normalized_load = load_1m / cpu_count
    active = _o1c67._active_conflicting_processes()
    if memory_free is not None and memory_free < MINIMUM_MEMORY_FREE_PERCENT:
        raise O1C73RunError("memory-pressure preflight is below gate")
    if disk_free < MINIMUM_DISK_FREE_BYTES:
        raise O1C73RunError("disk-free preflight is below gate")
    if normalized_load > MAXIMUM_NORMALIZED_LOAD_1M:
        raise O1C73RunError("normalized system load is above gate")
    if active:
        raise O1C73RunError("conflicting science process is active")
    return {
        "schema": PREFLIGHT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "ok": True,
        "ready_for_science": require_commit_binding and final_gate_frozen,
        "source_commit": source_commit,
        "source_commit_bound": require_commit_binding,
        "source_tree_clean": clean,
        "config_sha256": sha256_file(config_file),
        "source_sha256": observed,
        "unresolved_source_hashes": list(unresolved),
        "unresolved_gate_hashes": (
            []
            if final_gate_frozen
            else [
                name
                for name in (
                    "final_preflight_sha256",
                    "reader_spec_sha256",
                    "contrast_policy_spec_sha256",
                    "public_fixture_sha256",
                    "deterministic_native_repeat_sha256",
                    "deterministic_adapter_repeat_sha256",
                )
                if _mapping(config["target_free_gates"], "target_free_gates").get(name)
                == "PENDING"
            ]
        ),
        "adapter_source_sha256": observed["joint_score_sieve_v15"],
        "native_source_sha256": observed["native_source"],
        "native_adapter_schema": NATIVE_ADAPTER_SCHEMA,
        "native_result_schema": NATIVE_RESULT_SCHEMA,
        "native_implementation_parent_schema": NATIVE_IMPLEMENTATION_PARENT_SCHEMA,
        "native_decision_telemetry_schema": NATIVE_DECISION_TELEMETRY_SCHEMA,
        "reader": reader,
        "rank_source": dict(RANK_SOURCE_BINDING),
        "final_target_free_preflight": {
            "path": TARGET_FREE_PREFLIGHT_RELATIVE.as_posix(),
            "expected_sha256": _mapping(
                config["target_free_gates"], "target_free_gates"
            ).get("final_preflight_sha256"),
            "observed_sha256": final_gate_sha,
            "present": final_gate is not None,
            "validated": final_gate is not None,
            "frozen": final_gate_frozen,
        },
        "parent_result_sha256": PARENT_RESULT_SHA256,
        "parent_manifest_sha256": PARENT_MANIFEST_SHA256,
        "parent_lineage_calls_consumed": PARENT_LINEAGE_CALLS,
        "parent_last_consumed_ordinal": PARENT_LAST_CONSUMED_ORDINAL,
        "parent_failed_ordinal": PARENT_FAILED_ORDINAL,
        "parent_known_completed_billed_conflicts": (
            PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS
        ),
        "parent_failed_call_billed_conflicts": None,
        "parent_lineage_actual_billed_conflicts": None,
        "retained_vault_sha256": imported.independent.sha256,
        "retained_vault_clause_count": len(imported.independent.clauses),
        "retained_vault_literal_count": imported.independent.literal_count,
        "retained_vault_serialized_bytes": imported.independent.serialized_bytes,
        "capacity_reservation": capacity,
        "cnf_sha256": sha256_file(cnf),
        "potential_sha256": sha256_file(potential),
        "grouping_sha256": frozen.grouping.sha256,
        "invocation_id": INVOCATION_ID,
        "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
        "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
        "maximum_native_solver_calls": MAXIMUM_NATIVE_SOLVER_CALLS,
        "requested_conflicts": REQUESTED_CONFLICTS,
        "billing_rule": "actual-nonnegative-solve-conflicts",
        "maximum_billed_conflicts": None,
        "maximum_conflict_limit_overshoot": None,
        "timeout_seconds": TIMEOUT_SECONDS,
        "memory_limit_bytes": MEMORY_LIMIT_BYTES,
        "memory_pressure_free_percent": memory_free,
        "disk_free_bytes": disk_free,
        "load_1m": load_1m,
        "cpu_count": cpu_count,
        "normalized_load_1m": normalized_load,
        "active_conflicting_processes": active,
        "native_solver_calls": 0,
        "files_written": 0,
        "public_target_artifacts_validated": True,
        "fresh_target_bytes_generated": 0,
        "truth_key_bytes_read": False,
        "fresh_targets": 0,
        "scientific_entropy_calls": 0,
        "fresh_reveal_calls": 0,
        "refits": 0,
        "phase_calls": 0,
        "rank_sweeps": 0,
        "MPS_or_GPU": False,
    }


def _capture_preflight_config(
    config_file: Path,
    config: Mapping[str, object],
    preflight_row: Mapping[str, object],
) -> bytes:
    """Capture the exact commit-bound config bytes used and archived by science."""

    expected_sha256 = _sha256(
        preflight_row.get("config_sha256"), "preflight config sha256"
    )
    try:
        payload = config_file.read_bytes()
        decoded = json.loads(payload)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise O1C73RunError("preflight-bound config cannot be captured") from exc
    if (
        hashlib.sha256(payload).hexdigest() != expected_sha256
        or not isinstance(decoded, dict)
        or decoded != config
    ):
        raise O1C73RunError("config identity changed after preflight")
    return payload


def native_failure_evidence(exc: BaseException, directory: Path) -> dict[str, object]:
    """Persist bounded process streams while retaining full lengths and hashes."""

    raw_returncode = _o1c67._first_evidence(exc, "returncode")
    returncode = (
        raw_returncode
        if isinstance(raw_returncode, int) and not isinstance(raw_returncode, bool)
        else None
    )
    command = _o1c67._first_evidence(exc, "command") or _o1c67._first_evidence(
        exc, "cmd"
    )
    stdout = _o1c67._stream_bytes(_o1c67._first_evidence(exc, "stdout"))
    stderr = _o1c67._stream_bytes(_o1c67._first_evidence(exc, "stderr"))
    raw_telemetry = getattr(exc, "failure_telemetry", None)
    adapter_telemetry: dict[str, object] | None
    if isinstance(raw_telemetry, Mapping):
        adapter_telemetry = dict(raw_telemetry)
        adapter_telemetry["stdout"] = None
        adapter_telemetry["stderr"] = None
        adapter_telemetry["raw_streams_externalized"] = True
    else:
        adapter_telemetry = None
    return {
        "schema": FAILURE_EVIDENCE_SCHEMA,
        "returncode": returncode,
        "command": (
            [str(part) for part in command]
            if isinstance(command, (list, tuple))
            else str(command)
            if command is not None
            else None
        ),
        "stdout": _o1c67._failure_stream(directory, "stdout", stdout),
        "stderr": _o1c67._failure_stream(directory, "stderr", stderr),
        "exception_chain_outer_to_cause_or_context": _o1c67._exception_chain(exc),
        "adapter_failure_telemetry": adapter_telemetry,
    }


def _invocation(
    bindings: Mapping[str, object],
    vault: _o1c66.ClauseVault,
    reader: Mapping[str, object],
) -> dict[str, object]:
    return {
        "schema": INVOCATION_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "invocation_id": INVOCATION_ID,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
        "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
        "continuation_calls_before": 0,
        "lineage_calls_before": PARENT_LINEAGE_CALLS,
        "parent_last_consumed_ordinal": PARENT_LAST_CONSUMED_ORDINAL,
        "parent_failed_ordinal": PARENT_FAILED_ORDINAL,
        "parent_ordinal_replay_authorized": False,
        "episode_is_retry": False,
        "calls_authorized": 1,
        "requested_conflicts": REQUESTED_CONFLICTS,
        "billing_rule": "actual-nonnegative-solve-conflicts",
        "maximum_billed_conflicts": None,
        "maximum_conflict_limit_overshoot": None,
        "timeout_seconds": TIMEOUT_SECONDS,
        "memory_limit_bytes": MEMORY_LIMIT_BYTES,
        "parent_known_completed_billed_conflicts": (
            PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS
        ),
        "parent_failed_call_billed_conflicts": None,
        "lineage_actual_billed_conflicts": None,
        "reader": dict(reader),
        "rank_source": dict(RANK_SOURCE_BINDING),
        "capacity_reservation": dict(CAPACITY_RESERVATION),
        "retained_vault": vault.describe(),
        "bindings": dict(bindings),
        "rank_sweep_authorized": False,
        "horizon_sweep_authorized": False,
        "shortcut_authorized": False,
        "phase_calls": 0,
        "truth_key_reads": 0,
        "fresh_reveal_calls": 0,
        "entropy_calls": 0,
        "refits": 0,
        "MPS_or_GPU": False,
    }


def _intent(
    invocation_sha256: str,
    vault: _o1c66.ClauseVault,
    bindings: Mapping[str, object],
    reader: Mapping[str, object],
) -> dict[str, object]:
    return {
        "schema": INTENT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "invocation_id": INVOCATION_ID,
        "invocation_sha256": invocation_sha256,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
        "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
        "episode_is_retry": False,
        "parent_ordinal_replay_authorized": False,
        "calls_before": 0,
        "calls_authorized_by_this_intent": 1,
        "requested_conflicts": REQUESTED_CONFLICTS,
        "billing_rule": "actual-nonnegative-solve-conflicts",
        "timeout_seconds": TIMEOUT_SECONDS,
        "memory_limit_bytes": MEMORY_LIMIT_BYTES,
        "reader": dict(reader),
        "reader_spec_sha256": READER_SPEC_SHA256,
        "contrast_policy_spec_bytes": CONTRAST_POLICY_SPEC_BYTES,
        "contrast_policy_spec_sha256": CONTRAST_POLICY_SPEC_SHA256,
        "rank_source": dict(RANK_SOURCE_BINDING),
        "rank_sweep_authorized": False,
        "horizon_sweep_authorized": False,
        "shortcut_authorized": False,
        "phase_calls": 0,
        "capacity_reservation": dict(CAPACITY_RESERVATION),
        "adapter_source_sha256": bindings.get("adapter_source_sha256"),
        "native_source_sha256": bindings.get("native_source_sha256"),
        "native_adapter_schema": bindings.get("native_adapter_schema"),
        "native_result_schema": bindings.get("native_result_schema"),
        "bindings": dict(bindings),
        "input_vault": vault.describe(),
        "truth_key_reads": 0,
        "fresh_reveal_calls": 0,
        "entropy_calls": 0,
        "refits": 0,
        "MPS_or_GPU": False,
    }


_NATIVE_READER_RUNTIME_FIELDS = frozenset(_native_v15._RUNTIME_READER_FIELDS)


@dataclass(frozen=True)
class _ReaderRankProjection:
    """The two rank attributes used by v15's runtime-causality validator."""

    candidate_count: int
    ranked_literals: tuple[int, ...]


def _validate_native_reader(
    value: object,
    field: str,
    *,
    expected_decision: _rank_v1.VaultRankedDecision | None = None,
) -> tuple[dict[str, object], dict[str, object], bool]:
    """Revalidate v12's complete bounded causal trace and normalize telemetry."""

    combined = _mapping(value, field)
    runtime = {
        name: combined.get(name) for name in _NATIVE_READER_RUNTIME_FIELDS
    }
    static = {
        name: item
        for name, item in combined.items()
        if name not in _NATIVE_READER_RUNTIME_FIELDS
    }
    reader = _validate_reader(static, f"{field}.static")
    try:
        if expected_decision is not None:
            validated = _native_v15.validate_vault_ranked_decision_reader(
                combined,
                expected_decision=expected_decision,
                require_active_contrast=False,
            )
            if validated != dict(combined):
                raise O1C73RunError("native release-contrast projection differs")
        else:
            projection = _ReaderRankProjection(
                candidate_count=cast(int, reader["candidate_count"]),
                ranked_literals=tuple(
                    cast(Sequence[int], reader["ranked_literals"])
                ),
            )
            _native_v15._validate_runtime_causality(
                combined,
                expected_decision=cast(
                    _rank_v1.VaultRankedDecision, projection
                ),
                require_active_contrast=False,
            )
    except O1C73RunError:
        raise
    except Exception as exc:
        raise O1C73RunError("native release-contrast telemetry differs") from exc

    original_returns = _nonnegative_int(
        runtime.get("original_once_returns"), "native original once returns"
    )
    released_original = _nonnegative_int(
        runtime.get("released_original"), "native released originals"
    )
    contrast_enqueued = _nonnegative_int(
        runtime.get("contrast_enqueued"), "native contrasts enqueued"
    )
    contrast_returns = _nonnegative_int(
        runtime.get("contrast_returns"), "native contrast returns"
    )
    contrast_deferred_assigned = (
        _nonnegative_int(
            runtime.get("contrast_deferred_assigned"),
            "native assigned contrasts deferred",
        )
        if "contrast_deferred_assigned" in _NATIVE_READER_RUNTIME_FIELDS
        else 0
    )
    paired_variables = _nonnegative_int(
        runtime.get("paired_variables"), "native paired variables"
    )
    cursor = _nonnegative_int(runtime.get("cursor"), "native rank cursor")
    candidate_count = cast(int, reader["candidate_count"])
    active = contrast_returns > 0
    if (
        original_returns > RANKED_VARIABLE_COUNT
        or released_original > original_returns
        or contrast_enqueued != released_original
        or contrast_returns > MAXIMUM_COMPLEMENT_DECISIONS
        or contrast_deferred_assigned > contrast_enqueued
        or paired_variables != contrast_returns
    ):
        raise O1C73RunError("native release-contrast production bounds differ")
    telemetry = {
        "schema": NATIVE_DECISION_TELEMETRY_SCHEMA,
        "reader_spec_sha256": READER_SPEC_SHA256,
        "contrast_policy_spec_sha256": CONTRAST_POLICY_SPEC_SHA256,
        "order_sha256": RANKED_ORDER_SHA256,
        "rank_table_sha256": RANKED_TABLE_SHA256,
        **runtime,
        "active": active,
        "mechanism_validated": True,
        "original_rank_exhausted_before_contrast": (
            not active or cursor == candidate_count
        ),
        "contrast_requires_genuine_original_release": True,
        "contrasts_are_hard_opposites": True,
        "pair_count_alone_is_cryptanalytic_gain": False,
        "low_work_alone_is_cryptanalytic_gain": False,
    }
    return reader, telemetry, active


def _validated_native(
    result: object,
    *,
    expected_reader: Mapping[str, object],
    expected_decision: _rank_v1.VaultRankedDecision,
) -> tuple[
    dict[str, object],
    dict[str, int | float],
    Mapping[str, object],
    dict[str, object],
    dict[str, object],
    bool,
]:
    try:
        _native_v15.validate_vault_ranked_decision_reader(
            getattr(result, "reader"),
            expected_decision=expected_decision,
            require_active_contrast=False,
        )
        raw = _mapping(getattr(result, "raw"), "native.raw")
        _native_v15.validate_vault_ranked_decision_reader(
            raw.get("reader"),
            expected_decision=expected_decision,
            require_active_contrast=False,
        )
        result_reader, decision_telemetry, decision_active = _validate_native_reader(
            getattr(result, "reader"),
            "native.reader",
            expected_decision=expected_decision,
        )
        raw_reader, raw_decision_telemetry, raw_decision_active = (
            _validate_native_reader(
                raw.get("reader"),
                "native.raw.reader",
                expected_decision=expected_decision,
            )
        )
        stats = _native_v15.validate_vault_soft_conflict_ledger(
            _mapping(getattr(result, "stats"), "native.stats")
        )
        resources = _mapping(getattr(result, "resources"), "native.resources")
        sieve = _mapping(getattr(result, "sieve"), "native.sieve")
        vault_telemetry = _mapping(
            getattr(result, "vault_telemetry"), "native.vault_telemetry"
        )
        status = getattr(result, "status")
        conflict_limit = getattr(result, "conflict_limit")
        threshold = getattr(result, "threshold")
        peak = _nonnegative_int(resources.get("peak_rss_bytes"), "native peak RSS")
        wall = _nonnegative_int(resources.get("wall_microseconds"), "native wall")
        cpu = _nonnegative_int(resources.get("cpu_microseconds"), "native CPU")
        minimum_upper_bound = _finite_float(
            sieve.get("minimum_upper_bound"), "minimum upper bound"
        )
        root_upper_bound = _finite_float(
            sieve.get("root_upper_bound"), "root upper bound"
        )
        fully_emitted = _nonnegative_int(
            sieve.get("external_clauses_emitted"), "fully emitted clauses"
        )
        pending_clauses = _nonnegative_int(
            sieve.get("pending_clause_count"), "pending clauses"
        )
        if (
            result_reader != dict(expected_reader)
            or raw_reader != dict(expected_reader)
            or raw_decision_telemetry != decision_telemetry
            or raw_decision_active is not decision_active
            or isinstance(status, bool)
            or status not in (0, 10, 20)
            or conflict_limit != REQUESTED_CONFLICTS
            or threshold != THRESHOLD
            or stats["requested_conflicts"] != REQUESTED_CONFLICTS
            or stats["billed_conflicts"] != stats["solve_conflicts"]
            or raw.get("schema") != NATIVE_RESULT_SCHEMA
            or raw.get("implementation_parent_schema")
            != NATIVE_IMPLEMENTATION_PARENT_SCHEMA
            or vault_telemetry.get("schema") != NATIVE_VAULT_TELEMETRY_SCHEMA
            or peak > MEMORY_LIMIT_BYTES
            or wall > int(TIMEOUT_SECONDS * 1_000_000)
        ):
            raise O1C73RunError("native O1C-0073 contract differs")
        ledger: dict[str, int | float] = {
            **stats,
            "status": cast(int, status),
            "peak_rss_bytes": peak,
            "wall_microseconds": wall,
            "cpu_microseconds": cpu,
            "minimum_upper_bound": minimum_upper_bound,
            "root_upper_bound": root_upper_bound,
            "fully_emitted_clauses": fully_emitted,
            "pending_clause_count": pending_clauses,
        }
        return (
            dict(raw),
            ledger,
            vault_telemetry,
            decision_telemetry,
            result_reader,
            decision_active,
        )
    except O1C73RunError:
        raise
    except Exception as exc:
        raise O1C73RunError("native O1C-0073 result differs") from exc


def execute_single_continuation(
    *,
    capsule: Path,
    imported_vault: _o1c66.ClauseVault,
    adapter_vault: _vault_v1.ThresholdNoGoodVault,
    ranked_decision: _rank_v1.VaultRankedDecision,
    invoke_episode: EpisodeInvoker,
    verify_public_model: Callable[[bytes], bool],
    bindings: Mapping[str, object],
) -> SingleContinuationOutcome:
    """Persist lineage ordinal 9, consume exactly one call, and never retry."""

    reader = _validate_reader(bindings.get("reader"), "bindings.reader")
    if _release_reader_binding(ranked_decision, "execution reader") != reader:
        raise O1C73RunError("execution rank/release binding differs")
    if not capsule.is_dir() or imported_vault.sha256 != PARENT_RETAINED_VAULT_SHA256:
        raise O1C73RunError("single-continuation capsule or vault differs")
    if (
        len(imported_vault.clauses) != PARENT_RETAINED_VAULT_CLAUSES
        or imported_vault.literal_count != PARENT_RETAINED_VAULT_LITERALS
        or imported_vault.serialized_bytes != PARENT_RETAINED_VAULT_BYTES
        or PLANNING_RESERVED_CLAUSES > _o1c66.VAULT_MAXIMUM_CLAUSES
        or PLANNING_RESERVED_LITERALS > _o1c66.VAULT_MAXIMUM_LITERALS
        or PLANNING_RESERVED_BYTES > _o1c66.VAULT_MAXIMUM_SERIALIZED_BYTES
    ):
        raise O1C73RunError("capacity reservation is not call-safe")
    imported_path = capsule / "vault-imported.bin"
    _o1c66.write_vault(imported_path, imported_vault)
    if imported_path.read_bytes() != adapter_vault.serialized:
        raise O1C73RunError("dual-parsed imported vault bytes differ")
    reread = _o1c66.read_vault(
        imported_path,
        identity=imported_vault.identity,
        observed_variables=imported_vault.observed_variables,
    )
    if reread != imported_vault:
        raise O1C73RunError("capsule imported vault reread differs")

    invocation_path = capsule / "invocation.json"
    _atomic_json(invocation_path, _invocation(bindings, imported_vault, reader))
    invocation_sha = sha256_file(invocation_path)
    episode_dir = capsule / "episodes" / "00"
    episode_dir.mkdir(parents=True, exist_ok=False)
    intent_path = episode_dir / "intent.json"
    _atomic_json(
        intent_path,
        _intent(invocation_sha, imported_vault, bindings, reader),
    )
    intent_sha = sha256_file(intent_path)
    if not invocation_path.is_file() or not intent_path.is_file():
        raise O1C73RunError("invocation/intent not durable before call")

    try:
        result = invoke_episode(
            LOCAL_EPISODE_ORDINAL, LINEAGE_CALL_ORDINAL, imported_path
        )
    except BaseException as exc:
        evidence = native_failure_evidence(exc, episode_dir)
        evidence_path = episode_dir / "native_execution_failure.json"
        _atomic_json(evidence_path, evidence)
        failure = {
            "classification": OPERATIONAL_TERMINAL,
            "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
            "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
            "invocation_sha256": invocation_sha,
            "intent_sha256": intent_sha,
            "occurred_after_persisted_intent": True,
            "native_calls_consumed": 1,
            "retry_authorized": False,
            "reader": reader,
            "error_type": type(exc).__qualname__,
            "error_message": str(exc),
            "native_execution_failure_sha256": sha256_file(evidence_path),
            "truth_key_bytes_read": False,
        }
        _atomic_json(episode_dir / "terminal_failure.json", failure)
        episode = {
            "schema": EPISODE_SCHEMA,
            "completed": False,
            "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
            "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
            "intent_sha256": intent_sha,
            "reader": reader,
            "input_vault": imported_vault.describe(),
            "output_vault": None,
            "native_calls_consumed": 1,
            "requested_conflicts": REQUESTED_CONFLICTS,
            "billed_conflicts": None,
            "retry_authorized": False,
            "terminal_failure": failure,
        }
        _atomic_json(episode_dir / "episode.json", episode)
        return SingleContinuationOutcome(
            OPERATIONAL_TERMINAL,
            "native-call-or-resource-terminal",
            episode,
            imported_vault,
            1,
            REQUESTED_CONFLICTS,
            None,
            failure,
        )

    try:
        (
            raw,
            ledger,
            vault_telemetry,
            decision_telemetry,
            returned_reader,
            decision_active,
        ) = _validated_native(
            result,
            expected_reader=reader,
            expected_decision=ranked_decision,
        )
        eligible_raw = getattr(result, "eligible_emitted_clauses")
        if not isinstance(eligible_raw, Sequence):
            raise O1C73RunError("eligible emitted clause sequence differs")
        eligible = tuple(_o1c66._clause_literals(item) for item in eligible_raw)
        if (
            _o1c66._adapter_vault_payload(getattr(result, "input_vault"))
            != imported_vault.to_bytes()
        ):
            raise O1C73RunError("native input vault differs")
        status = cast(int, ledger["status"])
        key_model = getattr(result, "key_model", None)
        if status in (0, 10) and not decision_active:
            raise O1C73RunError("release-contrast telemetry was inactive")
        if status == 10:
            if not isinstance(key_model, bytes) or not verify_public_model(key_model):
                raise O1C73RunError("SAT model failed public eight-block verification")
        elif key_model is not None:
            raise O1C73RunError("non-SAT continuation returned a key")

        next_available = vault_telemetry.get("next_vault_available")
        terminal_reason = vault_telemetry.get("next_vault_terminal_reason")
        adapter_next = getattr(result, "next_vault")
        if not isinstance(next_available, bool):
            raise O1C73RunError("next-vault availability differs")
        if next_available:
            if terminal_reason is not None or adapter_next is None:
                raise O1C73RunError("available next vault differs")
            next_payload = _o1c66._adapter_vault_payload(adapter_next)
            parsed_next = _o1c66.ClauseVault.from_bytes(
                next_payload,
                expected_identity=imported_vault.identity,
                observed_variables=imported_vault.observed_variables,
            )
            expected_next, novel, duplicates = imported_vault.append_emitted(eligible)
            if parsed_next != expected_next:
                raise O1C73RunError("cumulative continuation vault differs")
        else:
            if (
                terminal_reason
                not in {
                    "terminal_empty_clause",
                    "capacity_clause_count",
                    "capacity_literal_count",
                    "capacity_payload_bytes",
                }
                or adapter_next is not None
            ):
                raise O1C73RunError("terminal next vault differs")
            parsed_next = imported_vault
            if terminal_reason == "terminal_empty_clause":
                novel, duplicates = (), 0
            else:
                novel, duplicates = _o1c66._deduplicate_without_capacity(
                    imported_vault, eligible
                )
        _o1c66._validate_vault_telemetry(
            vault_telemetry,
            current=imported_vault,
            eligible_raw=cast(Sequence[object], eligible_raw),
            eligible=eligible,
            parsed_next=parsed_next,
            next_available=next_available,
            terminal_reason=cast(str | None, terminal_reason),
        )
        native_path = episode_dir / "native_result.json"
        _atomic_json(native_path, raw)
        vault_telemetry_path = episode_dir / "vault_telemetry.json"
        _atomic_json(vault_telemetry_path, dict(vault_telemetry))
        decision_telemetry_path = episode_dir / "decision_telemetry.json"
        _atomic_json(decision_telemetry_path, decision_telemetry)
        final_vault = imported_vault if status == 20 else parsed_next
        archive_output = next_available and status != 20
        output_path = episode_dir / "vault-output.bin"
        if archive_output:
            assert adapter_next is not None
            _o1c66._write_adapter_vault(output_path, adapter_next)
            if (
                _o1c66.read_vault(
                    output_path,
                    identity=imported_vault.identity,
                    observed_variables=imported_vault.observed_variables,
                )
                != parsed_next
            ):
                raise O1C73RunError("continuation output vault reread differs")

        novel_count = len(novel)
        if status == 10:
            classification, stop_reason = (
                PUBLIC_EXACT_RECOVERY,
                "public-verified-candidate-with-valid-release-contrast-reader",
            )
        elif status == 20:
            classification, stop_reason = (
                THRESHOLD_REGION_EXHAUSTED,
                "frozen-score-region-exhausted",
            )
        elif not next_available:
            classification, stop_reason = CAPACITY_TERMINAL, cast(str, terminal_reason)
        elif novel_count:
            classification, stop_reason = (
                VAULT_RELEASE_CONTRAST_NOVEL_CLAUSE_GAIN,
                "novel-exact-clauses-with-valid-release-contrast-reader",
            )
        else:
            classification, stop_reason = (
                VAULT_RELEASE_CONTRAST_NO_GAIN,
                "no-verified-recovery-novel-exclusion-or-status20-frontier-proof",
            )
        episode = {
            "schema": EPISODE_SCHEMA,
            "completed": True,
            "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
            "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
            "invocation_sha256": invocation_sha,
            "intent_sha256": intent_sha,
            "reader": returned_reader,
            "native_calls_consumed": 1,
            "requested_conflicts": REQUESTED_CONFLICTS,
            "billed_conflicts": cast(int, ledger["billed_conflicts"]),
            "input_vault": imported_vault.describe(),
            "output_vault": None if status == 20 else parsed_next.describe(),
            "output_vault_archived": archive_output,
            "output_vault_sidecar": (
                "episodes/00/vault-output.bin" if archive_output else None
            ),
            "status20_retained_input_vault": (
                imported_vault.describe() if status == 20 else None
            ),
            "status20_unarchived_derived_vault": (
                parsed_next.describe() if status == 20 and next_available else None
            ),
            "status20_native_next_vault_available": (
                next_available if status == 20 else None
            ),
            "status20_native_terminal_reason": (
                terminal_reason if status == 20 else None
            ),
            "status20_exceptional_no_retry_audit": status == 20,
            "eligible_emitted": {
                "clause_count": len(eligible),
                "literal_count": sum(len(clause) for clause in eligible),
                "novel_clause_count": novel_count,
                "novel_literal_count": sum(len(clause) for clause in novel),
                "duplicate_clause_count": duplicates,
            },
            "release_contrast_active": decision_active,
            "release_contrast_mechanism_validated": (
                decision_telemetry.get("mechanism_validated") is True
            ),
            "decision_telemetry": decision_telemetry,
            "work_and_resources": ledger,
            "search_delta_from_parent": {
                "decisions_delta": cast(int, ledger["decisions"])
                - PARENT_LAST_DECISIONS,
                "propagations_delta": cast(int, ledger["propagations"])
                - PARENT_LAST_PROPAGATIONS,
                "minimum_upper_bound_delta": (
                    cast(float, ledger["minimum_upper_bound"])
                    - PARENT_LAST_MINIMUM_UPPER_BOUND
                ),
            },
            "native_result_sha256": sha256_file(native_path),
            "vault_telemetry_sha256": sha256_file(vault_telemetry_path),
            "decision_telemetry_sha256": sha256_file(decision_telemetry_path),
            "public_model": {
                "present": key_model is not None,
                "verified_8_of_8": status == 10,
                "model_sha256": (
                    hashlib.sha256(key_model).hexdigest()
                    if isinstance(key_model, bytes)
                    else None
                ),
                "truth_key_bytes_read": False,
            },
            "retry_authorized": False,
        }
        _atomic_json(episode_dir / "episode.json", episode)
        return SingleContinuationOutcome(
            classification,
            stop_reason,
            episode,
            final_vault,
            1,
            REQUESTED_CONFLICTS,
            cast(int, ledger["billed_conflicts"]),
            None,
        )
    except BaseException as exc:
        failure = {
            "classification": INVALID_RESULT_TERMINAL,
            "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
            "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
            "invocation_sha256": invocation_sha,
            "intent_sha256": intent_sha,
            "occurred_after_persisted_intent": True,
            "native_calls_consumed": 1,
            "native_result_returned": True,
            "retry_authorized": False,
            "expected_reader": reader,
            "error_type": type(exc).__qualname__,
            "error_message": str(exc),
            "truth_key_bytes_read": False,
        }
        _atomic_json(episode_dir / "terminal_failure.json", failure)
        episode = {
            "schema": EPISODE_SCHEMA,
            "completed": False,
            "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
            "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
            "intent_sha256": intent_sha,
            "reader": reader,
            "input_vault": imported_vault.describe(),
            "output_vault": None,
            "native_calls_consumed": 1,
            "requested_conflicts": REQUESTED_CONFLICTS,
            "billed_conflicts": None,
            "retry_authorized": False,
            "terminal_failure": failure,
        }
        _atomic_json(episode_dir / "episode.json", episode)
        return SingleContinuationOutcome(
            INVALID_RESULT_TERMINAL,
            "invalid-post-native-result",
            episode,
            imported_vault,
            1,
            REQUESTED_CONFLICTS,
            None,
            failure,
        )


def validate_native_build_identity(
    native_build: NativeGuidedSearchBuild,
    *,
    expected_source_sha256: str,
    expected_executable_sha256: str,
) -> None:
    try:
        executable_sha = sha256_file(native_build.executable)
    except (AttributeError, OSError) as exc:
        raise O1C73RunError("native-v12 build identity differs") from exc
    if (
        expected_source_sha256 == "PENDING"
        or expected_executable_sha256 == "PENDING"
        or not isinstance(native_build, NativeGuidedSearchBuild)
        or native_build.executable.is_symlink()
        or native_build.executable.name != "native-joint-score-sieve"
        or native_build.source_sha256 != expected_source_sha256
        or native_build.executable_sha256 != expected_executable_sha256
        or executable_sha != expected_executable_sha256
    ):
        raise O1C73RunError("native-v12 build identity differs")


def invoke_native_episode(
    *,
    executable: Path,
    cnf: Path,
    potential: Path,
    grouping: Path,
    vault: Path,
    expected_reader: Mapping[str, object],
) -> object:
    """Revalidate every frozen input immediately before entering the adapter."""

    _o1c65.validate_frozen_call_inputs(cnf=cnf, potential=potential, grouping=grouping)
    if vault.is_symlink() or sha256_file(vault) != PARENT_RETAINED_VAULT_SHA256:
        raise O1C73RunError("vault-ranked-decision input vault differs before call")
    try:
        vault_payload = vault.read_bytes()
        potential_payload = potential.read_bytes()
        grouping_payload = grouping.read_bytes()
        decision = _rank_v1.derive_production_vault_ranked_decision(
            vault_payload,
            potential_payload,
            grouping_payload,
        )
        observed_reader = _release_reader_binding(
            decision, "pre-invocation release reader"
        )
    except (OSError, _rank_v1.VaultRankedDecisionError) as exc:
        raise O1C73RunError("vault-ranked decision differs before call") from exc
    if observed_reader != dict(expected_reader):
        raise O1C73RunError("vault-ranked reader differs before call")
    return _native_v15.run_joint_score_sieve(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential,
        grouping_path=grouping,
        vault_path=vault,
        vault_caps=_vault_v1.O1C66_VAULT_CAPS,
        threshold=THRESHOLD,
        conflict_limit=REQUESTED_CONFLICTS,
        seed=SEED,
        timeout_seconds=TIMEOUT_SECONDS,
        memory_limit_bytes=MEMORY_LIMIT_BYTES,
        require_active_contrast=False,
    )


def _runtime_resources(
    started: float, cpu_started: float, child_started: resource.struct_rusage
) -> dict[str, object]:
    return _o1c67._runtime_resources(started, cpu_started, child_started)


def _result(
    *,
    capsule_relative: Path,
    source_commit: str,
    preflight_row: Mapping[str, object],
    outcome: SingleContinuationOutcome,
    runtime: Mapping[str, object],
    started_at: str,
) -> dict[str, object]:
    billed = outcome.billed_conflicts
    reader = _validate_reader(
        _mapping(outcome.episode, "episode").get("reader"), "episode reader"
    )
    return {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": started_at,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_commit": source_commit,
        "source_sha256": preflight_row.get("source_sha256"),
        "adapter_source_sha256": preflight_row.get("adapter_source_sha256"),
        "native_source_sha256": preflight_row.get("native_source_sha256"),
        "classification": outcome.classification,
        "stop_reason": outcome.stop_reason,
        "capsule": capsule_relative.as_posix(),
        "invocation_id": INVOCATION_ID,
        "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
        "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
        "reader": reader,
        "rank_source": dict(RANK_SOURCE_BINDING),
        "parent": {
            "attempt_id": "O1C-0072",
            "result_sha256": PARENT_RESULT_SHA256,
            "manifest_sha256": PARENT_MANIFEST_SHA256,
            "source_commit": PARENT_SOURCE_COMMIT,
            "native_calls_consumed": PARENT_ATTEMPT_NATIVE_CALLS,
            "lineage_calls_consumed": PARENT_LINEAGE_CALLS,
            "last_consumed_ordinal": PARENT_LAST_CONSUMED_ORDINAL,
            "failed_ordinal": PARENT_FAILED_ORDINAL,
            "known_completed_billed_conflicts": (
                PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS
            ),
            "failed_call_billed_conflicts": None,
            "lineage_actual_billed_conflicts": None,
            "decisions": PARENT_LAST_DECISIONS,
            "propagations": PARENT_LAST_PROPAGATIONS,
            "minimum_upper_bound": PARENT_LAST_MINIMUM_UPPER_BOUND,
            "redecisions": PARENT_LAST_REDECISIONS,
        },
        "claim_boundary": {
            "new_attempt_not_parent_retry": True,
            "parent_ordinal_replay_authorized": False,
            "exactly_one_new_native_call": outcome.native_calls == 1,
            "only_science_change": (
                "hard-opposite-once-after-sealed-o1c72-original-rank-exhaustion"
            ),
            "reader_spec_sha256": READER_SPEC_SHA256,
            "contrast_policy_spec_bytes": CONTRAST_POLICY_SPEC_BYTES,
            "contrast_policy_spec_sha256": CONTRAST_POLICY_SPEC_SHA256,
            "ranked_order_sha256": RANKED_ORDER_SHA256,
            "ranked_table_sha256": RANKED_TABLE_SHA256,
            "rank_rule": RANK_RULE,
            "sign_rule": SIGN_RULE,
            "zero_delta_variable_241_omitted": True,
            "release_contrast_telemetry_required": True,
            "original_rank_monotone_cursor": True,
            "original_assigned_before_opportunity_consumed": True,
            "original_each_candidate_returned_at_most_once": True,
            "original_released_literal_reasserted": False,
            "original_rank_exhausted_before_any_contrast": True,
            "contrast_requires_genuine_original_release": True,
            "contrast_literal_is_hard_opposite": True,
            "contrast_requires_unassigned_variable": True,
            "assigned_contrasts_deferred_and_retained": True,
            "maximum_complement_decisions": MAXIMUM_COMPLEMENT_DECISIONS,
            "same_signed_redecisions_required": 0,
            "pair_count_alone_is_cryptanalytic_gain": False,
            "low_work_alone_is_cryptanalytic_gain": False,
            "precommitted_frontier_gain_rule": (
                "status-20-frozen-threshold-region-exhaustion-only"
            ),
            "gain_requires_recovery_novel_exact_exclusion_or_frontier_proof": True,
            "requested_conflicts_is_soft_horizon": True,
            "actual_solve_conflicts_billed": billed is not None,
            "numeric_overshoot_ceiling_asserted": False,
            "hard_process_time_rss_caps_retained": True,
            "capacity_reservation_is_planning_not_formal_maximum": True,
            "status20_is_exceptional_no_retry_consistency_audit": True,
            "status20_scope": "frozen-CNF-and-score-greater-than-or-equal-threshold",
            "release_contrast_reader_closed_on_null": (
                outcome.classification == VAULT_RELEASE_CONTRAST_NO_GAIN
            ),
            "second_contrast_call_or_sweep_authorized": False,
            "phase_calls": 0,
            "vault_clauses_valid_for": (
                "CNF-and-potential-score-greater-than-or-equal-threshold"
            ),
            "vault_clauses_are_cnf_only_entailed": False,
            "truth_key_bytes_read": False,
            "fresh_targets": 0,
            "scientific_entropy_calls": 0,
            "fresh_reveal_calls": 0,
            "refits": 0,
            "MPS_or_GPU": False,
        },
        "episode": dict(outcome.episode),
        "final_vault": outcome.final_vault.describe(),
        "resources": {
            **dict(runtime),
            "native_solver_calls": outcome.native_calls,
            "requested_conflicts": outcome.requested_conflicts,
            "billed_conflicts": billed,
            "maximum_billed_conflicts": None,
            "parent_known_completed_billed_conflicts": (
                PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS
            ),
            "parent_failed_call_billed_conflicts": None,
            "lineage_known_completed_billed_conflicts": (
                PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS + billed
                if billed is not None
                else PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS
            ),
            "lineage_actual_billed_conflicts": None,
            "timeout_seconds": TIMEOUT_SECONDS,
            "memory_limit_bytes": MEMORY_LIMIT_BYTES,
            "persistent_artifact_bytes": 0,
        },
        "operational_failure": (
            None
            if outcome.operational_failure is None
            else dict(outcome.operational_failure)
        ),
        "publication_recovery": None,
        "preflight": dict(preflight_row),
        "next_action": (
            "Close this exact release-contrast reader. Do not retry, replay "
            "lineage ordinal 9, call phase(), or sweep rank or horizon variants."
        ),
    }


def _markdown(result: Mapping[str, object]) -> str:
    return (
        "# O1C-0073 — APPLE8 vault release contrast\n\n"
        f"- Classification: `{result['classification']}`\n"
        f"- Stop reason: `{result['stop_reason']}`\n"
        "- New native calls: `1`\n"
        "- Local / lineage ordinal: `0 / 9`\n"
        "- Reader: O1C72 original rank/release, then released hard opposites once\n"
        "- Ranked variables: `255`; omitted zero-delta variable: `241`\n"
        "- Maximum complement decisions: `255`\n"
        "- Phase calls / rank sweeps: `0 / 0`\n"
        "- Billing: actual observed solve conflicts\n"
        "- Truth key bytes read: `false`\n"
    )


def finalize_capsule(
    capsule: Path,
    authoritative: Path,
    result: dict[str, object],
    *,
    _after_capsule_seal: Callable[[], None] | None = None,
) -> None:
    if authoritative.exists() or (capsule / "artifacts.sha256").exists():
        raise O1C73RunError("O1C-0073 terminal publication already exists")
    _o1c65._replace_owned_bytes(capsule / "RUN.md", _markdown(result).encode())
    result_path = capsule / "result.json"
    resources = cast(dict[str, object], result["resources"])
    for _ in range(12):
        _replace_owned_json(result_path, result)
        manifest, persistent = _o1c65._capsule_manifest(capsule)
        if resources.get("persistent_artifact_bytes") == persistent:
            break
        resources["persistent_artifact_bytes"] = persistent
    else:
        raise O1C73RunError("persistent artifact ledger did not converge")
    if persistent > MAXIMUM_PERSISTENT_ARTIFACT_BYTES:
        raise O1C73RunError("persistent artifact byte budget exceeded")
    payload = _canonical_json_bytes(result)
    manifest_path = capsule / "artifacts.sha256"
    authoritative_published = False
    manifest_published = False
    try:
        _atomic_bytes(authoritative, payload)
        authoritative_published = True
        _atomic_bytes(manifest_path, manifest)
        manifest_published = True
        for path in sorted(
            capsule.rglob("*"), key=lambda item: len(item.parts), reverse=True
        ):
            path.chmod(0o444 if path.is_file() else 0o555)
        capsule.chmod(0o555)
        if _after_capsule_seal is not None:
            _after_capsule_seal()
        if authoritative.read_bytes() != payload or result_path.read_bytes() != payload:
            raise O1C73RunError("terminal publication bytes differ")
        _o1c65._assert_immutable_tree(capsule)
    except Exception:
        _o1c65._restore_owned_capsule_for_recovery(capsule)
        if manifest_published:
            _o1c65._unlink_owned_exact(
                manifest_path, manifest, "O1C73 capsule manifest"
            )
        if authoritative_published:
            _o1c65._unlink_owned_exact(
                authoritative, payload, "O1C73 authoritative result"
            )
        raise


def _validate_recovery_file(
    path: Path,
    *,
    expected_sha256: object,
    field: str,
    expected_bytes: object | None = None,
) -> None:
    """Bind a recovery input to its journaled hash and optional byte count."""

    expected_sha = _sha256(expected_sha256, f"{field} sha256")
    try:
        status = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise O1C73RunError(f"{field} cannot be read during recovery") from exc
    if path.is_symlink() or not stat.S_ISREG(status.st_mode):
        raise O1C73RunError(f"{field} differs during recovery")
    if expected_bytes is not None:
        size = _nonnegative_int(expected_bytes, f"{field} bytes")
        if status.st_size != size:
            raise O1C73RunError(f"{field} size differs during recovery")
    if sha256_file(path) != expected_sha:
        raise O1C73RunError(f"{field} hash differs during recovery")


def _validate_recovery_sidecars(
    capsule: Path,
    source: Mapping[str, object],
    episode: Mapping[str, object],
) -> None:
    """Revalidate every completed-call sidecar before zero-call publication."""

    episode_dir = capsule / "episodes" / "00"
    source_reader = _validate_reader(source.get("reader"), "recovery source reader")
    terminal = (
        None
        if episode.get("completed") is True
        else _mapping(episode.get("terminal_failure"), "recovery terminal failure")
    )
    invocation_sha = (
        episode.get("invocation_sha256")
        if terminal is None
        else terminal.get("invocation_sha256")
    )
    _validate_recovery_file(
        capsule / "invocation.json",
        expected_sha256=invocation_sha,
        field="recovery invocation",
    )
    _validate_recovery_file(
        episode_dir / "intent.json",
        expected_sha256=episode.get("intent_sha256"),
        field="recovery intent",
    )
    invocation = _read_json(capsule / "invocation.json", "recovery invocation")
    intent = _read_json(episode_dir / "intent.json", "recovery intent")
    if (
        invocation.get("invocation_id") != INVOCATION_ID
        or invocation.get("local_episode_ordinal") != LOCAL_EPISODE_ORDINAL
        or invocation.get("lineage_call_ordinal") != LINEAGE_CALL_ORDINAL
        or invocation.get("parent_ordinal_replay_authorized") is not False
        or invocation.get("episode_is_retry") is not False
        or invocation.get("rank_sweep_authorized") is not False
        or invocation.get("horizon_sweep_authorized") is not False
        or invocation.get("shortcut_authorized") is not False
        or invocation.get("phase_calls") != 0
        or _validate_reader(invocation.get("reader"), "recovery invocation reader")
        != source_reader
        or invocation.get("capacity_reservation") != CAPACITY_RESERVATION
        or intent.get("invocation_id") != INVOCATION_ID
        or intent.get("invocation_sha256")
        != _sha256(invocation_sha, "recovery invocation sha256")
        or intent.get("local_episode_ordinal") != LOCAL_EPISODE_ORDINAL
        or intent.get("lineage_call_ordinal") != LINEAGE_CALL_ORDINAL
        or intent.get("parent_ordinal_replay_authorized") is not False
        or intent.get("episode_is_retry") is not False
        or intent.get("rank_sweep_authorized") is not False
        or intent.get("horizon_sweep_authorized") is not False
        or intent.get("shortcut_authorized") is not False
        or intent.get("phase_calls") != 0
        or intent.get("reader_spec_sha256") != READER_SPEC_SHA256
        or intent.get("contrast_policy_spec_bytes") != CONTRAST_POLICY_SPEC_BYTES
        or intent.get("contrast_policy_spec_sha256")
        != CONTRAST_POLICY_SPEC_SHA256
        or _validate_reader(intent.get("reader"), "recovery intent reader")
        != source_reader
        or intent.get("capacity_reservation") != CAPACITY_RESERVATION
    ):
        raise O1C73RunError("recovery invocation/intent journal differs")

    input_vault = _mapping(episode.get("input_vault"), "recovery input vault")
    _validate_recovery_file(
        capsule / "vault-imported.bin",
        expected_sha256=input_vault.get("sha256"),
        expected_bytes=input_vault.get("serialized_bytes"),
        field="recovery imported vault",
    )

    native_result = episode_dir / "native_result.json"
    vault_telemetry = episode_dir / "vault_telemetry.json"
    decision_telemetry = episode_dir / "decision_telemetry.json"
    vault_output = episode_dir / "vault-output.bin"
    native_failure = episode_dir / "native_execution_failure.json"
    terminal_failure = episode_dir / "terminal_failure.json"
    if terminal is None:
        _validate_recovery_file(
            native_result,
            expected_sha256=episode.get("native_result_sha256"),
            field="recovery native result",
        )
        _validate_recovery_file(
            vault_telemetry,
            expected_sha256=episode.get("vault_telemetry_sha256"),
            field="recovery vault telemetry",
        )
        _validate_recovery_file(
            decision_telemetry,
            expected_sha256=episode.get("decision_telemetry_sha256"),
            field="recovery decision telemetry",
        )
        native_row = _read_json(native_result, "recovery native result")
        native_reader, normalized_decision, decision_active = _validate_native_reader(
            native_row.get("reader"), "recovery native reader"
        )
        persisted_decision = _read_json(
            decision_telemetry, "recovery decision telemetry"
        )
        if (
            native_reader != source_reader
            or persisted_decision != normalized_decision
            or episode.get("decision_telemetry") != persisted_decision
            or episode.get("release_contrast_active") is not decision_active
            or episode.get("release_contrast_mechanism_validated") is not True
            or native_failure.exists()
            or terminal_failure.exists()
        ):
            raise O1C73RunError("completed recovery decision evidence differs")
        final_vault = _mapping(source.get("final_vault"), "recovery final vault")
        archived = episode.get("output_vault_archived")
        work = _mapping(episode.get("work_and_resources"), "recovery work")
        telemetry_row = _read_json(vault_telemetry, "recovery vault telemetry")
        if work.get("status") == 20:
            retained = _mapping(
                episode.get("status20_retained_input_vault"),
                "recovery status20 retained input vault",
            )
            available = telemetry_row.get("next_vault_available")
            derived_raw = episode.get("status20_unarchived_derived_vault")
            derived = (
                _mapping(derived_raw, "recovery status20 derived vault")
                if available is True
                else None
            )
            if (
                source.get("classification") != THRESHOLD_REGION_EXHAUSTED
                or source.get("stop_reason") != "frozen-score-region-exhausted"
                or source.get("operational_failure") is not None
                or episode.get("output_vault") is not None
                or episode.get("status20_exceptional_no_retry_audit") is not True
                or retained != input_vault
                or final_vault != input_vault
                or not isinstance(available, bool)
                or episode.get("status20_native_next_vault_available") is not available
                or episode.get("status20_native_terminal_reason")
                != telemetry_row.get("next_vault_terminal_reason")
                or (
                    available
                    and (
                        derived is None
                        or derived.get("sha256")
                        != telemetry_row.get("next_vault_sha256")
                        or derived.get("serialized_bytes")
                        != telemetry_row.get("next_serialized_bytes")
                        or derived.get("clause_count")
                        != telemetry_row.get("next_clause_count")
                        or derived.get("literal_count")
                        != telemetry_row.get("next_literal_count")
                    )
                )
                or (not available and derived_raw is not None)
                or archived is not False
                or episode.get("output_vault_sidecar") is not None
                or vault_output.exists()
            ):
                raise O1C73RunError("status-20 recovery vault/result differs")
            return

        output_vault = _mapping(episode.get("output_vault"), "recovery output vault")
        status = work.get("status")
        eligible = _mapping(
            episode.get("eligible_emitted"), "recovery eligible emissions"
        )
        novel_count = _nonnegative_int(
            eligible.get("novel_clause_count"), "recovery novel clause count"
        )
        available = telemetry_row.get("next_vault_available")
        terminal_reason = telemetry_row.get("next_vault_terminal_reason")
        if status == 10:
            public_model = _mapping(
                episode.get("public_model"), "recovery public model"
            )
            if (
                not decision_active
                or public_model.get("present") is not True
                or public_model.get("verified_8_of_8") is not True
            ):
                raise O1C73RunError("recovery public model conclusion differs")
            expected_classification = PUBLIC_EXACT_RECOVERY
            expected_stop_reason = (
                "public-verified-candidate-with-valid-release-contrast-reader"
            )
        elif status == 0 and isinstance(available, bool):
            if not decision_active:
                raise O1C73RunError("recovery release-contrast activity differs")
            if not available:
                if terminal_reason not in {
                    "terminal_empty_clause",
                    "capacity_clause_count",
                    "capacity_literal_count",
                    "capacity_payload_bytes",
                }:
                    raise O1C73RunError("recovery capacity conclusion differs")
                expected_classification = CAPACITY_TERMINAL
                expected_stop_reason = terminal_reason
            elif novel_count:
                expected_classification = VAULT_RELEASE_CONTRAST_NOVEL_CLAUSE_GAIN
                expected_stop_reason = (
                    "novel-exact-clauses-with-valid-release-contrast-reader"
                )
            else:
                expected_classification = VAULT_RELEASE_CONTRAST_NO_GAIN
                expected_stop_reason = (
                    "no-verified-recovery-novel-exclusion-or-status20-frontier-proof"
                )
        else:
            raise O1C73RunError("completed recovery status conclusion differs")
        if (
            source.get("classification") != expected_classification
            or source.get("stop_reason") != expected_stop_reason
            or source.get("operational_failure") is not None
            or final_vault != output_vault
            or not isinstance(archived, bool)
            or episode.get("status20_retained_input_vault") is not None
            or episode.get("status20_unarchived_derived_vault") is not None
            or episode.get("status20_native_next_vault_available") is not None
            or episode.get("status20_native_terminal_reason") is not None
            or episode.get("status20_exceptional_no_retry_audit") is not False
        ):
            raise O1C73RunError("completed recovery vault/result differs")
        if archived:
            if episode.get("output_vault_sidecar") != "episodes/00/vault-output.bin":
                raise O1C73RunError("recovery output vault path differs")
            _validate_recovery_file(
                vault_output,
                expected_sha256=output_vault.get("sha256"),
                expected_bytes=output_vault.get("serialized_bytes"),
                field="recovery output vault",
            )
        elif episode.get("output_vault_sidecar") is not None or vault_output.exists():
            raise O1C73RunError("unarchived recovery output vault differs")
        return

    persisted_failure = _read_json(terminal_failure, "recovery terminal failure")
    operational_failure = _mapping(
        source.get("operational_failure"), "recovery operational failure"
    )
    if (
        persisted_failure != terminal
        or operational_failure != terminal
        or source.get("final_vault") != input_vault
        or episode.get("output_vault") is not None
        or native_result.exists()
        or vault_telemetry.exists()
        or decision_telemetry.exists()
        or vault_output.exists()
    ):
        raise O1C73RunError("failed recovery journal differs")
    failure_sha = terminal.get("native_execution_failure_sha256")
    if failure_sha is None:
        if (
            source.get("classification") != INVALID_RESULT_TERMINAL
            or source.get("stop_reason") != "invalid-post-native-result"
            or terminal.get("classification") != INVALID_RESULT_TERMINAL
            or native_failure.exists()
        ):
            raise O1C73RunError("invalid-result recovery failure sidecar differs")
    else:
        if (
            source.get("classification") != OPERATIONAL_TERMINAL
            or source.get("stop_reason") != "native-call-or-resource-terminal"
            or terminal.get("classification") != OPERATIONAL_TERMINAL
        ):
            raise O1C73RunError("operational recovery conclusion differs")
        _validate_recovery_file(
            native_failure,
            expected_sha256=failure_sha,
            field="recovery native execution failure",
        )


def _validate_recovery_freeze(
    capsule: Path, source: Mapping[str, object]
) -> None:
    """Prove a partial capsule crossed the frozen commit-bound gate pre-call."""

    required = {
        "config": capsule / "config.json",
        "preflight": capsule / "preflight.json",
        "native build": capsule / "native_build.json",
    }
    for field, path in required.items():
        try:
            status = path.stat(follow_symlinks=False)
        except OSError as exc:
            raise O1C73RunError(
                f"recovery {field} cannot be read"
            ) from exc
        if path.is_symlink() or not stat.S_ISREG(status.st_mode):
            raise O1C73RunError(f"recovery {field} differs")

    config_path = required["config"]
    config = _read_json(config_path, "recovery frozen config")
    preflight = _read_json(required["preflight"], "recovery frozen preflight")
    native_build = _read_json(
        required["native build"], "recovery frozen native build"
    )
    config_source = _mapping(config.get("source"), "recovery config source")
    expected_sources = _mapping(
        config_source.get("expected_sha256"),
        "recovery config expected source hashes",
    )
    gates = _mapping(
        config.get("target_free_gates"), "recovery config target-free gates"
    )
    native = _mapping(config.get("native"), "recovery config native")
    final_gate = _mapping(
        preflight.get("final_target_free_preflight"),
        "recovery preflight final target-free gate",
    )
    preflight_sources = _mapping(
        preflight.get("source_sha256"), "recovery preflight source hashes"
    )
    invocation = _read_json(capsule / "invocation.json", "recovery invocation")
    bindings = _mapping(invocation.get("bindings"), "recovery invocation bindings")

    if set(expected_sources) != set(SOURCE_NAMES) or any(
        _digest_or_pending(expected_sources.get(name), f"recovery source {name}")
        == "PENDING"
        for name in SOURCE_NAMES
    ):
        raise O1C73RunError("recovery source freeze differs")
    gate_names = (
        "final_preflight_sha256",
        "reader_spec_sha256",
        "contrast_policy_spec_sha256",
        "public_fixture_sha256",
        "deterministic_native_repeat_sha256",
        "deterministic_adapter_repeat_sha256",
    )
    if any(
        _digest_or_pending(gates.get(name), f"recovery gate {name}") == "PENDING"
        for name in gate_names
    ):
        raise O1C73RunError("recovery target-free freeze differs")

    config_sha256 = sha256_file(config_path)
    source_commit = source.get("source_commit")
    if (
        config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or preflight.get("schema") != PREFLIGHT_SCHEMA
        or preflight.get("attempt_id") != ATTEMPT_ID
        or preflight.get("ok") is not True
        or preflight.get("ready_for_science") is not True
        or preflight.get("source_commit_bound") is not True
        or preflight.get("source_tree_clean") is not True
        or preflight.get("unresolved_source_hashes") != []
        or preflight.get("unresolved_gate_hashes") != []
        or preflight.get("config_sha256") != config_sha256
        or dict(preflight_sources) != dict(expected_sources)
        or source.get("preflight") != preflight
        or source.get("source_sha256") != preflight_sources
        or source.get("adapter_source_sha256")
        != preflight.get("adapter_source_sha256")
        or source.get("native_source_sha256")
        != preflight.get("native_source_sha256")
        or not isinstance(source_commit, str)
        or len(source_commit) != 40
        or any(character not in "0123456789abcdef" for character in source_commit)
        or preflight.get("source_commit") != source_commit
        or preflight.get("reader") != source.get("reader")
        or preflight.get("rank_source") != RANK_SOURCE_BINDING
        or preflight.get("native_adapter_schema") != NATIVE_ADAPTER_SCHEMA
        or preflight.get("native_result_schema") != NATIVE_RESULT_SCHEMA
        or preflight.get("native_implementation_parent_schema")
        != NATIVE_IMPLEMENTATION_PARENT_SCHEMA
        or preflight.get("native_decision_telemetry_schema")
        != NATIVE_DECISION_TELEMETRY_SCHEMA
        or preflight.get("local_episode_ordinal") != LOCAL_EPISODE_ORDINAL
        or preflight.get("lineage_call_ordinal") != LINEAGE_CALL_ORDINAL
        or preflight.get("native_solver_calls") != 0
        or preflight.get("files_written") != 0
        or preflight.get("truth_key_bytes_read") is not False
        or final_gate.get("path") != TARGET_FREE_PREFLIGHT_RELATIVE.as_posix()
        or final_gate.get("expected_sha256")
        != gates.get("final_preflight_sha256")
        or final_gate.get("observed_sha256")
        != gates.get("final_preflight_sha256")
        or final_gate.get("present") is not True
        or final_gate.get("validated") is not True
        or final_gate.get("frozen") is not True
        or native_build.get("source_sha256")
        != native.get("expected_source_sha256")
        or native_build.get("source_sha256")
        != preflight.get("native_source_sha256")
        or native_build.get("executable_sha256")
        != native.get("expected_executable_sha256")
        or bindings.get("source_commit") != source_commit
        or bindings.get("config_sha256") != config_sha256
        or bindings.get("source_sha256") != preflight_sources
        or bindings.get("adapter_source_sha256")
        != preflight.get("adapter_source_sha256")
        or bindings.get("native_source_sha256")
        != preflight.get("native_source_sha256")
        or bindings.get("native_executable_sha256")
        != native_build.get("executable_sha256")
        or bindings.get("final_target_free_preflight_sha256")
        != gates.get("final_preflight_sha256")
    ):
        raise O1C73RunError("O1C-0073 recovery freeze differs")


def _validate_publication_source(root: Path, capsule: Path) -> dict[str, object]:
    if (
        not capsule.is_dir()
        or capsule.is_symlink()
        or capsule.parent != root / "runs"
        or not capsule.name.endswith(f"_{CAPSULE_SUFFIX}")
        or (capsule / "artifacts.sha256").exists()
    ):
        raise O1C73RunError("O1C-0073 recovery capsule differs")
    source = dict(
        _read_json(capsule / PUBLICATION_SOURCE_NAME, "O1C-0073 publication source")
    )
    episode = _mapping(source.get("episode"), "publication source episode")
    resources = _mapping(source.get("resources"), "publication source resources")
    persisted = _read_json(
        capsule / "episodes" / "00" / "episode.json", "persisted O1C-0073 episode"
    )
    publication_reader = _validate_reader(source.get("reader"), "publication reader")
    if (
        source.get("schema") != RESULT_SCHEMA
        or source.get("attempt_id") != ATTEMPT_ID
        or source.get("capsule") != capsule.relative_to(root).as_posix()
        or source.get("invocation_id") != INVOCATION_ID
        or source.get("local_episode_ordinal") != LOCAL_EPISODE_ORDINAL
        or source.get("lineage_call_ordinal") != LINEAGE_CALL_ORDINAL
        or _validate_reader(episode.get("reader"), "publication episode reader")
        != publication_reader
        or episode != persisted
        or episode.get("local_episode_ordinal") != LOCAL_EPISODE_ORDINAL
        or episode.get("lineage_call_ordinal") != LINEAGE_CALL_ORDINAL
        or episode.get("native_calls_consumed") != 1
        or episode.get("retry_authorized") is not False
        or resources.get("native_solver_calls") != 1
        or source.get("publication_recovery") is not None
        or not (capsule / "invocation.json").is_file()
        or not (capsule / "episodes" / "00" / "intent.json").is_file()
    ):
        raise O1C73RunError("O1C-0073 publication source differs")
    _validate_recovery_freeze(capsule, source)
    _validate_recovery_sidecars(capsule, source, episode)
    return source


def recover_publication(
    *,
    root: Path,
    capsule: Path,
    authoritative: Path,
    cause: BaseException | None,
) -> dict[str, object]:
    """Seal completed sidecars with zero native calls."""

    if authoritative.exists():
        raise O1C73RunError("O1C-0073 authoritative publication already exists")
    source = _validate_publication_source(root, capsule)
    reader = _validate_reader(source.get("reader"), "recovery reader")
    recovery = {
        "schema": PUBLICATION_RECOVERY_SCHEMA,
        "publication_recovered_from_completed_sidecars": True,
        "native_calls_consumed": 1,
        "native_calls_issued_during_recovery": 0,
        "completed_sidecars_revalidated": True,
        "retry_authorized": False,
        "science_classification_preserved": source.get("classification"),
        "science_stop_reason_preserved": source.get("stop_reason"),
        "reader": reader,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "error_type": type(cause).__qualname__ if cause is not None else None,
        "error_message": str(cause) if cause is not None else None,
        "exception_chain_outer_to_cause_or_context": (
            _o1c67._exception_chain(cause) if cause is not None else []
        ),
        "truth_key_bytes_read": False,
    }
    recovered = dict(source)
    recovered["publication_recovery"] = recovery
    resources = dict(_mapping(recovered["resources"], "recovered resources"))
    resources["publication_recovery_native_solver_calls"] = 0
    recovered["resources"] = resources
    finalize_capsule(capsule, authoritative, recovered)
    return recovered


def run(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    authoritative = root / RESULT_RELATIVE
    partial_capsules = tuple(root.glob(f"runs/*_{CAPSULE_SUFFIX}"))
    if authoritative.exists():
        raise O1C73RunError("O1C-0073 already exists")
    if partial_capsules:
        if len(partial_capsules) != 1:
            raise O1C73RunError("multiple O1C-0073 recovery capsules exist")
        return recover_publication(
            root=root,
            capsule=partial_capsules[0],
            authoritative=authoritative,
            cause=None,
        )
    config_file = Path(config_path).resolve(strict=True)
    preflight_row = preflight(config_file, require_commit_binding=True)
    config = load_config(config_file)
    config_payload = _capture_preflight_config(config_file, config, preflight_row)
    baseline = validate_apple8_baseline(root, config)
    potential = cast(Path, getattr(baseline, "potential"))
    cnf = cast(Path, getattr(baseline, "cnf"))
    frozen = _o1c65.build_frozen_grouping(potential, config)
    imported = validate_parent_and_import_vault(root, config, frozen)
    reader = _release_reader_binding(imported.ranked_decision, "science reader")
    public_target = _o1c66._public_target(baseline)
    source_commit = cast(str, preflight_row["source_commit"])
    source = _mapping(config["source"], "source")
    expected = _mapping(source["expected_sha256"], "source.expected_sha256")
    native = _mapping(config["native"], "native")
    expected_native_source = _sha256(
        native["expected_source_sha256"], "native expected source"
    )
    expected_executable = _sha256(
        native["expected_executable_sha256"], "native expected executable"
    )
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    child_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    with tempfile.TemporaryDirectory(
        prefix="o1c73-apple8-vault-release-contrast-"
    ) as raw:
        workspace = Path(raw)
        native_build = _native_v15.build_native_joint_score_sieve(
            source=_relative(root, source["native_source"], "native source"),
            output=workspace / "native-joint-score-sieve",
        )
        validate_native_build_identity(
            native_build,
            expected_source_sha256=expected_native_source,
            expected_executable_sha256=expected_executable,
        )
        observed_sources = _source_hashes(root, config)
        if observed_sources != {
            name: _sha256(expected[name], f"source expected {name}")
            for name in SOURCE_NAMES
        }:
            raise O1C73RunError("source identity changed after preflight")
        validate_final_target_free_preflight(root, config, required=True)
        imported = validate_parent_and_import_vault(root, config, frozen)
        reader = _release_reader_binding(
            imported.ranked_decision,
            "post-build science reader",
        )
        stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
        capsule_relative = Path("runs") / f"{stamp}_{CAPSULE_SUFFIX}"
        capsule = root / capsule_relative
        capsule.mkdir(parents=True, exist_ok=False)
        _atomic_bytes(capsule / "config.json", config_payload)
        _atomic_json(capsule / "preflight.json", preflight_row)
        _atomic_json(capsule / "native_build.json", native_build.describe())
        grouping_path = capsule / "apple8-width6.grouping"
        _atomic_json(
            capsule / "grouping.json",
            _o1c65.materialize_grouping(grouping_path, frozen),
        )
        _atomic_bytes(
            capsule / "command.txt",
            (
                "nice -n 10 env PYTHONPATH=src python3 -m "
                "o1_crypto_lab.o1c73_apple8_vault_release_contrast_run run "
                f"--config {config_file.relative_to(root).as_posix()}\n"
            ).encode(),
        )
        bindings = {
            "source_commit": source_commit,
            "config_sha256": hashlib.sha256(config_payload).hexdigest(),
            "source_sha256": observed_sources,
            "adapter_source_sha256": observed_sources["joint_score_sieve_v15"],
            "native_source_sha256": native_build.source_sha256,
            "native_executable_sha256": native_build.executable_sha256,
            "native_adapter_schema": NATIVE_ADAPTER_SCHEMA,
            "native_result_schema": NATIVE_RESULT_SCHEMA,
            "native_implementation_parent_schema": (
                NATIVE_IMPLEMENTATION_PARENT_SCHEMA
            ),
            "native_ledger_schema": NATIVE_LEDGER_SCHEMA,
            "reader": reader,
            "reader_spec_sha256": READER_SPEC_SHA256,
            "contrast_policy_spec_bytes": CONTRAST_POLICY_SPEC_BYTES,
            "contrast_policy_spec_sha256": CONTRAST_POLICY_SPEC_SHA256,
            "ranked_order_sha256": RANKED_ORDER_SHA256,
            "ranked_table_sha256": RANKED_TABLE_SHA256,
            "rank_source": dict(RANK_SOURCE_BINDING),
            "final_target_free_preflight_sha256": _mapping(
                config["target_free_gates"], "target_free_gates"
            )["final_preflight_sha256"],
            "parent_result_sha256": PARENT_RESULT_SHA256,
            "parent_manifest_sha256": PARENT_MANIFEST_SHA256,
            "retained_vault_sha256": PARENT_RETAINED_VAULT_SHA256,
            "parent_failed_ordinal": PARENT_FAILED_ORDINAL,
            "parent_failed_call_billed_conflicts": None,
            "parent_known_completed_billed_conflicts": (
                PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS
            ),
            "lineage_actual_billed_conflicts": None,
            "cnf_sha256": sha256_file(cnf),
            "potential_sha256": sha256_file(potential),
            "grouping_sha256": sha256_file(grouping_path),
            "threshold_f64le_hex": struct.pack("<d", THRESHOLD).hex(),
            "seed": SEED,
        }

        def invoke(local_ordinal: int, lineage_ordinal: int, vault: Path) -> object:
            if (
                local_ordinal != LOCAL_EPISODE_ORDINAL
                or lineage_ordinal != LINEAGE_CALL_ORDINAL
            ):
                raise O1C73RunError("vault-release-contrast ordinal differs")
            return invoke_native_episode(
                executable=native_build.executable,
                cnf=cnf,
                potential=potential,
                grouping=grouping_path,
                vault=vault,
                expected_reader=reader,
            )

        outcome = execute_single_continuation(
            capsule=capsule,
            imported_vault=imported.independent,
            adapter_vault=imported.adapter,
            ranked_decision=imported.ranked_decision,
            invoke_episode=invoke,
            verify_public_model=public_target.verify,
            bindings=bindings,
        )
        result = _result(
            capsule_relative=capsule_relative,
            source_commit=source_commit,
            preflight_row=preflight_row,
            outcome=outcome,
            runtime=_runtime_resources(started, cpu_started, child_started),
            started_at=started_at,
        )
        _atomic_json(capsule / PUBLICATION_SOURCE_NAME, result)
        try:
            finalize_capsule(capsule, authoritative, result)
            return result
        except Exception as exc:
            return recover_publication(
                root=root,
                capsule=capsule,
                authoritative=authoritative,
                cause=exc,
            )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Preflight or run O1C-0073's one vault release-contrast call"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("preflight", "run"):
        child = subparsers.add_parser(command)
        child.add_argument("--config", default=CONFIG_RELATIVE.as_posix())
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        result = (
            preflight(args.config) if args.command == "preflight" else run(args.config)
        )
    except O1C73RunError as exc:
        print(f"{ATTEMPT_ID}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
