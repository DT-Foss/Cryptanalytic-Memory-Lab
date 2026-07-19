"""O1C-0070: one vault-conditioned phase-reader call from O1C-0069.

The reader is derived target-free from the exact 190-clause suffix introduced
after O1C-0067's sealed 12-clause prefix.  O1C-0070 imports O1C-0069's exact
202-clause vault, journals local ordinal 0 / lineage ordinal 6, and authorizes
one fresh native-v9 process with no retry or phase sweep.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
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

from . import joint_score_sieve_v12 as _native_v12
from . import o1c69_apple8_alternating_reader_run as _o1c69
from . import vault_phase_field_v1 as _phase_v1
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


_o1c68 = _o1c69._o1c68
_o1c67 = _o1c69._o1c67
_o1c65 = _o1c69._o1c65
_o1c66 = _o1c69._o1c66
_vault_v1 = _o1c69._vault_v1

ATTEMPT_ID = "O1C-0070"
CONFIG_SCHEMA = "o1-256-apple8-vault-phase-reader-config-v1"
PREFLIGHT_SCHEMA = "o1-256-apple8-vault-phase-reader-preflight-v1"
INVOCATION_SCHEMA = "o1-256-apple8-vault-phase-reader-invocation-v1"
INTENT_SCHEMA = "o1-256-apple8-vault-phase-reader-intent-v1"
EPISODE_SCHEMA = "o1-256-apple8-vault-phase-reader-episode-v1"
RESULT_SCHEMA = "o1-256-apple8-vault-phase-reader-result-v1"
FAILURE_EVIDENCE_SCHEMA = "o1-256-o1c70-native-failure-evidence-v1"
PUBLICATION_RECOVERY_SCHEMA = "o1-256-o1c70-publication-recovery-v1"

INVOCATION_ID = "O1C-0070-apple8-vault-phase-reader-v1-call-0006"
CAPSULE_SUFFIX = "O1C-0070_apple8-vault-phase-reader-v1"
PUBLICATION_SOURCE_NAME = "publication_source.json"
RESULT_RELATIVE = Path(
    "research/O1C0070_APPLE8_VAULT_PHASE_READER_RESULT_20260719.json"
)
DESIGN_RELATIVE = Path("research/O1C0070_APPLE8_VAULT_PHASE_READER_DESIGN_20260719.md")
CONFIG_RELATIVE = Path("configs/o1c70_apple8_vault_phase_reader_v1.json")

PARENT_RESULT_RELATIVE = Path(
    "research/O1C0069_APPLE8_ALTERNATING_READER_RESULT_20260719.json"
)
PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260719_170824_O1C-0069_apple8-alternating-reader-v1"
)
PARENT_RESULT_SHA256 = (
    "43512370d7243d57bb3ffaed445ee9196315e350d3ee1169ee0c0d8ad94ba89b"
)
PARENT_MANIFEST_SHA256 = (
    "2a78e568f0be7eafad4d117cd84aeadd0d495d19296d8ba85676496219377cb8"
)
PARENT_SOURCE_COMMIT = "d6dfc06f3e7d6dfcc29d696829927b132bad23aa"
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
PARENT_LINEAGE_CALLS = 6
PARENT_COMPLETED_EPISODES = 1
PARENT_LAST_CONSUMED_ORDINAL = 5
PARENT_LAST_COMPLETED_ORDINAL = 5
PARENT_FAILED_ORDINAL = 2
PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS = 2_565
PARENT_FAILED_CALL_BILLED_CONFLICTS: None = None
PARENT_LINEAGE_ACTUAL_BILLED_CONFLICTS: None = None
PARENT_LAST_DECISIONS = 4_517
PARENT_LAST_PROPAGATIONS = 1_192_529
PARENT_LAST_MINIMUM_UPPER_BOUND = 9.111031965569408

LOCAL_EPISODE_ORDINAL = 0
LINEAGE_CALL_ORDINAL = 6
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

BASE_VAULT_RELATIVE = Path(
    "runs/20260719_152601_O1C-0067_apple8-vault-continuation-v1/"
    "episodes/00/vault-output.bin"
)
BASE_VAULT_SHA256 = "371dd8454e46eb6c53549efa53e6412f5798b22a06e6f96c927ab74df2ba687a"
BASE_VAULT_BYTES = 140_483
BASE_VAULT_CLAUSES = 12
BASE_VAULT_LITERALS = 35_061
BASE_VAULT_AGGREGATE_SHA256 = (
    "76d5bab1665fdfafa6ff7d8d7de6a830f3fa94f8742105f6ee41bcc192d05ff0"
)
PHASE_SUFFIX_START = BASE_VAULT_CLAUSES
PHASE_SUFFIX_STOP = PARENT_RETAINED_VAULT_CLAUSES
PHASE_SUFFIX_CLAUSES = 190
PHASE_SUFFIX_LITERALS = 564_667
PHASE_SUFFIX_RECORD_BYTES = 2_259_428
PHASE_SUFFIX_RECORDS_SHA256 = (
    "cbec487e215b70a22f91b0424f05809a06c0f6cdd5c3fa259bcab0b710e74521"
)
PHASE_FIELD_BYTES = 1_024
PHASE_FIELD_SHA256 = "5d7fd1cfca56c1ab29f9e1490d28e16d3f5def611dad2f52c4ea4015678605fe"
PHASE_EFFECTIVE_BITPACK_HEX = (
    "ec6d45759effd185e9a6c163d47659ea2557df6f22bb9a017361f3f6d20c3955"
)
PHASE_EFFECTIVE_BITPACK_SHA256 = (
    "6381f90ee279a8075d4279ecfec5a3560e910afc12c891cb0bd86dac0ad511ec"
)
PHASE_POSITIVE_COUNT = 139
PHASE_NEGATIVE_COUNT = 116
PHASE_UNPHASED_VARIABLES = (241,)
PHASE_APPLIED_CALLS = 255
KEY_VARIABLE_COUNT = 256
TARGET_FREE_ANALYSIS_RELATIVE = Path(
    "research/O1C0070_TARGET_FREE_VAULT_PHASE_ANALYSIS_20260719.json"
)
TARGET_FREE_ANALYSIS_SCHEMA = "o1-256-o1c70-target-free-vault-phase-analysis-v1"
TARGET_FREE_ANALYSIS_SHA256 = (
    "af28f9639b4dec9e861fc250d9cf43cd81c10ddfe19e88256dbebeb72135c53d"
)
TARGET_FREE_PREFLIGHT_RELATIVE = Path(
    "research/O1C0070_TARGET_FREE_PHASE_READER_PREFLIGHT_20260719.json"
)
TARGET_FREE_PREFLIGHT_SCHEMA = "o1-256-o1c70-target-free-phase-reader-preflight-v1"
TARGET_FREE_PREFLIGHT_CLASSIFICATION = (
    "O1C70_TARGET_FREE_VAULT_PHASE_READER_PREFLIGHT_PASS"
)

CAPACITY_RESERVATION: dict[str, object] = {
    "schema": "o1-256-o1c70-observed-envelope-capacity-reservation-v1",
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

PHASE_SOURCE_BINDING: dict[str, object] = {
    "schema": "o1-256-o1c70-vault-phase-source-v1",
    "base_vault": BASE_VAULT_RELATIVE.as_posix(),
    "base_vault_sha256": BASE_VAULT_SHA256,
    "base_vault_serialized_bytes": BASE_VAULT_BYTES,
    "base_vault_clause_count": BASE_VAULT_CLAUSES,
    "base_vault_literal_count": BASE_VAULT_LITERALS,
    "base_vault_aggregate_clause_sha256": BASE_VAULT_AGGREGATE_SHA256,
    "current_vault_sha256": PARENT_RETAINED_VAULT_SHA256,
    "current_vault_serialized_bytes": PARENT_RETAINED_VAULT_BYTES,
    "current_vault_clause_count": PARENT_RETAINED_VAULT_CLAUSES,
    "current_vault_literal_count": PARENT_RETAINED_VAULT_LITERALS,
    "current_vault_aggregate_clause_sha256": (PARENT_RETAINED_VAULT_AGGREGATE_SHA256),
    "exact_base_clause_prefix_required": True,
    "suffix_start_clause_index": PHASE_SUFFIX_START,
    "suffix_stop_clause_index_exclusive": PHASE_SUFFIX_STOP,
    "suffix_clause_count": PHASE_SUFFIX_CLAUSES,
    "suffix_literal_count": PHASE_SUFFIX_LITERALS,
    "suffix_canonical_record_bytes": PHASE_SUFFIX_RECORD_BYTES,
    "suffix_canonical_records_sha256": PHASE_SUFFIX_RECORDS_SHA256,
    "field_sha256": PHASE_FIELD_SHA256,
    "effective_bitpack_sha256": PHASE_EFFECTIVE_BITPACK_SHA256,
    "supported_ties": 0,
    "raw_vs_inverse_clause_length_hamming_distance": 0,
    "single_clause_jackknife_count": PHASE_SUFFIX_CLAUSES,
    "single_clause_jackknife_phase_flips": 0,
}

READER_SCHEMA = "o1-256-cadical-vault-phase-field-reader-v1"
READER_OPERATOR = "vault-suffix-cut-literal-majority-phase"
READER_SPEC_SHA256 = "3dba50d3a376c2c025e2edbcc47215f19610547ad5bd6260221c82a1641df075"
READER_BINDING: dict[str, object] = json.loads(
    json.dumps(dict(_phase_v1.PRODUCTION_VAULT_PHASE_READER))
)

NATIVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v9"
NATIVE_IMPLEMENTATION_PARENT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v6"
NATIVE_ADAPTER_SCHEMA = "o1-256-joint-score-sieve-v12-adapter-v1"
NATIVE_LEDGER_SCHEMA = _native_v12.O1C67_VAULT_SOFT_CONFLICT_LEDGER_SCHEMA
NATIVE_VAULT_TELEMETRY_SCHEMA = _o1c67.NATIVE_VAULT_TELEMETRY_SCHEMA

PUBLIC_EXACT_RECOVERY = "PUBLIC_EXACT_RECOVERY"
VAULT_PHASE_READER_GAIN = "EPISODIC_VAULT_ACTIVE_PHASE_READER_GAIN"
VAULT_PHASE_READER_NO_GAIN = "EPISODIC_VAULT_ACTIVE_PHASE_READER_NO_GAIN"
THRESHOLD_REGION_EXHAUSTED = "EPISODIC_VAULT_THRESHOLD_REGION_EXHAUSTED"
CAPACITY_TERMINAL = "EPISODIC_VAULT_CAPACITY_TERMINAL"
OPERATIONAL_TERMINAL = "EPISODIC_VAULT_ACTIVE_PHASE_READER_OPERATIONAL_TERMINAL"
INVALID_RESULT_TERMINAL = "EPISODIC_VAULT_ACTIVE_PHASE_READER_INVALID_RESULT"

SOURCE_RELATIVES = {
    "runner": "src/o1_crypto_lab/o1c70_apple8_vault_phase_reader_run.py",
    "joint_score_sieve_v12": "src/o1_crypto_lab/joint_score_sieve_v12.py",
    "joint_score_sieve_v11": "src/o1_crypto_lab/joint_score_sieve_v11.py",
    "vault_phase_field_v1": "src/o1_crypto_lab/vault_phase_field_v1.py",
    "native_source": "native/cadical_o1_joint_score_sieve_v9.cpp",
    "native_parent_source": "native/cadical_o1_joint_score_sieve_v6.cpp",
    "o1c69_runner": "src/o1_crypto_lab/o1c69_apple8_alternating_reader_run.py",
    "o1c68_runner": "src/o1_crypto_lab/o1c68_apple8_complementary_phase_run.py",
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
    "frozen_sha256",
    "grouping_provenance",
    "input",
    "parent",
    "retained_vault",
    "reader",
    "invocation",
    "native",
    "budgets",
    "capacity_reservation",
    "phase_source",
    "target_free_gates",
    "next_action",
}


class O1C70RunError(RuntimeError):
    """O1C-0070 provenance, protocol, reader, or result differs."""


class O1C70ParentError(O1C70RunError):
    """The sealed O1C-0069 parent, base prefix, or retained vault differs."""


class EpisodeInvoker(Protocol):
    def __call__(self, local_ordinal: int, lineage_ordinal: int, vault: Path) -> object:
        """Make the one authorized fresh native-v9 process call."""


@dataclass(frozen=True)
class ImportedParentVault:
    source_path: Path
    payload: bytes
    independent: _o1c66.ClauseVault
    adapter: _vault_v1.ThresholdNoGoodVault
    base: _o1c66.ClauseVault
    phase_field: _phase_v1.VaultPhaseField


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
        raise O1C70RunError(f"{field} must be an object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise O1C70RunError(f"{field} must be an array")
    return cast(Sequence[object], value)


def _nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise O1C70RunError(f"{field} differs")
    return value


def _finite_float(value: object, field: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        raise O1C70RunError(f"{field} differs")
    return float(value)


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C70RunError(f"{field} differs")
    return value


def _digest_or_pending(value: object, field: str) -> str:
    if value == "PENDING":
        return "PENDING"
    return _sha256(value, field)


def _relative(root: Path, value: object, field: str) -> Path:
    if not isinstance(value, str):
        raise O1C70RunError(f"{field} differs")
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise O1C70RunError(f"{field} escapes the lab")
    try:
        path = (root / candidate).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise O1C70RunError(f"{field} cannot be resolved") from exc
    if not path.is_relative_to(root):
        raise O1C70RunError(f"{field} escapes the lab")
    return path


def _read_json(path: Path, field: str) -> Mapping[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise O1C70RunError(f"{field} cannot be read") from exc
    return _mapping(value, field)


def _validate_reader(value: object, field: str = "reader") -> dict[str, object]:
    reader = _mapping(value, field)
    if set(reader) != set(READER_BINDING):
        raise O1C70RunError(f"{field} fields differ")
    integer_fields = {
        "phase_before_override": 1,
        "seed": 0,
        "quiet": 1,
        "factor": 0,
        "phase": 1,
        "rephase": 0,
    }
    boolean_fields = {
        "forcephase": True,
        "lucky": False,
        "walk": False,
    }
    if any(
        isinstance(reader.get(name), bool)
        or not isinstance(reader.get(name), int)
        or reader.get(name) != expected
        for name, expected in integer_fields.items()
    ) or any(
        not isinstance(reader.get(name), bool) or reader.get(name) is not expected
        for name, expected in boolean_fields.items()
    ):
        raise O1C70RunError(f"{field} phase binding differs")
    for name in set(READER_BINDING) - set(integer_fields) - set(boolean_fields):
        if reader.get(name) != READER_BINDING[name]:
            raise O1C70RunError(f"{field} identity differs")
    try:
        adapter_reader = _native_v12.validate_vault_phase_field_reader(reader)
    except Exception as exc:
        raise O1C70RunError(f"{field} adapter identity differs") from exc
    if dict(adapter_reader) != READER_BINDING:
        raise O1C70RunError(f"{field} adapter identity differs")
    return dict(reader)


FROZEN_APPLE8_SHA256 = {
    "authoritative_result": (
        "21c2170225a814bf715b6a4332bd88210fca7cbb4c6db21237becbfdd85795be"
    ),
    "manifest": "751b89019d1f65b8180b15eafbb4bdf45c6080b0894c50567ee63eff15405a69",
    "capsule_result": (
        "21c2170225a814bf715b6a4332bd88210fca7cbb4c6db21237becbfdd85795be"
    ),
    "native_result": (
        "2cbd354b2d39d7c80206c6f3fb06ed4583d4b7c8436334f76ccaa1feaac5ab20"
    ),
    "preflight": "c0456e495d340fe8f08569ffc511608db976c0702988101ceaf946b668cc5880",
    "native_build": (
        "03eecfdb8fb61322db90b5fa80046e255b5c325ff5b9877d63e37b05a9bc0b3a"
    ),
    "truth_reveal": (
        "63706f65c9e355711621e2188494514d1c201306d2b6a5c6928833aedfd77efd"
    ),
}


def load_config(path: str | Path) -> dict[str, object]:
    """Load the exact O1C-0070 protocol without a call or filesystem write."""

    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C70RunError("config escapes the lab")
    config = dict(_read_json(config_path, "O1C70 config"))
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "source.expected_sha256")
    frozen = _mapping(config.get("frozen_sha256"), "frozen_sha256")
    grouping = _mapping(config.get("grouping_provenance"), "grouping_provenance")
    input_row = _mapping(config.get("input"), "input")
    parent = _mapping(config.get("parent"), "parent")
    retained = _mapping(config.get("retained_vault"), "retained_vault")
    phase_source = _mapping(config.get("phase_source"), "phase_source")
    target_free = _mapping(config.get("target_free_gates"), "target_free_gates")
    invocation = _mapping(config.get("invocation"), "invocation")
    native = _mapping(config.get("native"), "native")
    budgets = _mapping(config.get("budgets"), "budgets")
    capacity = validate_capacity_reservation(config.get("capacity_reservation"))
    reader = _validate_reader(config.get("reader"), "config.reader")
    if (
        set(config) != CONFIG_FIELDS
        or config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "apple8-vault-phase-reader-v1"
        or config.get("claim_level") != "TEST"
        or set(source) != {*SOURCE_NAMES, "expected_sha256"}
        or set(expected) != set(SOURCE_NAMES)
        or any(source.get(name) != path for name, path in SOURCE_RELATIVES.items())
        or dict(frozen) != FROZEN_APPLE8_SHA256
        or grouping.get("source_attempt") != "APPLE-VIEW-0009"
        or grouping.get("result")
        != "research/APPLE_VIEW_0009_EXACT_GROUPED_BOUND_RESULT_20260719.json"
        or grouping.get("result_sha256")
        != "ebbe9e308f3e3dfa00685a9c10eba6554c85e453459178a26a03b9fc6b2b3728"
        or grouping.get("classification")
        != "PUBLIC_EXACT_GROUPED_BOUND_STRICTLY_DOMINATES_PAIR_RELAXATION_NO_SEARCH_CLAIM"
        or grouping.get("native_solver_calls") != 0
        or grouping.get("truth_bytes_read") is not False
        or input_row.get("apple8_result")
        != "research/apple_view_8/apple_view_8_matched_result.json"
        or input_row.get("apple8_capsule")
        != "runs/20260719_095509_APPLE-VIEW-0008-MATCHED_crossblock-consequence-sieve-v1"
        or input_row.get("cnf_relative")
        != "artifacts/cnf/full256-eight-block-apple-view-0008.cnf"
        or input_row.get("potential_relative")
        != "artifacts/potential/primary-eight-block.potential"
        or input_row.get("truth_reveal")
        != "runs/20260719_062932_O1C-0057_multiblock-parent-criticality-rank-v1/reveal.json"
        or input_row.get("cnf_sha256") != APPLE8_CNF_SHA256
        or input_row.get("potential_sha256") != APPLE8_POTENTIAL_SHA256
        or input_row.get("threshold") != THRESHOLD
        or input_row.get("seed") != SEED
        or input_row.get("fresh_targets") != 0
        or input_row.get("scientific_entropy_calls") != 0
        or input_row.get("fresh_reveal_calls") != 0
        or input_row.get("refits") != 0
        or parent.get("attempt_id") != "O1C-0069"
        or parent.get("result") != PARENT_RESULT_RELATIVE.as_posix()
        or parent.get("result_sha256") != PARENT_RESULT_SHA256
        or parent.get("capsule") != PARENT_CAPSULE_RELATIVE.as_posix()
        or parent.get("manifest_sha256") != PARENT_MANIFEST_SHA256
        or parent.get("source_commit") != PARENT_SOURCE_COMMIT
        or parent.get("classification") != _o1c69.ALTERNATING_READER_NO_GAIN
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
        or dict(phase_source) != PHASE_SOURCE_BINDING
        or set(target_free)
        != {
            "analysis",
            "analysis_schema",
            "analysis_sha256",
            "final_preflight",
            "final_preflight_schema",
            "final_preflight_sha256",
            "required_before_science",
            "native_adapter_field_identity_required",
            "public_synthetic_phase_consequence_required",
            "deterministic_repeats_required",
            "source_vault_capacity_resource_freeze_required",
        }
        or target_free.get("analysis") != TARGET_FREE_ANALYSIS_RELATIVE.as_posix()
        or target_free.get("analysis_schema") != TARGET_FREE_ANALYSIS_SCHEMA
        or target_free.get("analysis_sha256") != TARGET_FREE_ANALYSIS_SHA256
        or target_free.get("final_preflight")
        != TARGET_FREE_PREFLIGHT_RELATIVE.as_posix()
        or target_free.get("final_preflight_schema") != TARGET_FREE_PREFLIGHT_SCHEMA
        or target_free.get("required_before_science") is not True
        or target_free.get("native_adapter_field_identity_required") is not True
        or target_free.get("public_synthetic_phase_consequence_required") is not True
        or target_free.get("deterministic_repeats_required") is not True
        or target_free.get("source_vault_capacity_resource_freeze_required") is not True
        or invocation.get("invocation_id") != INVOCATION_ID
        or invocation.get("local_episode_ordinal") != LOCAL_EPISODE_ORDINAL
        or invocation.get("lineage_call_ordinal") != LINEAGE_CALL_ORDINAL
        or invocation.get("continuation_calls_before") != 0
        or invocation.get("lineage_calls_before") != PARENT_LINEAGE_CALLS
        or invocation.get("parent_last_consumed_ordinal")
        != PARENT_LAST_CONSUMED_ORDINAL
        or invocation.get("parent_ordinal_replay_authorized") is not False
        or invocation.get("episode_is_retry") is not False
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
        or native.get("reader_spec_sha256") != READER_SPEC_SHA256
        or native.get("phase_field_sha256") != PHASE_FIELD_SHA256
        or native.get("phase_source_vault_sha256") != PARENT_RETAINED_VAULT_SHA256
        or native.get("phase_base_prefix_vault_sha256") != BASE_VAULT_SHA256
        or native.get("phase_suffix_canonical_records_sha256")
        != PHASE_SUFFIX_RECORDS_SHA256
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
        or budgets.get("maximum_fresh_targets") != 0
        or budgets.get("maximum_scientific_entropy_calls") != 0
        or budgets.get("maximum_fresh_reveal_calls") != 0
        or budgets.get("maximum_refits") != 0
        or budgets.get("maximum_mps_calls") != 0
        or budgets.get("maximum_gpu_calls") != 0
        or capacity["projected_clause_count"] != PLANNING_RESERVED_CLAUSES
        or capacity["projected_literal_count"] != PLANNING_RESERVED_LITERALS
        or capacity["projected_serialized_bytes"] != PLANNING_RESERVED_BYTES
        or reader != READER_BINDING
    ):
        raise O1C70RunError("frozen O1C-0070 config differs")
    for name in SOURCE_NAMES:
        _digest_or_pending(expected[name], f"source.expected_sha256.{name}")
    _digest_or_pending(
        target_free.get("final_preflight_sha256"),
        "target_free_gates.final_preflight_sha256",
    )
    source_native = _digest_or_pending(
        native.get("expected_source_sha256"), "native.expected_source_sha256"
    )
    executable = _digest_or_pending(
        native.get("expected_executable_sha256"),
        "native.expected_executable_sha256",
    )
    if source_native != expected["native_source"] or executable == "":
        raise O1C70RunError("native source/executable binding differs")
    return config


def validate_capacity_reservation(value: object) -> dict[str, object]:
    """Validate the conservative observed-envelope reservation before a call."""

    capacity = _mapping(value, "capacity_reservation")
    if dict(capacity) != CAPACITY_RESERVATION:
        raise O1C70RunError("capacity reservation differs")
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
        raise O1C70RunError("capacity reservation exceeds a hard vault cap")
    return dict(capacity)


def _manifest_inventory(capsule: Path) -> dict[str, str]:
    manifest = capsule / "artifacts.sha256"
    if sha256_file(manifest) != PARENT_MANIFEST_SHA256:
        raise O1C70ParentError("O1C-0069 manifest identity differs")
    inventory: dict[str, str] = {}
    try:
        for line in manifest.read_text(encoding="ascii").splitlines():
            digest, separator, relative = line.partition("  ")
            if separator != "  " or relative in inventory:
                raise O1C70ParentError("O1C-0069 manifest syntax differs")
            _sha256(digest, "O1C-0069 manifest digest")
            path = Path(relative)
            if path.is_absolute() or ".." in path.parts:
                raise O1C70ParentError("O1C-0069 manifest path escapes")
            inventory[relative] = digest
    except (OSError, UnicodeError, ValueError) as exc:
        raise O1C70ParentError("O1C-0069 manifest cannot be read") from exc
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
        raise O1C70ParentError(f"{field} dual parse differs") from exc
    if (
        independent.to_bytes() != payload
        or adapter.serialized != payload
        or independent.sha256 != adapter.sha256
        or independent.sha256 != expected_sha256
        or len(independent.clauses) != expected_clauses
        or independent.literal_count != expected_literals
        or independent.aggregate_clause_sha256 != expected_aggregate_sha256
    ):
        raise O1C70ParentError(f"{field} parsers disagree")
    return independent, adapter


def _validate_phase_population(
    current: _o1c66.ClauseVault,
    base: _o1c66.ClauseVault,
) -> _phase_v1.VaultPhaseField:
    """Reproduce the exact suffix, field, and stability gates target-free."""

    if (
        tuple(current.clauses[:BASE_VAULT_CLAUSES]) != base.clauses
        or current.identity != base.identity
    ):
        raise O1C70ParentError("O1C-0067 vault is not the exact current prefix")
    suffix = current.clauses[PHASE_SUFFIX_START:PHASE_SUFFIX_STOP]
    records = b"".join(
        struct.pack("<I", len(clause))
        + b"".join(struct.pack("<i", literal) for literal in clause)
        for clause in suffix
    )
    if (
        len(suffix) != PHASE_SUFFIX_CLAUSES
        or sum(len(clause) for clause in suffix) != PHASE_SUFFIX_LITERALS
        or len(records) != PHASE_SUFFIX_RECORD_BYTES
        or hashlib.sha256(records).hexdigest() != PHASE_SUFFIX_RECORDS_SHA256
    ):
        raise O1C70ParentError("derived 190-clause phase suffix differs")
    try:
        phase_field = _phase_v1.validate_production_vault_phase_field(
            current.to_bytes()
        )
        spec = _phase_v1.vault_phase_field_reader_spec_bytes()
    except Exception as exc:
        raise O1C70ParentError("production vault phase field differs") from exc
    description = phase_field.describe()
    if (
        any(READER_BINDING.get(name) != value for name, value in description.items())
        or len(spec) != 847
        or hashlib.sha256(spec).hexdigest() != READER_SPEC_SHA256
    ):
        raise O1C70ParentError("phase field/reader binding differs")

    raw_delta = tuple(
        left - right
        for left, right in zip(
            phase_field.positive_occurrences,
            phase_field.negative_occurrences,
        )
    )
    weighted = [Fraction(0, 1) for _ in range(KEY_VARIABLE_COUNT)]
    jackknife_flips = 0
    for clause in suffix:
        weight = Fraction(1, len(clause))
        for literal in clause:
            variable = abs(literal)
            if variable <= KEY_VARIABLE_COUNT:
                literal_sign = 1 if literal > 0 else -1
                weighted[variable - 1] += literal_sign * weight
                before = raw_delta[variable - 1]
                after = before - literal_sign
                if (before > 0) != (after > 0) or (before < 0) != (after < 0):
                    jackknife_flips += 1

    def vote_sign(value: int | Fraction) -> int:
        return 1 if value > 0 else -1 if value < 0 else 0

    supported_ties = sum(
        delta == 0 and positive + negative > 0
        for delta, positive, negative in zip(
            raw_delta,
            phase_field.positive_occurrences,
            phase_field.negative_occurrences,
        )
    )
    inverse_hamming = sum(
        vote_sign(raw) != vote_sign(inverse)
        for raw, inverse in zip(raw_delta, weighted)
    )
    if supported_ties != 0 or inverse_hamming != 0 or jackknife_flips != 0:
        raise O1C70ParentError("phase population stability gate differs")
    return phase_field


def validate_parent_and_import_vault(
    root: Path, config: Mapping[str, object], frozen: object
) -> ImportedParentVault:
    """Verify O1C-0069 and derive the exact O1C-0067-prefix suffix reader."""

    del config
    result_path = root / PARENT_RESULT_RELATIVE
    capsule = root / PARENT_CAPSULE_RELATIVE
    if (
        sha256_file(result_path) != PARENT_RESULT_SHA256
        or not capsule.is_dir()
        or capsule.is_symlink()
    ):
        raise O1C70ParentError("O1C-0069 parent identity differs")
    result = _read_json(result_path, "O1C-0069 result")
    episode = _mapping(result.get("episode"), "O1C-0069 episode")
    final_vault = _mapping(result.get("final_vault"), "O1C-0069 final vault")
    resources = _mapping(result.get("resources"), "O1C-0069 resources")
    parent = _mapping(result.get("parent"), "O1C-0069 lineage parent")
    claim = _mapping(result.get("claim_boundary"), "O1C-0069 claim boundary")
    eligible = _mapping(episode.get("eligible_emitted"), "O1C-0069 eligible emitted")
    if (
        result.get("attempt_id") != "O1C-0069"
        or result.get("classification") != _o1c69.ALTERNATING_READER_NO_GAIN
        or result.get("source_commit") != PARENT_SOURCE_COMMIT
        or result.get("capsule") != PARENT_CAPSULE_RELATIVE.as_posix()
        or result.get("local_episode_ordinal") != 0
        or result.get("lineage_call_ordinal") != 5
        or episode.get("completed") is not True
        or episode.get("native_calls_consumed") != 1
        or episode.get("billed_conflicts") != 514
        or episode.get("output_vault_archived") is not True
        or episode.get("output_vault_sidecar")
        != PARENT_RETAINED_VAULT_RELATIVE.as_posix()
        or eligible.get("novel_clause_count") != 0
        or episode.get("retry_authorized") is not False
        or resources.get("native_solver_calls") != 1
        or resources.get("billed_conflicts") != 514
        or resources.get("lineage_known_completed_billed_conflicts")
        != PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS
        or resources.get("lineage_actual_billed_conflicts") is not None
        or parent.get("known_completed_billed_conflicts") != 2_051
        or parent.get("failed_call_billed_conflicts") is not None
        or claim.get("truth_key_bytes_read") is not False
        or final_vault.get("sha256") != PARENT_RETAINED_VAULT_SHA256
        or final_vault.get("serialized_bytes") != PARENT_RETAINED_VAULT_BYTES
        or final_vault.get("clause_count") != PARENT_RETAINED_VAULT_CLAUSES
        or final_vault.get("literal_count") != PARENT_RETAINED_VAULT_LITERALS
        or final_vault.get("aggregate_clause_sha256")
        != PARENT_RETAINED_VAULT_AGGREGATE_SHA256
    ):
        raise O1C70ParentError("O1C-0069 terminal evidence differs")
    inventory = _manifest_inventory(capsule)
    required = {
        PARENT_RETAINED_VAULT_RELATIVE.as_posix(): PARENT_RETAINED_VAULT_SHA256,
        "result.json": PARENT_RESULT_SHA256,
    }
    if any(inventory.get(name) != digest for name, digest in required.items()):
        raise O1C70ParentError("O1C-0069 manifest inventory differs")
    for relative, digest in required.items():
        if sha256_file(capsule / relative) != digest:
            raise O1C70ParentError("O1C-0069 capsule artifact differs")

    source = capsule / PARENT_RETAINED_VAULT_RELATIVE
    try:
        status = source.stat(follow_symlinks=False)
        if (
            source.is_symlink()
            or not stat.S_ISREG(status.st_mode)
            or status.st_size != PARENT_RETAINED_VAULT_BYTES
        ):
            raise O1C70ParentError("retained vault file identity differs")
        payload = source.read_bytes()
    except O1C70ParentError:
        raise
    except OSError as exc:
        raise O1C70ParentError("retained vault cannot be read") from exc
    if hashlib.sha256(payload).hexdigest() != PARENT_RETAINED_VAULT_SHA256:
        raise O1C70ParentError("retained vault hash differs")

    try:
        base_path = root / BASE_VAULT_RELATIVE
        base_status = base_path.stat(follow_symlinks=False)
        if (
            base_path.is_symlink()
            or not stat.S_ISREG(base_status.st_mode)
            or base_status.st_size != BASE_VAULT_BYTES
        ):
            raise O1C70ParentError("O1C-0067 base vault identity differs")
        base_payload = base_path.read_bytes()
    except O1C70ParentError:
        raise
    except OSError as exc:
        raise O1C70ParentError("O1C-0067 base vault cannot be read") from exc
    if hashlib.sha256(base_payload).hexdigest() != BASE_VAULT_SHA256:
        raise O1C70ParentError("O1C-0067 base vault hash differs")

    independent, adapter = _parse_bound_vault(
        payload,
        frozen=frozen,
        expected_sha256=PARENT_RETAINED_VAULT_SHA256,
        expected_clauses=PARENT_RETAINED_VAULT_CLAUSES,
        expected_literals=PARENT_RETAINED_VAULT_LITERALS,
        expected_aggregate_sha256=PARENT_RETAINED_VAULT_AGGREGATE_SHA256,
        field="retained vault",
    )
    base, _ = _parse_bound_vault(
        base_payload,
        frozen=frozen,
        expected_sha256=BASE_VAULT_SHA256,
        expected_clauses=BASE_VAULT_CLAUSES,
        expected_literals=BASE_VAULT_LITERALS,
        expected_aggregate_sha256=BASE_VAULT_AGGREGATE_SHA256,
        field="O1C-0067 base vault",
    )
    phase_field = _validate_phase_population(independent, base)
    return ImportedParentVault(
        source,
        payload,
        independent,
        adapter,
        base,
        phase_field,
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
        root / TARGET_FREE_ANALYSIS_RELATIVE,
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


def validate_target_free_analysis(
    root: Path, config: Mapping[str, object]
) -> dict[str, object]:
    """Validate the recorded suffix/field analysis without reading a target."""

    gates = _mapping(config["target_free_gates"], "target_free_gates")
    analysis_path = root / TARGET_FREE_ANALYSIS_RELATIVE
    if gates.get("analysis") != TARGET_FREE_ANALYSIS_RELATIVE.as_posix():
        raise O1C70RunError("target-free analysis path differs")
    try:
        status = analysis_path.stat(follow_symlinks=False)
    except OSError as exc:
        raise O1C70RunError("target-free phase analysis cannot be read") from exc
    if analysis_path.is_symlink() or not stat.S_ISREG(status.st_mode):
        raise O1C70RunError("target-free phase analysis identity differs")
    observed_sha = sha256_file(analysis_path)
    if (
        observed_sha != TARGET_FREE_ANALYSIS_SHA256
        or gates.get("analysis_sha256") != TARGET_FREE_ANALYSIS_SHA256
    ):
        raise O1C70RunError("target-free phase analysis hash differs")
    analysis = dict(_read_json(analysis_path, "target-free phase analysis"))
    vaults = _mapping(analysis.get("vaults"), "phase analysis vaults")
    base = _mapping(vaults.get("base"), "phase analysis base vault")
    current = _mapping(vaults.get("current"), "phase analysis current vault")
    population = _mapping(analysis.get("population"), "phase analysis population")
    rule = _mapping(analysis.get("rule"), "phase analysis rule")
    field = _mapping(analysis.get("field"), "phase analysis field")
    stability = _mapping(analysis.get("stability"), "phase analysis stability")
    cadical = _mapping(analysis.get("cadical_api"), "phase analysis CaDiCaL API")
    truth = _mapping(analysis.get("truth_boundary"), "phase analysis truth boundary")
    authorization = _mapping(
        analysis.get("authorization"), "phase analysis authorization"
    )
    spec_ascii = rule.get("spec_ascii")
    if (
        analysis.get("schema") != TARGET_FREE_ANALYSIS_SCHEMA
        or analysis.get("attempt_id") != ATTEMPT_ID
        or base.get("sha256") != BASE_VAULT_SHA256
        or base.get("clause_count") != BASE_VAULT_CLAUSES
        or base.get("literal_count") != BASE_VAULT_LITERALS
        or current.get("sha256") != PARENT_RETAINED_VAULT_SHA256
        or current.get("clause_count") != PARENT_RETAINED_VAULT_CLAUSES
        or current.get("literal_count") != PARENT_RETAINED_VAULT_LITERALS
        or current.get("serialized_bytes") != PARENT_RETAINED_VAULT_BYTES
        or vaults.get("exact_prefix_validated") is not True
        or population.get("start_index_zero_based") != PHASE_SUFFIX_START
        or population.get("clause_count") != PHASE_SUFFIX_CLAUSES
        or population.get("literal_count") != PHASE_SUFFIX_LITERALS
        or population.get("canonical_clause_record_bytes") != PHASE_SUFFIX_RECORD_BYTES
        or population.get("canonical_clause_records_sha256")
        != PHASE_SUFFIX_RECORDS_SHA256
        or rule.get("spec_ascii_bytes") != 847
        or rule.get("spec_ascii_lines") != 15
        or rule.get("spec_final_lf") is not True
        or rule.get("spec_sha256") != READER_SPEC_SHA256
        or not isinstance(spec_ascii, str)
        or hashlib.sha256(spec_ascii.encode("ascii")).hexdigest() != READER_SPEC_SHA256
        or field.get("serialized_bytes") != PHASE_FIELD_BYTES
        or field.get("sha256") != PHASE_FIELD_SHA256
        or field.get("positive_phase_count") != PHASE_POSITIVE_COUNT
        or field.get("negative_phase_count") != PHASE_NEGATIVE_COUNT
        or field.get("zero_vote_count") != len(PHASE_UNPHASED_VARIABLES)
        or field.get("zero_vote_variables") != list(PHASE_UNPHASED_VARIABLES)
        or field.get("applied_phase_calls") != PHASE_APPLIED_CALLS
        or field.get("effective_bitpack_hex") != PHASE_EFFECTIVE_BITPACK_HEX
        or field.get("effective_bitpack_sha256") != PHASE_EFFECTIVE_BITPACK_SHA256
        or stability.get("supported_ties") != 0
        or stability.get("raw_vs_inverse_clause_length_hamming_distance") != 0
        or stability.get("single_clause_jackknife_count") != PHASE_SUFFIX_CLAUSES
        or stability.get("single_clause_jackknife_phase_flips") != 0
        or cadical.get("api") != "Solver::phase(int literal)"
        or cadical.get("semantics")
        != (
            "persistent per-variable polarity preference; no variable-order or "
            "confidence-magnitude effect"
        )
        or cadical.get("fresh_solver_required") is not True
        or truth.get("truth_key_bytes_read") is not False
        or truth.get("fresh_targets") != 0
        or truth.get("fresh_reveal_calls") != 0
        or truth.get("scientific_solver_calls") != 0
        or truth.get("refits") != 0
        or truth.get("MPS_or_GPU") is not False
        or authorization.get("ready_for_native_implementation") is not True
        or authorization.get("ready_for_full256_science") is not False
    ):
        raise O1C70RunError("target-free phase analysis evidence differs")
    return analysis


def _validate_final_target_free_preflight(
    value: Mapping[str, object], config: Mapping[str, object]
) -> dict[str, object]:
    """Validate every final native/adapter/synthetic/freeze authorization gate."""

    reader = _validate_reader(value.get("reader_binding"), "gate reader binding")
    derivation = _mapping(value.get("derivation_analysis"), "gate derivation")
    identity = _mapping(
        value.get("native_adapter_field_identity"), "gate native/adapter identity"
    )
    synthetic = _mapping(
        value.get("public_synthetic_phase_consequence"), "gate synthetic consequence"
    )
    build = _mapping(value.get("native_build_reproducibility"), "gate native build")
    parent = _mapping(value.get("sealed_parent"), "gate sealed parent")
    capacity = _mapping(
        value.get("capacity_and_resources"), "gate capacity and resources"
    )
    protocol = _mapping(value.get("one_call_protocol"), "gate one-call protocol")
    claim = _mapping(value.get("claim_boundary"), "gate claim boundary")
    native = _mapping(config["native"], "native")
    expected_source = _digest_or_pending(
        native.get("expected_source_sha256"), "native expected source"
    )
    expected_executable = _digest_or_pending(
        native.get("expected_executable_sha256"), "native expected executable"
    )
    native_reader = _validate_reader(
        identity.get("native_reader"), "gate native reader"
    )
    adapter_reader = _validate_reader(
        identity.get("adapter_reader"), "gate adapter reader"
    )
    if (
        value.get("schema") != TARGET_FREE_PREFLIGHT_SCHEMA
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("classification") != TARGET_FREE_PREFLIGHT_CLASSIFICATION
        or value.get("target_free") is not True
        or value.get("all_gates_passed") is not True
        or value.get("full256_native_solver_calls") != 0
        or value.get("truth_key_bytes_read") is not False
        or value.get("fresh_targets") != 0
        or value.get("scientific_entropy_calls") != 0
        or value.get("fresh_reveal_calls") != 0
        or value.get("refits") != 0
        or value.get("mps_calls") != 0
        or value.get("gpu_calls") != 0
        or reader != READER_BINDING
        or derivation.get("path") != TARGET_FREE_ANALYSIS_RELATIVE.as_posix()
        or derivation.get("sha256") != TARGET_FREE_ANALYSIS_SHA256
        or derivation.get("exact_prefix_validated") is not True
        or derivation.get("raw_vs_inverse_clause_length_identical") is not True
        or derivation.get("supported_ties") != 0
        or derivation.get("single_clause_jackknife_phase_flips") != 0
        or identity.get("exact_equal") is not True
        or native_reader != READER_BINDING
        or adapter_reader != READER_BINDING
        or identity.get("native_field_sha256") != PHASE_FIELD_SHA256
        or identity.get("adapter_field_sha256") != PHASE_FIELD_SHA256
        or identity.get("native_effective_bitpack_sha256")
        != PHASE_EFFECTIVE_BITPACK_SHA256
        or identity.get("adapter_effective_bitpack_sha256")
        != PHASE_EFFECTIVE_BITPACK_SHA256
        or synthetic.get("reader_changes_search_consequence") is not True
        or synthetic.get("deterministic_repeats") is not True
        or _nonnegative_int(synthetic.get("repeat_count"), "gate repeat count") < 2
        or build.get("native_source_sha256") != expected_source
        or build.get("production_executable_sha256") != expected_executable
        or _nonnegative_int(build.get("independent_rebuilds"), "gate rebuilds") < 2
        or build.get("independent_rebuilds_identical") is not True
        or parent.get("result_sha256") != PARENT_RESULT_SHA256
        or parent.get("manifest_sha256") != PARENT_MANIFEST_SHA256
        or parent.get("retained_vault_sha256") != PARENT_RETAINED_VAULT_SHA256
        or parent.get("base_vault_sha256") != BASE_VAULT_SHA256
        or parent.get("exact_prefix_validated") is not True
        or capacity.get("all_passed") is not True
        or capacity.get("planning_reservation_is_formal_maximum") is not False
        or capacity.get("maximum_clause_count") != _o1c66.VAULT_MAXIMUM_CLAUSES
        or capacity.get("maximum_literal_count") != _o1c66.VAULT_MAXIMUM_LITERALS
        or capacity.get("maximum_serialized_bytes")
        != _o1c66.VAULT_MAXIMUM_SERIALIZED_BYTES
        or capacity.get("timeout_seconds") != TIMEOUT_SECONDS
        or capacity.get("memory_limit_bytes") != MEMORY_LIMIT_BYTES
        or protocol.get("local_episode_ordinal") != LOCAL_EPISODE_ORDINAL
        or protocol.get("lineage_call_ordinal") != LINEAGE_CALL_ORDINAL
        or protocol.get("maximum_native_solver_calls") != 1
        or protocol.get("requested_conflicts") != REQUESTED_CONFLICTS
        or protocol.get("requested_conflicts_is_soft_horizon") is not True
        or protocol.get("actual_solve_conflicts_billed") is not True
        or protocol.get("retry_authorized") is not False
        or protocol.get("phase_sweep_authorized") is not False
        or claim.get("polarity_only") is not True
        or claim.get("controls_variable_order") is not False
        or claim.get("encodes_confidence_magnitude") is not False
    ):
        raise O1C70RunError("final target-free phase-reader preflight differs")
    return dict(value)


def validate_final_target_free_preflight(
    root: Path,
    config: Mapping[str, object],
    *,
    required: bool,
) -> tuple[dict[str, object] | None, str | None, bool]:
    """Load the final gate artifact, allowing only an unfrozen draft pre-science."""

    gates = _mapping(config["target_free_gates"], "target_free_gates")
    expected = _digest_or_pending(
        gates.get("final_preflight_sha256"),
        "target_free_gates.final_preflight_sha256",
    )
    path = root / TARGET_FREE_PREFLIGHT_RELATIVE
    if not path.exists():
        if required or expected != "PENDING":
            raise O1C70RunError("final target-free preflight is absent")
        return None, None, False
    try:
        status = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise O1C70RunError("final target-free preflight cannot be read") from exc
    if path.is_symlink() or not stat.S_ISREG(status.st_mode):
        raise O1C70RunError("final target-free preflight identity differs")
    observed = sha256_file(path)
    if expected != "PENDING" and observed != expected:
        raise O1C70RunError("final target-free preflight hash differs")
    validated = _validate_final_target_free_preflight(
        _read_json(path, "final target-free preflight"), config
    )
    frozen = expected != "PENDING" and observed == expected
    if required and not frozen:
        raise O1C70RunError("final target-free preflight remains unfrozen")
    return validated, observed, frozen


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
            raise O1C70RunError(f"source hash differs for {name}")
    if require_commit_binding and unresolved:
        raise O1C70RunError("science source hashes remain PENDING")
    if (
        getattr(_native_v12, "JOINT_SCORE_SIEVE_ADAPTER_SCHEMA", None)
        != NATIVE_ADAPTER_SCHEMA
        or getattr(_native_v12, "JOINT_SCORE_SIEVE_RESULT_SCHEMA", None)
        != NATIVE_RESULT_SCHEMA
        or getattr(_native_v12, "JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA", None)
        != NATIVE_IMPLEMENTATION_PARENT_SCHEMA
        or dict(_phase_v1.PRODUCTION_VAULT_PHASE_READER)
        != {
            **READER_BINDING,
            "unphased_variables": tuple(PHASE_UNPHASED_VARIABLES),
        }
    ):
        raise O1C70RunError("adapter-v12/phase-field schema binding differs")

    baseline = _o1c65.validate_apple8_baseline(root, config)
    _o1c65.validate_grouping_provenance(root, config)
    potential = cast(Path, getattr(baseline, "potential"))
    cnf = cast(Path, getattr(baseline, "cnf"))
    frozen = _o1c65.build_frozen_grouping(potential, config)
    imported = validate_parent_and_import_vault(root, config, frozen)
    phase_analysis = validate_target_free_analysis(root, config)
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
            raise O1C70RunError("science sources/config are not clean")
        for name in SOURCE_NAMES:
            _commit_bound_bytes(
                root, source_commit, _relative(root, source[name], name), name
            )
        _commit_bound_bytes(root, source_commit, config_file, "config")
        _commit_bound_bytes(
            root,
            source_commit,
            root / TARGET_FREE_ANALYSIS_RELATIVE,
            "target-free phase analysis",
        )
        _commit_bound_bytes(
            root,
            source_commit,
            root / TARGET_FREE_PREFLIGHT_RELATIVE,
            "final target-free phase-reader preflight",
        )

    memory_free = _memory_free_percent()
    disk_free = shutil.disk_usage(root).free
    cpu_count = max(os.cpu_count() or 1, 1)
    load_1m = os.getloadavg()[0]
    normalized_load = load_1m / cpu_count
    active = _o1c67._active_conflicting_processes()
    if memory_free is not None and memory_free < MINIMUM_MEMORY_FREE_PERCENT:
        raise O1C70RunError("memory-pressure preflight is below gate")
    if disk_free < MINIMUM_DISK_FREE_BYTES:
        raise O1C70RunError("disk-free preflight is below gate")
    if normalized_load > MAXIMUM_NORMALIZED_LOAD_1M:
        raise O1C70RunError("normalized system load is above gate")
    if active:
        raise O1C70RunError("conflicting science process is active")
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
            [] if final_gate_frozen else ["target_free_gates.final_preflight_sha256"]
        ),
        "adapter_source_sha256": observed["joint_score_sieve_v12"],
        "native_source_sha256": observed["native_source"],
        "native_adapter_schema": NATIVE_ADAPTER_SCHEMA,
        "native_result_schema": NATIVE_RESULT_SCHEMA,
        "native_implementation_parent_schema": NATIVE_IMPLEMENTATION_PARENT_SCHEMA,
        "reader": dict(READER_BINDING),
        "phase_source": dict(PHASE_SOURCE_BINDING),
        "phase_only_limit": {
            "polarity_only": True,
            "controls_variable_order": False,
            "encodes_confidence_magnitude": False,
        },
        "reader_spec_sha256": READER_SPEC_SHA256,
        "phase_field": imported.phase_field.describe(),
        "phase_analysis": {
            "path": TARGET_FREE_ANALYSIS_RELATIVE.as_posix(),
            "sha256": TARGET_FREE_ANALYSIS_SHA256,
            "schema": phase_analysis.get("schema"),
            "validated": True,
        },
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
        "base_vault_sha256": imported.base.sha256,
        "exact_base_clause_prefix_validated": True,
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
        raise O1C70RunError("preflight-bound config cannot be captured") from exc
    if (
        hashlib.sha256(payload).hexdigest() != expected_sha256
        or not isinstance(decoded, dict)
        or decoded != config
    ):
        raise O1C70RunError("config identity changed after preflight")
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
    bindings: Mapping[str, object], vault: _o1c66.ClauseVault
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
        "reader": dict(READER_BINDING),
        "capacity_reservation": dict(CAPACITY_RESERVATION),
        "retained_vault": vault.describe(),
        "bindings": dict(bindings),
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
        "reader": dict(READER_BINDING),
        "reader_spec_sha256": READER_SPEC_SHA256,
        "phase_source": dict(PHASE_SOURCE_BINDING),
        "phase_only_limit": {
            "polarity_only": True,
            "controls_variable_order": False,
            "encodes_confidence_magnitude": False,
        },
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


def _validated_native(
    result: object,
) -> tuple[
    dict[str, object], dict[str, int | float], Mapping[str, object], dict[str, object]
]:
    try:
        raw = _mapping(getattr(result, "raw"), "native.raw")
        result_reader = _validate_reader(getattr(result, "reader"), "native.reader")
        raw_reader = _validate_reader(raw.get("reader"), "native.raw.reader")
        stats = _native_v12.validate_vault_soft_conflict_ledger(
            _mapping(getattr(result, "stats"), "native.stats")
        )
        resources = _mapping(getattr(result, "resources"), "native.resources")
        sieve = _mapping(getattr(result, "sieve"), "native.sieve")
        telemetry = _mapping(
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
            result_reader != READER_BINDING
            or raw_reader != READER_BINDING
            or isinstance(status, bool)
            or status not in (0, 10, 20)
            or conflict_limit != REQUESTED_CONFLICTS
            or threshold != THRESHOLD
            or stats["requested_conflicts"] != REQUESTED_CONFLICTS
            or stats["billed_conflicts"] != stats["solve_conflicts"]
            or raw.get("schema") != NATIVE_RESULT_SCHEMA
            or raw.get("implementation_parent_schema")
            != NATIVE_IMPLEMENTATION_PARENT_SCHEMA
            or telemetry.get("schema") != NATIVE_VAULT_TELEMETRY_SCHEMA
            or peak > MEMORY_LIMIT_BYTES
            or wall > int(TIMEOUT_SECONDS * 1_000_000)
        ):
            raise O1C70RunError("native O1C-0070 contract differs")
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
        return dict(raw), ledger, telemetry, result_reader
    except O1C70RunError:
        raise
    except Exception as exc:
        raise O1C70RunError("native O1C-0070 result differs") from exc


def execute_single_continuation(
    *,
    capsule: Path,
    imported_vault: _o1c66.ClauseVault,
    adapter_vault: _vault_v1.ThresholdNoGoodVault,
    invoke_episode: EpisodeInvoker,
    verify_public_model: Callable[[bytes], bool],
    bindings: Mapping[str, object],
) -> SingleContinuationOutcome:
    """Persist lineage ordinal 6, consume exactly one call, and never retry."""

    if not capsule.is_dir() or imported_vault.sha256 != PARENT_RETAINED_VAULT_SHA256:
        raise O1C70RunError("single-continuation capsule or vault differs")
    if (
        len(imported_vault.clauses) != PARENT_RETAINED_VAULT_CLAUSES
        or imported_vault.literal_count != PARENT_RETAINED_VAULT_LITERALS
        or imported_vault.serialized_bytes != PARENT_RETAINED_VAULT_BYTES
        or PLANNING_RESERVED_CLAUSES > _o1c66.VAULT_MAXIMUM_CLAUSES
        or PLANNING_RESERVED_LITERALS > _o1c66.VAULT_MAXIMUM_LITERALS
        or PLANNING_RESERVED_BYTES > _o1c66.VAULT_MAXIMUM_SERIALIZED_BYTES
    ):
        raise O1C70RunError("capacity reservation is not call-safe")
    imported_path = capsule / "vault-imported.bin"
    _o1c66.write_vault(imported_path, imported_vault)
    if imported_path.read_bytes() != adapter_vault.serialized:
        raise O1C70RunError("dual-parsed imported vault bytes differ")
    reread = _o1c66.read_vault(
        imported_path,
        identity=imported_vault.identity,
        observed_variables=imported_vault.observed_variables,
    )
    if reread != imported_vault:
        raise O1C70RunError("capsule imported vault reread differs")

    invocation_path = capsule / "invocation.json"
    _atomic_json(invocation_path, _invocation(bindings, imported_vault))
    invocation_sha = sha256_file(invocation_path)
    episode_dir = capsule / "episodes" / "00"
    episode_dir.mkdir(parents=True, exist_ok=False)
    intent_path = episode_dir / "intent.json"
    _atomic_json(intent_path, _intent(invocation_sha, imported_vault, bindings))
    intent_sha = sha256_file(intent_path)
    if not invocation_path.is_file() or not intent_path.is_file():
        raise O1C70RunError("invocation/intent not durable before call")

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
            "reader": dict(READER_BINDING),
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
            "reader": dict(READER_BINDING),
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
        raw, ledger, vault_telemetry, reader = _validated_native(result)
        eligible_raw = getattr(result, "eligible_emitted_clauses")
        if not isinstance(eligible_raw, Sequence):
            raise O1C70RunError("eligible emitted clause sequence differs")
        eligible = tuple(_o1c66._clause_literals(item) for item in eligible_raw)
        if (
            _o1c66._adapter_vault_payload(getattr(result, "input_vault"))
            != imported_vault.to_bytes()
        ):
            raise O1C70RunError("native input vault differs")
        status = cast(int, ledger["status"])
        key_model = getattr(result, "key_model", None)
        if status == 10:
            if not isinstance(key_model, bytes) or not verify_public_model(key_model):
                raise O1C70RunError("SAT model failed public eight-block verification")
        elif key_model is not None:
            raise O1C70RunError("non-SAT continuation returned a key")

        next_available = vault_telemetry.get("next_vault_available")
        terminal_reason = vault_telemetry.get("next_vault_terminal_reason")
        adapter_next = getattr(result, "next_vault")
        if not isinstance(next_available, bool):
            raise O1C70RunError("next-vault availability differs")
        if next_available:
            if terminal_reason is not None or adapter_next is None:
                raise O1C70RunError("available next vault differs")
            next_payload = _o1c66._adapter_vault_payload(adapter_next)
            parsed_next = _o1c66.ClauseVault.from_bytes(
                next_payload,
                expected_identity=imported_vault.identity,
                observed_variables=imported_vault.observed_variables,
            )
            expected_next, novel, duplicates = imported_vault.append_emitted(eligible)
            if parsed_next != expected_next:
                raise O1C70RunError("cumulative continuation vault differs")
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
                raise O1C70RunError("terminal next vault differs")
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
        telemetry_path = episode_dir / "vault_telemetry.json"
        _atomic_json(telemetry_path, dict(vault_telemetry))
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
                raise O1C70RunError("continuation output vault reread differs")

        novel_count = len(novel)
        if status == 10:
            classification, stop_reason = (
                PUBLIC_EXACT_RECOVERY,
                "public-verified-candidate",
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
                VAULT_PHASE_READER_GAIN,
                "novel-exact-clauses",
            )
        else:
            classification, stop_reason = (
                VAULT_PHASE_READER_NO_GAIN,
                "zero-novel-eligible-clauses",
            )
        episode = {
            "schema": EPISODE_SCHEMA,
            "completed": True,
            "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
            "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
            "invocation_sha256": invocation_sha,
            "intent_sha256": intent_sha,
            "reader": reader,
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
            "vault_telemetry_sha256": sha256_file(telemetry_path),
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
            "expected_reader": dict(READER_BINDING),
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
            "reader": dict(READER_BINDING),
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
        raise O1C70RunError("native-v9 build identity differs") from exc
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
        raise O1C70RunError("native-v9 build identity differs")


def invoke_native_episode(
    *, executable: Path, cnf: Path, potential: Path, grouping: Path, vault: Path
) -> object:
    _o1c65.validate_frozen_call_inputs(cnf=cnf, potential=potential, grouping=grouping)
    if vault.is_symlink() or sha256_file(vault) != PARENT_RETAINED_VAULT_SHA256:
        raise O1C70RunError("vault-phase-reader input vault differs before call")
    try:
        phase_field = _phase_v1.validate_production_vault_phase_field(
            vault.read_bytes()
        )
    except (OSError, _phase_v1.VaultPhaseFieldError) as exc:
        raise O1C70RunError("vault phase field differs before call") from exc
    if any(
        READER_BINDING.get(name) != value
        for name, value in phase_field.describe().items()
    ):
        raise O1C70RunError("vault phase reader differs before call")
    return _native_v12.run_joint_score_sieve(
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
        "reader": dict(READER_BINDING),
        "phase_source": dict(PHASE_SOURCE_BINDING),
        "parent": {
            "attempt_id": "O1C-0069",
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
        },
        "claim_boundary": {
            "new_attempt_not_parent_retry": True,
            "parent_ordinal_replay_authorized": False,
            "exactly_one_new_native_call": outcome.native_calls == 1,
            "only_science_change": (
                "suffix190-cut-literal-majority-polarity-field-on-sealed-o1c69-vault"
            ),
            "reader_spec_sha256": READER_SPEC_SHA256,
            "phase_field_sha256": PHASE_FIELD_SHA256,
            "phase_reader_changes_only_polarity": True,
            "phase_reader_controls_variable_order": False,
            "phase_reader_encodes_confidence_magnitude": False,
            "phase_reader_uses_exact_o1c67_prefix_suffix": True,
            "requested_conflicts_is_soft_horizon": True,
            "actual_solve_conflicts_billed": billed is not None,
            "numeric_overshoot_ceiling_asserted": False,
            "hard_process_time_rss_caps_retained": True,
            "capacity_reservation_is_planning_not_formal_maximum": True,
            "status20_is_exceptional_no_retry_consistency_audit": True,
            "status20_scope": "frozen-CNF-and-score-greater-than-or-equal-threshold",
            "phase_only_reader_closed_on_null": (
                outcome.classification == VAULT_PHASE_READER_NO_GAIN
            ),
            "second_phase_call_or_sweep_authorized": False,
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
            (
                "Close the phase-only reader after this null result. Do not issue "
                "a second phase call or sweep; hand off separately to a "
                "confidence-ranked cb_decide operator."
            )
            if outcome.classification == VAULT_PHASE_READER_NO_GAIN
            else (
                "Do not replay lineage ordinal 6 or issue a second phase call or "
                "sweep; any successor must precommit a separate operator."
            )
        ),
    }


def _markdown(result: Mapping[str, object]) -> str:
    return (
        "# O1C-0070 — APPLE8 vault phase reader\n\n"
        f"- Classification: `{result['classification']}`\n"
        f"- Stop reason: `{result['stop_reason']}`\n"
        "- New native calls: `1`\n"
        "- Local / lineage ordinal: `0 / 6`\n"
        "- Reader: suffix-190 sign-majority polarity field; 255 phase calls; "
        "one phase-1 fallback; seed `0`\n"
        "- Scope: polarity only; no variable ordering or confidence magnitude\n"
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
        raise O1C70RunError("O1C-0070 terminal publication already exists")
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
        raise O1C70RunError("persistent artifact ledger did not converge")
    if persistent > MAXIMUM_PERSISTENT_ARTIFACT_BYTES:
        raise O1C70RunError("persistent artifact byte budget exceeded")
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
            raise O1C70RunError("terminal publication bytes differ")
        _o1c65._assert_immutable_tree(capsule)
    except Exception:
        _o1c65._restore_owned_capsule_for_recovery(capsule)
        if manifest_published:
            _o1c65._unlink_owned_exact(
                manifest_path, manifest, "O1C70 capsule manifest"
            )
        if authoritative_published:
            _o1c65._unlink_owned_exact(
                authoritative, payload, "O1C70 authoritative result"
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
        raise O1C70RunError(f"{field} cannot be read during recovery") from exc
    if path.is_symlink() or not stat.S_ISREG(status.st_mode):
        raise O1C70RunError(f"{field} differs during recovery")
    if expected_bytes is not None:
        size = _nonnegative_int(expected_bytes, f"{field} bytes")
        if status.st_size != size:
            raise O1C70RunError(f"{field} size differs during recovery")
    if sha256_file(path) != expected_sha:
        raise O1C70RunError(f"{field} hash differs during recovery")


def _validate_recovery_sidecars(
    capsule: Path,
    source: Mapping[str, object],
    episode: Mapping[str, object],
) -> None:
    """Revalidate every completed-call sidecar before zero-call publication."""

    episode_dir = capsule / "episodes" / "00"
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
        or _validate_reader(invocation.get("reader"), "recovery invocation reader")
        != READER_BINDING
        or invocation.get("capacity_reservation") != CAPACITY_RESERVATION
        or intent.get("invocation_id") != INVOCATION_ID
        or intent.get("invocation_sha256")
        != _sha256(invocation_sha, "recovery invocation sha256")
        or intent.get("local_episode_ordinal") != LOCAL_EPISODE_ORDINAL
        or intent.get("lineage_call_ordinal") != LINEAGE_CALL_ORDINAL
        or intent.get("parent_ordinal_replay_authorized") is not False
        or intent.get("episode_is_retry") is not False
        or _validate_reader(intent.get("reader"), "recovery intent reader")
        != READER_BINDING
        or intent.get("capacity_reservation") != CAPACITY_RESERVATION
    ):
        raise O1C70RunError("recovery invocation/intent journal differs")

    input_vault = _mapping(episode.get("input_vault"), "recovery input vault")
    _validate_recovery_file(
        capsule / "vault-imported.bin",
        expected_sha256=input_vault.get("sha256"),
        expected_bytes=input_vault.get("serialized_bytes"),
        field="recovery imported vault",
    )

    native_result = episode_dir / "native_result.json"
    vault_telemetry = episode_dir / "vault_telemetry.json"
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
        if native_failure.exists() or terminal_failure.exists():
            raise O1C70RunError("completed recovery has failure sidecars")
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
                raise O1C70RunError("status-20 recovery vault/result differs")
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
                public_model.get("present") is not True
                or public_model.get("verified_8_of_8") is not True
            ):
                raise O1C70RunError("recovery public model conclusion differs")
            expected_classification = PUBLIC_EXACT_RECOVERY
            expected_stop_reason = "public-verified-candidate"
        elif status == 0 and isinstance(available, bool):
            if not available:
                if terminal_reason not in {
                    "terminal_empty_clause",
                    "capacity_clause_count",
                    "capacity_literal_count",
                    "capacity_payload_bytes",
                }:
                    raise O1C70RunError("recovery capacity conclusion differs")
                expected_classification = CAPACITY_TERMINAL
                expected_stop_reason = terminal_reason
            elif novel_count:
                expected_classification = VAULT_PHASE_READER_GAIN
                expected_stop_reason = "novel-exact-clauses"
            else:
                expected_classification = VAULT_PHASE_READER_NO_GAIN
                expected_stop_reason = "zero-novel-eligible-clauses"
        else:
            raise O1C70RunError("completed recovery status conclusion differs")
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
            raise O1C70RunError("completed recovery vault/result differs")
        if archived:
            if episode.get("output_vault_sidecar") != "episodes/00/vault-output.bin":
                raise O1C70RunError("recovery output vault path differs")
            _validate_recovery_file(
                vault_output,
                expected_sha256=output_vault.get("sha256"),
                expected_bytes=output_vault.get("serialized_bytes"),
                field="recovery output vault",
            )
        elif episode.get("output_vault_sidecar") is not None or vault_output.exists():
            raise O1C70RunError("unarchived recovery output vault differs")
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
        or vault_output.exists()
    ):
        raise O1C70RunError("failed recovery journal differs")
    failure_sha = terminal.get("native_execution_failure_sha256")
    if failure_sha is None:
        if (
            source.get("classification") != INVALID_RESULT_TERMINAL
            or source.get("stop_reason") != "invalid-post-native-result"
            or terminal.get("classification") != INVALID_RESULT_TERMINAL
            or native_failure.exists()
        ):
            raise O1C70RunError("invalid-result recovery failure sidecar differs")
    else:
        if (
            source.get("classification") != OPERATIONAL_TERMINAL
            or source.get("stop_reason") != "native-call-or-resource-terminal"
            or terminal.get("classification") != OPERATIONAL_TERMINAL
        ):
            raise O1C70RunError("operational recovery conclusion differs")
        _validate_recovery_file(
            native_failure,
            expected_sha256=failure_sha,
            field="recovery native execution failure",
        )


def _validate_publication_source(root: Path, capsule: Path) -> dict[str, object]:
    if (
        not capsule.is_dir()
        or capsule.is_symlink()
        or capsule.parent != root / "runs"
        or not capsule.name.endswith(f"_{CAPSULE_SUFFIX}")
        or (capsule / "artifacts.sha256").exists()
    ):
        raise O1C70RunError("O1C-0070 recovery capsule differs")
    source = dict(
        _read_json(capsule / PUBLICATION_SOURCE_NAME, "O1C-0070 publication source")
    )
    episode = _mapping(source.get("episode"), "publication source episode")
    resources = _mapping(source.get("resources"), "publication source resources")
    persisted = _read_json(
        capsule / "episodes" / "00" / "episode.json", "persisted O1C-0070 episode"
    )
    if (
        source.get("schema") != RESULT_SCHEMA
        or source.get("attempt_id") != ATTEMPT_ID
        or source.get("capsule") != capsule.relative_to(root).as_posix()
        or source.get("invocation_id") != INVOCATION_ID
        or source.get("local_episode_ordinal") != LOCAL_EPISODE_ORDINAL
        or source.get("lineage_call_ordinal") != LINEAGE_CALL_ORDINAL
        or _validate_reader(source.get("reader"), "publication reader")
        != READER_BINDING
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
        raise O1C70RunError("O1C-0070 publication source differs")
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
        raise O1C70RunError("O1C-0070 authoritative publication already exists")
    source = _validate_publication_source(root, capsule)
    recovery = {
        "schema": PUBLICATION_RECOVERY_SCHEMA,
        "publication_recovered_from_completed_sidecars": True,
        "native_calls_consumed": 1,
        "native_calls_issued_during_recovery": 0,
        "completed_sidecars_revalidated": True,
        "retry_authorized": False,
        "science_classification_preserved": source.get("classification"),
        "science_stop_reason_preserved": source.get("stop_reason"),
        "reader": dict(READER_BINDING),
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
        raise O1C70RunError("O1C-0070 already exists")
    if partial_capsules:
        if len(partial_capsules) != 1:
            raise O1C70RunError("multiple O1C-0070 recovery capsules exist")
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
    baseline = _o1c65.validate_apple8_baseline(root, config)
    potential = cast(Path, getattr(baseline, "potential"))
    cnf = cast(Path, getattr(baseline, "cnf"))
    frozen = _o1c65.build_frozen_grouping(potential, config)
    imported = validate_parent_and_import_vault(root, config, frozen)
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
    with tempfile.TemporaryDirectory(prefix="o1c70-apple8-vault-phase-reader-") as raw:
        workspace = Path(raw)
        native_build = _native_v12.build_native_joint_score_sieve(
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
            raise O1C70RunError("source identity changed after preflight")
        validate_target_free_analysis(root, config)
        validate_final_target_free_preflight(root, config, required=True)
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
                "o1_crypto_lab.o1c70_apple8_vault_phase_reader_run run "
                f"--config {config_file.relative_to(root).as_posix()}\n"
            ).encode(),
        )
        bindings = {
            "source_commit": source_commit,
            "config_sha256": hashlib.sha256(config_payload).hexdigest(),
            "source_sha256": observed_sources,
            "adapter_source_sha256": observed_sources["joint_score_sieve_v12"],
            "native_source_sha256": native_build.source_sha256,
            "native_executable_sha256": native_build.executable_sha256,
            "native_adapter_schema": NATIVE_ADAPTER_SCHEMA,
            "native_result_schema": NATIVE_RESULT_SCHEMA,
            "native_implementation_parent_schema": (
                NATIVE_IMPLEMENTATION_PARENT_SCHEMA
            ),
            "native_ledger_schema": NATIVE_LEDGER_SCHEMA,
            "reader": dict(READER_BINDING),
            "reader_spec_sha256": READER_SPEC_SHA256,
            "phase_field_sha256": PHASE_FIELD_SHA256,
            "phase_effective_bitpack_sha256": PHASE_EFFECTIVE_BITPACK_SHA256,
            "phase_suffix_canonical_records_sha256": (PHASE_SUFFIX_RECORDS_SHA256),
            "phase_analysis_sha256": TARGET_FREE_ANALYSIS_SHA256,
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
                raise O1C70RunError("vault-phase-reader ordinal differs")
            return invoke_native_episode(
                executable=native_build.executable,
                cnf=cnf,
                potential=potential,
                grouping=grouping_path,
                vault=vault,
            )

        outcome = execute_single_continuation(
            capsule=capsule,
            imported_vault=imported.independent,
            adapter_vault=imported.adapter,
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
        description="Preflight or run O1C-0070's one vault phase reader call"
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
    except O1C70RunError as exc:
        print(f"{ATTEMPT_ID}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
