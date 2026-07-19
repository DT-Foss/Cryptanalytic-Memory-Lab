"""O1C-0066: bounded episodic APPLE8 score-threshold no-good vault.

Eight fresh native subprocesses are permitted.  Every process receives the
same frozen APPLE8 CNF, potential, exact width-6 grouping, threshold, seed and
CaDiCaL options.  Only fully emitted score-threshold no-goods survive between
episodes; assignments, trails, learned clauses, grouped caches and policy
adaptation never do.

The archive is evidence for ``CNF and potential_score >= threshold``.  It is
not a CNF-only proof and an UNSAT result therefore exhausts only that frozen
threshold-constrained region.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
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

from . import joint_score_sieve_v8 as _native_v8
from . import joint_score_sieve_v7 as _native_v7
from . import o1c65_apple8_width6_grouped_run as _o1c65
from . import threshold_no_good_vault_v1 as _vault_v1
from .chacha_trace import chacha20_blocks
from .criticality_potential import CriticalityPotentialField
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


ATTEMPT_ID = "O1C-0066"
CONFIG_SCHEMA = "o1-256-apple8-episodic-vault-run-config-v1"
PREFLIGHT_SCHEMA = "o1-256-apple8-episodic-vault-preflight-v1"
INTENT_SCHEMA = "o1-256-apple8-episodic-vault-episode-intent-v1"
EPISODE_SCHEMA = "o1-256-apple8-episodic-vault-episode-result-v1"
RESULT_SCHEMA = "o1-256-apple8-episodic-vault-run-result-v1"
GEOMETRY_SMOKE_SCHEMA = "o1-256-o1c66-target-free-geometry-smoke-v1"
GEOMETRY_SMOKE_CLASSIFICATION = "TARGET_FREE_GEOMETRY_SMOKE_PASS"
POLICY_STATE_SCHEMA = "o1-256-fixed-empty-episodic-policy-state-v1"
VAULT_SCHEMA = _vault_v1.THRESHOLD_NO_GOOD_VAULT_SCHEMA
NATIVE_VAULT_TELEMETRY_SCHEMA = (
    "o1-256-cadical-score-threshold-no-good-vault-telemetry-v1"
)
CAPSULE_SUFFIX = "O1C-0066_apple8-episodic-vault-v1"
RESULT_RELATIVE = Path("research/O1C0066_APPLE8_EPISODIC_VAULT_RESULT_20260719.json")
GEOMETRY_SMOKE_RELATIVE = Path(
    "research/O1C0066_TARGET_FREE_GEOMETRY_SMOKE_20260719.json"
)

DESIGN_RELATIVE = Path("research/O1C0066_EPISODIC_CAUSAL_VAULT_DESIGN_20260719.md")
PARENT_RESULT_RELATIVE = _o1c65.RESULT_RELATIVE
PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260719_123602_O1C-0065_apple8-width6-grouped-sieve-v1"
)
PARENT_RESULT_SHA256 = (
    "04c2e0d32fff6e7a8f685880049579c90c4a399b14518ee3e650b15d01834bfb"
)
PARENT_MANIFEST_SHA256 = (
    "0450c64d60ed84f10e76248367318e363131194cebe93d079bef4b8679e407f4"
)
PARENT_SOURCE_COMMIT = "8f231003161c17608c3daba63da2a6ccf4d567da"

APPLE8_CNF_SHA256 = "e1fc0ac93724004291c960ea06e5584c598853b9ea8370552be09f29e73e2432"
APPLE8_POTENTIAL_SHA256 = (
    "8c6101b49c7050caf895bd9c496c05bcea9f43a2b27f378d7306be38b00d5390"
)
APPLE8_POTENTIAL_SOURCE_SHA256 = (
    "b0ef8533128cbfdbb618c46b686bff0bc20f6b2389251b1ae5a2109729d34f26"
)
GROUPING_SHA256 = _o1c65.EXPECTED_GROUPING_SHA256
GROUPING_SERIALIZED_BYTES = _o1c65.EXPECTED_GROUPING_SERIALIZED_BYTES
GROUPING_WIDTH_CAP = _o1c65.GROUPING_WIDTH_CAP
THRESHOLD = _o1c65.THRESHOLD
SEED = 0

GEOMETRY_SMOKE_VARIABLES = 257_024
GEOMETRY_SMOKE_CNF_BYTES = b"p cnf 257024 0\n"
GEOMETRY_SMOKE_CNF_SHA256 = hashlib.sha256(GEOMETRY_SMOKE_CNF_BYTES).hexdigest()
GEOMETRY_SMOKE_GROUPED_ROOT_UPPER_BOUND = 262.68644197084643
GEOMETRY_SMOKE_THRESHOLD = math.nextafter(
    GEOMETRY_SMOKE_GROUPED_ROOT_UPPER_BOUND, math.inf
)
EXPECTED_GEOMETRY_SMOKE_SHA256 = (
    "42529f9fd7350d7f4e25fdbb0e508d376e587be16c7b7c0460976a2bd8f0a75f"
)

MAXIMUM_EPISODES = 8
REQUESTED_CONFLICTS_PER_EPISODE = 512
MAXIMUM_CONFLICT_LIMIT_OVERSHOOT = 1
MAXIMUM_BILLED_CONFLICTS_PER_EPISODE = 513
MAXIMUM_TOTAL_REQUESTED_CONFLICTS = 4_096
MAXIMUM_TOTAL_BILLED_CONFLICTS = 4_104
EPISODE_TIMEOUT_SECONDS = 45.0
EPISODE_MEMORY_LIMIT_BYTES = 536_870_912
MAXIMUM_TOTAL_NATIVE_WALL_SECONDS = MAXIMUM_EPISODES * EPISODE_TIMEOUT_SECONDS

VAULT_MAGIC = _vault_v1.THRESHOLD_NO_GOOD_VAULT_MAGIC
VAULT_MAXIMUM_CLAUSES = _vault_v1.O1C66_VAULT_CAPS.maximum_clauses
VAULT_MAXIMUM_LITERALS = _vault_v1.O1C66_VAULT_CAPS.maximum_literals
VAULT_MAXIMUM_SERIALIZED_BYTES = _vault_v1.O1C66_VAULT_CAPS.maximum_serialized_bytes
VAULT_IDENTITY_DIGEST_COUNT = 5
VAULT_FIXED_BYTES = len(VAULT_MAGIC) + 32 * VAULT_IDENTITY_DIGEST_COUNT + 8 + 4
# Eight cumulative binary sidecars plus bounded native JSON clause telemetry can
# coexist at their independent maxima without turning a valid science terminal
# into a publication-only failure.
MAXIMUM_PERSISTENT_ARTIFACT_BYTES = 268_435_456
MINIMUM_DISK_FREE_BYTES = 1_073_741_824
MINIMUM_MEMORY_PRESSURE_FREE_PERCENT = 15
MAXIMUM_NATIVE_FAILURE_STREAM_BYTES = 1_048_576

POLICY_STATE_BYTES = b""
POLICY_STATE_SHA256 = hashlib.sha256(POLICY_STATE_BYTES).hexdigest()
BOUND_RULE_SHA256 = hashlib.sha256(
    COMPATIBILITY_GROUPING_BOUND_RULE.encode("ascii")
).hexdigest()

PUBLIC_EXACT_RECOVERY = "PUBLIC_EXACT_RECOVERY"
STRICT_CUMULATIVE_GAIN = "EPISODIC_VAULT_STRICT_CUMULATIVE_GAIN"
SATURATED_NO_GAIN = "EPISODIC_VAULT_SATURATED_NO_GAIN"
THRESHOLD_REGION_EXHAUSTED = "EPISODIC_VAULT_THRESHOLD_REGION_EXHAUSTED"
CAPACITY_TERMINAL = "EPISODIC_VAULT_CAPACITY_TERMINAL"
RESOURCE_TERMINAL = "EPISODIC_VAULT_RESOURCE_TERMINAL"
INVALID_RESULT_TERMINAL = "EPISODIC_VAULT_INVALID_RESULT_TERMINAL"
OPERATIONAL_TERMINAL = "EPISODIC_VAULT_OPERATIONAL_TERMINAL"

NATIVE_RESULT_SCHEMA = _native_v8.JOINT_SCORE_SIEVE_RESULT_SCHEMA
NATIVE_IMPLEMENTATION_PARENT_SCHEMA = (
    _native_v8.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
)
NATIVE_STATE_SCHEMA = _native_v7.JOINT_SCORE_SIEVE_STATE_SCHEMA
NATIVE_MEMORY_SERIES_SCHEMA = _native_v7.JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA
MAXIMUM_NATIVE_MEMORY_SAMPLES = _native_v7.JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES
NATIVE_EXECUTION_FAILURE_SCHEMA = _native_v7.JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA
TEARDOWN_RULE = _native_v7.JOINT_SCORE_SIEVE_TEARDOWN_RULE
PENDING_BACKTRACK_RULE = _native_v7.JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE

# Finalized from the committed native-v6 source and exact Darwin build before
# science authorization.  Root may replace these while concurrent files land.
EXPECTED_NATIVE_SOURCE_SHA256 = (
    "f0c936c6bee54842911af34627c406d1ae7d836d5132769d02a33e8ba3d376af"
)
EXPECTED_NATIVE_EXECUTABLE_SHA256 = (
    "438f01824557b2634b1b9a9719034a9759b9b26ba6e46596fceb27918672d132"
)
EXPECTED_JOINT_SCORE_SIEVE_V8_SHA256 = (
    "d98662ff1ddef33c199738c44852d3903507b6bb98b86c257b8b9022f2dab03d"
)
EXPECTED_THRESHOLD_NO_GOOD_VAULT_V1_SHA256 = (
    "622ede78c389ef9e6181e8ebf173c4cbc05197ea2c4795f352b433d2e87cbf5a"
)
EXPECTED_JOINT_SCORE_GROUPING_V1_SHA256 = (
    "a458c3567aa2bad5c5571d189bf8bee7e204eefa54f4bbc95081c0f7f1fddbd1"
)
MAXIMUM_GEOMETRY_SMOKE_ARTIFACT_BYTES = 4_194_304

SOURCE_NAMES = (
    "runner",
    "joint_score_sieve_v8",
    "joint_score_sieve_v7",
    "joint_score_grouping_v1",
    "threshold_no_good_vault_v1",
    "native_source",
    "native_base_source",
    "parent_runner",
    "capsule_parent_runner",
    "lifecycle_helpers",
    "chacha_trace",
    "full256_broker",
    "design",
    "geometry_smoke_artifact",
)
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
    "parent",
    "input",
    "grouping",
    "native",
    "vault",
    "policy",
    "promotion",
    "budgets",
    "geometry_smoke",
    "next_action",
}

HYPOTHESIS = (
    "Destroying each bounded grouped solver while carrying only cumulative fully "
    "emitted exact score-threshold no-goods can compound useful causal exclusions "
    "across fresh APPLE8 episodes without retaining the solver's large transient state."
)
PREDICTION = (
    "At most eight same-seed 512-conflict fresh subprocess episodes either publicly "
    "recover the Full-256 key, exhaust only the frozen score-threshold region, add a "
    "novel eligible clause after episode zero, saturate deterministically, or stop "
    "cleanly on an invalid/resource/cap terminal without retry or truth access."
)
NEXT_ACTION = (
    "Run only from a clean source-commit-bound zero-call preflight. Persist one intent "
    "before each fresh ordinal, never replay it, archive only fully emitted nonempty "
    "eligible clauses, and publish public recovery only after independent 8/8 verification."
)


class O1C66RunError(RuntimeError):
    """The frozen episodic protocol, identity, or accounting differs."""


class O1C66VaultError(O1C66RunError):
    """A score-threshold vault is noncanonical or identity-incompatible."""


class O1C66VaultCapacityError(O1C66VaultError):
    """A cumulative vault would exceed a frozen cap; eviction is forbidden."""


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise O1C66RunError(f"{field} must be an object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise O1C66RunError(f"{field} must be an array")
    return cast(Sequence[object], value)


def _nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise O1C66RunError(f"{field} differs")
    return value


def _finite_float(value: object, field: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        raise O1C66RunError(f"{field} differs")
    return float(value)


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C66RunError(f"{field} hash differs")
    return value


def _read_mapping(path: Path, field: str) -> Mapping[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise O1C66RunError(f"duplicate {field} JSON key")
            result[key] = value
        return result

    try:
        return _mapping(
            json.loads(path.read_bytes(), object_pairs_hook=reject_duplicates), field
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise O1C66RunError(f"{field} is not valid JSON") from exc


def _relative(root: Path, value: object, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise O1C66RunError(f"{field} path differs")
    try:
        path = (root / value).resolve(strict=True)
    except OSError as exc:
        raise O1C66RunError(f"{field} path differs") from exc
    if not path.is_relative_to(root):
        raise O1C66RunError(f"{field} escapes the lab")
    return path


@dataclass(frozen=True)
class VaultIdentity:
    """Every semantic byte needed to reuse one threshold-certified clause."""

    cnf_sha256: str
    potential_sha256: str
    grouping_sha256: str
    observed_variables_sha256: str
    bound_rule_sha256: str
    threshold: float

    def __post_init__(self) -> None:
        for name in (
            "cnf_sha256",
            "potential_sha256",
            "grouping_sha256",
            "observed_variables_sha256",
            "bound_rule_sha256",
        ):
            _sha256(getattr(self, name), name)
        if not math.isfinite(self.threshold):
            raise O1C66VaultError("vault threshold differs")

    @property
    def raw_identity(self) -> bytes:
        return b"".join(
            bytes.fromhex(getattr(self, name))
            for name in (
                "cnf_sha256",
                "potential_sha256",
                "grouping_sha256",
                "observed_variables_sha256",
                "bound_rule_sha256",
            )
        ) + struct.pack("<d", self.threshold)

    def describe(self) -> dict[str, object]:
        return {
            "cnf_sha256": self.cnf_sha256,
            "potential_sha256": self.potential_sha256,
            "grouping_sha256": self.grouping_sha256,
            "observed_variables_sha256": self.observed_variables_sha256,
            "bound_rule_sha256": self.bound_rule_sha256,
            "bound_rule": COMPATIBILITY_GROUPING_BOUND_RULE,
            "threshold": self.threshold,
            "threshold_f64le_hex": struct.pack("<d", self.threshold).hex(),
            "semantic_scope": "CNF-and-potential-score-greater-than-or-equal-threshold",
            "cnf_only_entailment": False,
        }


def observed_variables_sha256(field: CriticalityPotentialField) -> str:
    payload = b"".join(
        struct.pack("<I", variable) for variable in field.observed_variables
    )
    return hashlib.sha256(payload).hexdigest()


def frozen_vault_identity(field: CriticalityPotentialField) -> VaultIdentity:
    if field.state_sha256 != APPLE8_POTENTIAL_SHA256:
        raise O1C66VaultError("vault potential identity differs")
    return VaultIdentity(
        cnf_sha256=APPLE8_CNF_SHA256,
        potential_sha256=APPLE8_POTENTIAL_SHA256,
        grouping_sha256=GROUPING_SHA256,
        observed_variables_sha256=observed_variables_sha256(field),
        bound_rule_sha256=BOUND_RULE_SHA256,
        threshold=THRESHOLD,
    )


def _normalize_clause(
    clause: Sequence[int], *, observed_variables: frozenset[int]
) -> tuple[int, ...]:
    if not isinstance(clause, Sequence) or isinstance(clause, (str, bytes)):
        raise O1C66VaultError("vault clause differs")
    normalized: list[int] = []
    previous = 0
    for literal in clause:
        if (
            isinstance(literal, bool)
            or not isinstance(literal, int)
            or literal == 0
            or literal < -(2**31)
            or literal > 2**31 - 1
            or abs(literal) not in observed_variables
            or abs(literal) <= previous
        ):
            raise O1C66VaultError("vault clause literal order differs")
        previous = abs(literal)
        normalized.append(literal)
    if not normalized:
        raise O1C66VaultError("root empty clause cannot be archived")
    return tuple(normalized)


@dataclass(frozen=True)
class ClauseVault:
    """Canonical cumulative archive in first fully-emitted order."""

    identity: VaultIdentity
    observed_variables: frozenset[int]
    clauses: tuple[tuple[int, ...], ...] = ()

    def __post_init__(self) -> None:
        normalized = tuple(
            _normalize_clause(clause, observed_variables=self.observed_variables)
            for clause in self.clauses
        )
        if normalized != self.clauses or len(set(normalized)) != len(normalized):
            raise O1C66VaultError("vault clause order or deduplication differs")
        self._check_capacity()

    @property
    def literal_count(self) -> int:
        return sum(len(clause) for clause in self.clauses)

    @property
    def serialized_bytes(self) -> int:
        return VAULT_FIXED_BYTES + sum(4 + 4 * len(clause) for clause in self.clauses)

    def _check_capacity(self) -> None:
        if (
            len(self.clauses) > VAULT_MAXIMUM_CLAUSES
            or self.literal_count > VAULT_MAXIMUM_LITERALS
            or self.serialized_bytes > VAULT_MAXIMUM_SERIALIZED_BYTES
        ):
            raise O1C66VaultCapacityError("cumulative vault capacity reached")

    def to_bytes(self) -> bytes:
        self._check_capacity()
        payload = bytearray(VAULT_MAGIC)
        payload.extend(self.identity.raw_identity)
        payload.extend(struct.pack("<I", len(self.clauses)))
        for clause in self.clauses:
            payload.extend(struct.pack("<I", len(clause)))
            for literal in clause:
                payload.extend(struct.pack("<i", literal))
        serialized = bytes(payload)
        if len(serialized) != self.serialized_bytes:
            raise O1C66VaultError("vault serialized byte ledger differs")
        return serialized

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @property
    def aggregate_clause_sha256(self) -> str:
        payload = b"".join(
            struct.pack("<I", len(clause))
            + b"".join(struct.pack("<i", literal) for literal in clause)
            for clause in self.clauses
        )
        return hashlib.sha256(payload).hexdigest()

    def describe(self) -> dict[str, object]:
        return {
            "schema": VAULT_SCHEMA,
            **self.identity.describe(),
            "sha256": self.sha256,
            "serialized_bytes": self.serialized_bytes,
            "clause_count": len(self.clauses),
            "literal_count": self.literal_count,
            "aggregate_clause_sha256": self.aggregate_clause_sha256,
            "ordering": "first-fully-emitted-order",
            "deduplication": "exact-canonical-clause-first-occurrence",
            "subsumption": False,
            "eviction": False,
        }

    def append_emitted(
        self, emitted: Sequence[Sequence[int]]
    ) -> tuple[ClauseVault, tuple[tuple[int, ...], ...], int]:
        seen = set(self.clauses)
        cumulative = list(self.clauses)
        novel: list[tuple[int, ...]] = []
        duplicates = 0
        for raw in emitted:
            clause = _normalize_clause(raw, observed_variables=self.observed_variables)
            if clause in seen:
                duplicates += 1
                continue
            seen.add(clause)
            novel.append(clause)
            cumulative.append(clause)
        result = ClauseVault(
            identity=self.identity,
            observed_variables=self.observed_variables,
            clauses=tuple(cumulative),
        )
        return result, tuple(novel), duplicates

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_identity: VaultIdentity,
        observed_variables: frozenset[int],
    ) -> ClauseVault:
        if not isinstance(payload, bytes) or len(payload) < VAULT_FIXED_BYTES:
            raise O1C66VaultError("vault bytes are truncated")
        if len(payload) > VAULT_MAXIMUM_SERIALIZED_BYTES:
            raise O1C66VaultCapacityError("vault byte cap exceeded")
        if payload[: len(VAULT_MAGIC)] != VAULT_MAGIC:
            raise O1C66VaultError("vault magic differs")
        cursor = len(VAULT_MAGIC)
        digests: list[str] = []
        for _ in range(VAULT_IDENTITY_DIGEST_COUNT):
            digests.append(payload[cursor : cursor + 32].hex())
            cursor += 32
        threshold = struct.unpack_from("<d", payload, cursor)[0]
        cursor += 8
        identity = VaultIdentity(
            cnf_sha256=digests[0],
            potential_sha256=digests[1],
            grouping_sha256=digests[2],
            observed_variables_sha256=digests[3],
            bound_rule_sha256=digests[4],
            threshold=threshold,
        )
        # Compare the raw identity so IEEE-754 aliases such as -0.0/+0.0 can
        # never pass merely through Python float equality.
        if identity.raw_identity != expected_identity.raw_identity:
            raise O1C66VaultError("vault semantic identity differs")
        clause_count = struct.unpack_from("<I", payload, cursor)[0]
        cursor += 4
        if clause_count > VAULT_MAXIMUM_CLAUSES:
            raise O1C66VaultCapacityError("vault clause cap exceeded")
        clauses: list[tuple[int, ...]] = []
        literal_count = 0
        for _ in range(clause_count):
            if cursor > len(payload) or len(payload) - cursor < 4:
                raise O1C66VaultError("vault clause header is truncated")
            length = struct.unpack_from("<I", payload, cursor)[0]
            cursor += 4
            if length == 0:
                raise O1C66VaultError("root empty clause cannot be archived")
            literal_count += length
            if literal_count > VAULT_MAXIMUM_LITERALS:
                raise O1C66VaultCapacityError("vault literal cap exceeded")
            byte_length = 4 * length
            if cursor > len(payload) or len(payload) - cursor < byte_length:
                raise O1C66VaultError("vault clause body is truncated")
            raw = struct.unpack_from(f"<{length}i", payload, cursor)
            cursor += byte_length
            clauses.append(
                _normalize_clause(raw, observed_variables=observed_variables)
            )
        if cursor != len(payload):
            raise O1C66VaultError("vault has trailing bytes")
        result = cls(
            identity=identity,
            observed_variables=observed_variables,
            clauses=tuple(clauses),
        )
        if result.to_bytes() != payload:
            raise O1C66VaultError("vault is not canonical")
        return result


def write_vault(path: Path, vault: ClauseVault) -> None:
    if path.exists() or path.is_symlink():
        raise O1C66VaultError("vault output already exists")
    _atomic_bytes(path, vault.to_bytes())
    mode = path.stat(follow_symlinks=False).st_mode
    if (
        path.is_symlink()
        or not stat.S_ISREG(mode)
        or path.read_bytes() != vault.to_bytes()
    ):
        raise O1C66VaultError("vault publication differs")


def read_vault(
    path: Path, *, identity: VaultIdentity, observed_variables: frozenset[int]
) -> ClauseVault:
    try:
        mode = path.stat(follow_symlinks=False).st_mode
        size = path.stat(follow_symlinks=False).st_size
        if path.is_symlink() or not stat.S_ISREG(mode):
            raise O1C66VaultError("vault sidecar is not a regular file")
        if size > VAULT_MAXIMUM_SERIALIZED_BYTES:
            raise O1C66VaultCapacityError("vault byte cap exceeded")
        payload = path.read_bytes()
    except O1C66VaultError:
        raise
    except OSError as exc:
        raise O1C66VaultError("vault sidecar cannot be read") from exc
    return ClauseVault.from_bytes(
        payload, expected_identity=identity, observed_variables=observed_variables
    )


def _exact_parent_row() -> dict[str, object]:
    return {
        "attempt_id": "O1C-0065",
        "result": PARENT_RESULT_RELATIVE.as_posix(),
        "result_sha256": PARENT_RESULT_SHA256,
        "capsule": PARENT_CAPSULE_RELATIVE.as_posix(),
        "manifest_sha256": PARENT_MANIFEST_SHA256,
        "source_commit": PARENT_SOURCE_COMMIT,
        "classification": "O1C65_GROUPED_WIDTH6_EFFICACY_RETAINED",
        "native_solver_calls": 1,
        "external_clauses_emitted": 6,
        "truth_key_bytes_read": False,
    }


def _exact_config_rows() -> dict[str, object]:
    grouping_rows = _o1c65._exact_config_rows()
    return {
        "grouping_provenance": grouping_rows["grouping_provenance"],
        "parent": _exact_parent_row(),
        "input": {
            "apple8_result": _o1c65.APPLE8_RESULT_RELATIVE.as_posix(),
            "apple8_capsule": _o1c65.APPLE8_CAPSULE_RELATIVE.as_posix(),
            "cnf_relative": _o1c65.APPLE8_CNF_RELATIVE.as_posix(),
            "potential_relative": _o1c65.APPLE8_POTENTIAL_RELATIVE.as_posix(),
            "truth_reveal": _o1c65.O1C57_REVEAL_RELATIVE.as_posix(),
            "cnf_sha256": APPLE8_CNF_SHA256,
            "potential_sha256": APPLE8_POTENTIAL_SHA256,
            "threshold": THRESHOLD,
            "seed": SEED,
            "fresh_targets": 0,
            "scientific_entropy_calls": 0,
            "fresh_reveal_calls": 0,
            "refits": 0,
        },
        "grouping": _o1c65._exact_grouping_row(),
        "native": {
            "maximum_episodes": MAXIMUM_EPISODES,
            "requested_conflicts_per_episode": REQUESTED_CONFLICTS_PER_EPISODE,
            "maximum_conflict_limit_overshoot": MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
            "maximum_billed_conflicts_per_episode": (
                MAXIMUM_BILLED_CONFLICTS_PER_EPISODE
            ),
            "maximum_total_requested_conflicts": (MAXIMUM_TOTAL_REQUESTED_CONFLICTS),
            "maximum_total_billed_conflicts": MAXIMUM_TOTAL_BILLED_CONFLICTS,
            "timeout_seconds_per_episode": EPISODE_TIMEOUT_SECONDS,
            "memory_limit_bytes_per_episode": EPISODE_MEMORY_LIMIT_BYTES,
            "seed": SEED,
            "result_schema": NATIVE_RESULT_SCHEMA,
            "implementation_parent_schema": NATIVE_IMPLEMENTATION_PARENT_SCHEMA,
            "state_schema": NATIVE_STATE_SCHEMA,
            "vault_telemetry_schema": NATIVE_VAULT_TELEMETRY_SCHEMA,
            "teardown_rule": TEARDOWN_RULE,
            "pending_backtrack_rule": PENDING_BACKTRACK_RULE,
            "execution_failure_schema": NATIVE_EXECUTION_FAILURE_SCHEMA,
            "memory_series_schema": NATIVE_MEMORY_SERIES_SCHEMA,
            "maximum_memory_samples": MAXIMUM_NATIVE_MEMORY_SAMPLES,
            "expected_source_sha256": EXPECTED_NATIVE_SOURCE_SHA256,
            "expected_executable_sha256": EXPECTED_NATIVE_EXECUTABLE_SHA256,
            "exact_executable_basename": "native-joint-score-sieve",
            "fresh_process_each_episode": True,
            "episodes_are_retries": False,
        },
        "vault": {
            "schema": VAULT_SCHEMA,
            "magic_hex": VAULT_MAGIC.hex(),
            "header_bytes": VAULT_FIXED_BYTES,
            "maximum_clauses": VAULT_MAXIMUM_CLAUSES,
            "maximum_literals": VAULT_MAXIMUM_LITERALS,
            "maximum_serialized_bytes": VAULT_MAXIMUM_SERIALIZED_BYTES,
            "identity_digest_count": VAULT_IDENTITY_DIGEST_COUNT,
            "bound_rule_sha256": BOUND_RULE_SHA256,
            "ordering": "first-fully-emitted-order",
            "deduplication": "exact-canonical-clause-first-occurrence",
            "subsumption": False,
            "eviction": False,
            "empty_clause_archived": False,
            "pending_clause_archived": False,
            "semantic_scope": (
                "CNF-and-potential-score-greater-than-or-equal-threshold"
            ),
            "cnf_only_entailment": False,
        },
        "policy": {
            "schema": POLICY_STATE_SCHEMA,
            "canonical_state_bytes": 0,
            "canonical_state_sha256": POLICY_STATE_SHA256,
            "fixed": True,
            "adaptive": False,
            "updates": 0,
        },
        "promotion": {
            "public_exact_recovery": PUBLIC_EXACT_RECOVERY,
            "strict_cumulative_gain": STRICT_CUMULATIVE_GAIN,
            "strict_gain_requires_novel_clause_after_episode_zero": True,
            "saturated_no_gain": SATURATED_NO_GAIN,
            "threshold_region_exhausted": THRESHOLD_REGION_EXHAUSTED,
            "deterministic_saturation_rule": (
                "UNKNOWN episode emits zero novel eligible clauses"
            ),
            "search_work_change_reported_separately": True,
            "unsat_is_key_space_unsat": False,
            "public_model_verification_blocks": 8,
        },
        "budgets": {
            "maximum_native_solver_calls": MAXIMUM_EPISODES,
            "maximum_requested_conflicts": MAXIMUM_TOTAL_REQUESTED_CONFLICTS,
            "maximum_billed_conflicts": MAXIMUM_TOTAL_BILLED_CONFLICTS,
            "maximum_native_wall_seconds": MAXIMUM_TOTAL_NATIVE_WALL_SECONDS,
            "maximum_peak_rss_bytes_per_episode": EPISODE_MEMORY_LIMIT_BYTES,
            "minimum_memory_pressure_free_percent": (
                MINIMUM_MEMORY_PRESSURE_FREE_PERCENT
            ),
            "minimum_disk_free_bytes": MINIMUM_DISK_FREE_BYTES,
            "maximum_fresh_targets": 0,
            "maximum_scientific_entropy_calls": 0,
            "maximum_fresh_reveal_calls": 0,
            "maximum_refits": 0,
            "maximum_mps_calls": 0,
            "maximum_gpu_calls": 0,
            "maximum_native_failure_stream_bytes": (
                MAXIMUM_NATIVE_FAILURE_STREAM_BYTES
            ),
            "maximum_persistent_artifact_bytes": (MAXIMUM_PERSISTENT_ARTIFACT_BYTES),
        },
        "geometry_smoke": {
            "artifact": GEOMETRY_SMOKE_RELATIVE.as_posix(),
            "sha256": EXPECTED_GEOMETRY_SMOKE_SHA256,
            "schema": GEOMETRY_SMOKE_SCHEMA,
            "classification": GEOMETRY_SMOKE_CLASSIFICATION,
            "variable_count": GEOMETRY_SMOKE_VARIABLES,
            "cnf_clause_count": 0,
            "native_solver_calls": 1,
            "target_free": True,
            "truth_key_bytes_read": False,
            "scientific_full256_calls": 0,
        },
    }


def load_config(path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C66RunError("config escapes the lab")
    config = dict(_read_mapping(config_path, "O1C66 config"))
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "source.expected_sha256")
    frozen = _mapping(config.get("frozen_sha256"), "frozen_sha256")
    if (
        set(config) != CONFIG_FIELDS
        or config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "apple8-episodic-vault-v1"
        or config.get("claim_level") != "TEST"
        or config.get("hypothesis") != HYPOTHESIS
        or config.get("prediction") != PREDICTION
        or config.get("next_action") != NEXT_ACTION
        or set(source) != {*SOURCE_NAMES, "expected_sha256"}
        or set(expected) != set(SOURCE_NAMES)
        or dict(frozen) != _o1c65.FROZEN_APPLE8_SHA256
        or any(
            config.get(name) != value for name, value in _exact_config_rows().items()
        )
    ):
        raise O1C66RunError("frozen O1C-0066 config differs")
    for name in SOURCE_NAMES:
        source_path = _relative(root, source[name], f"source.{name}")
        if sha256_file(source_path) != _sha256(expected[name], f"source.{name}"):
            raise O1C66RunError(f"source hash differs for {name}")
    return config


def validate_parent(root: Path, config: Mapping[str, object]) -> Mapping[str, object]:
    row = _mapping(config.get("parent"), "parent")
    result_path = _relative(root, row.get("result"), "parent result")
    capsule = _relative(root, row.get("capsule"), "parent capsule")
    if (
        dict(row) != _exact_parent_row()
        or result_path != root / PARENT_RESULT_RELATIVE
        or sha256_file(result_path) != PARENT_RESULT_SHA256
        or capsule != root / PARENT_CAPSULE_RELATIVE
        or sha256_file(capsule / "artifacts.sha256") != PARENT_MANIFEST_SHA256
    ):
        raise O1C66RunError("frozen O1C-0065 parent identity differs")
    result = _read_mapping(result_path, "parent result")
    metrics = _mapping(result.get("metrics"), "parent metrics")
    claim = _mapping(result.get("claim_boundary"), "parent claim boundary")
    if (
        result.get("source_commit") != PARENT_SOURCE_COMMIT
        or result.get("classification") != row["classification"]
        or metrics.get("external_clauses_emitted") != 6
        or claim.get("native_solver_calls") != 1
        or claim.get("truth_key_bytes_read_after_public_diagnostic") is not False
    ):
        raise O1C66RunError("frozen O1C-0065 parent evidence differs")
    return result


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
    relative_paths = [
        _relative(root, source[name], f"source.{name}").relative_to(root).as_posix()
        for name in SOURCE_NAMES
    ]
    relative_paths.append(config_path.relative_to(root).as_posix())
    try:
        completed = subprocess.run(
            [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--",
                *relative_paths,
            ],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10.0,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise O1C66RunError("source cleanliness check failed") from exc
    return not completed.stdout


def _geometry_smoke_potential_path(root: Path) -> Path:
    return root / _o1c65.APPLE8_CAPSULE_RELATIVE / _o1c65.APPLE8_POTENTIAL_RELATIVE


def _geometry_smoke_expected_bindings(root: Path) -> dict[str, str]:
    paths = {
        "native_source_sha256": root / "native/cadical_o1_joint_score_sieve_v6.cpp",
        "joint_score_sieve_v8_sha256": root
        / "src/o1_crypto_lab/joint_score_sieve_v8.py",
        "threshold_no_good_vault_v1_sha256": root
        / "src/o1_crypto_lab/threshold_no_good_vault_v1.py",
        "joint_score_grouping_v1_sha256": root
        / "src/o1_crypto_lab/joint_score_grouping_v1.py",
        "potential_artifact_sha256": _geometry_smoke_potential_path(root),
    }
    try:
        observed = {name: sha256_file(path) for name, path in paths.items()}
    except OSError as exc:
        raise O1C66RunError("geometry-smoke source binding cannot be read") from exc
    expected = {
        "native_source_sha256": EXPECTED_NATIVE_SOURCE_SHA256,
        "native_executable_sha256": EXPECTED_NATIVE_EXECUTABLE_SHA256,
        "native_executable_basename": "native-joint-score-sieve",
        "joint_score_sieve_v8_sha256": EXPECTED_JOINT_SCORE_SIEVE_V8_SHA256,
        "threshold_no_good_vault_v1_sha256": (
            EXPECTED_THRESHOLD_NO_GOOD_VAULT_V1_SHA256
        ),
        "joint_score_grouping_v1_sha256": (EXPECTED_JOINT_SCORE_GROUPING_V1_SHA256),
        "potential_artifact_sha256": APPLE8_POTENTIAL_SHA256,
        "potential_source_sha256": APPLE8_POTENTIAL_SOURCE_SHA256,
        "grouping_sha256": GROUPING_SHA256,
    }
    if any(observed[name] != expected[name] for name in observed):
        raise O1C66RunError("geometry-smoke frozen source binding differs")
    return expected


def _geometry_smoke_geometry_row(
    frozen: _o1c65.FrozenGrouping,
) -> dict[str, object]:
    observed = tuple(frozen.field.observed_variables)
    return {
        "cnf_bytes_ascii": GEOMETRY_SMOKE_CNF_BYTES.decode("ascii"),
        "cnf_serialized_bytes": len(GEOMETRY_SMOKE_CNF_BYTES),
        "cnf_sha256": GEOMETRY_SMOKE_CNF_SHA256,
        "variable_count": GEOMETRY_SMOKE_VARIABLES,
        "cnf_clause_count": 0,
        "potential_relative": (
            _o1c65.APPLE8_CAPSULE_RELATIVE / _o1c65.APPLE8_POTENTIAL_RELATIVE
        ).as_posix(),
        "potential_artifact_sha256": APPLE8_POTENTIAL_SHA256,
        "potential_source_sha256": APPLE8_POTENTIAL_SOURCE_SHA256,
        "factor_count": len(frozen.field.factors),
        "observed_variable_count": len(observed),
        "observed_variables_sha256": _vault_v1.observed_variables_sha256(observed),
        "grouping_sha256": frozen.grouping.sha256,
        "grouping_width_cap": GROUPING_WIDTH_CAP,
        "grouping_serialized_bytes": len(frozen.grouping.serialized),
        "group_count": frozen.grouping.group_count,
        "group_table_rows": frozen.grouping.table_rows,
        "grouped_root_upper_bound": GEOMETRY_SMOKE_GROUPED_ROOT_UPPER_BOUND,
        "grouped_root_upper_bound_f64le_hex": struct.pack(
            "<d", GEOMETRY_SMOKE_GROUPED_ROOT_UPPER_BOUND
        ).hex(),
        "threshold": GEOMETRY_SMOKE_THRESHOLD,
        "threshold_f64le_hex": struct.pack("<d", GEOMETRY_SMOKE_THRESHOLD).hex(),
        "threshold_strictly_above_grouped_root_upper_bound": True,
        "bound_rule": COMPATIBILITY_GROUPING_BOUND_RULE,
        "bound_rule_sha256": BOUND_RULE_SHA256,
    }


def _geometry_smoke_empty_vault(
    frozen: _o1c65.FrozenGrouping,
) -> _vault_v1.ThresholdNoGoodVault:
    observed = tuple(frozen.field.observed_variables)
    identity = _vault_v1.vault_identity_from_sources(
        cnf_sha256=GEOMETRY_SMOKE_CNF_SHA256,
        potential_sha256=APPLE8_POTENTIAL_SHA256,
        grouping_sha256=GROUPING_SHA256,
        observed_variables=observed,
        bound_rule=COMPATIBILITY_GROUPING_BOUND_RULE,
        threshold=GEOMETRY_SMOKE_THRESHOLD,
    )
    return _vault_v1.empty_threshold_no_good_vault(
        identity=identity,
        observed_variables=observed,
        caps=_vault_v1.O1C66_VAULT_CAPS,
    )


def _validate_geometry_smoke_report(
    report: Mapping[str, object],
    *,
    root: Path,
    frozen: _o1c65.FrozenGrouping,
) -> Mapping[str, object]:
    expected_top = {
        "schema",
        "attempt_id",
        "classification",
        "bindings",
        "geometry",
        "input_vault",
        "invocation",
        "outcome",
        "native_result_sha256",
        "native_result",
        "adapter_memory",
        "claim_boundary",
    }
    bindings = _mapping(report.get("bindings"), "geometry-smoke bindings")
    geometry = _mapping(report.get("geometry"), "geometry-smoke geometry")
    input_vault = _mapping(report.get("input_vault"), "geometry-smoke input vault")
    invocation = _mapping(report.get("invocation"), "geometry-smoke invocation")
    outcome = _mapping(report.get("outcome"), "geometry-smoke outcome")
    raw = _mapping(report.get("native_result"), "geometry-smoke native result")
    claim = _mapping(report.get("claim_boundary"), "geometry-smoke claim boundary")
    if (
        set(report) != expected_top
        or report.get("schema") != GEOMETRY_SMOKE_SCHEMA
        or report.get("attempt_id") != ATTEMPT_ID
        or report.get("classification") != GEOMETRY_SMOKE_CLASSIFICATION
        or dict(bindings) != _geometry_smoke_expected_bindings(root)
        or dict(geometry) != _geometry_smoke_geometry_row(frozen)
    ):
        raise O1C66RunError("geometry-smoke frozen identity differs")

    expected_empty = _geometry_smoke_empty_vault(frozen)
    if dict(input_vault) != expected_empty.describe():
        raise O1C66RunError("geometry-smoke empty vault identity differs")
    expected_invocation = {
        "native_solver_calls": 1,
        "fresh_native_subprocess": True,
        "requested_conflicts": REQUESTED_CONFLICTS_PER_EPISODE,
        "maximum_billed_conflicts": MAXIMUM_BILLED_CONFLICTS_PER_EPISODE,
        "maximum_conflict_limit_overshoot": MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
        "seed": SEED,
        "timeout_seconds": EPISODE_TIMEOUT_SECONDS,
        "memory_limit_bytes": EPISODE_MEMORY_LIMIT_BYTES,
        "target_bytes_read": 0,
        "truth_key_bytes_read": False,
        "scientific_full256_calls": 0,
        "fresh_targets": 0,
    }
    expected_claim = {
        "target_free": True,
        "empty_cnf_relation": True,
        "public_apple8_potential_and_grouping": True,
        "threshold_strictly_above_grouped_root_upper_bound": True,
        "threshold_region_root_empty_unsat": True,
        "empty_clause_archived": False,
        "candidate_key_observed": False,
        "truth_key_bytes_read": False,
        "scientific_full256_calls": 0,
        "geometry_gate_is_scientific_full256_call": False,
        "artifact_binds_config_runner_or_source_commit": False,
    }
    if dict(invocation) != expected_invocation or dict(claim) != expected_claim:
        raise O1C66RunError("geometry-smoke zero-truth claim differs")

    raw_sha256 = hashlib.sha256(_canonical_json_bytes(raw)).hexdigest()
    if (
        report.get("native_result_sha256") != raw_sha256
        or set(raw) != _native_v8._TOP_LEVEL_FIELDS
        or raw.get("schema") != NATIVE_RESULT_SCHEMA
        or raw.get("implementation_parent_schema")
        != NATIVE_IMPLEMENTATION_PARENT_SCHEMA
        or raw.get("variables") != GEOMETRY_SMOKE_VARIABLES
        or raw.get("cnf_sha256") != GEOMETRY_SMOKE_CNF_SHA256
        or raw.get("potential_sha256") != APPLE8_POTENTIAL_SHA256
        or raw.get("conflict_limit") != REQUESTED_CONFLICTS_PER_EPISODE
        or raw.get("seed") != SEED
        or raw.get("threshold") != GEOMETRY_SMOKE_THRESHOLD
        or raw.get("status") != 20
        or raw.get("post_solve_state") != 64
        or raw.get("post_solve_state_name") != "UNSATISFIED"
        or raw.get("key_model_hex") is not None
        or raw.get("teardown_rule") != TEARDOWN_RULE
        or raw.get("pending_backtrack_rule") != PENDING_BACKTRACK_RULE
    ):
        raise O1C66RunError("geometry-smoke native result identity differs")

    stats = _mapping(raw.get("stats"), "geometry-smoke native stats")
    sieve = _mapping(raw.get("sieve"), "geometry-smoke native sieve")
    resources = _mapping(raw.get("resources"), "geometry-smoke native resources")
    telemetry = _mapping(raw.get("vault"), "geometry-smoke native vault")
    solve_conflicts = _nonnegative_int(
        stats.get("solve_conflicts"), "geometry-smoke solve conflicts"
    )
    wall_microseconds = _nonnegative_int(
        resources.get("wall_microseconds"), "geometry-smoke wall microseconds"
    )
    cpu_microseconds = _nonnegative_int(
        resources.get("cpu_microseconds"), "geometry-smoke CPU microseconds"
    )
    peak_rss_bytes = _nonnegative_int(
        resources.get("peak_rss_bytes"), "geometry-smoke peak RSS bytes"
    )
    root_upper = _finite_float(
        sieve.get("root_upper_bound"), "geometry-smoke root upper bound"
    )
    if (
        solve_conflicts > MAXIMUM_BILLED_CONFLICTS_PER_EPISODE
        or wall_microseconds > int(EPISODE_TIMEOUT_SECONDS * 1_000_000)
        or peak_rss_bytes > EPISODE_MEMORY_LIMIT_BYTES
        or root_upper != GEOMETRY_SMOKE_GROUPED_ROOT_UPPER_BOUND
        or not root_upper < GEOMETRY_SMOKE_THRESHOLD
        or sieve.get("root_upper_bound_f64le_hex")
        != struct.pack("<d", root_upper).hex()
        or sieve.get("threshold") != GEOMETRY_SMOKE_THRESHOLD
        or sieve.get("source_sha256") != APPLE8_POTENTIAL_SOURCE_SHA256
        or sieve.get("grouping_sha256") != GROUPING_SHA256
        or sieve.get("grouping_input_sha256") != GROUPING_SHA256
        or sieve.get("grouping_width_cap") != GROUPING_WIDTH_CAP
        or sieve.get("grouping_serialized_bytes") != GROUPING_SERIALIZED_BYTES
        or sieve.get("bound_rule") != COMPATIBILITY_GROUPING_BOUND_RULE
        or sieve.get("external_clauses_queued") != 1
        or sieve.get("external_clauses_emitted") != 1
        or sieve.get("external_clause_literals") != 0
        or sieve.get("pending_clause_count") != 0
        or sieve.get("trail_threshold_prunes") != 1
        or sieve.get("model_threshold_prunes") != 0
    ):
        raise O1C66RunError("geometry-smoke root-prune telemetry differs")

    emitted = _sequence(
        telemetry.get("fully_emitted_clauses"),
        "geometry-smoke fully emitted clauses",
    )
    empty_clause_bytes = struct.pack("<I", 0)
    expected_clause_sha = hashlib.sha256(empty_clause_bytes).hexdigest()
    expected_witness_sha = hashlib.sha256(
        b"\x01"
        + struct.pack("<d", GEOMETRY_SMOKE_GROUPED_ROOT_UPPER_BOUND)
        + empty_clause_bytes
    ).hexdigest()
    expected_emitted = {
        "index": 0,
        "source": "trail_upper_bound",
        "witness_score": GEOMETRY_SMOKE_GROUPED_ROOT_UPPER_BOUND,
        "witness_score_f64le_hex": struct.pack(
            "<d", GEOMETRY_SMOKE_GROUPED_ROOT_UPPER_BOUND
        ).hex(),
        "literal_count": 0,
        "literals": [],
        "clause_sha256": expected_clause_sha,
        "witness_sha256": expected_witness_sha,
        "classification": "terminal_empty",
    }
    if (
        set(telemetry) != _native_v8._VAULT_FIELDS
        or telemetry.get("schema") != NATIVE_VAULT_TELEMETRY_SCHEMA
        or telemetry.get("input_sha256") != expected_empty.sha256
        or telemetry.get("input_serialized_bytes") != expected_empty.serialized_bytes
        or telemetry.get("input_clause_count") != 0
        or telemetry.get("input_literal_count") != 0
        or telemetry.get("validated_input_clause_count") != 0
        or telemetry.get("validated_input_literal_count") != 0
        or telemetry.get("input_cnf_sha256") != GEOMETRY_SMOKE_CNF_SHA256
        or telemetry.get("input_potential_sha256") != APPLE8_POTENTIAL_SHA256
        or telemetry.get("input_grouping_sha256") != GROUPING_SHA256
        or telemetry.get("input_observed_variables_sha256")
        != expected_empty.identity.observed_variables_sha256
        or telemetry.get("input_bound_rule_sha256") != BOUND_RULE_SHA256
        or telemetry.get("input_threshold_f64le_hex")
        != struct.pack("<d", GEOMETRY_SMOKE_THRESHOLD).hex()
        or telemetry.get("preloaded_clause_count") != 0
        or telemetry.get("preloaded_literal_count") != 0
        or telemetry.get("fully_emitted_clause_count") != 1
        or telemetry.get("fully_emitted_literal_count") != 0
        or telemetry.get("emitted_new_clause_count") != 0
        or telemetry.get("emitted_new_literal_count") != 0
        or telemetry.get("emitted_input_duplicate_clause_count") != 0
        or telemetry.get("emitted_input_duplicate_literal_count") != 0
        or telemetry.get("emitted_current_duplicate_clause_count") != 0
        or telemetry.get("emitted_current_duplicate_literal_count") != 0
        or telemetry.get("terminal_empty_clause_count") != 1
        or telemetry.get("pending_clause_exported") is not False
        or telemetry.get("fully_emitted_aggregate_sha256") != expected_clause_sha
        or len(emitted) != 1
        or emitted[0] != expected_emitted
        or telemetry.get("next_vault_available") is not False
        or telemetry.get("next_vault_terminal_reason") != "terminal_empty_clause"
        or telemetry.get("next_vault_sha256") is not None
        or telemetry.get("next_serialized_bytes") is not None
        or telemetry.get("next_clause_count") is not None
        or telemetry.get("next_literal_count") is not None
    ):
        raise O1C66RunError("geometry-smoke empty-clause vault telemetry differs")

    expected_outcome = {
        "status": 20,
        "post_solve_state": 64,
        "post_solve_state_name": "UNSATISFIED",
        "threshold_region_root_empty_unsat": True,
        "root_pruned": True,
        "candidate_key_hex": None,
        "eligible_archived_clause_count": 0,
        "eligible_archived_literal_count": 0,
        "empty_clause_archived": False,
        "next_vault": None,
        "next_vault_terminal_reason": "terminal_empty_clause",
        "requested_conflicts": REQUESTED_CONFLICTS_PER_EPISODE,
        "billed_conflicts": solve_conflicts,
        "conflict_limit_overshoot": max(
            solve_conflicts - REQUESTED_CONFLICTS_PER_EPISODE, 0
        ),
        "solve_conflicts": solve_conflicts,
        "external_clauses_queued": 1,
        "external_clauses_emitted": 1,
        "external_clause_literals": 0,
        "pending_clause_count": 0,
        "terminal_empty_clause_count": 1,
        "root_upper_bound": GEOMETRY_SMOKE_GROUPED_ROOT_UPPER_BOUND,
        "root_upper_bound_f64le_hex": struct.pack(
            "<d", GEOMETRY_SMOKE_GROUPED_ROOT_UPPER_BOUND
        ).hex(),
        "threshold": GEOMETRY_SMOKE_THRESHOLD,
        "threshold_f64le_hex": struct.pack("<d", GEOMETRY_SMOKE_THRESHOLD).hex(),
        "wall_microseconds": wall_microseconds,
        "cpu_microseconds": cpu_microseconds,
        "peak_rss_bytes": peak_rss_bytes,
    }
    if dict(outcome) != expected_outcome:
        raise O1C66RunError("geometry-smoke normalized outcome differs")
    _validate_memory_ledger(
        _mapping(report.get("adapter_memory"), "geometry-smoke adapter memory")
    )
    return report


def _geometry_smoke_report(
    *,
    root: Path,
    frozen: _o1c65.FrozenGrouping,
    native_build: NativeGuidedSearchBuild,
    input_vault: _vault_v1.ThresholdNoGoodVault,
    result: object,
) -> dict[str, object]:
    validate_native_build_identity(native_build)
    bindings = _geometry_smoke_expected_bindings(root)
    if (
        native_build.source_sha256 != bindings["native_source_sha256"]
        or native_build.executable_sha256 != bindings["native_executable_sha256"]
        or native_build.executable.name != bindings["native_executable_basename"]
    ):
        raise O1C66RunError("geometry-smoke native build binding differs")
    expected_empty = _geometry_smoke_empty_vault(frozen)
    result_input = getattr(result, "input_vault", None)
    eligible = getattr(result, "eligible_emitted_clauses", None)
    next_vault = getattr(result, "next_vault", object())
    if (
        input_vault != expected_empty
        or result_input != expected_empty
        or eligible != ()
        or next_vault is not None
        or getattr(result, "key_model", object()) is not None
    ):
        raise O1C66RunError("geometry-smoke adapter vault result differs")
    raw = _result_mapping(result, "raw")
    telemetry = _result_mapping(result, "vault_telemetry")
    if dict(telemetry) != _mapping(raw.get("vault"), "raw.vault"):
        raise O1C66RunError("geometry-smoke raw/adapter vault telemetry differs")
    stats = _result_mapping(result, "stats")
    resources = _result_mapping(result, "resources")
    sieve = _result_mapping(result, "sieve")
    solve_conflicts = _nonnegative_int(
        stats.get("solve_conflicts"), "geometry-smoke solve conflicts"
    )
    requested = _nonnegative_int(
        stats.get("requested_conflicts"), "geometry-smoke requested conflicts"
    )
    billed = _nonnegative_int(
        stats.get("billed_conflicts"), "geometry-smoke billed conflicts"
    )
    overshoot = _nonnegative_int(
        stats.get("conflict_limit_overshoot"), "geometry-smoke conflict overshoot"
    )
    if (
        getattr(result, "status", None) != 20
        or getattr(result, "conflict_limit", None) != REQUESTED_CONFLICTS_PER_EPISODE
        or getattr(result, "threshold", None) != GEOMETRY_SMOKE_THRESHOLD
        or requested != REQUESTED_CONFLICTS_PER_EPISODE
        or billed != solve_conflicts
        or overshoot != max(solve_conflicts - requested, 0)
        or solve_conflicts > requested + MAXIMUM_CONFLICT_LIMIT_OVERSHOOT
    ):
        raise O1C66RunError("geometry-smoke adapter work ledger differs")
    raw_sha256 = hashlib.sha256(_canonical_json_bytes(raw)).hexdigest()
    report = {
        "schema": GEOMETRY_SMOKE_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "classification": GEOMETRY_SMOKE_CLASSIFICATION,
        "bindings": bindings,
        "geometry": _geometry_smoke_geometry_row(frozen),
        "input_vault": expected_empty.describe(),
        "invocation": {
            "native_solver_calls": 1,
            "fresh_native_subprocess": True,
            "requested_conflicts": REQUESTED_CONFLICTS_PER_EPISODE,
            "maximum_billed_conflicts": MAXIMUM_BILLED_CONFLICTS_PER_EPISODE,
            "maximum_conflict_limit_overshoot": MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
            "seed": SEED,
            "timeout_seconds": EPISODE_TIMEOUT_SECONDS,
            "memory_limit_bytes": EPISODE_MEMORY_LIMIT_BYTES,
            "target_bytes_read": 0,
            "truth_key_bytes_read": False,
            "scientific_full256_calls": 0,
            "fresh_targets": 0,
        },
        "outcome": {
            "status": 20,
            "post_solve_state": 64,
            "post_solve_state_name": "UNSATISFIED",
            "threshold_region_root_empty_unsat": True,
            "root_pruned": True,
            "candidate_key_hex": None,
            "eligible_archived_clause_count": 0,
            "eligible_archived_literal_count": 0,
            "empty_clause_archived": False,
            "next_vault": None,
            "next_vault_terminal_reason": "terminal_empty_clause",
            "requested_conflicts": requested,
            "billed_conflicts": billed,
            "conflict_limit_overshoot": overshoot,
            "solve_conflicts": solve_conflicts,
            "external_clauses_queued": sieve.get("external_clauses_queued"),
            "external_clauses_emitted": sieve.get("external_clauses_emitted"),
            "external_clause_literals": sieve.get("external_clause_literals"),
            "pending_clause_count": sieve.get("pending_clause_count"),
            "terminal_empty_clause_count": telemetry.get("terminal_empty_clause_count"),
            "root_upper_bound": sieve.get("root_upper_bound"),
            "root_upper_bound_f64le_hex": sieve.get("root_upper_bound_f64le_hex"),
            "threshold": GEOMETRY_SMOKE_THRESHOLD,
            "threshold_f64le_hex": struct.pack("<d", GEOMETRY_SMOKE_THRESHOLD).hex(),
            "wall_microseconds": resources.get("wall_microseconds"),
            "cpu_microseconds": resources.get("cpu_microseconds"),
            "peak_rss_bytes": resources.get("peak_rss_bytes"),
        },
        "native_result_sha256": raw_sha256,
        "native_result": dict(raw),
        "adapter_memory": _memory_ledger(result),
        "claim_boundary": {
            "target_free": True,
            "empty_cnf_relation": True,
            "public_apple8_potential_and_grouping": True,
            "threshold_strictly_above_grouped_root_upper_bound": True,
            "threshold_region_root_empty_unsat": True,
            "empty_clause_archived": False,
            "candidate_key_observed": False,
            "truth_key_bytes_read": False,
            "scientific_full256_calls": 0,
            "geometry_gate_is_scientific_full256_call": False,
            "artifact_binds_config_runner_or_source_commit": False,
        },
    }
    _validate_geometry_smoke_report(report, root=root, frozen=frozen)
    return report


def validate_geometry_smoke(
    root: Path,
    config: Mapping[str, object],
    *,
    frozen: _o1c65.FrozenGrouping,
) -> Mapping[str, object]:
    row = _mapping(config.get("geometry_smoke"), "geometry_smoke")
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "source.expected_sha256")
    path = _relative(root, source.get("geometry_smoke_artifact"), "geometry smoke")
    if (
        dict(row) != _exact_config_rows()["geometry_smoke"]
        or path != root / GEOMETRY_SMOKE_RELATIVE
        or row.get("artifact") != GEOMETRY_SMOKE_RELATIVE.as_posix()
        or row.get("sha256") != EXPECTED_GEOMETRY_SMOKE_SHA256
        or expected.get("geometry_smoke_artifact") != EXPECTED_GEOMETRY_SMOKE_SHA256
    ):
        raise O1C66RunError("geometry-smoke config binding differs")
    try:
        mode = path.stat(follow_symlinks=False).st_mode
        size = path.stat(follow_symlinks=False).st_size
        if (
            path.is_symlink()
            or not stat.S_ISREG(mode)
            or size > MAXIMUM_GEOMETRY_SMOKE_ARTIFACT_BYTES
            or sha256_file(path) != EXPECTED_GEOMETRY_SMOKE_SHA256
        ):
            raise O1C66RunError("geometry-smoke artifact bytes differ")
        report = _read_mapping(path, "geometry-smoke artifact")
        if path.read_bytes() != _canonical_json_bytes(report):
            raise O1C66RunError("geometry-smoke artifact is not canonical JSON")
    except O1C66RunError:
        raise
    except OSError as exc:
        raise O1C66RunError("geometry-smoke artifact cannot be read") from exc
    return _validate_geometry_smoke_report(report, root=root, frozen=frozen)


def preflight(
    config_path: str | Path, *, require_commit_binding: bool = False
) -> dict[str, object]:
    """Read-only authorization: exact sources/caps, disk/RAM, and zero truth/calls."""

    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    source = _mapping(config["source"], "source")
    try:
        baseline = _o1c65.validate_apple8_baseline(root, config)
        _o1c65.validate_grouping_provenance(root, config)
        validate_parent(root, config)
        potential = cast(Path, getattr(baseline, "potential"))
        frozen = _o1c65.build_frozen_grouping(potential, config)
    except Exception as exc:
        raise O1C66RunError("frozen O1C-0066 input evidence differs") from exc
    identity = frozen_vault_identity(frozen.field)
    observed = frozenset(frozen.field.observed_variables)
    empty = ClauseVault(identity=identity, observed_variables=observed)
    shared_identity = _vault_v1.vault_identity_from_sources(
        cnf_sha256=APPLE8_CNF_SHA256,
        potential_sha256=APPLE8_POTENTIAL_SHA256,
        grouping_sha256=GROUPING_SHA256,
        observed_variables=tuple(frozen.field.observed_variables),
        bound_rule=COMPATIBILITY_GROUPING_BOUND_RULE,
        threshold=THRESHOLD,
    )
    shared_empty = _vault_v1.empty_threshold_no_good_vault(
        identity=shared_identity,
        observed_variables=tuple(frozen.field.observed_variables),
        caps=_vault_v1.O1C66_VAULT_CAPS,
    )
    if shared_empty.serialized != empty.to_bytes():
        raise O1C66RunError("shared and independent empty vault identities differ")
    geometry_smoke = validate_geometry_smoke(root, config, frozen=frozen)
    source_commit = _git_commit(root)
    clean = _selected_sources_clean(root, config_file, config)
    if require_commit_binding:
        if not clean:
            raise O1C66RunError("science sources/config are not clean")
        for name in SOURCE_NAMES:
            _commit_bound_bytes(
                root, source_commit, _relative(root, source[name], name), name
            )
        _commit_bound_bytes(root, source_commit, config_file, "config")
    memory_free = _memory_free_percent()
    if memory_free is not None and memory_free < MINIMUM_MEMORY_PRESSURE_FREE_PERCENT:
        raise O1C66RunError("memory-pressure preflight is below frozen gate")
    disk = shutil.disk_usage(root)
    if disk.free < MINIMUM_DISK_FREE_BYTES:
        raise O1C66RunError("disk-free preflight is below frozen gate")
    cnf = cast(Path, getattr(baseline, "cnf"))
    return {
        "schema": PREFLIGHT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "ok": True,
        "ready_for_science": require_commit_binding,
        "source_commit": source_commit,
        "source_tree_clean": clean,
        "source_commit_bound": require_commit_binding,
        "config_sha256": sha256_file(config_file),
        "source_sha256": _source_hashes(root, config),
        "parent_result_sha256": PARENT_RESULT_SHA256,
        "parent_manifest_sha256": PARENT_MANIFEST_SHA256,
        "cnf_sha256": sha256_file(cnf),
        "potential_sha256": sha256_file(potential),
        "grouping_sha256": frozen.grouping.sha256,
        "grouping_serialized_bytes": len(frozen.grouping.serialized),
        "grouping_width_cap": GROUPING_WIDTH_CAP,
        "threshold": THRESHOLD,
        "empty_vault_sha256": empty.sha256,
        "empty_vault_serialized_bytes": empty.serialized_bytes,
        "observed_variables_sha256": identity.observed_variables_sha256,
        "bound_rule_sha256": BOUND_RULE_SHA256,
        "policy_state_sha256": POLICY_STATE_SHA256,
        "maximum_episodes": MAXIMUM_EPISODES,
        "requested_conflicts_per_episode": REQUESTED_CONFLICTS_PER_EPISODE,
        "maximum_billed_conflicts_per_episode": (MAXIMUM_BILLED_CONFLICTS_PER_EPISODE),
        "maximum_total_requested_conflicts": MAXIMUM_TOTAL_REQUESTED_CONFLICTS,
        "maximum_total_billed_conflicts": MAXIMUM_TOTAL_BILLED_CONFLICTS,
        "episode_timeout_seconds": EPISODE_TIMEOUT_SECONDS,
        "episode_memory_limit_bytes": EPISODE_MEMORY_LIMIT_BYTES,
        "exact_native_executable_basename": "native-joint-score-sieve",
        "expected_native_source_sha256": EXPECTED_NATIVE_SOURCE_SHA256,
        "expected_native_executable_sha256": EXPECTED_NATIVE_EXECUTABLE_SHA256,
        "geometry_smoke_sha256": EXPECTED_GEOMETRY_SMOKE_SHA256,
        "geometry_smoke_validated": True,
        "geometry_smoke_native_solver_calls": _mapping(
            geometry_smoke.get("invocation"), "geometry-smoke invocation"
        )["native_solver_calls"],
        "vault_caps": _vault_v1.O1C66_VAULT_CAPS.describe(),
        "disk_free_bytes": disk.free,
        "minimum_disk_free_bytes": MINIMUM_DISK_FREE_BYTES,
        "memory_pressure_free_percent": memory_free,
        "minimum_memory_pressure_free_percent": (MINIMUM_MEMORY_PRESSURE_FREE_PERCENT),
        "all_caps_validated": True,
        "native_solver_calls": 0,
        "files_written": 0,
        "truth_key_bytes_read": False,
        "truth_hash": None,
        "native_model_equals_committed_truth": None,
        "fresh_targets": 0,
        "scientific_entropy_calls": 0,
        "fresh_reveal_calls": 0,
        "refits": 0,
        "MPS_or_GPU": False,
    }


class EpisodeInvoker(Protocol):
    """One fresh native subprocess call; ordinal is evidence, never a retry."""

    def __call__(self, ordinal: int, vault_path: Path) -> object: ...


@dataclass(frozen=True)
class PublicTarget:
    nonce: bytes
    counters: tuple[int, ...]
    output_blocks: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if (
            len(self.nonce) != 12
            or len(self.counters) != 8
            or len(set(self.counters)) != 8
            or len(self.output_blocks) != 8
            or any(len(block) != 64 for block in self.output_blocks)
        ):
            raise O1C66RunError("public APPLE8 verifier geometry differs")

    def verify(self, key: bytes) -> bool:
        return (
            len(key) == 32
            and tuple(
                chacha20_blocks(key, counter, self.nonce, 1)[0]
                for counter in self.counters
            )
            == self.output_blocks
        )


@dataclass(frozen=True)
class EpisodeProtocolOutcome:
    classification: str
    stop_reason: str
    episodes: tuple[Mapping[str, object], ...]
    final_vault: ClauseVault
    totals: Mapping[str, object]
    operational_failure: Mapping[str, object] | None


def _exception_chain(exc: BaseException) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        result.append(
            {
                "type": type(current).__qualname__,
                "message": str(current),
            }
        )
        current = current.__cause__ or current.__context__
    return result


def _failure_classification(exc: BaseException) -> str:
    name = type(exc).__qualname__.lower()
    message = str(exc).lower()
    raw_telemetry = getattr(exc, "failure_telemetry", None)
    telemetry_kind = (
        raw_telemetry.get("classification_kind")
        if isinstance(raw_telemetry, Mapping)
        else None
    )
    if isinstance(exc, O1C66VaultCapacityError) or any(
        token in name or token in message
        for token in ("overflow", "capacity", "clause cap", "literal cap", "byte cap")
    ):
        return CAPACITY_TERMINAL
    if any(
        token in name or token in message
        for token in ("timeout", "memorylimit", "resource", "watchdog", "rss")
    ) or telemetry_kind in {"timeout", "watchdog_memory"}:
        return RESOURCE_TERMINAL
    if isinstance(exc, (O1C66VaultError, O1C66RunError)):
        return INVALID_RESULT_TERMINAL
    return OPERATIONAL_TERMINAL


def _result_mapping(result: object, name: str) -> Mapping[str, object]:
    try:
        return _mapping(getattr(result, name), f"native.{name}")
    except AttributeError as exc:
        raise O1C66RunError(f"native.{name} is missing") from exc


def _clause_literals(value: object) -> tuple[int, ...]:
    if isinstance(value, Mapping):
        raw = value.get("literals")
    elif hasattr(value, "literals"):
        raw = getattr(value, "literals")
    else:
        raw = value
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise O1C66VaultError("eligible emitted clause differs")
    return tuple(cast(Sequence[int], raw))


def _deduplicate_without_capacity(
    current: ClauseVault, emitted: Sequence[tuple[int, ...]]
) -> tuple[tuple[tuple[int, ...], ...], int]:
    """Count a terminal proposal without evicting or constructing an over-cap vault."""

    seen = set(current.clauses)
    novel: list[tuple[int, ...]] = []
    duplicates = 0
    for raw in emitted:
        clause = _normalize_clause(raw, observed_variables=current.observed_variables)
        if clause in seen:
            duplicates += 1
        else:
            seen.add(clause)
            novel.append(clause)
    return tuple(novel), duplicates


def _validate_vault_telemetry(
    telemetry: Mapping[str, object],
    *,
    current: ClauseVault,
    eligible_raw: Sequence[object],
    eligible: Sequence[tuple[int, ...]],
    parsed_next: ClauseVault,
    next_available: bool,
    terminal_reason: object,
) -> None:
    required = {
        "schema",
        "binary_magic_hex",
        "semantic_rule",
        "identity_rule",
        "clause_encoding",
        "input_certification_rule",
        "maximum_payload_bytes",
        "maximum_clause_count",
        "maximum_literal_count",
        "input_sha256",
        "input_serialized_bytes",
        "input_clause_count",
        "input_literal_count",
        "input_clause_aggregate_sha256",
        "validated_input_clause_count",
        "validated_input_literal_count",
        "validated_input_clause_aggregate_sha256",
        "input_cnf_sha256",
        "input_potential_sha256",
        "input_grouping_sha256",
        "input_observed_variables_sha256",
        "input_bound_rule_sha256",
        "input_threshold_f64le_hex",
        "preloaded_clause_count",
        "preloaded_literal_count",
        "fully_emitted_clause_count",
        "fully_emitted_literal_count",
        "emitted_new_clause_count",
        "emitted_new_literal_count",
        "emitted_input_duplicate_clause_count",
        "emitted_input_duplicate_literal_count",
        "emitted_current_duplicate_clause_count",
        "emitted_current_duplicate_literal_count",
        "terminal_empty_clause_count",
        "pending_clause_exported",
        "next_vault_available",
        "next_vault_terminal_reason",
        "next_vault_sha256",
        "next_serialized_bytes",
        "next_clause_count",
        "next_literal_count",
    }
    if not required <= set(telemetry):
        raise O1C66RunError("native vault telemetry fields differ")
    terminal_empty_count = _nonnegative_int(
        telemetry["terminal_empty_clause_count"], "terminal empty clause count"
    )
    input_seen = set(current.clauses)
    episode_seen: set[tuple[int, ...]] = set()
    class_counts = {"new": 0, "input_duplicate": 0, "current_duplicate": 0}
    class_literals = {"new": 0, "input_duplicate": 0, "current_duplicate": 0}
    for raw_object, raw_clause in zip(eligible_raw, eligible, strict=True):
        clause = _normalize_clause(
            raw_clause, observed_variables=current.observed_variables
        )
        if clause in input_seen:
            classification = "input_duplicate"
        elif clause in episode_seen:
            classification = "current_duplicate"
        else:
            classification = "new"
            episode_seen.add(clause)
        reported = (
            raw_object.get("classification")
            if isinstance(raw_object, Mapping)
            else getattr(raw_object, "classification", classification)
        )
        if reported != classification:
            raise O1C66RunError("eligible emitted classification differs")
        class_counts[classification] += 1
        class_literals[classification] += len(clause)
    expected_counts = {
        "emitted_new_clause_count": class_counts["new"],
        "emitted_new_literal_count": class_literals["new"],
        "emitted_input_duplicate_clause_count": class_counts["input_duplicate"],
        "emitted_input_duplicate_literal_count": class_literals["input_duplicate"],
        "emitted_current_duplicate_clause_count": class_counts["current_duplicate"],
        "emitted_current_duplicate_literal_count": class_literals["current_duplicate"],
    }
    expected_identity = current.identity.describe()
    if (
        telemetry["schema"] != NATIVE_VAULT_TELEMETRY_SCHEMA
        or telemetry["binary_magic_hex"] != VAULT_MAGIC.hex()
        or telemetry["semantic_rule"] != _vault_v1.THRESHOLD_NO_GOOD_VAULT_SEMANTIC_RULE
        or telemetry["identity_rule"] != _vault_v1.THRESHOLD_NO_GOOD_VAULT_IDENTITY_RULE
        or telemetry["clause_encoding"]
        != _vault_v1.THRESHOLD_NO_GOOD_VAULT_CLAUSE_ENCODING
        or telemetry["input_certification_rule"]
        != _native_v8.JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE
        or telemetry["maximum_payload_bytes"] != VAULT_MAXIMUM_SERIALIZED_BYTES
        or telemetry["maximum_clause_count"] != VAULT_MAXIMUM_CLAUSES
        or telemetry["maximum_literal_count"] != VAULT_MAXIMUM_LITERALS
        or telemetry["input_sha256"] != current.sha256
        or telemetry["input_serialized_bytes"] != current.serialized_bytes
        or telemetry["input_clause_count"] != len(current.clauses)
        or telemetry["input_literal_count"] != current.literal_count
        or telemetry["input_clause_aggregate_sha256"] != current.aggregate_clause_sha256
        or telemetry["validated_input_clause_count"] != len(current.clauses)
        or telemetry["validated_input_literal_count"] != current.literal_count
        or telemetry["validated_input_clause_aggregate_sha256"]
        != current.aggregate_clause_sha256
        or telemetry["input_cnf_sha256"] != expected_identity["cnf_sha256"]
        or telemetry["input_potential_sha256"] != expected_identity["potential_sha256"]
        or telemetry["input_grouping_sha256"] != expected_identity["grouping_sha256"]
        or telemetry["input_observed_variables_sha256"]
        != expected_identity["observed_variables_sha256"]
        or telemetry["input_bound_rule_sha256"]
        != expected_identity["bound_rule_sha256"]
        or telemetry["input_threshold_f64le_hex"]
        != expected_identity["threshold_f64le_hex"]
        or telemetry["preloaded_clause_count"] != len(current.clauses)
        or telemetry["preloaded_literal_count"] != current.literal_count
        or telemetry["fully_emitted_clause_count"]
        != len(eligible) + terminal_empty_count
        or telemetry["fully_emitted_literal_count"]
        != sum(len(clause) for clause in eligible)
        or any(telemetry[name] != value for name, value in expected_counts.items())
        or telemetry["pending_clause_exported"] is not False
        or telemetry["next_vault_available"] is not next_available
        or telemetry["next_vault_terminal_reason"] != terminal_reason
    ):
        raise O1C66RunError("native vault telemetry ledger differs")
    if next_available:
        if (
            telemetry["next_vault_sha256"] != parsed_next.sha256
            or telemetry["next_serialized_bytes"] != parsed_next.serialized_bytes
            or telemetry["next_clause_count"] != len(parsed_next.clauses)
            or telemetry["next_literal_count"] != parsed_next.literal_count
        ):
            raise O1C66RunError("native next-vault telemetry differs")
    elif any(
        telemetry[name] is not None
        for name in (
            "next_vault_sha256",
            "next_serialized_bytes",
            "next_clause_count",
            "next_literal_count",
        )
    ):
        raise O1C66RunError("terminal next-vault telemetry must be null")


def _adapter_vault_payload(vault: object) -> bytes:
    """Use the shared v8 serializer in production; ClauseVault is a test oracle."""

    if isinstance(vault, ClauseVault):
        return vault.to_bytes()
    try:
        payload = _vault_v1.serialize_threshold_no_good_vault(
            cast(_vault_v1.ThresholdNoGoodVault, vault),
            caps=_vault_v1.O1C66_VAULT_CAPS,
        )
    except Exception as exc:
        raise O1C66VaultError("adapter next-vault serialization failed") from exc
    if not isinstance(payload, bytes):
        raise O1C66VaultError("adapter next-vault serialization differs")
    return payload


def _write_adapter_vault(path: Path, vault: object) -> None:
    if isinstance(vault, ClauseVault):
        write_vault(path, vault)
        return
    if path.exists() or path.is_symlink():
        raise O1C66VaultError("adapter vault output already exists")
    try:
        payload = _vault_v1.serialize_threshold_no_good_vault(
            cast(_vault_v1.ThresholdNoGoodVault, vault),
            caps=_vault_v1.O1C66_VAULT_CAPS,
        )
        _atomic_bytes(path, payload)
    except Exception as exc:
        raise O1C66VaultError("adapter vault publication failed") from exc
    if path.is_symlink() or path.read_bytes() != payload:
        raise O1C66VaultError("adapter vault publication differs")


def _validate_memory_ledger(row: Mapping[str, object]) -> dict[str, object]:
    expected_fields = {
        "memory_series_schema",
        "memory_sample_limit",
        "memory_sample_count",
        "memory_samples",
        "memory_peak_bytes",
        "memory_last_bytes",
        "memory_last_elapsed_seconds",
    }
    if set(row) != expected_fields:
        raise O1C66RunError("native adapter memory fields differ")
    raw_samples = row["memory_samples"]
    if not isinstance(raw_samples, list):
        raise O1C66RunError("native RSS series differs")
    samples: list[dict[str, int | float]] = []
    for raw_sample in raw_samples:
        sample = _mapping(raw_sample, "native RSS sample")
        elapsed = _finite_float(sample.get("elapsed_seconds"), "RSS elapsed")
        rss = _nonnegative_int(sample.get("rss_bytes"), "RSS bytes")
        if (
            set(sample) != {"elapsed_seconds", "rss_bytes"}
            or elapsed > EPISODE_TIMEOUT_SECONDS
            or rss > EPISODE_MEMORY_LIMIT_BYTES
        ):
            raise O1C66RunError("native RSS sample exceeds episode cap")
        samples.append({"elapsed_seconds": elapsed, "rss_bytes": rss})
    if samples != sorted(samples, key=lambda sample: sample["elapsed_seconds"]):
        raise O1C66RunError("native RSS sample order differs")
    count = _nonnegative_int(row["memory_sample_count"], "RSS sample count")
    peak = max((cast(int, sample["rss_bytes"]) for sample in samples), default=None)
    last_rss = cast(int, samples[-1]["rss_bytes"]) if samples else None
    last_elapsed = cast(float, samples[-1]["elapsed_seconds"]) if samples else None
    if (
        row["memory_series_schema"] != NATIVE_MEMORY_SERIES_SCHEMA
        or row["memory_sample_limit"] != MAXIMUM_NATIVE_MEMORY_SAMPLES
        or count != len(samples)
        or count > MAXIMUM_NATIVE_MEMORY_SAMPLES
        or row["memory_peak_bytes"] != peak
        or row["memory_last_bytes"] != last_rss
        or row["memory_last_elapsed_seconds"] != last_elapsed
    ):
        raise O1C66RunError("native RSS ledger differs")
    return {**dict(row), "memory_samples": samples}


def _memory_ledger(result: object) -> dict[str, object]:
    return _validate_memory_ledger(_result_mapping(result, "adapter_memory"))


def _native_episode_ledger(
    result: object, *, vault_telemetry: Mapping[str, object]
) -> dict[str, object]:
    status = getattr(result, "status", None)
    conflict_limit = getattr(result, "conflict_limit", None)
    threshold = getattr(result, "threshold", None)
    if (
        isinstance(status, bool)
        or status not in (0, 10, 20)
        or conflict_limit != REQUESTED_CONFLICTS_PER_EPISODE
        or threshold != THRESHOLD
    ):
        raise O1C66RunError("native episode scalar contract differs")
    raw = _result_mapping(result, "raw")
    stats = _result_mapping(result, "stats")
    sieve = _result_mapping(result, "sieve")
    resources = _result_mapping(result, "resources")
    state = _mapping(sieve.get("state"), "native.sieve.state")
    requested = _nonnegative_int(
        stats.get("requested_conflicts"), "requested conflicts"
    )
    billed = _nonnegative_int(stats.get("billed_conflicts"), "billed conflicts")
    overshoot = _nonnegative_int(
        stats.get("conflict_limit_overshoot"), "conflict overshoot"
    )
    decisions = _nonnegative_int(stats.get("decisions"), "decisions")
    propagations = _nonnegative_int(stats.get("propagations"), "propagations")
    solve_conflicts = _nonnegative_int(stats.get("solve_conflicts"), "solve conflicts")
    cuts = _nonnegative_int(sieve.get("external_clauses_emitted"), "fully emitted cuts")
    telemetry_cuts = _nonnegative_int(
        vault_telemetry.get("fully_emitted_clause_count"),
        "vault fully emitted cuts",
    )
    pending = _nonnegative_int(sieve.get("pending_clause_count"), "pending clauses")
    wall_microseconds = _nonnegative_int(
        resources.get("wall_microseconds"), "native wall microseconds"
    )
    cpu_microseconds = _nonnegative_int(
        resources.get("cpu_microseconds"), "native CPU microseconds"
    )
    peak_rss_bytes = _nonnegative_int(
        resources.get("peak_rss_bytes"), "native peak RSS bytes"
    )
    expected_state = {
        0: (256, "INCONCLUSIVE"),
        10: (32, "SATISFIED"),
        20: (64, "UNSATISFIED"),
    }[cast(int, status)]
    if (
        requested != REQUESTED_CONFLICTS_PER_EPISODE
        or billed > MAXIMUM_BILLED_CONFLICTS_PER_EPISODE
        or overshoot > MAXIMUM_CONFLICT_LIMIT_OVERSHOOT
        or billed != solve_conflicts
        or overshoot != max(solve_conflicts - requested, 0)
        or solve_conflicts > requested + MAXIMUM_CONFLICT_LIMIT_OVERSHOOT
    ):
        raise O1C66RunError("native episode conflict ledger differs")
    if (
        raw.get("schema") != NATIVE_RESULT_SCHEMA
        or raw.get("implementation_parent_schema")
        != NATIVE_IMPLEMENTATION_PARENT_SCHEMA
        or (raw.get("post_solve_state"), raw.get("post_solve_state_name"))
        != expected_state
        or raw.get("teardown_rule") != TEARDOWN_RULE
        or raw.get("pending_backtrack_rule") != PENDING_BACKTRACK_RULE
        or state.get("schema") != NATIVE_STATE_SCHEMA
        or cuts != telemetry_cuts
        or pending > 1
        or wall_microseconds > int(EPISODE_TIMEOUT_SECONDS * 1_000_000)
        or peak_rss_bytes > EPISODE_MEMORY_LIMIT_BYTES
        or sieve.get("grouping_sha256") != GROUPING_SHA256
        or sieve.get("grouping_input_sha256") != GROUPING_SHA256
        or sieve.get("grouping_width_cap") != GROUPING_WIDTH_CAP
        or sieve.get("grouping_serialized_bytes") != GROUPING_SERIALIZED_BYTES
        or sieve.get("bound_rule") != COMPATIBILITY_GROUPING_BOUND_RULE
        or sieve.get("source_sha256") != APPLE8_POTENTIAL_SOURCE_SHA256
    ):
        raise O1C66RunError("native episode lifecycle/resource ledger differs")
    memory = _memory_ledger(result)
    return {
        "status": status,
        "requested_conflicts": requested,
        "billed_conflicts": billed,
        "conflict_limit_overshoot": overshoot,
        "solve_conflicts": solve_conflicts,
        "decisions": decisions,
        "propagations": propagations,
        "fully_emitted_cuts": cuts,
        "pending_clause_count": pending,
        "trail_threshold_prunes": _nonnegative_int(
            sieve.get("trail_threshold_prunes"), "trail threshold prunes"
        ),
        "model_threshold_prunes": _nonnegative_int(
            sieve.get("model_threshold_prunes"), "model threshold prunes"
        ),
        "root_upper_bound": _finite_float(
            sieve.get("root_upper_bound"), "root upper bound"
        ),
        "minimum_upper_bound": _finite_float(
            sieve.get("minimum_upper_bound"), "minimum upper bound"
        ),
        "wall_microseconds": wall_microseconds,
        "cpu_microseconds": cpu_microseconds,
        "peak_rss_bytes": peak_rss_bytes,
        "rss_series": memory,
        "process": {
            "fresh_native_subprocess": True,
            "ordinary_solver_learning_persisted": False,
            "assignment_persisted": False,
            "trail_persisted": False,
            "group_cache_persisted": False,
        },
        "lifecycle": {
            "post_solve_state": raw.get("post_solve_state"),
            "post_solve_state_name": raw.get("post_solve_state_name"),
            "teardown_rule": raw.get("teardown_rule"),
            "pending_backtrack_rule": raw.get("pending_backtrack_rule"),
        },
    }


def _empty_totals() -> dict[str, object]:
    return {
        "native_solver_calls": 0,
        "completed_episodes": 0,
        "requested_conflicts": 0,
        "billed_conflicts": 0,
        "solve_conflicts": 0,
        "decisions": 0,
        "propagations": 0,
        "fully_emitted_eligible_clauses": 0,
        "novel_eligible_clauses": 0,
        "duplicate_eligible_clauses": 0,
        "pending_clauses_not_archived": 0,
        "native_wall_microseconds": 0,
        "native_cpu_microseconds": 0,
        "maximum_peak_rss_bytes": 0,
    }


def _add_episode_totals(
    totals: dict[str, object],
    ledger: Mapping[str, object],
    *,
    novel: int,
    duplicate: int,
) -> None:
    additions = {
        "completed_episodes": 1,
        "billed_conflicts": cast(int, ledger["billed_conflicts"]),
        "solve_conflicts": cast(int, ledger["solve_conflicts"]),
        "decisions": cast(int, ledger["decisions"]),
        "propagations": cast(int, ledger["propagations"]),
        "fully_emitted_eligible_clauses": cast(int, ledger["fully_emitted_cuts"]),
        "novel_eligible_clauses": novel,
        "duplicate_eligible_clauses": duplicate,
        "pending_clauses_not_archived": cast(int, ledger["pending_clause_count"]),
        "native_wall_microseconds": cast(int, ledger["wall_microseconds"]),
        "native_cpu_microseconds": cast(int, ledger["cpu_microseconds"]),
    }
    for name, increment in additions.items():
        totals[name] = cast(int, totals[name]) + increment
    totals["maximum_peak_rss_bytes"] = max(
        cast(int, totals["maximum_peak_rss_bytes"]),
        cast(int, ledger["peak_rss_bytes"]),
    )
    if (
        cast(int, totals["native_solver_calls"]) > MAXIMUM_EPISODES
        or cast(int, totals["requested_conflicts"]) > MAXIMUM_TOTAL_REQUESTED_CONFLICTS
        or cast(int, totals["billed_conflicts"]) > MAXIMUM_TOTAL_BILLED_CONFLICTS
    ):
        raise O1C66RunError("cumulative episode work cap exceeded")


def _intent(
    *,
    ordinal: int,
    current_vault: ClauseVault,
    totals: Mapping[str, object],
    bindings: Mapping[str, object],
) -> dict[str, object]:
    if ordinal != totals["native_solver_calls"]:
        raise O1C66RunError("episode ordinal does not follow consumed-call ledger")
    return {
        "schema": INTENT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "episode_ordinal": ordinal,
        "episode_is_retry": False,
        "calls_before": totals["native_solver_calls"],
        "calls_authorized_by_this_intent": 1,
        "maximum_episodes": MAXIMUM_EPISODES,
        "requested_conflicts": REQUESTED_CONFLICTS_PER_EPISODE,
        "maximum_billed_conflicts": MAXIMUM_BILLED_CONFLICTS_PER_EPISODE,
        "timeout_seconds": EPISODE_TIMEOUT_SECONDS,
        "memory_limit_bytes": EPISODE_MEMORY_LIMIT_BYTES,
        "seed": SEED,
        "threshold": THRESHOLD,
        "policy_state": {
            "schema": POLICY_STATE_SCHEMA,
            "canonical_bytes": 0,
            "sha256": POLICY_STATE_SHA256,
            "adaptive": False,
            "updates": 0,
        },
        "input_vault": current_vault.describe(),
        "previous_vault_sha256": current_vault.sha256,
        "cumulative_call_work_ledger_before": dict(totals),
        "semantic_boundary": {
            "vault_clauses_valid_for": (
                "CNF-and-potential-score-greater-than-or-equal-threshold"
            ),
            "cnf_only_entailment": False,
            "unsat_means_key_space_unsat": False,
        },
        "bindings": dict(bindings),
        "truth_key_reads": 0,
        "entropy_calls": 0,
        "fresh_reveal_calls": 0,
        "refits": 0,
        "MPS_or_GPU": False,
    }


def _terminal_outcome(
    *,
    classification: str,
    stop_reason: str,
    episodes: list[Mapping[str, object]],
    current_vault: ClauseVault,
    totals: Mapping[str, object],
    failure: Mapping[str, object] | None = None,
) -> EpisodeProtocolOutcome:
    return EpisodeProtocolOutcome(
        classification=classification,
        stop_reason=stop_reason,
        episodes=tuple(episodes),
        final_vault=current_vault,
        totals=dict(totals),
        operational_failure=None if failure is None else dict(failure),
    )


def execute_episodic_protocol(
    *,
    capsule: Path,
    initial_vault: ClauseVault,
    adapter_initial_vault: object,
    invoke_episode: EpisodeInvoker,
    verify_public_model: Callable[[bytes], bool],
    intent_bindings: Mapping[str, object],
) -> EpisodeProtocolOutcome:
    """Execute at most eight consumed ordinals with no replay or retry path."""

    if initial_vault.clauses:
        raise O1C66RunError("episode zero vault must be canonical and empty")
    if not capsule.is_dir():
        raise O1C66RunError("episode capsule must already exist")
    episode_root = capsule / "episodes"
    episode_root.mkdir(exist_ok=False)
    initial_path = capsule / "vault-initial.bin"
    _write_adapter_vault(initial_path, adapter_initial_vault)
    if initial_path.read_bytes() != initial_vault.to_bytes():
        raise O1C66VaultError("shared empty vault differs from independent parser")

    current = initial_vault
    current_path = initial_path
    totals = _empty_totals()
    episodes: list[Mapping[str, object]] = []
    episode_zero_search: tuple[int, int] | None = None
    novel_after_episode_zero = False

    for ordinal in range(MAXIMUM_EPISODES):
        episode_dir = episode_root / f"{ordinal:02d}"
        episode_dir.mkdir(exist_ok=False)
        intent_path = episode_dir / "intent.json"
        intent = _intent(
            ordinal=ordinal,
            current_vault=current,
            totals=totals,
            bindings=intent_bindings,
        )
        _atomic_json(intent_path, intent)
        intent_sha256 = sha256_file(intent_path)
        totals["native_solver_calls"] = cast(int, totals["native_solver_calls"]) + 1
        totals["requested_conflicts"] = (
            cast(int, totals["requested_conflicts"]) + REQUESTED_CONFLICTS_PER_EPISODE
        )
        if (
            cast(int, totals["native_solver_calls"]) > MAXIMUM_EPISODES
            or cast(int, totals["requested_conflicts"])
            > MAXIMUM_TOTAL_REQUESTED_CONFLICTS
        ):
            raise O1C66RunError("consumed intent exceeds cumulative call/work cap")

        try:
            result = invoke_episode(ordinal, current_path)
        except BaseException as exc:
            classification = _failure_classification(exc)
            raw_failure_telemetry = getattr(exc, "failure_telemetry", None)
            adapter_failure_telemetry = (
                dict(raw_failure_telemetry)
                if isinstance(raw_failure_telemetry, Mapping)
                else None
            )
            failure = {
                "classification": classification,
                "episode_ordinal": ordinal,
                "occurred_after_persisted_intent": True,
                "intent_sha256": intent_sha256,
                "native_calls_consumed": totals["native_solver_calls"],
                "retry_authorized": False,
                "error_type": type(exc).__qualname__,
                "error_message": str(exc),
                "exception_chain_outer_to_cause_or_context": _exception_chain(exc),
                "adapter_failure_telemetry": adapter_failure_telemetry,
                "truth_key_bytes_read": False,
            }
            _atomic_json(episode_dir / "terminal_failure.json", failure)
            episodes.append(
                {
                    "schema": EPISODE_SCHEMA,
                    "episode_ordinal": ordinal,
                    "intent_sha256": intent_sha256,
                    "completed": False,
                    "retry_authorized": False,
                    "input_vault": current.describe(),
                    "output_vault": None,
                    "process": {
                        "fresh_native_subprocess": True,
                        "completed_result_returned": False,
                    },
                    "cumulative_call_work_ledger_after": dict(totals),
                    "terminal_failure": failure,
                }
            )
            return _terminal_outcome(
                classification=classification,
                stop_reason="native-call-or-resource-terminal",
                episodes=episodes,
                current_vault=current,
                totals=totals,
                failure=failure,
            )

        try:
            raw = _result_mapping(result, "raw")
            vault_telemetry = _mapping(
                getattr(result, "vault_telemetry"), "native.vault_telemetry"
            )
            if vault_telemetry.get("schema") != NATIVE_VAULT_TELEMETRY_SCHEMA:
                raise O1C66RunError("native vault telemetry schema differs")
            eligible_raw = getattr(result, "eligible_emitted_clauses")
            if not isinstance(eligible_raw, Sequence):
                raise O1C66RunError("eligible emitted clause sequence differs")
            eligible = tuple(_clause_literals(item) for item in eligible_raw)
            ledger = _native_episode_ledger(result, vault_telemetry=vault_telemetry)
            status = cast(int, ledger["status"])
            key_model = getattr(result, "key_model", None)
            if status == 10:
                if not isinstance(key_model, bytes) or not verify_public_model(
                    key_model
                ):
                    raise O1C66RunError(
                        "SAT model failed independent public eight-block verification"
                    )
            elif key_model is not None:
                raise O1C66RunError("non-SAT episode returned a key model")

            adapter_input_payload = _adapter_vault_payload(
                getattr(result, "input_vault")
            )
            if adapter_input_payload != current.to_bytes():
                raise O1C66VaultError("adapter input-vault identity differs")
            native_result_path = episode_dir / "native_result.json"
            _atomic_json(native_result_path, raw)
            _atomic_json(episode_dir / "vault_telemetry.json", dict(vault_telemetry))
            next_available = vault_telemetry.get("next_vault_available")
            terminal_reason = vault_telemetry.get("next_vault_terminal_reason")
            adapter_next: object | None = getattr(result, "next_vault")
            if not isinstance(next_available, bool):
                raise O1C66RunError("next-vault availability differs")
            allowed_terminal_reasons = {
                "terminal_empty_clause",
                "capacity_clause_count",
                "capacity_literal_count",
                "capacity_payload_bytes",
            }
            if next_available:
                if terminal_reason is not None:
                    raise O1C66RunError("available next vault has terminal reason")
                if adapter_next is None:
                    raise O1C66RunError("available next vault is missing")
                next_payload = _adapter_vault_payload(adapter_next)
                parsed_next = ClauseVault.from_bytes(
                    next_payload,
                    expected_identity=current.identity,
                    observed_variables=current.observed_variables,
                )
                expected_next, novel_clauses, duplicate_count = current.append_emitted(
                    eligible
                )
                if parsed_next != expected_next:
                    raise O1C66VaultError(
                        "adapter cumulative first-emission deduplication differs"
                    )
            else:
                if terminal_reason not in allowed_terminal_reasons:
                    raise O1C66RunError("unavailable next-vault reason differs")
                if adapter_next is not None:
                    raise O1C66RunError("terminal next vault must be absent")
                parsed_next = current
                if terminal_reason == "terminal_empty_clause":
                    if status != 20:
                        raise O1C66RunError(
                            "terminal empty clause must return threshold-region UNSAT"
                        )
                    novel_clauses = ()
                    duplicate_count = 0
                else:
                    novel_clauses, duplicate_count = _deduplicate_without_capacity(
                        current, eligible
                    )

            _validate_vault_telemetry(
                vault_telemetry,
                current=current,
                eligible_raw=cast(Sequence[object], eligible_raw),
                eligible=eligible,
                parsed_next=parsed_next,
                next_available=next_available,
                terminal_reason=terminal_reason,
            )

            next_path = episode_dir / "vault-output.bin"
            archive_output = next_available and status != 20
            if archive_output:
                assert adapter_next is not None
                _write_adapter_vault(next_path, adapter_next)
                reread = read_vault(
                    next_path,
                    identity=current.identity,
                    observed_variables=current.observed_variables,
                )
                if reread != parsed_next:
                    raise O1C66VaultError("completed vault sidecar differs")

            new_count = len(novel_clauses)
            if ordinal > 0 and new_count:
                novel_after_episode_zero = True
            decisions = cast(int, ledger["decisions"])
            propagations = cast(int, ledger["propagations"])
            if ordinal == 0:
                episode_zero_search = (decisions, propagations)
                search_delta: dict[str, object] | None = None
            else:
                assert episode_zero_search is not None
                search_delta = {
                    "decisions_delta_from_episode_zero": (
                        decisions - episode_zero_search[0]
                    ),
                    "propagations_delta_from_episode_zero": (
                        propagations - episode_zero_search[1]
                    ),
                    "search_work_changed_from_episode_zero": (
                        (decisions, propagations) != episode_zero_search
                    ),
                }
            _add_episode_totals(
                totals, ledger, novel=new_count, duplicate=duplicate_count
            )
            episode = {
                "schema": EPISODE_SCHEMA,
                "episode_ordinal": ordinal,
                "intent_sha256": intent_sha256,
                "completed": True,
                "retry_authorized": False,
                "input_vault": current.describe(),
                "output_vault": parsed_next.describe(),
                "output_vault_archived": archive_output,
                "output_vault_sidecar": next_path.relative_to(capsule).as_posix()
                if archive_output
                else None,
                "next_vault_available": next_available,
                "next_vault_terminal_reason": terminal_reason,
                "eligible_emitted": {
                    "clause_count": len(eligible),
                    "literal_count": sum(len(clause) for clause in eligible),
                    "novel_clause_count": new_count,
                    "novel_literal_count": sum(len(clause) for clause in novel_clauses),
                    "duplicate_clause_count": duplicate_count,
                    "pending_clause_count": ledger["pending_clause_count"],
                    "pending_exported": False,
                },
                "work_and_resources": ledger,
                "search_delta": search_delta,
                "native_result_sha256": sha256_file(native_result_path),
                "vault_telemetry_sha256": sha256_file(
                    episode_dir / "vault_telemetry.json"
                ),
                "public_model": {
                    "present": key_model is not None,
                    "verified_8_of_8": status == 10,
                    "model_sha256": hashlib.sha256(key_model).hexdigest()
                    if isinstance(key_model, bytes)
                    else None,
                    "truth_key_sha256": None,
                    "native_model_equals_committed_truth": None,
                    "truth_key_bytes_read": False,
                },
                "cumulative_call_work_ledger_after": dict(totals),
                "vault_semantic_scope": (
                    "CNF-and-potential-score-greater-than-or-equal-threshold"
                ),
            }
            _atomic_json(episode_dir / "episode.json", episode)
            episodes.append(episode)

            if status == 10:
                return _terminal_outcome(
                    classification=PUBLIC_EXACT_RECOVERY,
                    stop_reason="public-verified-candidate",
                    episodes=episodes,
                    current_vault=parsed_next,
                    totals=totals,
                )
            if status == 20:
                return _terminal_outcome(
                    classification=THRESHOLD_REGION_EXHAUSTED,
                    stop_reason=(
                        "episode-zero-root-empty-or-unsat-threshold-region"
                        if ordinal == 0
                        else "unsat-threshold-region"
                    ),
                    episodes=episodes,
                    current_vault=parsed_next,
                    totals=totals,
                )
            if not next_available:
                failure = {
                    "classification": CAPACITY_TERMINAL,
                    "episode_ordinal": ordinal,
                    "capacity_terminal_reason": terminal_reason,
                    "native_calls_consumed": totals["native_solver_calls"],
                    "retry_authorized": False,
                    "eviction_performed": False,
                    "truth_key_bytes_read": False,
                }
                return _terminal_outcome(
                    classification=CAPACITY_TERMINAL,
                    stop_reason=cast(str, terminal_reason),
                    episodes=episodes,
                    current_vault=current,
                    totals=totals,
                    failure=failure,
                )
            if new_count == 0:
                return _terminal_outcome(
                    classification=(
                        STRICT_CUMULATIVE_GAIN
                        if novel_after_episode_zero
                        else SATURATED_NO_GAIN
                    ),
                    stop_reason="zero-novel-eligible-clauses",
                    episodes=episodes,
                    current_vault=parsed_next,
                    totals=totals,
                )
            current = parsed_next
            current_path = next_path
        except BaseException as exc:
            classification = _failure_classification(exc)
            failure = {
                "classification": classification,
                "episode_ordinal": ordinal,
                "occurred_after_persisted_intent": True,
                "intent_sha256": intent_sha256,
                "native_calls_consumed": totals["native_solver_calls"],
                "retry_authorized": False,
                "native_result_returned": True,
                "error_type": type(exc).__qualname__,
                "error_message": str(exc),
                "exception_chain_outer_to_cause_or_context": _exception_chain(exc),
                "truth_key_bytes_read": False,
            }
            _atomic_json(episode_dir / "terminal_failure.json", failure)
            episodes.append(
                {
                    "schema": EPISODE_SCHEMA,
                    "episode_ordinal": ordinal,
                    "intent_sha256": intent_sha256,
                    "completed": False,
                    "retry_authorized": False,
                    "input_vault": current.describe(),
                    "output_vault": None,
                    "cumulative_call_work_ledger_after": dict(totals),
                    "terminal_failure": failure,
                }
            )
            return _terminal_outcome(
                classification=classification,
                stop_reason="invalid-post-native-result",
                episodes=episodes,
                current_vault=current,
                totals=totals,
                failure=failure,
            )

    return _terminal_outcome(
        classification=(
            STRICT_CUMULATIVE_GAIN if novel_after_episode_zero else SATURATED_NO_GAIN
        ),
        stop_reason="maximum-eight-episodes-completed",
        episodes=episodes,
        current_vault=current,
        totals=totals,
    )


def validate_native_build_identity(native_build: NativeGuidedSearchBuild) -> None:
    try:
        executable_sha256 = sha256_file(native_build.executable)
    except (AttributeError, OSError) as exc:
        raise O1C66RunError("native-v6 build identity differs") from exc
    if (
        not isinstance(native_build, NativeGuidedSearchBuild)
        or native_build.executable.is_symlink()
        or native_build.executable.name != "native-joint-score-sieve"
        or native_build.source_sha256 != EXPECTED_NATIVE_SOURCE_SHA256
        or native_build.executable_sha256 != EXPECTED_NATIVE_EXECUTABLE_SHA256
        or executable_sha256 != EXPECTED_NATIVE_EXECUTABLE_SHA256
    ):
        raise O1C66RunError("native-v6 build identity differs")


def validate_frozen_episode_inputs(
    *, cnf: Path, potential: Path, grouping: Path, vault_path: Path
) -> None:
    expected = {
        cnf: APPLE8_CNF_SHA256,
        potential: APPLE8_POTENTIAL_SHA256,
        grouping: GROUPING_SHA256,
    }
    try:
        for path, digest in expected.items():
            mode = path.stat(follow_symlinks=False).st_mode
            if (
                path.is_symlink()
                or not stat.S_ISREG(mode)
                or sha256_file(path) != digest
            ):
                raise O1C66RunError("frozen episode input identity differs")
        vault_mode = vault_path.stat(follow_symlinks=False).st_mode
        if vault_path.is_symlink() or not stat.S_ISREG(vault_mode):
            raise O1C66RunError("frozen episode vault path differs")
        if grouping.stat().st_size != GROUPING_SERIALIZED_BYTES:
            raise O1C66RunError("frozen grouping byte size differs")
        if vault_path.stat().st_size > VAULT_MAXIMUM_SERIALIZED_BYTES:
            raise O1C66VaultCapacityError("episode input vault byte cap exceeded")
    except O1C66RunError:
        raise
    except OSError as exc:
        raise O1C66RunError("frozen episode input identity differs") from exc
    if (
        REQUESTED_CONFLICTS_PER_EPISODE != 512
        or MAXIMUM_BILLED_CONFLICTS_PER_EPISODE != 513
        or EPISODE_TIMEOUT_SECONDS != 45.0
        or EPISODE_MEMORY_LIMIT_BYTES != 536_870_912
        or THRESHOLD != 14.606178797892962
        or GROUPING_WIDTH_CAP != 6
        or SEED != 0
    ):
        raise O1C66RunError("frozen episode scalar identity differs")


def invoke_native_episode(
    *,
    executable: Path,
    cnf: Path,
    potential: Path,
    grouping: Path,
    vault_path: Path,
    runner: Callable[..., object] = _native_v8.run_joint_score_sieve,
) -> object:
    """Make one fresh episode call; callers own ordinal/no-replay accounting."""

    validate_frozen_episode_inputs(
        cnf=cnf, potential=potential, grouping=grouping, vault_path=vault_path
    )
    return runner(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential,
        grouping_path=grouping,
        vault_path=vault_path,
        vault_caps=_vault_v1.O1C66_VAULT_CAPS,
        threshold=THRESHOLD,
        conflict_limit=REQUESTED_CONFLICTS_PER_EPISODE,
        seed=SEED,
        timeout_seconds=EPISODE_TIMEOUT_SECONDS,
        memory_limit_bytes=EPISODE_MEMORY_LIMIT_BYTES,
    )


def run_target_free_geometry_smoke(
    output_path: str | Path,
    *,
    runner: Callable[..., object] = _native_v8.run_joint_score_sieve,
) -> dict[str, object]:
    """Run the one-call empty-CNF root-prune gate and publish canonical evidence."""

    root = lab_root().resolve(strict=True)
    raw_output = Path(output_path)
    if not raw_output.is_absolute():
        raw_output = root / raw_output
    try:
        output = raw_output.parent.resolve(strict=True) / raw_output.name
    except OSError as exc:
        raise O1C66RunError("geometry-smoke output parent differs") from exc
    if output.exists() or output.is_symlink():
        raise O1C66RunError("geometry-smoke output already exists")

    potential = _geometry_smoke_potential_path(root)
    try:
        potential_mode = potential.stat(follow_symlinks=False).st_mode
        if (
            potential.is_symlink()
            or not stat.S_ISREG(potential_mode)
            or sha256_file(potential) != APPLE8_POTENTIAL_SHA256
        ):
            raise O1C66RunError("geometry-smoke potential identity differs")
        frozen = _o1c65.build_frozen_grouping(
            potential,
            {"input": {"potential_sha256": APPLE8_POTENTIAL_SHA256}},
        )
    except O1C66RunError:
        raise
    except Exception as exc:
        raise O1C66RunError("geometry-smoke grouping construction failed") from exc
    if (
        frozen.field.source_sha256 != APPLE8_POTENTIAL_SOURCE_SHA256
        or frozen.grouping.sha256 != GROUPING_SHA256
        or len(frozen.grouping.serialized) != GROUPING_SERIALIZED_BYTES
        or frozen.diagnostics.get("grouped_root_upper_bound")
        != GEOMETRY_SMOKE_GROUPED_ROOT_UPPER_BOUND
        or not GEOMETRY_SMOKE_GROUPED_ROOT_UPPER_BOUND < GEOMETRY_SMOKE_THRESHOLD
    ):
        raise O1C66RunError("geometry-smoke frozen geometry differs")

    with tempfile.TemporaryDirectory(prefix="o1c66-target-free-geometry-") as raw:
        workspace = Path(raw)
        native_build = _native_v7.build_native_joint_score_sieve(
            source=root / "native/cadical_o1_joint_score_sieve_v6.cpp",
            output=workspace / "native-joint-score-sieve",
        )
        validate_native_build_identity(native_build)
        cnf = workspace / "empty-257024.cnf"
        grouping = workspace / "apple8-width6.grouping"
        vault_path = workspace / "empty-threshold-vault.bin"
        _atomic_bytes(cnf, GEOMETRY_SMOKE_CNF_BYTES)
        _o1c65.materialize_grouping(grouping, frozen)
        input_vault = _geometry_smoke_empty_vault(frozen)
        _atomic_bytes(vault_path, input_vault.serialized)
        try:
            parsed_vault = _vault_v1.read_threshold_no_good_vault(
                vault_path,
                observed_variables=tuple(frozen.field.observed_variables),
                caps=_vault_v1.O1C66_VAULT_CAPS,
            )
        except Exception as exc:
            raise O1C66RunError("geometry-smoke empty vault reread failed") from exc
        if (
            cnf.read_bytes() != GEOMETRY_SMOKE_CNF_BYTES
            or sha256_file(grouping) != GROUPING_SHA256
            or parsed_vault != input_vault
        ):
            raise O1C66RunError("geometry-smoke materialized input differs")
        result = runner(
            executable=native_build.executable,
            cnf_path=cnf,
            potential_path=potential,
            grouping_path=grouping,
            vault_path=vault_path,
            vault_caps=_vault_v1.O1C66_VAULT_CAPS,
            threshold=GEOMETRY_SMOKE_THRESHOLD,
            conflict_limit=REQUESTED_CONFLICTS_PER_EPISODE,
            seed=SEED,
            timeout_seconds=EPISODE_TIMEOUT_SECONDS,
            memory_limit_bytes=EPISODE_MEMORY_LIMIT_BYTES,
        )
        report = _geometry_smoke_report(
            root=root,
            frozen=frozen,
            native_build=native_build,
            input_vault=input_vault,
            result=result,
        )
        payload = _atomic_json(output, report)
        try:
            mode = output.stat(follow_symlinks=False).st_mode
            if (
                output.is_symlink()
                or not stat.S_ISREG(mode)
                or output.read_bytes() != payload
                or len(payload) > MAXIMUM_GEOMETRY_SMOKE_ARTIFACT_BYTES
            ):
                raise O1C66RunError("geometry-smoke publication differs")
        except OSError as exc:
            raise O1C66RunError("geometry-smoke publication cannot be read") from exc
        return report


def _public_target(baseline: object) -> PublicTarget:
    public = _mapping(getattr(baseline, "public_preflight"), "public preflight")
    counters = tuple(
        _nonnegative_int(value, "public counter")
        for value in _sequence(public.get("counters"), "public counters")
    )
    raw_outputs = _sequence(public.get("output_blocks_hex"), "public outputs")
    try:
        nonce = bytes.fromhex(cast(str, public["nonce_hex"]))
        outputs = tuple(bytes.fromhex(cast(str, value)) for value in raw_outputs)
    except (KeyError, TypeError, ValueError) as exc:
        raise O1C66RunError("public APPLE8 verifier bytes differ") from exc
    return PublicTarget(nonce=nonce, counters=counters, output_blocks=outputs)


def _peak_rss_bytes() -> int:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform == "darwin" else value * 1024)


def _runtime_resources(
    *, started: float, cpu_started: float, child_started: resource.struct_rusage
) -> dict[str, object]:
    try:
        child = resource.getrusage(resource.RUSAGE_CHILDREN)
        return {
            "elapsed_seconds": max(0.0, time.perf_counter() - started),
            "parent_cpu_seconds": max(0.0, time.process_time() - cpu_started),
            "child_cpu_seconds": max(
                0.0,
                child.ru_utime
                + child.ru_stime
                - child_started.ru_utime
                - child_started.ru_stime,
            ),
            "runner_peak_rss_bytes": _peak_rss_bytes(),
        }
    except Exception as exc:
        return {
            "elapsed_seconds": max(0.0, time.perf_counter() - started),
            "parent_cpu_seconds": None,
            "child_cpu_seconds": None,
            "runner_peak_rss_bytes": None,
            "capture_failure": {
                "type": type(exc).__qualname__,
                "message": str(exc),
            },
        }


def _result_from_outcome(
    *,
    capsule_relative: Path,
    source_commit: str,
    preflight_row: Mapping[str, object],
    outcome: EpisodeProtocolOutcome,
    runtime: Mapping[str, object],
    started_at: str,
) -> dict[str, object]:
    totals = dict(outcome.totals)
    calls = cast(int, totals["native_solver_calls"])
    requested = cast(int, totals["requested_conflicts"])
    billed = cast(int, totals["billed_conflicts"])
    strict_novel = any(
        cast(int, episode.get("episode_ordinal", 0)) > 0
        and cast(Mapping[str, object], episode.get("eligible_emitted", {})).get(
            "novel_clause_count", 0
        )
        != 0
        for episode in outcome.episodes
    )
    return {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": started_at,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_commit": source_commit,
        "classification": outcome.classification,
        "stop_reason": outcome.stop_reason,
        "capsule": capsule_relative.as_posix(),
        "claim_boundary": {
            "same_full256_target_cnf_potential_grouping_threshold_seed": True,
            "vault_clauses_valid_for": (
                "CNF-and-potential-score-greater-than-or-equal-threshold"
            ),
            "vault_clauses_are_cnf_only_entailed": False,
            "unsat_means_key_space_unsat": False,
            "unsat_means_frozen_threshold_region_exhausted": (
                outcome.classification == THRESHOLD_REGION_EXHAUSTED
            ),
            "native_solver_calls": calls,
            "episodes_are_retries": False,
            "written_intent_consumes_ordinal": True,
            "ordinal_replay_authorized": False,
            "only_fully_emitted_nonempty_clauses_persisted": True,
            "ordinary_solver_learning_persisted": False,
            "assignment_trail_group_cache_persisted": False,
            "fixed_policy_state_sha256": POLICY_STATE_SHA256,
            "strict_gain_has_novel_clause_after_episode_zero": strict_novel,
            "public_model_verification_blocks": 8,
            "truth_key_bytes_read": False,
            "truth_hash": None,
            "native_model_equals_committed_truth": None,
            "fresh_targets": 0,
            "scientific_entropy_calls": 0,
            "fresh_reveal_calls": 0,
            "refits": 0,
            "MPS_or_GPU": False,
        },
        "episodes": [dict(episode) for episode in outcome.episodes],
        "final_vault": outcome.final_vault.describe(),
        "totals": totals,
        "operational_failure": (
            None
            if outcome.operational_failure is None
            else dict(outcome.operational_failure)
        ),
        "resources": {
            **dict(runtime),
            "native_solver_calls": calls,
            "requested_conflicts": requested,
            "maximum_requested_conflicts": MAXIMUM_TOTAL_REQUESTED_CONFLICTS,
            "billed_conflicts": billed,
            "maximum_billed_conflicts": MAXIMUM_TOTAL_BILLED_CONFLICTS,
            "native_wall_seconds": cast(int, totals["native_wall_microseconds"])
            / 1_000_000.0,
            "native_cpu_seconds": cast(int, totals["native_cpu_microseconds"])
            / 1_000_000.0,
            "maximum_episode_peak_rss_bytes": totals["maximum_peak_rss_bytes"],
            "episode_memory_limit_bytes": EPISODE_MEMORY_LIMIT_BYTES,
            "episode_timeout_seconds": EPISODE_TIMEOUT_SECONDS,
            "persistent_artifact_bytes": 0,
        },
        "preflight": dict(preflight_row),
        "next_action": (
            "Do not replay any consumed ordinal or read committed truth. Treat public "
            "recovery as exact only after 8/8 verification; treat UNSAT only as frozen "
            "score-threshold-region exhaustion."
        ),
    }


def _markdown(result: Mapping[str, object]) -> str:
    return (
        "# O1C-0066 — APPLE8 episodic score-threshold no-good vault\n\n"
        f"- Classification: `{result['classification']}`\n"
        f"- Stop reason: `{result['stop_reason']}`\n"
        f"- Native solver episodes: "
        f"`{cast(Mapping[str, object], result['resources'])['native_solver_calls']}`\n"
        "- Truth key bytes read: `false`\n"
        "- Vault scope: `CNF and potential_score >= threshold` (not CNF-only)\n\n"
        "Each episode is a fresh subprocess, not a retry. Only fully emitted exact "
        "score-threshold no-goods survive in first-emission order.\n"
    )


def finalize_capsule(
    *,
    capsule: Path,
    authoritative_result: Path,
    result: dict[str, object],
    maximum_persistent_bytes: int,
    _after_capsule_seal: Callable[[], None] | None = None,
) -> None:
    if (capsule / "artifacts.sha256").exists() or authoritative_result.exists():
        raise O1C66RunError("O1C-0066 terminal publication already exists")
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
        raise O1C66RunError("persistent artifact byte ledger did not converge")
    if persistent > maximum_persistent_bytes:
        raise O1C66RunError("persistent artifact byte budget exceeded")
    payload = _canonical_json_bytes(result)
    manifest_path = capsule / "artifacts.sha256"
    authoritative_published = False
    manifest_published = False
    try:
        _atomic_bytes(authoritative_result, payload)
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
        if (
            authoritative_result.read_bytes() != payload
            or result_path.read_bytes() != payload
        ):
            raise O1C66RunError("terminal publication bytes differ")
        _o1c65._assert_immutable_tree(capsule)
    except Exception:
        _o1c65._restore_owned_capsule_for_recovery(capsule)
        if manifest_published:
            _o1c65._unlink_owned_exact(manifest_path, manifest, "O1C66 manifest")
        if authoritative_published:
            _o1c65._unlink_owned_exact(
                authoritative_result, payload, "O1C66 authoritative result"
            )
        raise


def run(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    authoritative = root / RESULT_RELATIVE
    if authoritative.exists() or tuple(root.glob(f"runs/*_{CAPSULE_SUFFIX}")):
        raise O1C66RunError("O1C-0066 already exists")
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    preflight_row = preflight(config_file, require_commit_binding=True)
    baseline = _o1c65.validate_apple8_baseline(root, config)
    validate_parent(root, config)
    potential = cast(Path, getattr(baseline, "potential"))
    cnf = cast(Path, getattr(baseline, "cnf"))
    frozen = _o1c65.build_frozen_grouping(potential, config)
    target = _public_target(baseline)
    source_commit = cast(str, preflight_row["source_commit"])
    source = _mapping(config["source"], "source")
    budgets = _mapping(config["budgets"], "budgets")
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    child_started = resource.getrusage(resource.RUSAGE_CHILDREN)

    with tempfile.TemporaryDirectory(prefix="o1c66-apple8-episodic-vault-") as raw:
        workspace = Path(raw)
        native_build = _native_v7.build_native_joint_score_sieve(
            source=_relative(root, source["native_source"], "native source"),
            output=workspace / "native-joint-score-sieve",
        )
        validate_native_build_identity(native_build)
        observed_sources = _source_hashes(root, config)
        if observed_sources != dict(
            _mapping(source["expected_sha256"], "source.expected_sha256")
        ):
            raise O1C66RunError("source identity changed after preflight")

        stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
        capsule_relative = Path("runs") / f"{stamp}_{CAPSULE_SUFFIX}"
        capsule = root / capsule_relative
        capsule.mkdir(parents=True, exist_ok=False)
        _atomic_bytes(capsule / "config.json", config_file.read_bytes())
        _atomic_json(capsule / "preflight.json", preflight_row)
        _atomic_json(capsule / "native_build.json", native_build.describe())
        grouping_path = capsule / "apple9-width6.grouping"
        grouping_report = _o1c65.materialize_grouping(grouping_path, frozen)
        _atomic_json(capsule / "grouping.json", grouping_report)
        _atomic_bytes(
            capsule / "command.txt",
            (
                "nice -n 10 env PYTHONPATH=src python3 -m "
                "o1_crypto_lab.o1c66_apple8_episodic_vault_run run --config "
                f"{config_file.relative_to(root).as_posix()}\n"
            ).encode(),
        )

        identity = frozen_vault_identity(frozen.field)
        observed_tuple = tuple(frozen.field.observed_variables)
        initial = ClauseVault(
            identity=identity, observed_variables=frozenset(observed_tuple)
        )
        shared_identity = _vault_v1.vault_identity_from_sources(
            cnf_sha256=APPLE8_CNF_SHA256,
            potential_sha256=APPLE8_POTENTIAL_SHA256,
            grouping_sha256=GROUPING_SHA256,
            observed_variables=observed_tuple,
            bound_rule=COMPATIBILITY_GROUPING_BOUND_RULE,
            threshold=THRESHOLD,
        )
        shared_initial = _vault_v1.empty_threshold_no_good_vault(
            identity=shared_identity,
            observed_variables=observed_tuple,
            caps=_vault_v1.O1C66_VAULT_CAPS,
        )
        intent_bindings = {
            "source_commit": source_commit,
            "config_sha256": sha256_file(config_file),
            "source_sha256": observed_sources,
            "native_source_sha256": native_build.source_sha256,
            "native_executable_sha256": native_build.executable_sha256,
            "native_executable_basename": native_build.executable.name,
            "native_result_schema": NATIVE_RESULT_SCHEMA,
            "native_vault_telemetry_schema": NATIVE_VAULT_TELEMETRY_SCHEMA,
            "adapter_sha256": observed_sources["joint_score_sieve_v8"],
            "vault_module_sha256": observed_sources["threshold_no_good_vault_v1"],
            "cnf_sha256": sha256_file(cnf),
            "potential_sha256": sha256_file(potential),
            "grouping_sha256": sha256_file(grouping_path),
            "grouping_width_cap": GROUPING_WIDTH_CAP,
            "grouping_serialized_bytes": grouping_path.stat().st_size,
            "observed_variables_sha256": identity.observed_variables_sha256,
            "bound_rule_sha256": BOUND_RULE_SHA256,
            "threshold_f64le_hex": struct.pack("<d", THRESHOLD).hex(),
            "seed": SEED,
            "cadical_options": (
                "plain,quiet=1,factor=0,lucky=0,walk=0,rephase=0,forcephase=1"
            ),
        }

        def invoke(ordinal: int, vault_path: Path) -> object:
            del ordinal
            return invoke_native_episode(
                executable=native_build.executable,
                cnf=cnf,
                potential=potential,
                grouping=grouping_path,
                vault_path=vault_path,
            )

        outcome = execute_episodic_protocol(
            capsule=capsule,
            initial_vault=initial,
            adapter_initial_vault=shared_initial,
            invoke_episode=invoke,
            verify_public_model=target.verify,
            intent_bindings=intent_bindings,
        )
        runtime = _runtime_resources(
            started=started, cpu_started=cpu_started, child_started=child_started
        )
        result = _result_from_outcome(
            capsule_relative=capsule_relative,
            source_commit=source_commit,
            preflight_row=preflight_row,
            outcome=outcome,
            runtime=runtime,
            started_at=started_at,
        )
        try:
            finalize_capsule(
                capsule=capsule,
                authoritative_result=authoritative,
                result=result,
                maximum_persistent_bytes=cast(
                    int, budgets["maximum_persistent_artifact_bytes"]
                ),
            )
            return result
        except Exception as exc:
            # Every native call already has an immutable intent and completed
            # sidecars.  Publication recovery may replace only the summary; it
            # never invokes another episode or adopts incomplete output.
            failure = {
                "classification": OPERATIONAL_TERMINAL,
                "publication_recovered_from_completed_sidecars": True,
                "native_calls_consumed": outcome.totals["native_solver_calls"],
                "retry_authorized": False,
                "error_type": type(exc).__qualname__,
                "error_message": str(exc),
                "exception_chain_outer_to_cause_or_context": _exception_chain(exc),
                "truth_key_bytes_read": False,
            }
            recovered = dict(result)
            recovered["classification"] = OPERATIONAL_TERMINAL
            recovered["stop_reason"] = "publication-recovery"
            recovered["operational_failure"] = failure
            recovered["recorded_at"] = (
                datetime.now().astimezone().isoformat(timespec="seconds")
            )
            finalize_capsule(
                capsule=capsule,
                authoritative_result=authoritative,
                result=recovered,
                maximum_persistent_bytes=cast(
                    int, budgets["maximum_persistent_artifact_bytes"]
                ),
            )
            return recovered


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Preflight or run the frozen O1C-0066 APPLE8 episodic vault"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("preflight", "run"):
        child = subparsers.add_parser(command)
        child.add_argument(
            "--config",
            default="configs/o1c66_apple8_episodic_vault_v1.json",
        )
    smoke = subparsers.add_parser("geometry-smoke")
    smoke.add_argument("--output", required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "geometry-smoke":
            result = run_target_free_geometry_smoke(args.output)
        elif args.command == "preflight":
            result = preflight(args.config)
        else:
            result = run(args.config)
    except O1C66RunError as exc:
        print(f"{ATTEMPT_ID}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
