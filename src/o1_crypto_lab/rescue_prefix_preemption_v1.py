"""Canonical once-only rescue-prefix preemption plans.

The plan binary is deliberately just the ordered signed-i32le literals.  Its
identity is therefore the already-predeclared prefix identity, while source,
active-vault, inherited-plan, and baseline-trace provenance stay separately
cross-bound by preparation and execution manifests.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence, cast

from .threshold_no_good_vault_v1 import ThresholdNoGoodVault


RESCUE_PREFIX_PREEMPTION_PLAN_SCHEMA = "o1-rescue-prefix-preemption-plan-v1"
RESCUE_PREFIX_PREEMPTION_PLAN_VERSION = 1
RESCUE_PREFIX_PREEMPTION_PREFIX_ENCODING = "signed-i32le"
RESCUE_PREFIX_PREEMPTION_ASSIGNMENT_ENCODING = "observed-ascending-i8-sign"
RESCUE_PREFIX_PREEMPTION_SOURCE_STATE_SCHEMA = (
    "o1-256-cadical-joint-score-sieve-grouped-state-v2"
)
RESCUE_PREFIX_PREEMPTION_MAXIMUM_SERIALIZED_BYTES = 16_384
RESCUE_PREFIX_PREEMPTION_MAXIMUM_PREFIX_ROWS = (
    RESCUE_PREFIX_PREEMPTION_MAXIMUM_SERIALIZED_BYTES // 4
)
RESCUE_PREFIX_PREEMPTION_MAXIMUM_SOURCE_RESULT_BYTES = 16_777_216
RESCUE_PREFIX_PREEMPTION_MAXIMUM_ASSIGNMENTS = 1_600_000

O1C78_SOURCE_RESULT_SHA256 = (
    "8980046510cd80417260436d73fdbe3cb24da6d233e136aff616972f92aadfd0"
)
O1C78_SOURCE_ASSIGNMENT_SHA256 = (
    "2d26cfd7d2cba61bd49d116a6cb64c35a8fabbacdb4244a431703ef1a562e6bc"
)
O1C78_ACTIVE_VAULT_SHA256 = (
    "07c73013705898e228a05b0578b0f8090a6f094c427dbd8f32d856467b08e208"
)
O1C78_PARENT_STAGING_PLAN_SHA256 = (
    "ecbca2bd3ab2e5196d4cae76a968c7957909ada49e4d225d28841a4c21d2e023"
)
O1C78_BASELINE_TRACE_SHA256 = (
    "706ad4fa13a8a47cd81f99bc693c1bede46612112214e6f77dc52ee61d32bf15"
)
O1C78_PREFIX_LITERALS = (
    130,
    -131,
    31_874,
    63_746,
    190_565,
    190_566,
    190_569,
    191_212,
    191_213,
    191_216,
    191_234,
)
O1C78_PREFIX_ORDER_SHA256 = (
    "b5debc5f55f7cbc1e728d00ce1d14d0c437249793f8c10e8b80e614a00ed155c"
)

_INT32_MIN = -(1 << 31)
_INT32_MAX = (1 << 31) - 1


class RescuePrefixPreemptionError(ValueError):
    """A prefix plan, evidence source, or external binding differs."""


def _sha256(value: object, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RescuePrefixPreemptionError(
            f"rescue prefix preemption {field_name} differs"
        )
    return value


def _prefix_tuple(value: object) -> tuple[int, ...]:
    if (
        not isinstance(value, tuple)
        or not 1 <= len(value) <= RESCUE_PREFIX_PREEMPTION_MAXIMUM_PREFIX_ROWS
    ):
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption prefix population differs"
        )
    seen: set[int] = set()
    result: list[int] = []
    for literal in value:
        if (
            isinstance(literal, bool)
            or not isinstance(literal, int)
            or literal in (0, _INT32_MIN)
            or not _INT32_MIN < literal <= _INT32_MAX
            or abs(literal) in seen
        ):
            raise RescuePrefixPreemptionError(
                "rescue prefix preemption prefix literal differs"
            )
        seen.add(abs(literal))
        result.append(literal)
    return tuple(result)


def rescue_prefix_order_bytes(literals: Sequence[int]) -> bytes:
    """Return the canonical signed-i32le plan bytes for ``literals``."""

    if isinstance(literals, (str, bytes, bytearray)):
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption prefix population differs"
        )
    try:
        prefix = _prefix_tuple(tuple(literals))
    except TypeError as exc:
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption prefix population differs"
        ) from exc
    return b"".join(struct.pack("<i", literal) for literal in prefix)


def rescue_prefix_order_sha256(literals: Sequence[int]) -> str:
    """Return the SHA-256 identity of one canonical prefix plan."""

    return hashlib.sha256(rescue_prefix_order_bytes(literals)).hexdigest()


@dataclass(frozen=True)
class RescuePrefixPreemptionPlan:
    """An immutable, duplicate-free once-only literal prefix."""

    prefix_literals: tuple[int, ...]

    def __post_init__(self) -> None:
        prefix = _prefix_tuple(self.prefix_literals)
        if prefix != self.prefix_literals:
            raise RescuePrefixPreemptionError(
                "rescue prefix preemption prefix literals differ"
            )

    @property
    def serialized(self) -> bytes:
        return serialize_rescue_prefix_preemption_plan(self)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.serialized).hexdigest()

    @property
    def serialized_bytes(self) -> int:
        return len(self.serialized)

    @property
    def prefix_order_bytes(self) -> bytes:
        return self.serialized

    @property
    def prefix_order_sha256(self) -> str:
        return self.sha256

    def describe(self) -> dict[str, object]:
        return {
            "schema": RESCUE_PREFIX_PREEMPTION_PLAN_SCHEMA,
            "version": RESCUE_PREFIX_PREEMPTION_PLAN_VERSION,
            "sha256": self.sha256,
            "serialized_bytes": self.serialized_bytes,
            "prefix_order_encoding": RESCUE_PREFIX_PREEMPTION_PREFIX_ENCODING,
            "prefix_order_sha256": self.prefix_order_sha256,
            "prefix_literals": list(self.prefix_literals),
        }


def _source_mapping_and_hash(
    source_result: Mapping[str, object] | bytes,
    source_result_sha256: str | None,
) -> tuple[Mapping[str, object], str]:
    if isinstance(source_result, bytes):
        if len(source_result) > RESCUE_PREFIX_PREEMPTION_MAXIMUM_SOURCE_RESULT_BYTES:
            raise RescuePrefixPreemptionError(
                "rescue prefix preemption source result is too large"
            )
        digest = hashlib.sha256(source_result).hexdigest()
        if source_result_sha256 is not None and source_result_sha256 != digest:
            raise RescuePrefixPreemptionError(
                "rescue prefix preemption source result hash differs"
            )
        try:
            decoded = json.loads(source_result)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise RescuePrefixPreemptionError(
                "rescue prefix preemption source result JSON differs"
            ) from exc
        if not isinstance(decoded, Mapping) or not all(
            isinstance(key, str) for key in decoded
        ):
            raise RescuePrefixPreemptionError(
                "rescue prefix preemption source result differs"
            )
        return cast(Mapping[str, object], decoded), digest
    if not isinstance(source_result, Mapping) or not all(
        isinstance(key, str) for key in source_result
    ):
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption source result differs"
        )
    expected = _sha256(source_result_sha256, "source result hash")
    try:
        canonical = json.dumps(
            source_result,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption source result canonicalization differs"
        ) from exc
    if (
        len(canonical) > RESCUE_PREFIX_PREEMPTION_MAXIMUM_SOURCE_RESULT_BYTES
        or hashlib.sha256(canonical).hexdigest() != expected
    ):
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption source result hash differs"
        )
    return source_result, expected


def _source_assignment(
    source_result: Mapping[str, object], observed_count: int
) -> tuple[tuple[int, ...], str]:
    if not 0 < observed_count <= RESCUE_PREFIX_PREEMPTION_MAXIMUM_ASSIGNMENTS:
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption observed population differs"
        )
    sieve = source_result.get("sieve")
    state = sieve.get("state") if isinstance(sieve, Mapping) else None
    if not isinstance(state, Mapping):
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption source state differs"
        )
    encoding = state.get("encoding")
    assignment_hex = state.get("assignment_hex")
    if (
        state.get("schema") != RESCUE_PREFIX_PREEMPTION_SOURCE_STATE_SCHEMA
        or not isinstance(encoding, str)
        or encoding.split(";", 1)[0]
        != RESCUE_PREFIX_PREEMPTION_ASSIGNMENT_ENCODING
        or not isinstance(assignment_hex, str)
        or len(assignment_hex) % 2
    ):
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption source assignment differs"
        )
    try:
        payload = bytes.fromhex(assignment_hex)
    except ValueError as exc:
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption source assignment differs"
        ) from exc
    digest = _sha256(state.get("assignment_sha256"), "source assignment hash")
    if (
        len(payload) != observed_count
        or state.get("assignment_bytes") != len(payload)
        or hashlib.sha256(payload).hexdigest() != digest
        or any(byte not in (0, 1, 255) for byte in payload)
    ):
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption source assignment differs"
        )
    signs = tuple(-1 if byte == 255 else byte for byte in payload)
    if state.get("current_assigned_variables") != sum(sign != 0 for sign in signs):
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption assigned-variable count differs"
        )
    return signs, digest


def derive_rescue_prefix_preemption_plan(
    *,
    prefix_literals: Sequence[int],
    source_result: Mapping[str, object] | bytes | None = None,
    active_vault: ThresholdNoGoodVault | None = None,
    parent_staging_plan_sha256: str | None = None,
    baseline_trace_sha256: str | None = None,
    source_result_sha256: str | None = None,
) -> RescuePrefixPreemptionPlan:
    """Build a plan, optionally validating all external evidence bindings."""

    plan = RescuePrefixPreemptionPlan(_prefix_tuple(tuple(prefix_literals)))
    evidence_values = (
        source_result,
        active_vault,
        parent_staging_plan_sha256,
        baseline_trace_sha256,
    )
    if any(value is not None for value in evidence_values):
        if any(value is None for value in evidence_values):
            raise RescuePrefixPreemptionError(
                "rescue prefix preemption evidence inputs differ"
            )
        validate_rescue_prefix_preemption_evidence(
            plan,
            source_result=cast(Mapping[str, object] | bytes, source_result),
            source_result_sha256=source_result_sha256,
            active_vault=cast(ThresholdNoGoodVault, active_vault),
            parent_staging_plan_sha256=cast(str, parent_staging_plan_sha256),
            baseline_trace_sha256=cast(str, baseline_trace_sha256),
        )
    elif source_result_sha256 is not None:
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption source result binding differs"
        )
    return plan


def recompute_rescue_prefix_preemption_plan(
    *,
    prefix_literals: Sequence[int],
    source_result: Mapping[str, object] | bytes | None = None,
    active_vault: ThresholdNoGoodVault | None = None,
    parent_staging_plan_sha256: str | None = None,
    baseline_trace_sha256: str | None = None,
    source_result_sha256: str | None = None,
) -> RescuePrefixPreemptionPlan:
    """Recompute a plan from the same explicit builder inputs."""

    return derive_rescue_prefix_preemption_plan(
        prefix_literals=prefix_literals,
        source_result=source_result,
        active_vault=active_vault,
        parent_staging_plan_sha256=parent_staging_plan_sha256,
        baseline_trace_sha256=baseline_trace_sha256,
        source_result_sha256=source_result_sha256,
    )


def validate_rescue_prefix_preemption_plan(
    plan: RescuePrefixPreemptionPlan,
    *,
    active_vault: ThresholdNoGoodVault | None = None,
    parent_staging_plan_sha256: str | None = None,
    baseline_trace_sha256: str | None = None,
    required_prefix_literals: Sequence[int] | None = None,
    source_result_sha256: str | None = None,
) -> RescuePrefixPreemptionPlan:
    """Validate plan shape and optional independently sealed bindings."""

    if not isinstance(plan, RescuePrefixPreemptionPlan):
        raise RescuePrefixPreemptionError("rescue prefix preemption plan differs")
    if active_vault is not None:
        if not isinstance(active_vault, ThresholdNoGoodVault):
            raise RescuePrefixPreemptionError(
                "rescue prefix preemption active vault differs"
            )
        observed = set(active_vault.observed_variables)
        if any(abs(literal) not in observed for literal in plan.prefix_literals):
            raise RescuePrefixPreemptionError(
                "rescue prefix preemption prefix variable is unobserved"
            )
    for value, name in (
        (parent_staging_plan_sha256, "parent staging plan hash"),
        (baseline_trace_sha256, "baseline trace hash"),
        (source_result_sha256, "source result hash"),
    ):
        if value is not None:
            _sha256(value, name)
    if required_prefix_literals is not None and plan.prefix_literals != _prefix_tuple(
        tuple(required_prefix_literals)
    ):
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption required prefix differs"
        )
    return plan


def validate_rescue_prefix_preemption_evidence(
    plan: RescuePrefixPreemptionPlan,
    *,
    source_result: Mapping[str, object] | bytes,
    active_vault: ThresholdNoGoodVault,
    parent_staging_plan_sha256: str,
    baseline_trace_sha256: str,
    source_result_sha256: str | None = None,
) -> RescuePrefixPreemptionPlan:
    """Validate source state plus separately sealed successor bindings."""

    validate_rescue_prefix_preemption_plan(
        plan,
        active_vault=active_vault,
        parent_staging_plan_sha256=parent_staging_plan_sha256,
        baseline_trace_sha256=baseline_trace_sha256,
        source_result_sha256=source_result_sha256,
    )
    source, source_digest = _source_mapping_and_hash(
        source_result, source_result_sha256
    )
    sieve = source.get("sieve")
    if (
        not isinstance(sieve, Mapping)
        or _sha256(sieve.get("trace_sha256"), "source trace hash")
        != baseline_trace_sha256
    ):
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption source trace binding differs"
        )
    _, assignment_digest = _source_assignment(
        source, len(active_vault.observed_variables)
    )
    # Computing these digests is itself the source-state integrity check.  The
    # manifest-facing recomputation helper returns both values below.
    _sha256(source_digest, "source result hash")
    _sha256(assignment_digest, "source assignment hash")
    return plan


def recompute_rescue_prefix_preemption_evidence(
    *,
    plan: RescuePrefixPreemptionPlan,
    source_result: Mapping[str, object] | bytes,
    active_vault: ThresholdNoGoodVault,
    parent_staging_plan_sha256: str,
    baseline_trace_sha256: str,
    source_result_sha256: str | None = None,
) -> dict[str, object]:
    """Return canonical manifest evidence after full independent validation."""

    validate_rescue_prefix_preemption_evidence(
        plan,
        source_result=source_result,
        source_result_sha256=source_result_sha256,
        active_vault=active_vault,
        parent_staging_plan_sha256=parent_staging_plan_sha256,
        baseline_trace_sha256=baseline_trace_sha256,
    )
    source, source_digest = _source_mapping_and_hash(
        source_result, source_result_sha256
    )
    _, assignment_digest = _source_assignment(
        source, len(active_vault.observed_variables)
    )
    return {
        **plan.describe(),
        "source_result_sha256": source_digest,
        "source_assignment_sha256": assignment_digest,
        "active_vault_sha256": active_vault.sha256,
        "parent_staging_plan_sha256": parent_staging_plan_sha256,
        "baseline_trace_sha256": baseline_trace_sha256,
    }


def validate_o1c78_production_plan(plan: RescuePrefixPreemptionPlan) -> None:
    """Apply the frozen O1C-0078 prefix identity seal."""

    if (
        not isinstance(plan, RescuePrefixPreemptionPlan)
        or plan.prefix_literals != O1C78_PREFIX_LITERALS
        or plan.sha256 != O1C78_PREFIX_ORDER_SHA256
        or plan.serialized_bytes != 44
    ):
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption O1C78 production identity differs"
        )


def serialize_rescue_prefix_preemption_plan(
    plan: RescuePrefixPreemptionPlan,
) -> bytes:
    """Return the raw canonical signed-i32le prefix plan."""

    if not isinstance(plan, RescuePrefixPreemptionPlan):
        raise RescuePrefixPreemptionError("rescue prefix preemption plan differs")
    return rescue_prefix_order_bytes(plan.prefix_literals)


def parse_rescue_prefix_preemption_plan(
    payload: bytes,
    *,
    active_vault: ThresholdNoGoodVault | None = None,
) -> RescuePrefixPreemptionPlan:
    """Parse a bounded canonical raw signed-i32le prefix plan."""

    if (
        not isinstance(payload, bytes)
        or not payload
        or len(payload) % 4
        or len(payload) > RESCUE_PREFIX_PREEMPTION_MAXIMUM_SERIALIZED_BYTES
    ):
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption binary size differs"
        )
    prefix = tuple(
        struct.unpack_from("<i", payload, offset)[0]
        for offset in range(0, len(payload), 4)
    )
    plan = RescuePrefixPreemptionPlan(prefix)
    if plan.serialized != payload:
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption binary is not canonical"
        )
    return validate_rescue_prefix_preemption_plan(plan, active_vault=active_vault)


def _read_regular_file(path: str | Path) -> tuple[Path, bytes]:
    candidate = Path(path)
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption plan is unreadable"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption plan is not a regular file"
        )
    if metadata.st_size > RESCUE_PREFIX_PREEMPTION_MAXIMUM_SERIALIZED_BYTES:
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption plan exceeds cap"
        )
    try:
        payload = candidate.read_bytes()
    except OSError as exc:
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption plan is unreadable"
        ) from exc
    if len(payload) != metadata.st_size:
        raise RescuePrefixPreemptionError(
            "rescue prefix preemption plan changed while reading"
        )
    return candidate, payload


def read_rescue_prefix_preemption_plan(
    path: str | Path,
    *,
    active_vault: ThresholdNoGoodVault | None = None,
) -> RescuePrefixPreemptionPlan:
    """Read one bounded regular prefix-plan file."""

    _, payload = _read_regular_file(path)
    return parse_rescue_prefix_preemption_plan(payload, active_vault=active_vault)


def write_rescue_prefix_preemption_plan(
    path: str | Path, plan: RescuePrefixPreemptionPlan
) -> None:
    """Atomically write one canonical plan without following links."""

    destination = Path(path)
    payload = serialize_rescue_prefix_preemption_plan(plan)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


__all__ = [
    "O1C78_ACTIVE_VAULT_SHA256",
    "O1C78_BASELINE_TRACE_SHA256",
    "O1C78_PARENT_STAGING_PLAN_SHA256",
    "O1C78_PREFIX_LITERALS",
    "O1C78_PREFIX_ORDER_SHA256",
    "O1C78_SOURCE_ASSIGNMENT_SHA256",
    "O1C78_SOURCE_RESULT_SHA256",
    "RESCUE_PREFIX_PREEMPTION_ASSIGNMENT_ENCODING",
    "RESCUE_PREFIX_PREEMPTION_MAXIMUM_ASSIGNMENTS",
    "RESCUE_PREFIX_PREEMPTION_MAXIMUM_PREFIX_ROWS",
    "RESCUE_PREFIX_PREEMPTION_MAXIMUM_SERIALIZED_BYTES",
    "RESCUE_PREFIX_PREEMPTION_MAXIMUM_SOURCE_RESULT_BYTES",
    "RESCUE_PREFIX_PREEMPTION_PLAN_SCHEMA",
    "RESCUE_PREFIX_PREEMPTION_PLAN_VERSION",
    "RESCUE_PREFIX_PREEMPTION_PREFIX_ENCODING",
    "RescuePrefixPreemptionError",
    "RescuePrefixPreemptionPlan",
    "derive_rescue_prefix_preemption_plan",
    "parse_rescue_prefix_preemption_plan",
    "read_rescue_prefix_preemption_plan",
    "recompute_rescue_prefix_preemption_evidence",
    "recompute_rescue_prefix_preemption_plan",
    "rescue_prefix_order_bytes",
    "rescue_prefix_order_sha256",
    "serialize_rescue_prefix_preemption_plan",
    "validate_o1c78_production_plan",
    "validate_rescue_prefix_preemption_evidence",
    "validate_rescue_prefix_preemption_plan",
    "write_rescue_prefix_preemption_plan",
]
