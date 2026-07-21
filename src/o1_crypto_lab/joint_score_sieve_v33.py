"""Fail-closed O1C-0103 adapter for composed Page 19 and its live bank.

Version 33 preserves v32's proof-mining and result-validation semantics while
moving the native boundary to result/source v30 and fresh lineage-32 Page 19.
The adapter accepts only a prebuilt executable whose byte count and SHA-256 are
supplied by the caller; it performs exactly one native launch and never builds
or smoke-runs an executable itself.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
import subprocess
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping, Sequence, cast

from . import joint_score_sieve_v9 as _v9
from . import joint_score_sieve_v21 as _v21
from . import joint_score_sieve_v22 as _v22
from . import o1c102_page19_causal_rollover_prepare as _o1c102
from .criticality_potential import CriticalityPotentialField
from .o1_relational_search import O1RelationalSearchError
from .o1c82_parent_centered_seed import (
    BANK_BYTES,
    COORDINATE_COUNT,
    ELIGIBILITY_MINIMUM_COUNT,
    MISSING_VARIABLE,
    RECORD_BYTES,
    RECORD_STRUCT,
)
from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultError,
    VaultCaps,
    parse_threshold_no_good_vault,
    validate_threshold_no_good_vault_identity,
    vault_identity_from_sources,
)


JOINT_SCORE_SIEVE_ADAPTER_SCHEMA = "o1-256-joint-score-sieve-v33-adapter-v1"
JOINT_SCORE_SIEVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v30"
JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA = (
    "o1-256-cadical-joint-score-sieve-result-v6"
)
PRIORITY_STATE_SCHEMA = (
    "o1-256-o1c103-live-parent-centered-continuation-priority-state-v1"
)
PRIORITY_ACTION_SCHEMA = "o1-256-o1c103-failure-first-proof-mining-actions-v1"
PRIORITY_SEED_SCHEMA = "o1-256-o1c82-parent-centered-priority-seed-v1"
PRIORITY_SEED_MAGIC = "O1C82-PCP-SEED1"
PRIORITY_SEED_SOURCE = "sealed-live-continuation-bank"
OWNERSHIP_SCHEMA = "o1-256-bounded-decision-ownership-v3"
OWNERSHIP_LIFECYCLE = (
    "PROPOSED->LEVEL_BOUND->optional-CONFIRMED->"
    "RELEASED-or-LEVEL_BOUND_UNOBSERVED_RELEASE"
)
OWNERSHIP_EVENT_RETENTION = (
    "state-bearing-lifecycle-only;nonclaim-observations-counted-and-sha256-committed"
)
OWNERSHIP_ELIGIBILITY_RULE = (
    "origin-row-level-token;never-returned-ever-plus-variable-sign"
)
OWNERSHIP_ASSIGNMENT_RULE = (
    "confirmation-is-evidence-not-release-precondition;"
    "opposite-and-foreign-never-claim-token"
)
OWNERSHIP_ORIGINS = (
    "PREFIX",
    "RANK_ORIGINAL",
    "RANK_CONTRAST",
    "FRONTIER_INITIAL",
    "FRONTIER_CONTRAST",
    "BOUND_LOSING_CHILD",
)
OWNERSHIP_LIFECYCLE_KINDS = {
    "PROPOSED",
    "LEVEL_BOUND",
    "CONFIRMED",
    "RELEASED",
    "LEVEL_BOUND_UNOBSERVED_RELEASE",
}
NONCLAIM_DIGEST_ENCODING = "o1c101-nonclaim-canonical-le-v1"
NONCLAIM_DIGEST_RECORD_BYTES = 42
NONCLAIM_DIGEST_LAYOUT = (
    "sequence:u64le,kind:u8,token:u64le,callback:u64le,origin:u8,"
    "row:u32le,literal:i32le,level:u32le,observed_literal:i32le"
)

OPERATOR_SEMANTICS = _v22.OPERATOR_SEMANTICS
PRODUCTION_CANDIDATES = _v22.PRODUCTION_CANDIDATES
PROBE_TRACE_RECORD_BYTES = _v22.PROBE_TRACE_RECORD_BYTES
ACTION_TRACE_RECORD_BYTES = _v22.ACTION_TRACE_RECORD_BYTES

LIVE_BANK_SHA256 = "a8e137b1546076f32902acbb97163ae419ad45e61c4b311a3d8c9c941ba58f01"
LIVE_BANK_TOTAL_COUNT = 349_534
LIVE_BANK_MAXIMUM_COUNT = 3_167
LIVE_BANK_MINIMUM_NONZERO_COUNT = 233
LIVE_BANK_ELIGIBLE_COORDINATES = 255

O1C102_MANIFEST_SCHEMA = _o1c102.PREPARATION_SCHEMA
O1C102_MANIFEST_BYTES = _o1c102.PREPARATION_MANIFEST_BYTES
O1C102_MANIFEST_SHA256 = _o1c102.PREPARATION_MANIFEST_SHA256
O1C102_MANIFEST_ARTIFACTS = frozenset(
    {
        _o1c102.NEW_CHUNK_NAME,
        _o1c102.ACTIVE_PROJECTION_NAME,
        _o1c102.RESIDENCY_NAME,
        _o1c102.ACTIVATION_LEDGER_NAME,
        _o1c102.OCCURRENCES_NAME,
        _o1c102.RELATIONS_NAME,
        _o1c102.COMMON_CORE_AUDIT_NAME,
        _o1c102.FINAL_BANK_NAME,
        _o1c102.PRIORITY_RECEIPT_NAME,
        _o1c102.DERIVED_RECEIPT_NAME,
        _o1c102.DERIVED_CLOSURE_NAME,
        _o1c102.DERIVED_OVERLAY_NAME,
    }
)
O1C102_PUBLISHED_ARTIFACTS = O1C102_MANIFEST_ARTIFACTS | {
    _o1c102.PREPARATION_MANIFEST_NAME
}
O1C102_BUNDLE_RELATIVE = Path(
    "research/o1c102_page19_causal_rollover_seed_20260721"
)
O1C102_MANIFEST_RELATIVE = O1C102_BUNDLE_RELATIVE / _o1c102.PREPARATION_MANIFEST_NAME
O1C102_PAGE19_RELATIVE = O1C102_BUNDLE_RELATIVE / _o1c102.ACTIVE_PROJECTION_NAME

O1C101_PRIORITY_RECEIPT_SCHEMA = PRIORITY_STATE_SCHEMA.replace("o1c103", "o1c101")
O1C101_PRIORITY_RECEIPT_BYTES = _o1c102.PRIORITY_RECEIPT_BYTES
O1C101_PRIORITY_RECEIPT_SHA256 = _o1c102.PRIORITY_RECEIPT_SHA256
O1C102_DERIVED_RECEIPT_SCHEMA = _o1c102.DERIVED_RECEIPT_SCHEMA
O1C102_DERIVED_RECEIPT_BYTES = _o1c102.DERIVED_RECEIPT_BYTES
O1C102_DERIVED_RECEIPT_SHA256 = _o1c102.DERIVED_RECEIPT_SHA256
PRODUCTION_PAGE19_BYTES = _o1c102.PAGE19_SERIALIZED_BYTES
PRODUCTION_PAGE19_SHA256 = _o1c102.PAGE19_SHA256
PRODUCTION_PAGE19_LINEAGE_ORDINAL = _o1c102.PAGE19_LINEAGE_ORDINAL
PRODUCTION_PAGE19_ACTIVE_LIMIT = _o1c102.PAGE19_ACTIVE_LIMIT
PRODUCTION_PAGE19_CLAUSE_COUNT = _o1c102.PAGE19_CLAUSE_COUNT
PRODUCTION_PAGE19_LITERAL_COUNT = _o1c102.PAGE19_LITERAL_COUNT
PRODUCTION_PAGE19_CATEGORY_COUNTS: Mapping[str, int] = _o1c102.PAGE19_CATEGORY_COUNTS
PRODUCTION_PAGE19_HEADROOM: Mapping[str, int] = _o1c102.PAGE19_HEADROOM
GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT = _o1c102.LOGICAL_KNOWN_CLAUSE_COUNT

BURNED_PAGE18_BYTES = 2_680_827
BURNED_PAGE18_SHA256 = (
    "5d89bbe07c8b988b4f1ce5dc2a31b860ab59192d3efc02854e27b8f779de417c"
)

BURNED_PAGE17_BYTES = 2_773_919
BURNED_PAGE17_SHA256 = (
    "0c25ce470df0945fb05914bab107ecea05531166575ec88ebf7d15bb9a22fbfd"
)
BURNED_PAGE16_BYTES = 2_831_459
BURNED_PAGE16_SHA256 = (
    "fb3b56690ec4f50d699c2598dd4fa752376d1609d1e242ee8aa987694cdc48f5"
)

BURNED_PAGE15_BYTES = 2_843_047
BURNED_PAGE15_SHA256 = (
    "71f4b544fd74c7979386bf607d82902dc03c4fe1485404fe8fb7111e970ecfe2"
)
BURNED_PAGE14_BYTES = 2_817_779
BURNED_PAGE14_SHA256 = (
    "00a5a4a7b33f1c09c8df24162709b17994bad5825d92476a5f5283a3bf025c7e"
)
BURNED_PAGE13_BYTES = 2_846_623
BURNED_PAGE13_SHA256 = (
    "4c1b7d5a6d40fad9439d95433bcc7a60ff3e7ddc0e4542b0cf003cdf4581e546"
)
BURNED_PAGE12_BYTES = 2_725_423
BURNED_PAGE12_SHA256 = (
    "44205f81322d526c1cf7b7c96f28a3baf02b6b9bcb08a04f0bab2e66651fa660"
)
BURNED_PAGE11_BYTES = 2_876_731
BURNED_PAGE11_SHA256 = (
    "9853f06bc882bfbb6312207bc8c20e0e9ca1500e49aad14594f6d7c66b62a04d"
)
BURNED_PAGE10_BYTES = 2_874_387
BURNED_PAGE10_SHA256 = (
    "bf1fd3e3938bc4125e672ee94ee599e5f21881b4fc87e2bc81e8fc57fc4d3556"
)
BURNED_PAGE9_BYTES = 2_885_959
BURNED_PAGE9_SHA256 = "8c3b8cc33badd4aa23920caabc5ea3fc5006675d93805578b74b2b20788c8204"

PRIOR_LIVE_BANK_SHA256 = frozenset(
    {
        "8100bccf7e463c11b41d97a07017202c5e7ffc37763a76d38114c3044f9fa2fc",
        "715bfbc22fa2162ec8546eed21cf609318d3c5be806092dc4fe4b07cc4d9d654",
        "0203de9f1732b095bf30062cb8a07b018ded829ee99f18ffbca715c653c0cc6a",
        "658fd2856b83d1a0ff8d28e92a604c99b3843a49a589811bf9b61845959ec31f",
        "2c0c4ccba476bc642778b68234cc497c1776d144092ea9f1aead367559f59b07",
        "05b8acf3ecd5423016e5d7ef7d649f790e758e3477a943fe7306280064a4c630",
        "97a325c91b9a853a094fcc8b7fd9fafdafe6b5ec4022952e1a86af068c834fca",
    }
)

NATIVE_SOURCE_RELATIVE = Path("native/cadical_o1_joint_score_sieve_v30.cpp")
NATIVE_SOURCE_BYTES = 52_390
NATIVE_SOURCE_SHA256 = (
    "65bbc6758e2c2cdac876d0de07129712c7186f3c705e0d6fb1d2c25925e5020f"
)
O1C102_LIVE_BANK_RELATIVE = O1C102_BUNDLE_RELATIVE / _o1c102.FINAL_BANK_NAME
O1C101_PRIORITY_RECEIPT_RELATIVE = (
    O1C102_BUNDLE_RELATIVE / _o1c102.PRIORITY_RECEIPT_NAME
)
O1C102_DERIVED_RECEIPT_RELATIVE = (
    O1C102_BUNDLE_RELATIVE / _o1c102.DERIVED_RECEIPT_NAME
)

_SEED_FIELDS = {
    "magic",
    "schema",
    "payload_bytes",
    "payload_sha256",
    "production_seal_enforced",
    "expected_production_sha256",
    "source_priority_state_receipt_sha256",
    "source_priority_state_receipt_bytes",
    "source_preparation_manifest_sha256",
    "source_preparation_manifest_bytes",
    "source_derived_resolution_receipt_sha256",
    "source_derived_resolution_receipt_bytes",
    "import_roundtrip_exact",
    "initial_eligible_coordinate_count",
    "seed_source",
    "live_continuation_bank_identity",
    "fresh_seed_parser_used",
}


class JointScoreSieveV33Error(O1RelationalSearchError):
    """Native-v30 execution or continuation validation failed."""


@dataclass(frozen=True)
class LiveBankRecord:
    """One decoded live 96-byte accumulator record."""

    variable: int
    count: int
    raw_mean: float
    raw_m2: float
    raw_positive_count: int
    raw_zero_count: int
    centered_mean: float
    centered_m2: float
    centered_positive_count: int
    centered_zero_count: int
    robust_z_mean: float
    robust_abs_z_mean: float
    robust_abs_z_max: float


@dataclass(frozen=True)
class JointScoreSieveV33Result:
    """Typed native-v30 result and its validated evolved bank."""

    status: int
    conflict_limit: int
    threshold: float
    key_model: bytes | None
    stats: Mapping[str, int]
    resources: Mapping[str, int]
    base_result: _v9.JointScoreSieveV9Result
    priority_seed: Mapping[str, object]
    priority_state: Mapping[str, object]
    priority_actions: Mapping[str, object]
    decision_ownership: Mapping[str, object]
    next_priority_seed: bytes
    normalized_summary: Mapping[str, object]
    raw: Mapping[str, object]
    native_stdout: str | None = None
    native_stdout_sha256: str | None = None
    command: tuple[str, ...] = ()

    @property
    def status_name(self) -> str:
        return {0: "UNKNOWN", 10: "SAT", 20: "UNSAT"}[self.status]


@dataclass(frozen=True)
class _SealedPrelaunch:
    source_path: Path
    source_bytes: bytes
    executable_path: Path
    executable_bytes: bytes
    manifest_path: Path
    manifest_bytes: bytes
    receipt_path: Path
    receipt_bytes: bytes
    derived_receipt_path: Path
    derived_receipt_bytes: bytes
    bank_path: Path
    bank_bytes: bytes
    bank_records: tuple[LiveBankRecord, ...]
    page19_path: Path
    page19_bytes: bytes


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _error(field: str) -> JointScoreSieveV33Error:
    return JointScoreSieveV33Error(f"joint-score-sieve-v33 {field} differs")


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise _error(field)
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise _error(field)
    return cast(Sequence[object], value)


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise _error(field)
    return value


def _literal_i32(value: object, field: str, *, zero: bool = False) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < -(1 << 31)
        or value > (1 << 31) - 1
        or value == -(1 << 31)
        or (not zero and value == 0)
    ):
        raise _error(field)
    return value


def _nonnegative(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _error(field)
    return value


def _positive(value: object, field: str) -> int:
    result = _nonnegative(value, field)
    if result == 0:
        raise _error(field)
    return result


def _finite(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _error(field)
    result = float(value)
    if not math.isfinite(result):
        raise _error(field)
    return result


def _sha(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise _error(field)
    return value


def _same_f64(left: object, right: float, field: str) -> float:
    value = _finite(left, field)
    if struct.pack("<d", value) != struct.pack("<d", right):
        raise _error(field)
    return value


def _decode_live_bank(
    payload: bytes,
    *,
    expected_sha256: str | None,
    sealed_input: bool,
) -> tuple[LiveBankRecord, ...]:
    """Decode the live layout without imposing the original 74-parent cap."""

    if not isinstance(payload, bytes) or len(payload) != BANK_BYTES:
        raise _error("live bank byte count")
    digest = hashlib.sha256(payload).hexdigest()
    if digest in PRIOR_LIVE_BANK_SHA256:
        raise _error("prior live bank rejection")
    if expected_sha256 is not None and digest != _sha(
        expected_sha256, "live bank expected digest"
    ):
        raise _error("live bank digest")
    records: list[LiveBankRecord] = []
    for variable in range(1, COORDINATE_COUNT + 1):
        offset = (variable - 1) * RECORD_BYTES
        values = RECORD_STRUCT.unpack_from(payload, offset)
        record = LiveBankRecord(variable, *values)
        floats = (
            record.raw_mean,
            record.raw_m2,
            record.centered_mean,
            record.centered_m2,
            record.robust_z_mean,
            record.robust_abs_z_mean,
            record.robust_abs_z_max,
        )
        if any(not math.isfinite(value) for value in floats):
            raise _error("live bank finite record")
        if record.raw_m2 < 0.0 or record.centered_m2 < 0.0:
            raise _error("live bank nonnegative M2")
        if (
            record.raw_positive_count + record.raw_zero_count > record.count
            or record.centered_positive_count + record.centered_zero_count
            > record.count
        ):
            raise _error("live bank sign partition")
        if (
            record.robust_abs_z_mean < 0.0
            or record.robust_abs_z_max < 0.0
            or record.robust_abs_z_mean < abs(record.robust_z_mean)
            or record.robust_abs_z_max < record.robust_abs_z_mean
        ):
            raise _error("live bank absolute-z order")
        records.append(record)
    result = tuple(records)
    zero_variables = tuple(record.variable for record in result if record.count == 0)
    if payload[
        (MISSING_VARIABLE - 1) * RECORD_BYTES : MISSING_VARIABLE * RECORD_BYTES
    ] != bytes(RECORD_BYTES) or zero_variables != (MISSING_VARIABLE,):
        raise _error("live bank zero coordinate")
    if sealed_input and (
        digest != LIVE_BANK_SHA256
        or sum(record.count for record in result) != LIVE_BANK_TOTAL_COUNT
        or max(record.count for record in result) != LIVE_BANK_MAXIMUM_COUNT
        or min(record.count for record in result if record.count)
        != LIVE_BANK_MINIMUM_NONZERO_COUNT
        or sum(record.count >= ELIGIBILITY_MINIMUM_COUNT for record in result)
        != LIVE_BANK_ELIGIBLE_COORDINATES
    ):
        raise _error("live bank aggregate identity")
    return result


def _validate_continuation_transition(
    before: Sequence[LiveBankRecord],
    after: Sequence[LiveBankRecord],
    *,
    probe_count: int,
) -> None:
    """Bind every added observation to exactly one native probe."""

    if len(before) != COORDINATE_COUNT or len(after) != COORDINATE_COUNT:
        raise _error("continuation record population")
    if any(
        old.variable != new.variable or new.count < old.count
        for old, new in zip(before, after, strict=True)
    ):
        raise _error("continuation coordinate count monotonicity")
    delta = sum(record.count for record in after) - sum(
        record.count for record in before
    )
    if delta != _nonnegative(probe_count, "continuation probe count"):
        raise _error("continuation total count delta")


def _read_exact(
    path: str | Path, *, label: str, expected_bytes: int, expected_sha256: str
) -> tuple[Path, bytes]:
    io_v1 = _v9._v8._v7._v1
    resolved, payload, digest = io_v1._read_input(path, label)
    if len(payload) != expected_bytes or digest != _sha(
        expected_sha256, f"{label} expected digest"
    ):
        raise _error(f"{label} seal")
    return resolved, payload


def _read_page19(path: str | Path) -> tuple[Path, bytes]:
    io_v1 = _v9._v8._v7._v1
    resolved, payload, digest = io_v1._read_input(path, "Page19")
    if len(payload) == BURNED_PAGE18_BYTES and digest == BURNED_PAGE18_SHA256:
        raise _error("burned Page18 rejection")
    if len(payload) == BURNED_PAGE17_BYTES and digest == BURNED_PAGE17_SHA256:
        raise _error("burned Page17 rejection")
    if len(payload) == BURNED_PAGE16_BYTES and digest == BURNED_PAGE16_SHA256:
        raise _error("burned Page16 rejection")
    if len(payload) == BURNED_PAGE15_BYTES and digest == BURNED_PAGE15_SHA256:
        raise _error("burned Page15 rejection")
    if len(payload) == BURNED_PAGE14_BYTES and digest == BURNED_PAGE14_SHA256:
        raise _error("burned Page14 rejection")
    if len(payload) == BURNED_PAGE13_BYTES and digest == BURNED_PAGE13_SHA256:
        raise _error("burned Page13 rejection")
    if len(payload) == BURNED_PAGE12_BYTES and digest == BURNED_PAGE12_SHA256:
        raise _error("burned Page12 rejection")
    if len(payload) == BURNED_PAGE11_BYTES and digest == BURNED_PAGE11_SHA256:
        raise _error("burned Page11 rejection")
    if len(payload) == BURNED_PAGE10_BYTES and digest == BURNED_PAGE10_SHA256:
        raise _error("burned Page10 rejection")
    if len(payload) == BURNED_PAGE9_BYTES and digest == BURNED_PAGE9_SHA256:
        raise _error("burned Page9 rejection")
    if len(payload) != PRODUCTION_PAGE19_BYTES or digest != PRODUCTION_PAGE19_SHA256:
        raise _error("Page19 active projection seal")
    return resolved, payload


def _read_live_bank(path: str | Path) -> tuple[Path, bytes]:
    io_v1 = _v9._v8._v7._v1
    resolved, payload, digest = io_v1._read_input(path, "live priority bank")
    if digest in PRIOR_LIVE_BANK_SHA256:
        raise _error("prior live bank rejection")
    if len(payload) != BANK_BYTES or digest != LIVE_BANK_SHA256:
        raise _error("live priority bank seal")
    return resolved, payload


def _manifest_contract() -> tuple[str, int, str, frozenset[str]]:
    """Return the sealed O1C-0102 composed Page-19 contract."""

    return (
        O1C102_MANIFEST_SCHEMA,
        _positive(O1C102_MANIFEST_BYTES, "O1C102 manifest byte count"),
        _sha(O1C102_MANIFEST_SHA256, "O1C102 manifest digest"),
        O1C102_MANIFEST_ARTIFACTS,
    )


def _artifact_contract(
    artifacts: Mapping[str, object],
    name: str,
    *,
    serialized_bytes: int,
    sha256: str,
    role: str,
) -> None:
    row = _mapping(artifacts.get(name), f"manifest artifact {name}")
    if row != {
        "serialized_bytes": serialized_bytes,
        "sha256": sha256,
        "role": role,
    }:
        raise _error(f"manifest artifact {name}")


def _validate_manifest(payload: bytes) -> None:
    """Validate the exact canonical O1C-0102 Page-19 preparation manifest."""

    schema, expected_bytes, expected_sha256, artifact_names = _manifest_contract()
    try:
        root = _mapping(_v21.load_native_json(payload.decode("utf-8")), "manifest")
        canonical = (
            json.dumps(
                root,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("ascii")
    except (
        UnicodeError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        O1RelationalSearchError,
    ) as exc:
        raise _error("O1C102 manifest JSON") from exc
    if (
        canonical != payload
        or len(payload) != expected_bytes
        or hashlib.sha256(payload).hexdigest() != expected_sha256
    ):
        raise _error("O1C102 canonical manifest seal")

    artifacts = _mapping(root.get("artifacts"), "manifest artifacts")
    authorization = _mapping(root.get("authorization"), "manifest authorization")
    zero_call = _mapping(root.get("zero_call"), "manifest zero-call")
    science = _mapping(root.get("science_boundary"), "manifest science boundary")
    emitted = _mapping(root.get("emitted_causal_attic"), "manifest emitted attic")
    logical = _mapping(root.get("logical_known_registry"), "manifest logical registry")
    derived = _mapping(root.get("derived_resolution"), "manifest derived resolution")
    page19 = _mapping(root.get("page19"), "manifest Page19")
    final_bank = _mapping(root.get("final_priority_bank"), "manifest final bank")
    if (
        root.get("schema") != schema
        or root.get("attempt_id") != "O1C-0102"
        or set(artifacts) != artifact_names
        or O1C102_PUBLISHED_ARTIFACTS
        != artifact_names | {_o1c102.PREPARATION_MANIFEST_NAME}
        or zero_call
        != {
            "native_solver_calls": 0,
            "native_preflight_calls": 0,
            "science_calls": 0,
            "target_bytes_read": False,
            "truth_key_bytes_read": False,
            "reveal_calls": 0,
            "refits": 0,
        }
        or authorization.get("page19_burned") is not False
        or authorization.get("lineage32_burned") is not False
        or authorization.get("science_call_authorized") is not False
        or authorization.get("page18_retry_or_replay_authorized") is not False
        or emitted.get("union_clause_count") != 2_338
        or emitted.get("derived_occurrence_count") != 0
        or emitted.get("derived_sidecars_excluded") is not True
        or logical.get("emitted_clause_count") != 2_338
        or logical.get("derived_clause_count") != 5
        or logical.get("combined_clause_count") != GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT
        or logical.get("combined_sha256") != _o1c102.LOGICAL_KNOWN_SHA256
        or logical.get("emitted_inventory_sha256")
        != _o1c102.EMITTED_KNOWN_INVENTORY_SHA256
        or logical.get("derived_inventory_sha256")
        != _o1c102.DERIVED_KNOWN_INVENTORY_SHA256
        or logical.get("combined_inventory_sha256")
        != _o1c102.COMBINED_KNOWN_INVENTORY_SHA256
        or logical.get("next_global_novelty_baseline_clause_count")
        != GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT
        or derived.get("closure_clause_count") != 5
        or derived.get("overlay_clause_count") != 3
        or derived.get("causal_attic_occurrence_rows_added") != 0
        or derived.get("receipt_sha256") != O1C102_DERIVED_RECEIPT_SHA256
        or derived.get("receipt_serialized_bytes") != O1C102_DERIVED_RECEIPT_BYTES
        or science.get("certified_derived_resolution_clause_count") != 5
        or science.get("certified_logical_consequence") is not True
        or science.get("certified_model_or_key") is not False
        or science.get("derived_clauses_are_native_emissions") is not False
        or science.get("derived_occurrence_count") != 0
        or science.get("attacker_valid_domain_reduction") != 0
        or science.get("attacker_valid_entropy_gain_bits") != 0.0
        or page19.get("lineage_ordinal") != PRODUCTION_PAGE19_LINEAGE_ORDINAL
        or page19.get("active_limit") != PRODUCTION_PAGE19_ACTIVE_LIMIT
        or page19.get("active_sha256") != PRODUCTION_PAGE19_SHA256
        or page19.get("clause_count") != PRODUCTION_PAGE19_CLAUSE_COUNT
        or page19.get("literal_count") != PRODUCTION_PAGE19_LITERAL_COUNT
        or page19.get("serialized_bytes") != PRODUCTION_PAGE19_BYTES
        or page19.get("category_counts") != PRODUCTION_PAGE19_CATEGORY_COUNTS
        or page19.get("headroom") != PRODUCTION_PAGE19_HEADROOM
        or page19.get("selected_derived_clause_count") != 3
        or page19.get("selected_emitted_clause_count") != 245
        or page19.get("fresh_identity") is not True
        or final_bank.get("serialized_bytes") != BANK_BYTES
        or final_bank.get("sha256") != LIVE_BANK_SHA256
        or final_bank.get("receipt_serialized_bytes")
        != O1C101_PRIORITY_RECEIPT_BYTES
        or final_bank.get("receipt_sha256") != O1C101_PRIORITY_RECEIPT_SHA256
        or final_bank.get("coordinate_record_count") != COORDINATE_COUNT
        or final_bank.get("record_bytes") != RECORD_BYTES
        or final_bank.get("eligible_coordinate_count") != LIVE_BANK_ELIGIBLE_COORDINATES
        or final_bank.get("receipt_bank_hex_byte_equal") is not True
        or final_bank.get("priority_is_key_bit_belief") is not False
    ):
        raise _error("O1C102 Page19 lineage-32 manifest contract")

    exact_artifacts = {
        _o1c102.ACTIVE_PROJECTION_NAME: (
            PRODUCTION_PAGE19_BYTES,
            PRODUCTION_PAGE19_SHA256,
            "fresh-lineage-32-composed-page19-science-input",
        ),
        _o1c102.FINAL_BANK_NAME: (
            BANK_BYTES,
            LIVE_BANK_SHA256,
            "sealed-evolved-live-continuation-bank-bytes",
        ),
        _o1c102.PRIORITY_RECEIPT_NAME: (
            O1C101_PRIORITY_RECEIPT_BYTES,
            O1C101_PRIORITY_RECEIPT_SHA256,
            "canonical-o1c101-evolved-priority-state-receipt",
        ),
        _o1c102.DERIVED_RECEIPT_NAME: (
            O1C102_DERIVED_RECEIPT_BYTES,
            O1C102_DERIVED_RECEIPT_SHA256,
            "exact-public-resolution-proof-and-known-registry",
        ),
    }
    for name, (serialized_bytes, sha256, role) in exact_artifacts.items():
        _artifact_contract(
            artifacts,
            name,
            serialized_bytes=serialized_bytes,
            sha256=sha256,
            role=role,
        )
    for name, row_value in artifacts.items():
        row = _mapping(row_value, f"manifest artifact {name}")
        if (
            set(row) != {"serialized_bytes", "sha256", "role"}
            or _positive(row.get("serialized_bytes"), f"manifest artifact {name} bytes")
            <= 0
            or len(_sha(row.get("sha256"), f"manifest artifact {name} digest")) != 64
            or not isinstance(row.get("role"), str)
            or not row.get("role")
        ):
            raise _error(f"manifest artifact {name} envelope")


def _validate_receipt(payload: bytes, bank: bytes) -> None:
    try:
        document = _mapping(
            _v21.load_native_json(payload.decode("utf-8")),
            "O1C101 priority receipt",
        )
        if document.get("schema") != O1C101_PRIORITY_RECEIPT_SCHEMA:
            raise _error("O1C101 priority receipt schema")
        replay = dict(document)
        replay["schema"] = _v22.PRIORITY_STATE_SCHEMA
        _, receipt_bank, _ = _v22._validate_priority_state(
            replay, candidates=PRODUCTION_CANDIDATES
        )
    except (UnicodeDecodeError, json.JSONDecodeError, O1RelationalSearchError) as exc:
        raise _error("O1C101 priority receipt contract") from exc
    if receipt_bank != bank:
        raise _error("O1C101 priority receipt bank linkage")


def _validate_derived_receipt(payload: bytes) -> None:
    try:
        receipt = _mapping(
            _v21.load_native_json(payload.decode("utf-8")),
            "O1C102 derived resolution receipt",
        )
        canonical = (
            json.dumps(
                receipt,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("ascii")
    except (
        UnicodeError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        O1RelationalSearchError,
    ) as exc:
        raise _error("O1C102 derived resolution receipt JSON") from exc
    claim = _mapping(receipt.get("claim_boundary"), "derived receipt claim boundary")
    registry = _mapping(
        receipt.get("logical_known_registry"), "derived receipt logical registry"
    )
    emitted = _mapping(registry.get("emitted"), "derived receipt emitted registry")
    derived = _mapping(registry.get("derived"), "derived receipt derived registry")
    combined = _mapping(registry.get("combined"), "derived receipt combined registry")
    binding = _mapping(receipt.get("page19_binding"), "derived receipt Page19 binding")
    if (
        canonical != payload
        or len(payload) != O1C102_DERIVED_RECEIPT_BYTES
        or hashlib.sha256(payload).hexdigest() != O1C102_DERIVED_RECEIPT_SHA256
        or receipt.get("schema") != O1C102_DERIVED_RECEIPT_SCHEMA
        or receipt.get("attempt_id") != "O1C-0102"
        or claim.get("certified_logical_consequence") is not True
        or claim.get("certified_model_or_key") is not False
        or claim.get("derived_clauses_are_native_occurrences") is not False
        or claim.get("derived_clauses_enter_causal_attic") is not False
        or claim.get("attacker_valid_domain_reduction") != 0
        or claim.get("attacker_valid_entropy_gain_bits") != 0.0
        or emitted.get("clause_count") != 2_338
        or emitted.get("inventory_sha256")
        != _o1c102.EMITTED_KNOWN_INVENTORY_SHA256
        or derived.get("clause_count") != 5
        or derived.get("inventory_sha256")
        != _o1c102.DERIVED_KNOWN_INVENTORY_SHA256
        or combined.get("clause_count") != GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT
        or combined.get("inventory_sha256")
        != _o1c102.COMBINED_KNOWN_INVENTORY_SHA256
        or combined.get("next_global_novelty_baseline_clause_count")
        != GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT
        or binding.get("active_sha256") != PRODUCTION_PAGE19_SHA256
        or binding.get("active_clause_count") != PRODUCTION_PAGE19_CLAUSE_COUNT
        or binding.get("selected_derived_clause_count") != 3
        or binding.get("selected_emitted_clause_count") != 245
        or binding.get("pure_emitted_candidate_activated") is not False
    ):
        raise _error("O1C102 derived resolution receipt contract")


def _validate_seed_report(
    value: object, *, seed_sha256: str, production_seal: bool
) -> Mapping[str, object]:
    report = _mapping(value, "priority seed")
    if set(report) != _SEED_FIELDS:
        raise _error("priority seed fields")
    if (
        report.get("magic") != PRIORITY_SEED_MAGIC
        or report.get("schema") != PRIORITY_SEED_SCHEMA
        or report.get("payload_bytes") != BANK_BYTES
        or report.get("payload_sha256") != seed_sha256
        or report.get("expected_production_sha256") != LIVE_BANK_SHA256
        or report.get("source_priority_state_receipt_sha256")
        != O1C101_PRIORITY_RECEIPT_SHA256
        or report.get("source_priority_state_receipt_bytes")
        != O1C101_PRIORITY_RECEIPT_BYTES
        or report.get("source_preparation_manifest_sha256") != O1C102_MANIFEST_SHA256
        or report.get("source_preparation_manifest_bytes") != O1C102_MANIFEST_BYTES
        or report.get("source_derived_resolution_receipt_sha256")
        != O1C102_DERIVED_RECEIPT_SHA256
        or report.get("source_derived_resolution_receipt_bytes")
        != O1C102_DERIVED_RECEIPT_BYTES
        or report.get("production_seal_enforced") is not production_seal
        or report.get("import_roundtrip_exact") is not True
        or report.get("initial_eligible_coordinate_count")
        != LIVE_BANK_ELIGIBLE_COORDINATES
        or report.get("seed_source") != PRIORITY_SEED_SOURCE
        or report.get("live_continuation_bank_identity") is not True
        or report.get("fresh_seed_parser_used") is not False
    ):
        raise _error("priority seed contract")
    return dict(report)


def _candidate_order(field: CriticalityPotentialField) -> tuple[int, ...]:
    return tuple(
        variable for variable in field.observed_variables if 1 <= variable <= 256
    )


def _validate_ownership_v3(
    value: object,
    *,
    actions: Sequence[Mapping[str, object]],
    counts: Mapping[str, int],
) -> Mapping[str, object]:
    """Replay retained lifecycle rows and validate the hidden-stream commitment.

    The v3 ledger deliberately omits high-volume nonclaim observations.  Their
    payload cannot be reconstructed by the adapter; only the exact counter and
    SHA-256 commitment envelope is claimed here.  Retained lifecycle rows keep
    their global sequence numbers, so gaps are required to account exactly for
    compacted records.
    """

    ownership = _mapping(value, "decision ownership")
    fields = {
        "schema",
        "lifecycle",
        "event_retention",
        "eligibility_rule",
        "assignment_notification_rule",
        "current_level",
        "proposals",
        "level_bound_interventions",
        "confirmed_interventions",
        "releases",
        "confirmed_releases",
        "level_bound_unobserved_releases",
        "opposite_assignments",
        "foreign_assignments",
        "renotifications",
        "live_tokens",
        "pending_tokens",
        "maximum_live_tokens",
        "maximum_tokens",
        "maximum_recorded_lifecycle_events",
        "event_count",
        "total_event_count",
        "lifecycle_event_count",
        "recorded_event_count",
        "recorded_lifecycle_event_count",
        "omitted_event_count",
        "compacted_nonclaim_count",
        "events_are_lifecycle_only",
        "events_have_global_sequence",
        "proposal_activated",
        "level_bound_activated",
        "confirmed_activated",
        "nonclaim_kind_counts",
        "nonclaim_stream_digest",
        "events",
        "origin_counts",
    }
    if (
        set(ownership) != fields
        or ownership.get("schema") != OWNERSHIP_SCHEMA
        or ownership.get("lifecycle") != OWNERSHIP_LIFECYCLE
        or ownership.get("event_retention") != OWNERSHIP_EVENT_RETENTION
        or ownership.get("eligibility_rule") != OWNERSHIP_ELIGIBILITY_RULE
        or ownership.get("assignment_notification_rule") != OWNERSHIP_ASSIGNMENT_RULE
        or _boolean(
            ownership.get("events_are_lifecycle_only"),
            "ownership lifecycle-only flag",
        )
        is not True
        or _boolean(
            ownership.get("events_have_global_sequence"),
            "ownership global sequence flag",
        )
        is not True
    ):
        raise _error("decision ownership v3 identity")

    count_names = (
        "current_level",
        "proposals",
        "level_bound_interventions",
        "confirmed_interventions",
        "releases",
        "confirmed_releases",
        "level_bound_unobserved_releases",
        "opposite_assignments",
        "foreign_assignments",
        "renotifications",
        "live_tokens",
        "pending_tokens",
        "maximum_live_tokens",
        "maximum_tokens",
        "maximum_recorded_lifecycle_events",
        "event_count",
        "total_event_count",
        "lifecycle_event_count",
        "recorded_event_count",
        "recorded_lifecycle_event_count",
        "omitted_event_count",
        "compacted_nonclaim_count",
    )
    ledger_counts = {
        name: _nonnegative(ownership.get(name), f"ownership {name}")
        for name in count_names
    }
    nonclaim_counts_raw = _mapping(
        ownership.get("nonclaim_kind_counts"), "ownership nonclaim counts"
    )
    nonclaim_names = {
        "OPPOSITE_ASSIGNMENT": "opposite_assignments",
        "FOREIGN_ASSIGNMENT": "foreign_assignments",
        "RENOTIFIED": "renotifications",
    }
    if set(nonclaim_counts_raw) != set(nonclaim_names):
        raise _error("ownership nonclaim count fields")
    nonclaim_counts = {
        kind: _nonnegative(nonclaim_counts_raw.get(kind), f"ownership {kind}")
        for kind in nonclaim_names
    }
    compacted = sum(nonclaim_counts.values())
    lifecycle = (
        ledger_counts["proposals"]
        + ledger_counts["level_bound_interventions"]
        + ledger_counts["confirmed_interventions"]
        + ledger_counts["releases"]
    )
    if (
        ledger_counts["maximum_tokens"] != 256
        or ledger_counts["maximum_recorded_lifecycle_events"] != 1_024
        or ledger_counts["pending_tokens"] != 0
        or ledger_counts["proposals"] != ledger_counts["level_bound_interventions"]
        or ledger_counts["confirmed_interventions"]
        > ledger_counts["level_bound_interventions"]
        or ledger_counts["releases"] > ledger_counts["level_bound_interventions"]
        or ledger_counts["releases"]
        != ledger_counts["confirmed_releases"]
        + ledger_counts["level_bound_unobserved_releases"]
        or ledger_counts["live_tokens"] + ledger_counts["releases"]
        != ledger_counts["level_bound_interventions"]
        or ledger_counts["maximum_live_tokens"] < ledger_counts["live_tokens"]
        or ledger_counts["maximum_live_tokens"] > ledger_counts["maximum_tokens"]
        or ledger_counts["lifecycle_event_count"] != lifecycle
        or ledger_counts["recorded_event_count"] != lifecycle
        or ledger_counts["recorded_lifecycle_event_count"] != lifecycle
        or ledger_counts["omitted_event_count"] != compacted
        or ledger_counts["compacted_nonclaim_count"] != compacted
        or ledger_counts["total_event_count"] != lifecycle + compacted
        or ledger_counts["event_count"] != ledger_counts["total_event_count"]
        or any(
            nonclaim_counts[kind] != ledger_counts[counter]
            for kind, counter in nonclaim_names.items()
        )
        or _boolean(ownership.get("proposal_activated"), "ownership proposal activated")
        != bool(ledger_counts["proposals"])
        or _boolean(
            ownership.get("level_bound_activated"),
            "ownership level-bound activated",
        )
        != bool(ledger_counts["level_bound_interventions"])
        or _boolean(
            ownership.get("confirmed_activated"),
            "ownership confirmed activated",
        )
        != bool(ledger_counts["confirmed_interventions"])
    ):
        raise _error("decision ownership v3 arithmetic")

    digest = _mapping(
        ownership.get("nonclaim_stream_digest"), "ownership nonclaim digest"
    )
    digest_fields = {
        "algorithm",
        "encoding",
        "record_bytes",
        "field_layout",
        "record_count",
        "sha256",
    }
    digest_sha256 = _sha(digest.get("sha256"), "ownership nonclaim digest sha256")
    if (
        set(digest) != digest_fields
        or digest.get("algorithm") != "SHA-256"
        or digest.get("encoding") != NONCLAIM_DIGEST_ENCODING
        or digest.get("record_bytes") != NONCLAIM_DIGEST_RECORD_BYTES
        or digest.get("field_layout") != NONCLAIM_DIGEST_LAYOUT
        or digest.get("record_count") != compacted
        or (compacted == 0 and digest_sha256 != hashlib.sha256(b"").hexdigest())
    ):
        raise _error("decision ownership v3 nonclaim commitment envelope")

    origin_raw = _mapping(ownership.get("origin_counts"), "ownership origins")
    origin_fields = {"proposals", "level_bound", "confirmed", "releases"}
    if set(origin_raw) != set(OWNERSHIP_ORIGINS):
        raise _error("ownership origin fields")
    origins: dict[str, dict[str, int]] = {}
    for origin in OWNERSHIP_ORIGINS:
        row = _mapping(origin_raw.get(origin), f"ownership origin {origin}")
        if set(row) != origin_fields:
            raise _error(f"ownership origin {origin} fields")
        origins[origin] = {
            name: _nonnegative(row.get(name), f"ownership origin {origin} {name}")
            for name in origin_fields
        }
    if (
        sum(row["proposals"] for row in origins.values()) != ledger_counts["proposals"]
        or sum(row["level_bound"] for row in origins.values())
        != ledger_counts["level_bound_interventions"]
        or sum(row["confirmed"] for row in origins.values())
        != ledger_counts["confirmed_interventions"]
        or sum(row["releases"] for row in origins.values()) != ledger_counts["releases"]
    ):
        raise _error("ownership origin totals")

    event_values = _sequence(ownership.get("events"), "ownership events")
    if len(event_values) != lifecycle:
        raise _error("ownership retained lifecycle count")
    event_fields = {
        "sequence",
        "kind",
        "token",
        "callback",
        "origin",
        "row",
        "literal",
        "level",
        "observed_literal",
    }
    tokens: dict[int, dict[str, object]] = {}
    event_origins = {
        origin: {name: 0 for name in origin_fields} for origin in OWNERSHIP_ORIGINS
    }
    pending: int | None = None
    live: set[int] = set()
    release_queue: list[int] = []
    release_target: int | None = None
    prior_sequence = 0
    maximum_live = 0
    kind_counts = {kind: 0 for kind in OWNERSHIP_LIFECYCLE_KINDS}
    events: list[Mapping[str, object]] = []
    for raw_event in event_values:
        event = _mapping(raw_event, "ownership lifecycle event")
        if set(event) != event_fields:
            raise _error("ownership lifecycle event fields")
        sequence = _positive(event.get("sequence"), "ownership event sequence")
        kind = event.get("kind")
        origin = event.get("origin")
        token = _positive(event.get("token"), "ownership event token")
        callback = _positive(event.get("callback"), "ownership event callback")
        row = _nonnegative(event.get("row"), "ownership event row")
        literal = _literal_i32(event.get("literal"), "ownership event literal")
        level = _nonnegative(event.get("level"), "ownership event level")
        observed = _literal_i32(
            event.get("observed_literal"),
            "ownership event observed literal",
            zero=True,
        )
        if (
            sequence <= prior_sequence
            or sequence > ledger_counts["total_event_count"]
            or kind not in OWNERSHIP_LIFECYCLE_KINDS
            or origin not in OWNERSHIP_ORIGINS
            or row >= 256
        ):
            raise _error("ownership lifecycle chronology")
        prior_sequence = sequence
        kind = cast(str, kind)
        origin = cast(str, origin)
        kind_counts[kind] += 1
        events.append(dict(event))

        is_release = kind in {
            "RELEASED",
            "LEVEL_BOUND_UNOBSERVED_RELEASE",
        }
        if pending is not None and not (kind == "LEVEL_BOUND" and token == pending):
            raise _error("ownership pending proposal binding")
        if release_queue and not is_release:
            raise _error("ownership release batch")
        if kind == "PROPOSED":
            if (
                pending is not None
                or token != len(tokens) + 1
                or token in tokens
                or observed != 0
                or any(
                    abs(cast(int, tokens[live_token]["literal"])) == abs(literal)
                    for live_token in live
                )
            ):
                raise _error("ownership proposal transition")
            tokens[token] = {
                "callback": callback,
                "origin": origin,
                "row": row,
                "literal": literal,
                "proposal_level": level,
                "bound_level": 0,
                "phase": "PROPOSED",
                "events": {"PROPOSED": dict(event)},
            }
            pending = token
            event_origins[origin]["proposals"] += 1
            continue

        state = tokens.get(token)
        if state is None or any(
            state[name] != expected
            for name, expected in (
                ("callback", callback),
                ("origin", origin),
                ("row", row),
                ("literal", literal),
            )
        ):
            raise _error("ownership token binding")
        phase = state["phase"]
        token_events = cast(dict[str, Mapping[str, object]], state["events"])
        if kind == "LEVEL_BOUND":
            if (
                pending != token
                or phase != "PROPOSED"
                or level != cast(int, state["proposal_level"]) + 1
                or observed != 0
                or any(
                    cast(int, tokens[live_token]["bound_level"]) == level
                    or abs(cast(int, tokens[live_token]["literal"])) == abs(literal)
                    for live_token in live
                )
            ):
                raise _error("ownership level-bound transition")
            state["phase"] = "LEVEL_BOUND"
            state["bound_level"] = level
            token_events["LEVEL_BOUND"] = dict(event)
            live.add(token)
            pending = None
            maximum_live = max(maximum_live, len(live))
            event_origins[origin]["level_bound"] += 1
        elif kind == "CONFIRMED":
            if (
                phase != "LEVEL_BOUND"
                or observed != literal
                or level < cast(int, state["bound_level"])
            ):
                raise _error("ownership confirmation transition")
            state["phase"] = "CONFIRMED"
            token_events["CONFIRMED"] = dict(event)
            event_origins[origin]["confirmed"] += 1
        elif is_release:
            if not release_queue:
                release_target = level
                release_queue = sorted(
                    (
                        live_token
                        for live_token in live
                        if cast(int, tokens[live_token]["bound_level"]) > level
                    ),
                    key=lambda live_token: (
                        -cast(int, tokens[live_token]["bound_level"]),
                        -live_token,
                    ),
                )
                if not release_queue:
                    raise _error("ownership release without live token")
            expected_phase = "CONFIRMED" if kind == "RELEASED" else "LEVEL_BOUND"
            if (
                release_target != level
                or release_queue[0] != token
                or phase != expected_phase
                or observed != 0
                or level >= cast(int, state["bound_level"])
            ):
                raise _error("ownership release transition")
            state["phase"] = "RELEASED"
            token_events[kind] = dict(event)
            live.remove(token)
            del release_queue[0]
            if not release_queue:
                release_target = None
            event_origins[origin]["releases"] += 1
        else:
            raise _error("ownership lifecycle kind")

    if (
        pending is not None
        or release_queue
        or len(tokens) != ledger_counts["proposals"]
        or len(live) != ledger_counts["live_tokens"]
        or maximum_live != ledger_counts["maximum_live_tokens"]
        or ledger_counts["total_event_count"] - len(events) != compacted
        or kind_counts["PROPOSED"] != ledger_counts["proposals"]
        or kind_counts["LEVEL_BOUND"] != ledger_counts["level_bound_interventions"]
        or kind_counts["CONFIRMED"] != ledger_counts["confirmed_interventions"]
        or kind_counts["RELEASED"] != ledger_counts["confirmed_releases"]
        or kind_counts["LEVEL_BOUND_UNOBSERVED_RELEASE"]
        != ledger_counts["level_bound_unobserved_releases"]
        or event_origins != origins
        or any(
            cast(int, tokens[token]["bound_level"]) > ledger_counts["current_level"]
            for token in live
        )
    ):
        raise _error("ownership lifecycle replay projection")

    bound_origin = origins["BOUND_LOSING_CHILD"]
    if (
        ledger_counts["proposals"] != counts["action_count"]
        or ledger_counts["level_bound_interventions"] != counts["level_bindings"]
        or ledger_counts["confirmed_interventions"] != counts["confirmed_actions"]
        or ledger_counts["releases"] != counts["releases"]
        or ledger_counts["level_bound_unobserved_releases"]
        != counts["unobserved_releases"]
        or ledger_counts["live_tokens"]
        != sum(not bool(action["released"]) for action in actions)
        or bound_origin["proposals"] != counts["action_count"]
        or bound_origin["level_bound"] != counts["level_bindings"]
        or bound_origin["confirmed"] != counts["confirmed_actions"]
        or bound_origin["releases"] != counts["releases"]
        or any(
            any(row.values())
            for origin, row in origins.items()
            if origin != "BOUND_LOSING_CHILD"
        )
    ):
        raise _error("ownership action aggregate linkage")
    for action in actions:
        token = _positive(action.get("token"), "action ownership token")
        state = tokens.get(token)
        if state is None:
            raise _error("ownership action token")
        token_events = cast(Mapping[str, Mapping[str, object]], state["events"])
        proposal = token_events.get("PROPOSED")
        bound = token_events.get("LEVEL_BOUND")
        confirmed = token_events.get("CONFIRMED")
        released = token_events.get("RELEASED")
        unobserved = token_events.get("LEVEL_BOUND_UNOBSERVED_RELEASE")
        action_bound = action.get("bound_level")
        if (
            proposal is None
            or bound is None
            or action_bound is None
            or bound.get("level") != action_bound
            or proposal.get("callback") != action.get("call")
            or proposal.get("row") != action.get("coordinate_index")
            or proposal.get("literal") != action.get("literal")
            or proposal.get("origin") != "BOUND_LOSING_CHILD"
            or bool(confirmed) is not bool(action.get("confirmed"))
            or bool(released or unobserved) is not bool(action.get("released"))
            or bool(unobserved) is not bool(action.get("unobserved_release"))
            or (released is not None and confirmed is None)
            or (unobserved is not None and confirmed is not None)
        ):
            raise _error("ownership action event linkage")
    return dict(ownership)


def _parse_native_payload(
    payload: object,
    *,
    input_vault: ThresholdNoGoodVault,
    vault_caps: VaultCaps,
    field: CriticalityPotentialField,
    grouping: object,
    grouping_sha256: str,
    cnf_sha256: str,
    potential_sha256: str,
    threshold: float,
    requested_conflicts: int,
    seed: int,
    priority_seed_sha256: str,
    priority_seed_records: Sequence[LiveBankRecord],
    production_seal: bool,
    memory_limit_bytes: int | None = None,
    memory_samples: tuple[dict[str, int | float], ...] = (),
) -> JointScoreSieveV33Result:
    """Validate one native-v30 document and its unchanged v6 lifecycle."""

    root = _mapping(payload, "result")
    if set(root) != _v22._TOP_LEVEL_FIELDS:
        raise _error("result fields")
    candidates = _candidate_order(field)
    if production_seal and candidates != PRODUCTION_CANDIDATES:
        raise _error("production candidate population including missing 241")
    if (
        root.get("schema") != JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or root.get("implementation_parent_schema")
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
        or root.get("operator_semantics") != OPERATOR_SEMANTICS
        or root.get("cnf_sha256") != cnf_sha256
        or root.get("potential_sha256") != potential_sha256
        or root.get("active_vault_sha256") != input_vault.sha256
        or root.get("seed") != seed
        or root.get("conflict_limit") != requested_conflicts
    ):
        raise _error("result identity")
    _same_f64(root.get("threshold"), threshold, "result threshold")
    priority_seed = _validate_seed_report(
        root.get("priority_seed"),
        seed_sha256=priority_seed_sha256,
        production_seal=production_seal,
    )

    native_state = _mapping(root.get("priority_state"), "priority state")
    if native_state.get("schema") != PRIORITY_STATE_SCHEMA:
        raise _error("priority state schema")
    state_for_replay = dict(native_state)
    state_for_replay["schema"] = _v22.PRIORITY_STATE_SCHEMA
    try:
        _, next_seed, state_counts = _v22._validate_priority_state(
            state_for_replay, candidates=candidates
        )
    except O1RelationalSearchError as exc:
        raise _error("priority state replay") from exc
    output_records = _decode_live_bank(
        next_seed, expected_sha256=None, sealed_input=False
    )
    _validate_continuation_transition(
        priority_seed_records,
        output_records,
        probe_count=state_counts["probe_count"],
    )

    native_actions = _mapping(root.get("priority_actions"), "priority actions")
    if native_actions.get("schema") != PRIORITY_ACTION_SCHEMA:
        raise _error("priority action schema")
    actions_for_replay = dict(native_actions)
    actions_for_replay["schema"] = _v22.PRIORITY_ACTION_SCHEMA
    try:
        _, action_rows, action_counts = _v22._validate_actions(
            actions_for_replay,
            threshold=threshold,
            candidates=candidates,
            probe_count=state_counts["probe_count"],
            parent_scans=state_counts["parent_scans"],
        )
    except O1RelationalSearchError as exc:
        raise _error("priority action replay") from exc
    if (
        action_counts["action_count"] != state_counts["nonzero_returns"]
        or action_counts["action_count"] != state_counts["consumed_coordinate_count"]
    ):
        raise _error("action and one-shot state linkage")
    ownership = _validate_ownership_v3(
        root.get("decision_ownership"),
        actions=action_rows,
        counts=action_counts,
    )

    try:
        base = _v9._parse_native_payload(
            _v22._base_v6_payload(root),
            input_vault=input_vault,
            vault_caps=vault_caps,
            field=field,
            grouping=grouping,  # type: ignore[arg-type]
            grouping_sha256=grouping_sha256,
            cnf_sha256=cnf_sha256,
            potential_sha256=potential_sha256,
            threshold=threshold,
            requested_conflicts=requested_conflicts,
            seed=seed,
            memory_limit_bytes=memory_limit_bytes,
            memory_samples=memory_samples,
        )
    except O1RelationalSearchError as exc:
        raise _error("unchanged v6 base and vault lifecycle") from exc
    if (
        base.sieve.get("cb_decide_calls") != state_counts["callback_calls"]
        or base.sieve.get("cb_decide_nonzero") != 0
    ):
        raise _error("one unchanged-v6 call per priority callback")
    realized_actions = sum(
        bool(action["confirmed"])
        and (
            action["semantic"] == _v22.CERTIFIED_CROSSING_SEMANTIC
            or bool(action["coincident_v6_pending"])
        )
        for action in action_rows
    )
    for name in (
        "threshold_prunes",
        "trail_threshold_prunes",
        "external_clauses_queued",
    ):
        if _nonnegative(base.sieve.get(name), f"base {name}") < realized_actions:
            raise _error("certified/coincident v6 prune linkage")
    soft_stats = _v9.derive_vault_soft_conflict_ledger(
        base.stats, requested_conflicts=requested_conflicts
    )
    summary: dict[str, object] = {
        "schema": JOINT_SCORE_SIEVE_ADAPTER_SCHEMA,
        "status": base.status,
        "candidate_population": len(candidates),
        "missing_key_coordinate": 241 if production_seal else None,
        "parent_scans": state_counts["parent_scans"],
        "probe_count": state_counts["probe_count"],
        "child_bound_evaluations": state_counts["child_bound_evaluations"],
        "action_count": action_counts["action_count"],
        "failure_first_count": action_counts["failure_first_count"],
        "certified_crossing_count": action_counts["certified_crossing_count"],
        "coincident_v6_pending_nonclaims": action_counts[
            "coincident_v6_pending_actions"
        ],
        "threshold_prunes": base.threshold_prunes,
        "input_priority_seed_sha256": priority_seed_sha256,
        "input_priority_seed_total_count": sum(
            record.count for record in priority_seed_records
        ),
        "next_priority_seed_sha256": hashlib.sha256(next_seed).hexdigest(),
        "next_priority_seed_bytes": len(next_seed),
        "next_priority_seed_total_count": sum(
            record.count for record in output_records
        ),
        "belief_orientation_authorized": False,
        "key_bits_emitted": 0,
    }
    return JointScoreSieveV33Result(
        status=base.status,
        conflict_limit=base.conflict_limit,
        threshold=base.threshold,
        key_model=base.key_model,
        stats=soft_stats,
        resources=base.resources,
        base_result=base,
        priority_seed=priority_seed,
        priority_state=dict(native_state),
        priority_actions=dict(native_actions),
        decision_ownership=ownership,
        next_priority_seed=next_seed,
        normalized_summary=summary,
        raw=dict(root),
    )


def _validate_prelaunch(
    *,
    source_path: str | Path,
    executable_path: str | Path,
    manifest_path: str | Path,
    receipt_path: str | Path,
    derived_receipt_path: str | Path,
    bank_path: str | Path,
    page19_path: str | Path,
    expected_source_sha256: str,
    expected_executable_sha256: str,
    expected_executable_bytes: int,
) -> _SealedPrelaunch:
    _, manifest_expected_bytes, manifest_expected_sha256, _ = _manifest_contract()
    if _sha(expected_source_sha256, "expected native source digest") != (
        NATIVE_SOURCE_SHA256
    ):
        raise _error("native-v30 source identity")
    source, source_bytes = _read_exact(
        source_path,
        label="native source",
        expected_bytes=NATIVE_SOURCE_BYTES,
        expected_sha256=NATIVE_SOURCE_SHA256,
    )
    executable, executable_bytes = _read_exact(
        executable_path,
        label="native executable",
        expected_bytes=_positive(
            expected_executable_bytes, "expected native executable bytes"
        ),
        expected_sha256=expected_executable_sha256,
    )
    if executable.stat().st_mode & 0o111 == 0:
        raise _error("native executable mode")
    manifest, manifest_bytes = _read_exact(
        manifest_path,
        label="O1C102 manifest",
        expected_bytes=manifest_expected_bytes,
        expected_sha256=manifest_expected_sha256,
    )
    receipt, receipt_bytes = _read_exact(
        receipt_path,
        label="O1C101 priority receipt",
        expected_bytes=O1C101_PRIORITY_RECEIPT_BYTES,
        expected_sha256=O1C101_PRIORITY_RECEIPT_SHA256,
    )
    derived_receipt, derived_receipt_bytes = _read_exact(
        derived_receipt_path,
        label="O1C102 derived resolution receipt",
        expected_bytes=O1C102_DERIVED_RECEIPT_BYTES,
        expected_sha256=O1C102_DERIVED_RECEIPT_SHA256,
    )
    bank, bank_bytes = _read_live_bank(bank_path)
    page19, page19_bytes = _read_page19(page19_path)
    _validate_manifest(manifest_bytes)
    bank_records = _decode_live_bank(
        bank_bytes, expected_sha256=LIVE_BANK_SHA256, sealed_input=True
    )
    _validate_receipt(receipt_bytes, bank_bytes)
    _validate_derived_receipt(derived_receipt_bytes)
    return _SealedPrelaunch(
        source,
        source_bytes,
        executable,
        executable_bytes,
        manifest,
        manifest_bytes,
        receipt,
        receipt_bytes,
        derived_receipt,
        derived_receipt_bytes,
        bank,
        bank_bytes,
        bank_records,
        page19,
        page19_bytes,
    )


def run_joint_score_sieve(
    *,
    executable: str | Path,
    cnf_path: str | Path,
    potential_path: str | Path,
    grouping_path: str | Path,
    vault_path: str | Path,
    priority_seed_path: str | Path,
    vault_caps: VaultCaps,
    threshold: float,
    conflict_limit: int,
    expected_source_sha256: str,
    expected_executable_sha256: str,
    expected_executable_bytes: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
    memory_limit_bytes: int | None = None,
    source_path: str | Path | None = None,
    rollover_manifest_path: str | Path | None = None,
    priority_state_receipt_path: str | Path | None = None,
    derived_resolution_receipt_path: str | Path | None = None,
    sealed_page19_path: str | Path | None = None,
) -> JointScoreSieveV33Result:
    """Validate a prebuilt native-v30 executable, then launch it exactly once."""

    started = time.perf_counter()
    post_launch_evidence: (
        tuple[
            list[str],
            subprocess.CompletedProcess[str],
            tuple[dict[str, int | float], ...],
        ]
        | None
    ) = None
    try:
        requested = _v9._requested_conflicts(conflict_limit)
        if (
            not isinstance(vault_caps, VaultCaps)
            or vault_caps != O1C66_VAULT_CAPS
            or isinstance(seed, bool)
            or not isinstance(seed, int)
            or seed != 0
            or isinstance(expected_executable_bytes, bool)
            or not isinstance(expected_executable_bytes, int)
            or expected_executable_bytes <= 0
            or isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0.0
            or (
                memory_limit_bytes is not None
                and (
                    isinstance(memory_limit_bytes, bool)
                    or not isinstance(memory_limit_bytes, int)
                    or memory_limit_bytes <= 0
                )
            )
        ):
            raise _error("run configuration")
        expected_source = _sha(expected_source_sha256, "expected native source digest")
        if expected_source != NATIVE_SOURCE_SHA256:
            raise _error("native-v30 source identity")
        expected_executable = _sha(
            expected_executable_sha256, "expected native executable digest"
        )
        requested_threshold = _finite(threshold, "requested threshold")
        root = lab_root()
        source = (
            Path(source_path)
            if source_path is not None
            else root / NATIVE_SOURCE_RELATIVE
        )
        manifest = (
            Path(rollover_manifest_path)
            if rollover_manifest_path is not None
            else root / O1C102_MANIFEST_RELATIVE
        )
        receipt = (
            Path(priority_state_receipt_path)
            if priority_state_receipt_path is not None
            else root / O1C101_PRIORITY_RECEIPT_RELATIVE
        )
        derived_receipt = (
            Path(derived_resolution_receipt_path)
            if derived_resolution_receipt_path is not None
            else root / O1C102_DERIVED_RECEIPT_RELATIVE
        )
        page19 = (
            Path(sealed_page19_path)
            if sealed_page19_path is not None
            else root / O1C102_PAGE19_RELATIVE
        )
        source_resolved, source_before, source_digest = _v9._v8._v7._v1._read_input(
            source, "native source"
        )
        if source_digest != expected_source:
            raise _error("native source seal")
        executable_path = Path(executable)
        sealed = _validate_prelaunch(
            source_path=source,
            executable_path=executable_path,
            manifest_path=manifest,
            receipt_path=receipt,
            derived_receipt_path=derived_receipt,
            bank_path=priority_seed_path,
            page19_path=page19,
            expected_source_sha256=expected_source,
            expected_executable_sha256=expected_executable,
            expected_executable_bytes=expected_executable_bytes,
        )
        if (
            sealed.source_path != source_resolved
            or sealed.source_bytes != source_before
        ):
            raise _error("native source prelaunch stability")

        io_v1 = _v9._v8._v7._v1
        cnf_file, cnf_bytes, cnf_sha = io_v1._read_input(cnf_path, "CNF")
        potential_file, potential_bytes, potential_sha = io_v1._read_input(
            potential_path, "potential"
        )
        grouping_file, grouping_bytes, grouping_sha = io_v1._read_input(
            grouping_path, "grouping"
        )
        vault_file, vault_bytes = _v9._v8._read_bounded_vault_input(
            vault_path, caps=vault_caps
        )
        vault_sha = hashlib.sha256(vault_bytes).hexdigest()
        if (
            len(vault_bytes) == BURNED_PAGE18_BYTES
            and vault_sha == BURNED_PAGE18_SHA256
        ):
            raise _error("burned Page18 vault rejection")
        if (
            len(vault_bytes) == BURNED_PAGE17_BYTES
            and vault_sha == BURNED_PAGE17_SHA256
        ):
            raise _error("burned Page17 vault rejection")
        if (
            len(vault_bytes) == BURNED_PAGE16_BYTES
            and vault_sha == BURNED_PAGE16_SHA256
        ):
            raise _error("burned Page16 vault rejection")
        if (
            len(vault_bytes) == BURNED_PAGE15_BYTES
            and vault_sha == BURNED_PAGE15_SHA256
        ):
            raise _error("burned Page15 vault rejection")
        if (
            len(vault_bytes) == BURNED_PAGE14_BYTES
            and vault_sha == BURNED_PAGE14_SHA256
        ):
            raise _error("burned Page14 vault rejection")
        if (
            len(vault_bytes) == BURNED_PAGE13_BYTES
            and vault_sha == BURNED_PAGE13_SHA256
        ):
            raise _error("burned Page13 vault rejection")
        if (
            len(vault_bytes) == BURNED_PAGE12_BYTES
            and vault_sha == BURNED_PAGE12_SHA256
        ):
            raise _error("burned Page12 vault rejection")
        if (
            len(vault_bytes) == BURNED_PAGE11_BYTES
            and vault_sha == BURNED_PAGE11_SHA256
        ):
            raise _error("burned Page11 vault rejection")
        if (
            len(vault_bytes) == BURNED_PAGE10_BYTES
            and vault_sha == BURNED_PAGE10_SHA256
        ):
            raise _error("burned Page10 vault rejection")
        if len(vault_bytes) == BURNED_PAGE9_BYTES and vault_sha == BURNED_PAGE9_SHA256:
            raise _error("burned Page9 vault rejection")
        if (
            len(vault_bytes) != PRODUCTION_PAGE19_BYTES
            or vault_sha != PRODUCTION_PAGE19_SHA256
            or vault_bytes != sealed.page19_bytes
        ):
            raise _error("Page19 production seal")
        field = io_v1._potential(potential_bytes)
        grouping = _v9.validate_joint_score_sieve_grouping(field, grouping_bytes)
        if grouping.potential_sha256 != potential_sha:
            raise _error("grouping potential identity")
        try:
            input_vault = parse_threshold_no_good_vault(
                vault_bytes,
                observed_variables=field.observed_variables,
                caps=vault_caps,
            )
            expected_identity = vault_identity_from_sources(
                cnf_sha256=cnf_sha,
                potential_sha256=potential_sha,
                grouping_sha256=grouping_sha,
                observed_variables=field.observed_variables,
                bound_rule=_v9.JOINT_SCORE_SIEVE_BOUND_RULE,
                threshold=requested_threshold,
            )
            validate_threshold_no_good_vault_identity(
                input_vault, expected=expected_identity
            )
            _v9._v8._certify_input_vault(
                input_vault,
                field=field,
                grouping=grouping,
                threshold=requested_threshold,
            )
        except ThresholdNoGoodVaultError as exc:
            raise _error("input vault") from exc
        if (
            input_vault.sha256 != PRODUCTION_PAGE19_SHA256
            or _candidate_order(field) != PRODUCTION_CANDIDATES
        ):
            raise _error("Page19 parsed production seal")

        command = [
            str(sealed.executable_path),
            "--cnf",
            str(cnf_file),
            "--potential",
            str(potential_file),
            "--grouping",
            str(grouping_file),
            "--vault-in",
            str(vault_file),
            "--priority-seed",
            str(sealed.bank_path),
            "--threshold",
            format(requested_threshold, ".17g"),
            "--conflict-limit",
            str(requested),
            "--seed",
            "0",
        ]
        launch_executable, launch_executable_bytes = _read_exact(
            executable_path,
            label="native executable immediately before launch",
            expected_bytes=expected_executable_bytes,
            expected_sha256=expected_executable,
        )
        if (
            launch_executable != sealed.executable_path
            or launch_executable_bytes != sealed.executable_bytes
        ):
            raise _error("native executable prelaunch stability")
        execution = _v9._v8._v7._execute_native(
            command,
            timeout_seconds=float(timeout_seconds),
            memory_limit_bytes=memory_limit_bytes,
        )
        completed = execution.completed
        post_launch_evidence = (
            list(command),
            completed,
            execution.memory_samples,
        )
        for original, resolved, before, name in (
            (source, sealed.source_path, sealed.source_bytes, "native source"),
            (
                executable_path,
                sealed.executable_path,
                sealed.executable_bytes,
                "executable",
            ),
            (manifest, sealed.manifest_path, sealed.manifest_bytes, "O1C102 manifest"),
            (receipt, sealed.receipt_path, sealed.receipt_bytes, "priority receipt"),
            (
                derived_receipt,
                sealed.derived_receipt_path,
                sealed.derived_receipt_bytes,
                "derived resolution receipt",
            ),
            (
                priority_seed_path,
                sealed.bank_path,
                sealed.bank_bytes,
                "priority seed",
            ),
            (page19, sealed.page19_path, sealed.page19_bytes, "sealed Page19"),
            (cnf_path, cnf_file, cnf_bytes, "CNF"),
            (potential_path, potential_file, potential_bytes, "potential"),
            (grouping_path, grouping_file, grouping_bytes, "grouping"),
        ):
            io_v1._verify_stable_input(original, resolved, before, field=name)
        _v9._v8._verify_stable_vault_input(
            vault_path, vault_file, vault_bytes, caps=vault_caps
        )
        if completed.returncode:
            failure = subprocess.CalledProcessError(
                completed.returncode,
                command,
                output=completed.stdout,
                stderr=completed.stderr,
            )
            _v9._attach_native_process_evidence(
                failure,
                command=command,
                completed=completed,
                memory_samples=execution.memory_samples,
            )
            raise JointScoreSieveV33Error(
                "joint-score-sieve-v33 execution failed: "
                + (completed.stderr.strip() or completed.stdout.strip())
            ) from failure
        try:
            payload = _v21.load_native_json(completed.stdout)
        except (json.JSONDecodeError, O1RelationalSearchError) as exc:
            raise _error("native JSON") from exc
        result = _parse_native_payload(
            payload,
            input_vault=input_vault,
            vault_caps=vault_caps,
            field=field,
            grouping=grouping,
            grouping_sha256=grouping_sha,
            cnf_sha256=cnf_sha,
            potential_sha256=potential_sha,
            threshold=requested_threshold,
            requested_conflicts=requested,
            seed=0,
            priority_seed_sha256=LIVE_BANK_SHA256,
            priority_seed_records=sealed.bank_records,
            production_seal=True,
            memory_limit_bytes=memory_limit_bytes,
            memory_samples=execution.memory_samples,
        )
        return replace(
            result,
            native_stdout=completed.stdout,
            native_stdout_sha256=hashlib.sha256(completed.stdout.encode()).hexdigest(),
            command=tuple(command),
        )
    except Exception as exc:
        if post_launch_evidence is not None:
            evidence_command, evidence_completed, evidence_memory = post_launch_evidence
            _v9._attach_native_process_evidence(
                exc,
                command=evidence_command,
                completed=evidence_completed,
                memory_samples=evidence_memory,
            )
        elapsed = max(0.0, time.perf_counter() - started)
        telemetry = _v9._v8._v7._failure_telemetry(
            exc,
            elapsed_seconds=elapsed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
        message = str(exc)
        if not message.startswith("joint-score-sieve-v33"):
            message = f"joint-score-sieve-v33 adapter failed: {message}"
        outward = _v9.JointScoreSieveExecutionError(
            message, failure_telemetry=telemetry
        )
        if post_launch_evidence is not None:
            evidence_command, evidence_completed, evidence_memory = post_launch_evidence
            _v9._attach_native_process_evidence(
                outward,
                command=evidence_command,
                completed=evidence_completed,
                memory_samples=evidence_memory,
            )
        raise outward from exc


__all__ = [
    "JOINT_SCORE_SIEVE_ADAPTER_SCHEMA",
    "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
    "LIVE_BANK_SHA256",
    "NATIVE_SOURCE_BYTES",
    "NATIVE_SOURCE_SHA256",
    "JointScoreSieveV33Error",
    "JointScoreSieveV33Result",
    "LiveBankRecord",
    "run_joint_score_sieve",
]
