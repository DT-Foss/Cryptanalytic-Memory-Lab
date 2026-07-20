"""Fail-closed O1C-0096 adapter for Page 16 and the sealed live bank.

Version 30 preserves v28's proof-mining and result-validation semantics while
moving the native boundary to result/source v27 and fresh lineage 29 Page 16.
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


JOINT_SCORE_SIEVE_ADAPTER_SCHEMA = "o1-256-joint-score-sieve-v30-adapter-v1"
JOINT_SCORE_SIEVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v27"
JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA = (
    "o1-256-cadical-joint-score-sieve-result-v6"
)
PRIORITY_STATE_SCHEMA = (
    "o1-256-o1c97-live-parent-centered-continuation-priority-state-v1"
)
PRIORITY_ACTION_SCHEMA = "o1-256-o1c97-failure-first-proof-mining-actions-v1"
PRIORITY_SEED_SCHEMA = "o1-256-o1c82-parent-centered-priority-seed-v1"
PRIORITY_SEED_MAGIC = "O1C82-PCP-SEED1"
PRIORITY_SEED_SOURCE = "sealed-live-continuation-bank"

OPERATOR_SEMANTICS = _v22.OPERATOR_SEMANTICS
PRODUCTION_CANDIDATES = _v22.PRODUCTION_CANDIDATES
PROBE_TRACE_RECORD_BYTES = _v22.PROBE_TRACE_RECORD_BYTES
ACTION_TRACE_RECORD_BYTES = _v22.ACTION_TRACE_RECORD_BYTES

LIVE_BANK_SHA256 = "97a325c91b9a853a094fcc8b7fd9fafdafe6b5ec4022952e1a86af068c834fca"
LIVE_BANK_TOTAL_COUNT = 283_069
LIVE_BANK_MAXIMUM_COUNT = 2_675
LIVE_BANK_MINIMUM_NONZERO_COUNT = 227
LIVE_BANK_ELIGIBLE_COORDINATES = 255

O1C96_MANIFEST_SCHEMA = "o1-256-o1c96-page16-transport-recovery-preparation-v1"
O1C96_MANIFEST_BYTES = 6_414
O1C96_MANIFEST_SHA256 = (
    "68d42b0f4cfaaf8a5b03f4b61515a8032860623dd5517fc87dac87b087a1c7b7"
)
O1C96_MANIFEST_ARTIFACTS = frozenset(
    {
        "page-16-active.bin",
        "residency.json",
        "activation-ledger.json",
        "occurrence-ledger.json",
        "subsumption-relations.json",
        "common-signed-intersection-audit.json",
        "final-parent-centered-priority-bank.bin",
        "o1c92-priority-state-receipt.json",
        "o1c95-terminal-failure-receipt.json",
    }
)
O1C96_PUBLISHED_ARTIFACTS = O1C96_MANIFEST_ARTIFACTS | {
    "transport-recovery-preparation-manifest.json"
}
O1C96_MANIFEST_RELATIVE = Path(
    "research/o1c96_page16_transport_recovery_seed_20260720/"
    "transport-recovery-preparation-manifest.json"
)
O1C96_PAGE16_RELATIVE = Path(
    "research/o1c96_page16_transport_recovery_seed_20260720/page-16-active.bin"
)

O1C92_PRIORITY_RECEIPT_SCHEMA = (
    "o1-256-o1c92-live-parent-centered-continuation-priority-state-v1"
)
O1C92_PRIORITY_RECEIPT_BYTES = 52_014
O1C92_PRIORITY_RECEIPT_SHA256 = (
    "1c69bb329819ff873758e72ccfd69649310e5dd089c68665c34d0a287821c1e6"
)
PRODUCTION_PAGE16_BYTES = 2_831_459
PRODUCTION_PAGE16_SHA256 = (
    "fb3b56690ec4f50d699c2598dd4fa752376d1609d1e242ee8aa987694cdc48f5"
)
PRODUCTION_PAGE16_LINEAGE_ORDINAL = 29
PRODUCTION_PAGE16_ACTIVE_LIMIT = 251
PRODUCTION_PAGE16_CLAUSE_COUNT = 251
PRODUCTION_PAGE16_LITERAL_COUNT = 707_566
PRODUCTION_PAGE16_CATEGORY_COUNTS: Mapping[str, int] = {
    "structural_root": 9,
    "pinned_core": 43,
    "inherited_debt": 0,
    "new_debt": 167,
    "hot_event": 0,
    "recycled": 32,
}
PRODUCTION_PAGE16_HEADROOM: Mapping[str, int] = {
    "clauses": 261,
    "literals": 892_434,
    "serialized_bytes": 5_557_149,
}

O1C95_FAILURE_RECEIPT_BYTES = 831
O1C95_FAILURE_RECEIPT_SHA256 = (
    "88c95c6aabf1c3877c9d026fb0d03bf037fb5efd38ddb3ebbc2826dfe1efe5a6"
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
        "715bfbc22fa2162ec8546eed21cf609318d3c5be806092dc4fe4b07cc4d9d654",
        "0203de9f1732b095bf30062cb8a07b018ded829ee99f18ffbca715c653c0cc6a",
        "658fd2856b83d1a0ff8d28e92a604c99b3843a49a589811bf9b61845959ec31f",
        "2c0c4ccba476bc642778b68234cc497c1776d144092ea9f1aead367559f59b07",
        "05b8acf3ecd5423016e5d7ef7d649f790e758e3477a943fe7306280064a4c630",
    }
)

NATIVE_SOURCE_RELATIVE = Path("native/cadical_o1_joint_score_sieve_v27.cpp")
NATIVE_SOURCE_BYTES = 50_154
NATIVE_SOURCE_SHA256 = (
    "fa6ab51bbf8db39b57f9414dc675d5391969c2bafab30b8e1355337576ff090a"
)
O1C96_LIVE_BANK_RELATIVE = Path(
    "research/o1c96_page16_transport_recovery_seed_20260720/"
    "final-parent-centered-priority-bank.bin"
)
O1C92_PRIORITY_RECEIPT_RELATIVE = Path(
    "research/o1c96_page16_transport_recovery_seed_20260720/"
    "o1c92-priority-state-receipt.json"
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
    "import_roundtrip_exact",
    "initial_eligible_coordinate_count",
    "seed_source",
    "live_continuation_bank_identity",
    "fresh_seed_parser_used",
}


class JointScoreSieveV30Error(O1RelationalSearchError):
    """Native-v27 execution or continuation validation failed."""


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
class JointScoreSieveV30Result:
    """Typed native-v27 result and its validated evolved bank."""

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
    bank_path: Path
    bank_bytes: bytes
    bank_records: tuple[LiveBankRecord, ...]
    page16_path: Path
    page16_bytes: bytes


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _error(field: str) -> JointScoreSieveV30Error:
    return JointScoreSieveV30Error(f"joint-score-sieve-v30 {field} differs")


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise _error(field)
    return cast(Mapping[str, object], value)


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


def _read_page16(path: str | Path) -> tuple[Path, bytes]:
    io_v1 = _v9._v8._v7._v1
    resolved, payload, digest = io_v1._read_input(path, "Page16")
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
    if len(payload) != PRODUCTION_PAGE16_BYTES or digest != PRODUCTION_PAGE16_SHA256:
        raise _error("Page16 active projection seal")
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
    """Return the sealed O1C-0096 Page-16 transport-recovery contract."""

    return (
        O1C96_MANIFEST_SCHEMA,
        _positive(O1C96_MANIFEST_BYTES, "O1C96 manifest byte count"),
        _sha(O1C96_MANIFEST_SHA256, "O1C96 manifest digest"),
        O1C96_MANIFEST_ARTIFACTS,
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
        raise _error("O1C96 manifest JSON") from exc
    if canonical != payload:
        raise _error("O1C96 canonical manifest encoding")
    if (
        len(payload) != expected_bytes
        or hashlib.sha256(payload).hexdigest() != expected_sha256
    ):
        raise _error("O1C96 manifest seal")

    artifacts = _mapping(root.get("artifacts"), "manifest artifacts")
    zero_call = _mapping(root.get("zero_call"), "manifest zero-call boundary")
    authorization = _mapping(
        root.get("authorization"), "manifest authorization boundary"
    )
    parent = _mapping(root.get("parent"), "manifest parent")
    science = _mapping(root.get("science_boundary"), "manifest science boundary")
    recovery = _mapping(root.get("transport_recovery"), "manifest recovery")
    attic = _mapping(root.get("attic"), "manifest attic")
    page16 = _mapping(root.get("page16"), "manifest Page16")
    debt = _mapping(page16.get("debt_completion"), "manifest Page16 debt")
    final_bank = _mapping(root.get("final_priority_bank"), "manifest final bank")

    if (
        set(root)
        != {
            "schema",
            "attempt_id",
            "zero_call",
            "authorization",
            "parent",
            "science_boundary",
            "transport_recovery",
            "attic",
            "page16",
            "final_priority_bank",
            "artifacts",
        }
        or root.get("schema") != schema
        or root.get("attempt_id") != "O1C-0096"
        or set(artifacts) != artifact_names
        or O1C96_PUBLISHED_ARTIFACTS
        != artifact_names | {O1C96_MANIFEST_RELATIVE.name}
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
        or authorization
        != {
            "science_call_authorized": False,
            "intent_created": False,
            "page16_burned": False,
            "lineage29_burned": False,
            "page15_retry_or_replay_authorized": False,
            "lineage28_retry_or_replay_authorized": False,
            "historical_page_retry_or_replay_authorized": False,
        }
        or parent.get("attempt_id") != "O1C-0095"
        or parent.get("classification")
        != "PARENT_CENTERED_CONTINUATION_OPERATIONAL_TERMINAL"
        or parent.get("stop_reason") != "burned-terminal-failure-no-retry"
        or parent.get("failure_reason")
        != "adapter-v29-priority-seed-fields-mismatch"
        or parent.get("terminal_failure_sha256")
        != O1C95_FAILURE_RECEIPT_SHA256
        or parent.get("native_process_returncode_zero_before_adapter_validation")
        is not True
        or parent.get("native_json_discarded_before_runner_result") is not True
        or parent.get("page15_burned") is not True
        or parent.get("lineage28_burned") is not True
        or parent.get("native_result_returned_to_runner") is not False
        or parent.get("science_gain") is not False
        or parent.get("state_update_available") is not False
        or parent.get("priority_receipt_sha256")
        != O1C92_PRIORITY_RECEIPT_SHA256
        or parent.get("priority_receipt_serialized_bytes")
        != O1C92_PRIORITY_RECEIPT_BYTES
        or science
        != {
            "imported_science_attempt_id": None,
            "imported_clause_count": 0,
            "imported_priority_state_update": False,
            "o1c95_terminal_failure_imported_as_science": False,
            "o1c95_native_json_imported": False,
            "o1c95_output_artifacts_imported": [],
        }
        or recovery
        != {
            "source_lineage_ordinal": 28,
            "next_lineage_ordinal": 29,
            "fully_emitted_event_count": 0,
            "new_chunk_count": 0,
            "attic_evidence_unchanged": True,
            "occurrence_ledger_unchanged": True,
            "relation_ledger_unchanged": True,
            "common_core_audit_unchanged": True,
            "continuation_bank_unchanged": True,
            "priority_receipt_unchanged": True,
            "api": (
                "reproject_causal_residency(same_attic,"
                "fully_emitted_union_indices=(),next_lineage_ordinal=29,"
                "next_active_limit=251)"
            ),
        }
        or attic
        != {
            "chunk_count": 18,
            "union_sha256": (
                "d8b9d1d8adadacfede38e9bb278240fcb463c9d0d91b48bca45db0c8a740ae9b"
            ),
            "union_clause_count": 1_812,
            "union_literal_count": 5_090_528,
            "union_serialized_bytes": 20_369_551,
            "occurrence_count": 1_820,
            "duplicate_occurrence_count": 8,
            "strict_subsumption_pair_count": 14,
            "undominated_clause_count": 1_801,
            "byte_and_relation_equal_to_o1c93": True,
        }
        or page16.get("lineage_ordinal") != PRODUCTION_PAGE16_LINEAGE_ORDINAL
        or page16.get("active_limit") != PRODUCTION_PAGE16_ACTIVE_LIMIT
        or page16.get("active_sha256") != PRODUCTION_PAGE16_SHA256
        or page16.get("clause_count") != PRODUCTION_PAGE16_CLAUSE_COUNT
        or page16.get("literal_count") != PRODUCTION_PAGE16_LITERAL_COUNT
        or page16.get("serialized_bytes") != PRODUCTION_PAGE16_BYTES
        or page16.get("category_counts") != PRODUCTION_PAGE16_CATEGORY_COUNTS
        or page16.get("headroom") != PRODUCTION_PAGE16_HEADROOM
        or page16.get("selected_union_indices_sha256")
        != "27f64155956dea34b73a26808aca324b60550908a43a2ebd9cc23ef889c77166"
        or page16.get("selection_order_sha256")
        != "3337fc6f229c2bbbd503d5c1ab880eaf4c7e20dccaf5bcfa36c4a9808e557b42"
        or page16.get("fresh_identity") is not True
        or page16.get("activation_ledger_prior_entry_count") != 16
        or page16.get("activation_ledger_next_entry_count") != 17
        or page16.get("activation_entries_added") != 1
        or debt
        != {
            "prior_never_resident_undominated_clause_count": 167,
            "admitted_as_new_debt_clause_count": 167,
            "remaining_never_resident_undominated_clause_count": 0,
            "recycled_clause_count": 32,
            "all_prior_debt_admitted": True,
        }
        or final_bank.get("serialized_bytes") != BANK_BYTES
        or final_bank.get("sha256") != LIVE_BANK_SHA256
        or final_bank.get("receipt_serialized_bytes")
        != O1C92_PRIORITY_RECEIPT_BYTES
        or final_bank.get("receipt_sha256") != O1C92_PRIORITY_RECEIPT_SHA256
        or final_bank.get("fresh_seed_parser_compatible") is not False
        or final_bank.get("maximum_evolved_count") != LIVE_BANK_MAXIMUM_COUNT
        or final_bank.get("maximum_evolved_count_variables") != [15]
        or final_bank.get("minimum_nonzero_evolved_count")
        != LIVE_BANK_MINIMUM_NONZERO_COUNT
        or final_bank.get("aggregate_evolved_count") != LIVE_BANK_TOTAL_COUNT
        or final_bank.get("coordinate_record_count") != COORDINATE_COUNT
        or final_bank.get("record_bytes") != RECORD_BYTES
        or final_bank.get("zero_coordinate_variables") != [MISSING_VARIABLE]
        or final_bank.get("eligible_coordinate_count")
        != LIVE_BANK_ELIGIBLE_COORDINATES
        or final_bank.get("receipt_bank_hex_byte_equal") is not True
        or final_bank.get("priority_is_key_bit_belief") is not False
        or final_bank.get("semantic_role")
        != "unchanged-sealed-live-continuation-bytes"
    ):
        raise _error("O1C96 Page16 lineage-29 manifest contract")

    _artifact_contract(
        artifacts,
        "page-16-active.bin",
        serialized_bytes=PRODUCTION_PAGE16_BYTES,
        sha256=PRODUCTION_PAGE16_SHA256,
        role="fresh-lineage-29-page16-science-input",
    )
    _artifact_contract(
        artifacts,
        "final-parent-centered-priority-bank.bin",
        serialized_bytes=BANK_BYTES,
        sha256=LIVE_BANK_SHA256,
        role="unchanged-sealed-live-continuation-bank-bytes",
    )
    _artifact_contract(
        artifacts,
        "o1c92-priority-state-receipt.json",
        serialized_bytes=O1C92_PRIORITY_RECEIPT_BYTES,
        sha256=O1C92_PRIORITY_RECEIPT_SHA256,
        role="unchanged-canonical-o1c92-priority-state-receipt",
    )
    _artifact_contract(
        artifacts,
        "o1c95-terminal-failure-receipt.json",
        serialized_bytes=O1C95_FAILURE_RECEIPT_BYTES,
        sha256=O1C95_FAILURE_RECEIPT_SHA256,
        role="canonical-o1c95-terminal-failure-receipt",
    )


def _validate_receipt(payload: bytes, bank: bytes) -> None:
    try:
        document = _mapping(
            _v21.load_native_json(payload.decode("utf-8")),
            "O1C92 priority receipt",
        )
        if document.get("schema") != O1C92_PRIORITY_RECEIPT_SCHEMA:
            raise _error("O1C92 priority receipt schema")
        replay = dict(document)
        replay["schema"] = _v22.PRIORITY_STATE_SCHEMA
        _, receipt_bank, _ = _v22._validate_priority_state(
            replay, candidates=PRODUCTION_CANDIDATES
        )
    except (UnicodeDecodeError, json.JSONDecodeError, O1RelationalSearchError) as exc:
        raise _error("O1C92 priority receipt contract") from exc
    if receipt_bank != bank:
        raise _error("O1C92 priority receipt bank linkage")


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
        != O1C92_PRIORITY_RECEIPT_SHA256
        or report.get("source_priority_state_receipt_bytes")
        != O1C92_PRIORITY_RECEIPT_BYTES
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
) -> JointScoreSieveV30Result:
    """Validate one native-v27 document and its unchanged v6 lifecycle."""

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
    try:
        ownership = _v22._validate_ownership_linkage(
            root.get("decision_ownership"),
            actions=action_rows,
            counts=action_counts,
        )
    except O1RelationalSearchError as exc:
        raise _error("decision ownership replay") from exc

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
    return JointScoreSieveV30Result(
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
    bank_path: str | Path,
    page16_path: str | Path,
    expected_source_sha256: str,
    expected_executable_sha256: str,
    expected_executable_bytes: int,
) -> _SealedPrelaunch:
    _, manifest_expected_bytes, manifest_expected_sha256, _ = _manifest_contract()
    if _sha(expected_source_sha256, "expected native source digest") != (
        NATIVE_SOURCE_SHA256
    ):
        raise _error("native-v27 source identity")
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
        label="O1C96 manifest",
        expected_bytes=manifest_expected_bytes,
        expected_sha256=manifest_expected_sha256,
    )
    receipt, receipt_bytes = _read_exact(
        receipt_path,
        label="O1C92 priority receipt",
        expected_bytes=O1C92_PRIORITY_RECEIPT_BYTES,
        expected_sha256=O1C92_PRIORITY_RECEIPT_SHA256,
    )
    bank, bank_bytes = _read_live_bank(bank_path)
    page16, page16_bytes = _read_page16(page16_path)
    _validate_manifest(manifest_bytes)
    bank_records = _decode_live_bank(
        bank_bytes, expected_sha256=LIVE_BANK_SHA256, sealed_input=True
    )
    _validate_receipt(receipt_bytes, bank_bytes)
    return _SealedPrelaunch(
        source,
        source_bytes,
        executable,
        executable_bytes,
        manifest,
        manifest_bytes,
        receipt,
        receipt_bytes,
        bank,
        bank_bytes,
        bank_records,
        page16,
        page16_bytes,
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
    sealed_page16_path: str | Path | None = None,
) -> JointScoreSieveV30Result:
    """Validate a prebuilt native-v27 executable, then launch it exactly once."""

    started = time.perf_counter()
    post_launch_evidence: tuple[
        list[str],
        subprocess.CompletedProcess[str],
        tuple[dict[str, int | float], ...],
    ] | None = None
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
            raise _error("native-v27 source identity")
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
            else root / O1C96_MANIFEST_RELATIVE
        )
        receipt = (
            Path(priority_state_receipt_path)
            if priority_state_receipt_path is not None
            else root / O1C92_PRIORITY_RECEIPT_RELATIVE
        )
        page16 = (
            Path(sealed_page16_path)
            if sealed_page16_path is not None
            else root / O1C96_PAGE16_RELATIVE
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
            bank_path=priority_seed_path,
            page16_path=page16,
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
            len(vault_bytes) != PRODUCTION_PAGE16_BYTES
            or vault_sha != PRODUCTION_PAGE16_SHA256
            or vault_bytes != sealed.page16_bytes
        ):
            raise _error("Page16 production seal")
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
            input_vault.sha256 != PRODUCTION_PAGE16_SHA256
            or _candidate_order(field) != PRODUCTION_CANDIDATES
        ):
            raise _error("Page16 parsed production seal")

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
            (manifest, sealed.manifest_path, sealed.manifest_bytes, "O1C96 manifest"),
            (receipt, sealed.receipt_path, sealed.receipt_bytes, "priority receipt"),
            (
                priority_seed_path,
                sealed.bank_path,
                sealed.bank_bytes,
                "priority seed",
            ),
            (page16, sealed.page16_path, sealed.page16_bytes, "sealed Page16"),
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
            raise JointScoreSieveV30Error(
                "joint-score-sieve-v30 execution failed: "
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
            evidence_command, evidence_completed, evidence_memory = (
                post_launch_evidence
            )
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
        if not message.startswith("joint-score-sieve-v30"):
            message = f"joint-score-sieve-v30 adapter failed: {message}"
        outward = _v9.JointScoreSieveExecutionError(
            message, failure_telemetry=telemetry
        )
        if post_launch_evidence is not None:
            evidence_command, evidence_completed, evidence_memory = (
                post_launch_evidence
            )
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
    "JointScoreSieveV30Error",
    "JointScoreSieveV30Result",
    "LiveBankRecord",
    "run_joint_score_sieve",
]
