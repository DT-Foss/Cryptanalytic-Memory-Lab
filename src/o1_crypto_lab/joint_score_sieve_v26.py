"""Fail-closed O1C-0087 adapter for Page 12 and the sealed live bank.

Version 26 preserves v25's proof-mining and result-validation semantics while
moving the native boundary to result/source v23 and fresh lineage 25 Page 12.
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


JOINT_SCORE_SIEVE_ADAPTER_SCHEMA = "o1-256-joint-score-sieve-v26-adapter-v1"
JOINT_SCORE_SIEVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v23"
JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA = (
    "o1-256-cadical-joint-score-sieve-result-v6"
)
PRIORITY_STATE_SCHEMA = (
    "o1-256-o1c87-live-parent-centered-continuation-priority-state-v1"
)
PRIORITY_ACTION_SCHEMA = "o1-256-o1c87-failure-first-proof-mining-actions-v1"
PRIORITY_SEED_SCHEMA = "o1-256-o1c82-parent-centered-priority-seed-v1"
PRIORITY_SEED_MAGIC = "O1C82-PCP-SEED1"
PRIORITY_SEED_SOURCE = "sealed-live-continuation-bank"

OPERATOR_SEMANTICS = _v22.OPERATOR_SEMANTICS
PRODUCTION_CANDIDATES = _v22.PRODUCTION_CANDIDATES
PROBE_TRACE_RECORD_BYTES = _v22.PROBE_TRACE_RECORD_BYTES
ACTION_TRACE_RECORD_BYTES = _v22.ACTION_TRACE_RECORD_BYTES

LIVE_BANK_SHA256 = "658fd2856b83d1a0ff8d28e92a604c99b3843a49a589811bf9b61845959ec31f"
LIVE_BANK_TOTAL_COUNT = 182_368
LIVE_BANK_MAXIMUM_COUNT = 1_576
LIVE_BANK_ELIGIBLE_COORDINATES = 255

O1C87_MANIFEST_SCHEMA = "o1-256-o1c87-page12-causal-rollover-preparation-v1"
O1C87_MANIFEST_BYTES = 6_910
O1C87_MANIFEST_SHA256 = (
    "64427e4861507e373cc02b52b9c0f2d25d62f26cf9362af681b9bc90ef4a57b6"
)
O1C87_MANIFEST_ARTIFACTS = frozenset(
    {
        "lineage-25-new-chunk.vault",
        "page-12-active.bin",
        "residency.json",
        "activation-ledger.json",
        "occurrence-ledger.json",
        "subsumption-relations.json",
        "common-signed-intersection-audit.json",
        "final-parent-centered-priority-bank.bin",
        "o1c86-priority-state-receipt.json",
    }
)
O1C87_PUBLISHED_ARTIFACTS = O1C87_MANIFEST_ARTIFACTS | {
    "causal-rollover-preparation-manifest.json"
}
O1C87_MANIFEST_RELATIVE = Path(
    "research/o1c87_page12_causal_rollover_seed_20260720/"
    "causal-rollover-preparation-manifest.json"
)
O1C87_PAGE12_RELATIVE = Path(
    "research/o1c87_page12_causal_rollover_seed_20260720/page-12-active.bin"
)

O1C86_PRIORITY_RECEIPT_SCHEMA = (
    "o1-256-o1c86-live-parent-centered-continuation-priority-state-v1"
)
O1C86_PRIORITY_RECEIPT_BYTES = 52_009
O1C86_PRIORITY_RECEIPT_SHA256 = (
    "e5ffda54ec91dc325abe0d87051e4045aecebd9e9d89655fc9a9b5539dafeeec"
)
PRODUCTION_PAGE12_BYTES = 2_725_423
PRODUCTION_PAGE12_SHA256 = (
    "44205f81322d526c1cf7b7c96f28a3baf02b6b9bcb08a04f0bab2e66651fa660"
)
PRODUCTION_PAGE12_LINEAGE_ORDINAL = 25
PRODUCTION_PAGE12_ACTIVE_LIMIT = 254
PRODUCTION_PAGE12_CLAUSE_COUNT = 254
PRODUCTION_PAGE12_LITERAL_COUNT = 681_054
PRODUCTION_PAGE12_CATEGORY_COUNTS: Mapping[str, int] = {
    "structural_root": 5,
    "pinned_core": 43,
    "inherited_debt": 0,
    "new_debt": 202,
    "hot_event": 0,
    "recycled": 4,
}
PRODUCTION_PAGE12_HEADROOM: Mapping[str, int] = {
    "clauses": 258,
    "literals": 918_946,
    "serialized_bytes": 5_663_185,
}

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

NATIVE_SOURCE_RELATIVE = Path("native/cadical_o1_joint_score_sieve_v23.cpp")
O1C87_LIVE_BANK_RELATIVE = Path(
    "research/o1c87_page12_causal_rollover_seed_20260720/"
    "final-parent-centered-priority-bank.bin"
)
O1C86_PRIORITY_RECEIPT_RELATIVE = Path(
    "research/o1c87_page12_causal_rollover_seed_20260720/"
    "o1c86-priority-state-receipt.json"
)

_SEED_FIELDS = {
    "magic",
    "schema",
    "payload_bytes",
    "payload_sha256",
    "production_seal_enforced",
    "expected_production_sha256",
    "import_roundtrip_exact",
    "initial_eligible_coordinate_count",
    "seed_source",
    "live_continuation_bank_identity",
    "fresh_seed_parser_used",
}


class JointScoreSieveV26Error(O1RelationalSearchError):
    """Native-v23 execution or continuation validation failed."""


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
class JointScoreSieveV26Result:
    """Typed native-v23 result and its validated evolved bank."""

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
    page12_path: Path
    page12_bytes: bytes


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _error(field: str) -> JointScoreSieveV26Error:
    return JointScoreSieveV26Error(f"joint-score-sieve-v26 {field} differs")


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
    if expected_sha256 is not None and hashlib.sha256(payload).hexdigest() != _sha(
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
        hashlib.sha256(payload).hexdigest() != LIVE_BANK_SHA256
        or sum(record.count for record in result) != LIVE_BANK_TOTAL_COUNT
        or max(record.count for record in result) != LIVE_BANK_MAXIMUM_COUNT
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


def _read_page12(path: str | Path) -> tuple[Path, bytes]:
    io_v1 = _v9._v8._v7._v1
    resolved, payload, digest = io_v1._read_input(path, "Page12")
    if len(payload) == BURNED_PAGE11_BYTES and digest == BURNED_PAGE11_SHA256:
        raise _error("burned Page11 rejection")
    if len(payload) == BURNED_PAGE10_BYTES and digest == BURNED_PAGE10_SHA256:
        raise _error("burned Page10 rejection")
    if len(payload) == BURNED_PAGE9_BYTES and digest == BURNED_PAGE9_SHA256:
        raise _error("burned Page9 rejection")
    if len(payload) != PRODUCTION_PAGE12_BYTES or digest != PRODUCTION_PAGE12_SHA256:
        raise _error("Page12 active projection seal")
    return resolved, payload


def _manifest_contract() -> tuple[str, int, str, frozenset[str]]:
    """Return the sealed O1C-0087 preparation contract."""

    return (
        O1C87_MANIFEST_SCHEMA,
        _positive(O1C87_MANIFEST_BYTES, "O1C87 manifest byte count"),
        _sha(O1C87_MANIFEST_SHA256, "O1C87 manifest digest"),
        O1C87_MANIFEST_ARTIFACTS,
    )


def _validate_manifest(payload: bytes) -> None:
    schema, _, _, artifact_names = _manifest_contract()
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
        raise _error("O1C87 manifest JSON") from exc
    if canonical != payload:
        raise _error("O1C87 canonical manifest encoding")
    artifacts = _mapping(root.get("artifacts"), "manifest artifacts")
    zero_call = _mapping(root.get("zero_call"), "manifest zero-call boundary")
    authorization = _mapping(
        root.get("authorization"), "manifest authorization boundary"
    )
    parent = _mapping(root.get("parent"), "manifest parent")
    science = _mapping(root.get("science_boundary"), "manifest science boundary")
    rollover = _mapping(root.get("rollover"), "manifest rollover")
    attic = _mapping(root.get("attic"), "manifest attic")
    bank = _mapping(
        artifacts.get("final-parent-centered-priority-bank.bin"),
        "manifest live bank",
    )
    page12 = _mapping(artifacts.get("page-12-active.bin"), "manifest Page12")
    receipt = _mapping(
        artifacts.get("o1c86-priority-state-receipt.json"),
        "manifest priority receipt",
    )
    final_bank = _mapping(root.get("final_priority_bank"), "manifest final bank")
    page12_report = _mapping(root.get("page12"), "manifest Page12 report")
    capacity = _mapping(
        page12_report.get("native_capacity_proof"), "manifest Page12 capacity"
    )
    clause_capacity = _mapping(
        capacity.get("clause_headroom_guarantee"),
        "manifest Page12 clause capacity",
    )
    residual_headroom = _mapping(
        capacity.get("recorded_residual_headroom"),
        "manifest Page12 residual headroom",
    )
    if (
        root.get("schema") != schema
        or root.get("attempt_id") != "O1C-0087"
        or set(artifacts) != artifact_names
        or O1C87_PUBLISHED_ARTIFACTS
        != artifact_names | {O1C87_MANIFEST_RELATIVE.name}
        or zero_call
        != {
            "native_solver_calls": 0,
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
            "page12_burned": False,
            "lineage25_burned": False,
            "page11_replay_authorized": False,
            "lineage24_replay_authorized": False,
            "page9_retry_or_replay_authorized": False,
        }
        or parent.get("attempt_id") != "O1C-0086"
        or parent.get("classification")
        != "PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN"
        or parent.get("stop_reason") != "globally-novel-clause"
        or parent.get("source_lineage_ordinal") != 24
        or parent.get("source_active_sha256") != BURNED_PAGE11_SHA256
        or parent.get("page11_burned") is not True
        or parent.get("lineage24_burned") is not True
        or parent.get("retry_or_replay_authorized") is not False
        or parent.get("global_novelty_baseline_clause_count") != 830
        or science.get("imported_science_attempt_id") != "O1C-0086"
        or science.get("imported_science_kind")
        != "fully-emitted-globally-novel-clauses"
        or science.get("imported_fully_emitted_clause_count") != 202
        or science.get("imported_globally_novel_clause_count") != 202
        or science.get("imported_literal_count") != 546_864
        or science.get("page9_retry_imported") is not False
        or science.get("o1c84_terminal_failure_imported_as_science") is not False
        or science.get("priority_magnitude_imported_as_science") is not False
        or rollover.get("source_active_sha256") != BURNED_PAGE11_SHA256
        or rollover.get("clause_count") != 202
        or rollover.get("literal_count") != 546_864
        or rollover.get("all_occurrences_new") is not True
        or rollover.get("all_occurrences_unique") is not True
        or rollover.get("all_occurrences_globally_novel_against_830_clause_attic")
        is not True
        or rollover.get("api")
        != "advance_causal_residency(next_lineage_ordinal=25,next_active_limit=254)"
        or attic.get("chunk_count") != 15
        or attic.get("union_clause_count") != 1_032
        or attic.get("union_literal_count") != 2_845_347
        or attic.get("union_serialized_bytes") != 11_385_707
        or attic.get("occurrence_count") != 1_040
        or attic.get("duplicate_occurrence_count") != 8
        or attic.get("strict_subsumption_pair_count") != 10
        or attic.get("undominated_clause_count") != 1_025
        or attic.get("prior_830_clause_union_is_exact_prefix") is not True
        or bank.get("serialized_bytes") != BANK_BYTES
        or bank.get("sha256") != LIVE_BANK_SHA256
        or bank.get("role") != "sealed-evolved-live-continuation-bank-bytes"
        or page12.get("serialized_bytes") != PRODUCTION_PAGE12_BYTES
        or page12.get("sha256") != PRODUCTION_PAGE12_SHA256
        or page12.get("role") != "fresh-lineage-25-page12-science-input"
        or receipt.get("serialized_bytes") != O1C86_PRIORITY_RECEIPT_BYTES
        or receipt.get("sha256") != O1C86_PRIORITY_RECEIPT_SHA256
        or receipt.get("role") != "canonical-o1c86-evolved-priority-state-receipt"
        or final_bank.get("serialized_bytes") != BANK_BYTES
        or final_bank.get("sha256") != LIVE_BANK_SHA256
        or final_bank.get("receipt_serialized_bytes") != O1C86_PRIORITY_RECEIPT_BYTES
        or final_bank.get("receipt_sha256") != O1C86_PRIORITY_RECEIPT_SHA256
        or final_bank.get("fresh_seed_parser_compatible") is not False
        or final_bank.get("maximum_evolved_count") != LIVE_BANK_MAXIMUM_COUNT
        or final_bank.get("maximum_evolved_count_variables") != [256]
        or final_bank.get("minimum_nonzero_evolved_count") != 139
        or final_bank.get("aggregate_evolved_count") != LIVE_BANK_TOTAL_COUNT
        or final_bank.get("coordinate_record_count") != COORDINATE_COUNT
        or final_bank.get("record_bytes") != RECORD_BYTES
        or final_bank.get("zero_coordinate_variables") != [MISSING_VARIABLE]
        or final_bank.get("eligible_coordinate_count") != LIVE_BANK_ELIGIBLE_COORDINATES
        or final_bank.get("receipt_bank_hex_byte_equal") is not True
        or final_bank.get("priority_is_key_bit_belief") is not False
        or page12_report.get("active_sha256") != PRODUCTION_PAGE12_SHA256
        or page12_report.get("serialized_bytes") != PRODUCTION_PAGE12_BYTES
        or page12_report.get("lineage_ordinal") != PRODUCTION_PAGE12_LINEAGE_ORDINAL
        or page12_report.get("active_limit") != PRODUCTION_PAGE12_ACTIVE_LIMIT
        or page12_report.get("clause_count") != PRODUCTION_PAGE12_CLAUSE_COUNT
        or page12_report.get("literal_count") != PRODUCTION_PAGE12_LITERAL_COUNT
        or page12_report.get("category_counts") != PRODUCTION_PAGE12_CATEGORY_COUNTS
        or page12_report.get("headroom") != PRODUCTION_PAGE12_HEADROOM
        or page12_report.get("fresh_identity") is not True
        or capacity.get("caps")
        != {
            "maximum_clauses": 512,
            "maximum_literals": 1_600_000,
            "maximum_serialized_bytes": 8_388_608,
        }
        or clause_capacity
        != {
            "native_vault_maximum_clauses": 512,
            "page12_input_clauses": 254,
            "maximum_additional_clauses_before_capacity_terminal": 258,
            "parent_centered_action_capacity": 256,
            "spare_clause_slots_beyond_action_capacity": 2,
            "proved_sufficient": True,
        }
        or residual_headroom != {"literals": 918_946, "serialized_bytes": 5_663_185}
        or capacity.get("literal_future_emission_safety_claimed") is not False
        or capacity.get("serialized_byte_future_emission_safety_claimed") is not False
    ):
        raise _error("O1C87 Page12 lineage-25 manifest contract")


def _validate_receipt(payload: bytes, bank: bytes) -> None:
    try:
        document = _mapping(
            _v21.load_native_json(payload.decode("utf-8")),
            "O1C86 priority receipt",
        )
        if document.get("schema") != O1C86_PRIORITY_RECEIPT_SCHEMA:
            raise _error("O1C86 priority receipt schema")
        replay = dict(document)
        replay["schema"] = _v22.PRIORITY_STATE_SCHEMA
        _, receipt_bank, _ = _v22._validate_priority_state(
            replay, candidates=PRODUCTION_CANDIDATES
        )
    except (UnicodeDecodeError, json.JSONDecodeError, O1RelationalSearchError) as exc:
        raise _error("O1C86 priority receipt contract") from exc
    if receipt_bank != bank:
        raise _error("O1C86 priority receipt bank linkage")


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
) -> JointScoreSieveV26Result:
    """Validate one native-v23 document and its unchanged v6 lifecycle."""

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
    return JointScoreSieveV26Result(
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
    page12_path: str | Path,
    expected_source_sha256: str,
    expected_executable_sha256: str,
    expected_executable_bytes: int,
) -> _SealedPrelaunch:
    _, manifest_expected_bytes, manifest_expected_sha256, _ = _manifest_contract()
    source, source_bytes = _read_exact(
        source_path,
        label="native source",
        expected_bytes=Path(source_path).resolve(strict=True).stat().st_size,
        expected_sha256=expected_source_sha256,
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
        label="O1C87 manifest",
        expected_bytes=manifest_expected_bytes,
        expected_sha256=manifest_expected_sha256,
    )
    receipt, receipt_bytes = _read_exact(
        receipt_path,
        label="O1C86 priority receipt",
        expected_bytes=O1C86_PRIORITY_RECEIPT_BYTES,
        expected_sha256=O1C86_PRIORITY_RECEIPT_SHA256,
    )
    bank, bank_bytes = _read_exact(
        bank_path,
        label="live priority bank",
        expected_bytes=BANK_BYTES,
        expected_sha256=LIVE_BANK_SHA256,
    )
    page12, page12_bytes = _read_page12(page12_path)
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
        page12,
        page12_bytes,
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
    sealed_page12_path: str | Path | None = None,
) -> JointScoreSieveV26Result:
    """Validate a prebuilt native-v23 executable, then launch it exactly once."""

    started = time.perf_counter()
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
            else root / O1C87_MANIFEST_RELATIVE
        )
        receipt = (
            Path(priority_state_receipt_path)
            if priority_state_receipt_path is not None
            else root / O1C86_PRIORITY_RECEIPT_RELATIVE
        )
        page12 = (
            Path(sealed_page12_path)
            if sealed_page12_path is not None
            else root / O1C87_PAGE12_RELATIVE
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
            page12_path=page12,
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
            len(vault_bytes) != PRODUCTION_PAGE12_BYTES
            or vault_sha != PRODUCTION_PAGE12_SHA256
            or vault_bytes != sealed.page12_bytes
        ):
            raise _error("Page12 production seal")
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
            input_vault.sha256 != PRODUCTION_PAGE12_SHA256
            or _candidate_order(field) != PRODUCTION_CANDIDATES
        ):
            raise _error("Page12 parsed production seal")

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
        for original, resolved, before, name in (
            (source, sealed.source_path, sealed.source_bytes, "native source"),
            (
                executable_path,
                sealed.executable_path,
                sealed.executable_bytes,
                "executable",
            ),
            (manifest, sealed.manifest_path, sealed.manifest_bytes, "O1C87 manifest"),
            (receipt, sealed.receipt_path, sealed.receipt_bytes, "priority receipt"),
            (
                priority_seed_path,
                sealed.bank_path,
                sealed.bank_bytes,
                "priority seed",
            ),
            (page12, sealed.page12_path, sealed.page12_bytes, "sealed Page12"),
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
            raise JointScoreSieveV26Error(
                "joint-score-sieve-v26 execution failed: "
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
        elapsed = max(0.0, time.perf_counter() - started)
        telemetry = _v9._v8._v7._failure_telemetry(
            exc,
            elapsed_seconds=elapsed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
        message = str(exc)
        if not message.startswith("joint-score-sieve-v26"):
            message = f"joint-score-sieve-v26 adapter failed: {message}"
        raise _v9.JointScoreSieveExecutionError(
            message, failure_telemetry=telemetry
        ) from exc


__all__ = [
    "JOINT_SCORE_SIEVE_ADAPTER_SCHEMA",
    "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
    "LIVE_BANK_SHA256",
    "JointScoreSieveV26Error",
    "JointScoreSieveV26Result",
    "LiveBankRecord",
    "run_joint_score_sieve",
]
