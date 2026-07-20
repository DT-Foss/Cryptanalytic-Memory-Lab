"""Fail-closed O1C-0091 adapter for Page 14 and the sealed live bank.

Version 28 preserves v27's proof-mining and result-validation semantics while
moving the native boundary to result/source v25 and fresh lineage 27 Page 14.
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


JOINT_SCORE_SIEVE_ADAPTER_SCHEMA = "o1-256-joint-score-sieve-v28-adapter-v1"
JOINT_SCORE_SIEVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v25"
JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA = (
    "o1-256-cadical-joint-score-sieve-result-v6"
)
PRIORITY_STATE_SCHEMA = (
    "o1-256-o1c92-live-parent-centered-continuation-priority-state-v1"
)
PRIORITY_ACTION_SCHEMA = "o1-256-o1c92-failure-first-proof-mining-actions-v1"
PRIORITY_SEED_SCHEMA = "o1-256-o1c82-parent-centered-priority-seed-v1"
PRIORITY_SEED_MAGIC = "O1C82-PCP-SEED1"
PRIORITY_SEED_SOURCE = "sealed-live-continuation-bank"

OPERATOR_SEMANTICS = _v22.OPERATOR_SEMANTICS
PRODUCTION_CANDIDATES = _v22.PRODUCTION_CANDIDATES
PROBE_TRACE_RECORD_BYTES = _v22.PROBE_TRACE_RECORD_BYTES
ACTION_TRACE_RECORD_BYTES = _v22.ACTION_TRACE_RECORD_BYTES

LIVE_BANK_SHA256 = "715bfbc22fa2162ec8546eed21cf609318d3c5be806092dc4fe4b07cc4d9d654"
LIVE_BANK_TOTAL_COUNT = 249_671
LIVE_BANK_MAXIMUM_COUNT = 2_180
LIVE_BANK_ELIGIBLE_COORDINATES = 255

O1C91_MANIFEST_SCHEMA = "o1-256-o1c91-page14-causal-rollover-preparation-v1"
O1C91_MANIFEST_BYTES = 20_129
O1C91_MANIFEST_SHA256 = (
    "e46ca7373bc3a94efc30dcd309728005e3bee8b93983dc2c396f45bd487dd458"
)
O1C91_MANIFEST_ARTIFACTS = frozenset(
    {
        "lineage-27-new-chunk.vault",
        "page-14-active.bin",
        "residency.json",
        "activation-ledger.json",
        "occurrence-ledger.json",
        "subsumption-relations.json",
        "common-signed-intersection-audit.json",
        "final-parent-centered-priority-bank.bin",
        "o1c90-priority-state-receipt.json",
    }
)
O1C91_PUBLISHED_ARTIFACTS = O1C91_MANIFEST_ARTIFACTS | {
    "causal-rollover-preparation-manifest.json"
}
O1C91_MANIFEST_RELATIVE = Path(
    "research/o1c91_page14_causal_rollover_seed_20260720/"
    "causal-rollover-preparation-manifest.json"
)
O1C91_PAGE14_RELATIVE = Path(
    "research/o1c91_page14_causal_rollover_seed_20260720/page-14-active.bin"
)

O1C90_PRIORITY_RECEIPT_SCHEMA = (
    "o1-256-o1c90-live-parent-centered-continuation-priority-state-v1"
)
O1C90_PRIORITY_RECEIPT_BYTES = 52_016
O1C90_PRIORITY_RECEIPT_SHA256 = (
    "4e13df322e5c30b0022e4a6346ceb4db239628d317f4c9480cb81177b8ab53dd"
)
PRODUCTION_PAGE14_BYTES = 2_817_779
PRODUCTION_PAGE14_SHA256 = (
    "00a5a4a7b33f1c09c8df24162709b17994bad5825d92476a5f5283a3bf025c7e"
)
PRODUCTION_PAGE14_LINEAGE_ORDINAL = 27
PRODUCTION_PAGE14_ACTIVE_LIMIT = 252
PRODUCTION_PAGE14_CLAUSE_COUNT = 252
PRODUCTION_PAGE14_LITERAL_COUNT = 704_145
PRODUCTION_PAGE14_CATEGORY_COUNTS: Mapping[str, int] = {
    "structural_root": 8,
    "pinned_core": 43,
    "inherited_debt": 0,
    "new_debt": 201,
    "hot_event": 0,
    "recycled": 0,
}
PRODUCTION_PAGE14_HEADROOM: Mapping[str, int] = {
    "clauses": 260,
    "literals": 895_855,
    "serialized_bytes": 5_570_829,
}
PRODUCTION_PAGE14_MISSING_NEW_UNION_INDICES = (
    1295,
    1297,
    1327,
    1425,
    1426,
    1430,
    1431,
    1434,
    1435,
    1436,
    1437,
    1440,
    1441,
    1442,
    1443,
    1447,
    1455,
    1457,
    1458,
    1462,
    1463,
    1467,
    1476,
    1477,
    1481,
    1482,
    1494,
    1495,
    1499,
    1500,
    1504,
    1505,
    1506,
    1507,
    1508,
    1509,
    1510,
    1511,
    1515,
    1516,
    1517,
    1518,
    1519,
    1520,
    1521,
    1522,
    1525,
    1526,
    1527,
    1528,
    1529,
    1530,
    1531,
    1532,
    1533,
    1534,
    1535,
    1536,
    1539,
    1540,
    1541,
    1542,
    1543,
    1544,
    1545,
    1546,
    1547,
    1548,
    1549,
    1550,
)
PRODUCTION_PAGE14_RESIDENT_NEW_UNION_INDICES = tuple(
    index
    for index in range(1_291, 1_551)
    if index not in frozenset(PRODUCTION_PAGE14_MISSING_NEW_UNION_INDICES)
)
PRODUCTION_PAGE14_NEW_STRICT_SUBSUMPTION_RELATIONS = (
    (1296, 1295),
    (1298, 1297),
    (1328, 1327),
)
_PRODUCTION_PAGE14_NEW_STRICT_SUBSUMPTION_ROWS: tuple[
    Mapping[str, int | str], ...
] = (
    {
        "literal_delta": 2,
        "subsumed_clause_sha256": (
            "9f3f043b2ce8df69a7a7e917cd5d66bcb5ff12c2716520904f89650c3f7a09a2"
        ),
        "subsumed_index": 1295,
        "subsumed_literal_count": 2789,
        "subsumer_clause_sha256": (
            "763f3090d46afbf29733c1559ce2225ef3063c24f6213d5a92518cc1c30a5b62"
        ),
        "subsumer_index": 1296,
        "subsumer_literal_count": 2787,
    },
    {
        "literal_delta": 15,
        "subsumed_clause_sha256": (
            "b525b33338694347010134e2d63b58e4c8e1897491bea77d9eccf87287de2c03"
        ),
        "subsumed_index": 1297,
        "subsumed_literal_count": 2804,
        "subsumer_clause_sha256": (
            "338e5a568c91bc132c49c5c33b392de8ff87862081dc5ab4cc6462fa3ab6ec55"
        ),
        "subsumer_index": 1298,
        "subsumer_literal_count": 2789,
    },
    {
        "literal_delta": 17,
        "subsumed_clause_sha256": (
            "c548f7c610701c3d840b7f1d73355690ec7b36b8725c6b8c1f472a7f1cf12a1f"
        ),
        "subsumed_index": 1327,
        "subsumed_literal_count": 2852,
        "subsumer_clause_sha256": (
            "4f5197d4eca4ba51b336e5575d9adfa0dcce94078ddb8ce33bc727f737427f24"
        ),
        "subsumer_index": 1328,
        "subsumer_literal_count": 2835,
    },
)
PRODUCTION_PAGE14_DOMINATED_MISSING_NEW_UNION_INDICES = (
    1295,
    1297,
    1327,
)
PRODUCTION_PAGE14_UNDOMINATED_MISSING_NEW_UNION_INDICES = tuple(
    index
    for index in PRODUCTION_PAGE14_MISSING_NEW_UNION_INDICES
    if index
    not in frozenset(PRODUCTION_PAGE14_DOMINATED_MISSING_NEW_UNION_INDICES)
)
PRODUCTION_PAGE14_PRIOR_NEWLY_RESIDENT_UNION_INDICES = (
    1032,
    1055,
    1061,
    1072,
    1089,
    1105,
    1111,
    1121,
    1127,
    1136,
    1190,
    1209,
    1224,
    1235,
)
PRODUCTION_PAGE14_PRIOR_REMAINING_MISSING_UNION_INDICES = (
    1036,
    1051,
    1069,
    1092,
    1093,
    1099,
    1109,
    1116,
    1120,
    1123,
    1132,
    1133,
    1152,
    1185,
    1187,
    1206,
    1230,
    1238,
    1244,
    1247,
    1250,
    1256,
    1258,
    1260,
    1262,
    1265,
    1268,
    1270,
    1272,
    1273,
    1274,
    1276,
    1277,
    1279,
    1282,
    1284,
    1286,
    1287,
    1288,
    1290,
)
PRODUCTION_PAGE14_NEVER_RESIDENT_UNDOMINATED_UNION_INDICES = (
    PRODUCTION_PAGE14_PRIOR_REMAINING_MISSING_UNION_INDICES
    + PRODUCTION_PAGE14_UNDOMINATED_MISSING_NEW_UNION_INDICES
)

O1C91_LINEAGE27_CHUNK_BYTES = 2_976_407
O1C91_LINEAGE27_CHUNK_SHA256 = (
    "75778121b2cf9277e861057eafec70a8fca649feef38d635fdfae1b2626ed3df"
)
O1C91_LINEAGE27_CHUNK_CLAUSE_COUNT = 260
O1C91_LINEAGE27_CHUNK_LITERAL_COUNT = 743_794

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

NATIVE_SOURCE_RELATIVE = Path("native/cadical_o1_joint_score_sieve_v25.cpp")
O1C91_LIVE_BANK_RELATIVE = Path(
    "research/o1c91_page14_causal_rollover_seed_20260720/"
    "final-parent-centered-priority-bank.bin"
)
O1C90_PRIORITY_RECEIPT_RELATIVE = Path(
    "research/o1c91_page14_causal_rollover_seed_20260720/"
    "o1c90-priority-state-receipt.json"
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


class JointScoreSieveV28Error(O1RelationalSearchError):
    """Native-v25 execution or continuation validation failed."""


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
class JointScoreSieveV28Result:
    """Typed native-v25 result and its validated evolved bank."""

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
    page14_path: Path
    page14_bytes: bytes


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _error(field: str) -> JointScoreSieveV28Error:
    return JointScoreSieveV28Error(f"joint-score-sieve-v28 {field} differs")


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


def _read_page14(path: str | Path) -> tuple[Path, bytes]:
    io_v1 = _v9._v8._v7._v1
    resolved, payload, digest = io_v1._read_input(path, "Page14")
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
    if len(payload) != PRODUCTION_PAGE14_BYTES or digest != PRODUCTION_PAGE14_SHA256:
        raise _error("Page14 active projection seal")
    return resolved, payload


def _manifest_contract() -> tuple[str, int, str, frozenset[str]]:
    """Return the sealed O1C-0091 preparation contract."""

    return (
        O1C91_MANIFEST_SCHEMA,
        _positive(O1C91_MANIFEST_BYTES, "O1C91 manifest byte count"),
        _sha(O1C91_MANIFEST_SHA256, "O1C91 manifest digest"),
        O1C91_MANIFEST_ARTIFACTS,
    )


def _validate_new_clause_residency(value: object) -> None:
    report = _mapping(value, "manifest Page14 new-clause residency")
    missing_indices = list(PRODUCTION_PAGE14_MISSING_NEW_UNION_INDICES)
    rows_value = report.get("missing_clauses")
    if not isinstance(rows_value, list) or len(rows_value) != len(missing_indices):
        raise _error("manifest Page14 new-clause residency")
    rows: list[dict[str, object]] = []
    for union_index, row_value in zip(missing_indices, rows_value, strict=True):
        row = _mapping(row_value, "manifest Page14 missing clause")
        if (
            set(row) != {"clause_sha256", "source_index", "union_index"}
            or row.get("union_index") != union_index
            or row.get("source_index") != union_index - 1_291
        ):
            raise _error("manifest Page14 missing clause")
        rows.append(
            {
                "clause_sha256": _sha(
                    row.get("clause_sha256"), "manifest Page14 missing clause digest"
                ),
                "source_index": union_index - 1_291,
                "union_index": union_index,
            }
        )
    if report != {
        "new_union_index_start": 1_291,
        "new_union_index_stop_exclusive": 1_551,
        "attic_retained_clause_count": 260,
        "resident_clause_count": 190,
        "resident_union_indices": list(
            PRODUCTION_PAGE14_RESIDENT_NEW_UNION_INDICES
        ),
        "missing_clause_count": 70,
        "missing_union_indices": missing_indices,
        "dominated_missing_clause_count": 3,
        "dominated_missing_union_indices": list(
            PRODUCTION_PAGE14_DOMINATED_MISSING_NEW_UNION_INDICES
        ),
        "undominated_missing_clause_count": 67,
        "undominated_missing_union_indices": list(
            PRODUCTION_PAGE14_UNDOMINATED_MISSING_NEW_UNION_INDICES
        ),
        "missing_clauses": rows,
    }:
        raise _error("manifest Page14 new-clause residency")


def _validate_prior_clause_residency(value: object) -> None:
    report = _mapping(value, "manifest Page14 prior-clause residency")
    if report != {
        "prior_missing_clause_count": 54,
        "newly_resident_clause_count": 14,
        "newly_resident_union_indices": list(
            PRODUCTION_PAGE14_PRIOR_NEWLY_RESIDENT_UNION_INDICES
        ),
        "remaining_missing_clause_count": 40,
        "remaining_missing_union_indices": list(
            PRODUCTION_PAGE14_PRIOR_REMAINING_MISSING_UNION_INDICES
        ),
    }:
        raise _error("manifest Page14 prior-clause residency")


def _validate_never_resident_undominated(value: object) -> None:
    report = _mapping(value, "manifest Page14 never-resident-undominated")
    if report != {
        "clause_count": 107,
        "union_indices": list(
            PRODUCTION_PAGE14_NEVER_RESIDENT_UNDOMINATED_UNION_INDICES
        ),
    }:
        raise _error("manifest Page14 never-resident-undominated")


def _validate_new_strict_subsumption_relations(value: object) -> None:
    if not isinstance(value, list) or len(value) != len(
        _PRODUCTION_PAGE14_NEW_STRICT_SUBSUMPTION_ROWS
    ):
        raise _error("manifest Page14 new strict-subsumption relations")
    rows: list[Mapping[str, object]] = []
    for row_value, expected in zip(
        value, _PRODUCTION_PAGE14_NEW_STRICT_SUBSUMPTION_ROWS, strict=True
    ):
        row = _mapping(
            row_value, "manifest Page14 new strict-subsumption relation"
        )
        for field in ("subsumed_clause_sha256", "subsumer_clause_sha256"):
            _sha(row.get(field), f"manifest Page14 relation {field}")
        if row != expected:
            raise _error("manifest Page14 new strict-subsumption relation")
        rows.append(row)
    pairs = tuple(
        (
            _nonnegative(row["subsumer_index"], "manifest Page14 subsumer index"),
            _nonnegative(row["subsumed_index"], "manifest Page14 subsumed index"),
        )
        for row in rows
    )
    if pairs != PRODUCTION_PAGE14_NEW_STRICT_SUBSUMPTION_RELATIONS:
        raise _error("manifest Page14 new strict-subsumption relation pairs")


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
        raise _error("O1C91 manifest JSON") from exc
    if canonical != payload:
        raise _error("O1C91 canonical manifest encoding")

    artifacts = _mapping(root.get("artifacts"), "manifest artifacts")
    zero_call = _mapping(root.get("zero_call"), "manifest zero-call boundary")
    authorization = _mapping(
        root.get("authorization"), "manifest authorization boundary"
    )
    parent = _mapping(root.get("parent"), "manifest parent")
    science = _mapping(root.get("science_boundary"), "manifest science boundary")
    rollover = _mapping(root.get("rollover"), "manifest rollover")
    attic = _mapping(root.get("attic"), "manifest attic")
    chunk = _mapping(
        artifacts.get("lineage-27-new-chunk.vault"), "manifest lineage27 chunk"
    )
    bank = _mapping(
        artifacts.get("final-parent-centered-priority-bank.bin"),
        "manifest live bank",
    )
    page14 = _mapping(artifacts.get("page-14-active.bin"), "manifest Page14")
    receipt = _mapping(
        artifacts.get("o1c90-priority-state-receipt.json"),
        "manifest priority receipt",
    )
    final_bank = _mapping(root.get("final_priority_bank"), "manifest final bank")
    page14_report = _mapping(root.get("page14"), "manifest Page14 report")
    sacrifice = _mapping(
        page14_report.get("one_slot_residency_sacrifice"),
        "manifest Page14 one-slot residency sacrifice",
    )
    capacity = _mapping(
        page14_report.get("native_capacity_proof"), "manifest Page14 capacity"
    )
    clause_capacity = _mapping(
        capacity.get("clause_headroom_guarantee"),
        "manifest Page14 clause capacity",
    )
    residual_headroom = _mapping(
        capacity.get("recorded_residual_headroom"),
        "manifest Page14 residual headroom",
    )
    _validate_new_clause_residency(page14_report.get("new_clause_residency"))
    _validate_prior_clause_residency(page14_report.get("prior_clause_residency"))
    _validate_never_resident_undominated(
        page14_report.get("never_resident_undominated")
    )
    _validate_new_strict_subsumption_relations(
        attic.get("new_strict_subsumption_relations")
    )

    if (
        set(root)
        != {
            "schema",
            "attempt_id",
            "zero_call",
            "authorization",
            "parent",
            "science_boundary",
            "rollover",
            "attic",
            "page14",
            "carried_context",
            "final_priority_bank",
            "artifacts",
        }
        or root.get("schema") != schema
        or root.get("attempt_id") != "O1C-0091"
        or set(artifacts) != artifact_names
        or O1C91_PUBLISHED_ARTIFACTS
        != artifact_names | {O1C91_MANIFEST_RELATIVE.name}
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
            "page14_burned": False,
            "lineage27_burned": False,
            "page13_replay_authorized": False,
            "lineage26_replay_authorized": False,
            "page9_retry_or_replay_authorized": False,
        }
        or parent.get("attempt_id") != "O1C-0090"
        or parent.get("classification")
        != "PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN"
        or parent.get("stop_reason") != "globally-novel-clause"
        or parent.get("source_lineage_ordinal") != 26
        or parent.get("source_active_sha256") != BURNED_PAGE13_SHA256
        or parent.get("page13_burned") is not True
        or parent.get("lineage26_burned") is not True
        or parent.get("retry_or_replay_authorized") is not False
        or parent.get("global_novelty_baseline_clause_count") != 1_291
        or parent.get("preparation_manifest_sha256")
        != "467e519df281db4fc10de9223195dfedba9fd51edc93b40883f59fd3821e29ec"
        or parent.get("initial_artifact_count") != 10
        or parent.get("initial_artifacts_byte_equal_to_fresh_page13_regeneration")
        is not True
        or science.get("imported_science_attempt_id") != "O1C-0090"
        or science.get("imported_science_kind")
        != "fully-emitted-globally-novel-clauses"
        or science.get("imported_fully_emitted_clause_count")
        != O1C91_LINEAGE27_CHUNK_CLAUSE_COUNT
        or science.get("imported_globally_novel_clause_count")
        != O1C91_LINEAGE27_CHUNK_CLAUSE_COUNT
        or science.get("imported_literal_count")
        != O1C91_LINEAGE27_CHUNK_LITERAL_COUNT
        or science.get("all_sources") != ["trail_upper_bound"]
        or science.get("all_classifications") != ["new"]
        or science.get("page9_retry_imported") is not False
        or science.get("o1c84_terminal_failure_imported_as_science") is not False
        or science.get("priority_magnitude_imported_as_science") is not False
        or rollover.get("source_active_sha256") != BURNED_PAGE13_SHA256
        or rollover.get("chunk_sha256") != O1C91_LINEAGE27_CHUNK_SHA256
        or rollover.get("clause_count") != O1C91_LINEAGE27_CHUNK_CLAUSE_COUNT
        or rollover.get("literal_count") != O1C91_LINEAGE27_CHUNK_LITERAL_COUNT
        or rollover.get("serialized_bytes") != O1C91_LINEAGE27_CHUNK_BYTES
        or rollover.get("all_occurrences_new") is not True
        or rollover.get("all_occurrences_unique") is not True
        or rollover.get("all_occurrences_globally_novel_against_1291_clause_attic")
        is not True
        or rollover.get("source_counts") != {"trail_upper_bound": 260}
        or rollover.get("classification_counts") != {"new": 260}
        or rollover.get("stream_id") != "o1c90-episode-00"
        or rollover.get("api")
        != "advance_causal_residency(next_lineage_ordinal=27,next_active_limit=252)"
        or attic.get("chunk_count") != 17
        or attic.get("union_sha256")
        != "3db1ae23e3aa7b99196905f13234c2001aa75407af322eba1fc431f7a5540475"
        or attic.get("union_clause_count") != 1_551
        or attic.get("union_literal_count") != 4_334_114
        or attic.get("union_serialized_bytes") != 17_342_851
        or attic.get("occurrence_count") != 1_559
        or attic.get("duplicate_occurrence_count") != 8
        or attic.get("strict_subsumption_pair_count") != 13
        or attic.get("new_strict_subsumption_pair_count") != 3
        or attic.get("prior_relation_set_preserved_exactly") is not True
        or attic.get("undominated_clause_count") != 1_541
        or attic.get("prior_1291_clause_union_is_exact_prefix") is not True
        or chunk
        != {
            "serialized_bytes": O1C91_LINEAGE27_CHUNK_BYTES,
            "sha256": O1C91_LINEAGE27_CHUNK_SHA256,
            "role": "immutable-all-new-lineage-26-evidence-chunk",
        }
        or bank.get("serialized_bytes") != BANK_BYTES
        or bank.get("sha256") != LIVE_BANK_SHA256
        or bank.get("role") != "sealed-evolved-live-continuation-bank-bytes"
        or page14
        != {
            "serialized_bytes": PRODUCTION_PAGE14_BYTES,
            "sha256": PRODUCTION_PAGE14_SHA256,
            "role": "fresh-lineage-27-page14-science-input",
        }
        or receipt
        != {
            "serialized_bytes": O1C90_PRIORITY_RECEIPT_BYTES,
            "sha256": O1C90_PRIORITY_RECEIPT_SHA256,
            "role": "canonical-o1c90-evolved-priority-state-receipt",
        }
        or final_bank.get("serialized_bytes") != BANK_BYTES
        or final_bank.get("sha256") != LIVE_BANK_SHA256
        or final_bank.get("receipt_artifact")
        != "o1c90-priority-state-receipt.json"
        or final_bank.get("receipt_serialized_bytes")
        != O1C90_PRIORITY_RECEIPT_BYTES
        or final_bank.get("receipt_sha256") != O1C90_PRIORITY_RECEIPT_SHA256
        or final_bank.get("fresh_seed_parser_compatible") is not False
        or final_bank.get("maximum_evolved_count") != LIVE_BANK_MAXIMUM_COUNT
        or final_bank.get("maximum_evolved_count_variables") != [15]
        or final_bank.get("minimum_nonzero_evolved_count") != 224
        or final_bank.get("aggregate_evolved_count") != LIVE_BANK_TOTAL_COUNT
        or final_bank.get("coordinate_record_count") != COORDINATE_COUNT
        or final_bank.get("record_bytes") != RECORD_BYTES
        or final_bank.get("zero_coordinate_variables") != [MISSING_VARIABLE]
        or final_bank.get("eligible_coordinate_count")
        != LIVE_BANK_ELIGIBLE_COORDINATES
        or final_bank.get("receipt_bank_hex_byte_equal") is not True
        or final_bank.get("priority_is_key_bit_belief") is not False
        or final_bank.get("validation_contract")
        != "o1c90-live-continuation-bank-with-state-receipt"
        or final_bank.get("next_action_parser_gate")
        != "require-live-continuation-parser;do-not-use-fresh-seed-parser"
        or page14_report.get("active_sha256") != PRODUCTION_PAGE14_SHA256
        or page14_report.get("serialized_bytes") != PRODUCTION_PAGE14_BYTES
        or page14_report.get("lineage_ordinal")
        != PRODUCTION_PAGE14_LINEAGE_ORDINAL
        or page14_report.get("active_limit") != PRODUCTION_PAGE14_ACTIVE_LIMIT
        or page14_report.get("clause_count") != PRODUCTION_PAGE14_CLAUSE_COUNT
        or page14_report.get("literal_count") != PRODUCTION_PAGE14_LITERAL_COUNT
        or page14_report.get("category_counts")
        != PRODUCTION_PAGE14_CATEGORY_COUNTS
        or page14_report.get("headroom") != PRODUCTION_PAGE14_HEADROOM
        or page14_report.get("fresh_identity") is not True
        or sacrifice
        != {
            "source_input_clause_count": 253,
            "fully_emitted_clause_count": 260,
            "unsacrificed_terminal_clause_count": 513,
            "native_vault_maximum_clauses": 512,
            "terminal_overflow_clause_count": 1,
            "prior_active_limit": 253,
            "next_active_limit": 252,
            "residency_slots_sacrificed": 1,
            "measured_clause_headroom": 260,
            "prior_structural_root_count": 5,
            "new_structural_root_count": 3,
            "next_structural_root_count": 8,
            "pinned_core_count_preserved": 43,
        }
        or capacity.get("caps")
        != {
            "maximum_clauses": 512,
            "maximum_literals": 1_600_000,
            "maximum_serialized_bytes": 8_388_608,
        }
        or clause_capacity
        != {
            "native_vault_maximum_clauses": 512,
            "page14_input_clauses": 252,
            "maximum_additional_clauses_before_capacity_terminal": 260,
            "parent_centered_action_capacity": 256,
            "spare_clause_slots_beyond_action_capacity": 4,
            "proved_sufficient": True,
        }
        or residual_headroom
        != {"literals": 895_855, "serialized_bytes": 5_570_829}
        or capacity.get("literal_future_emission_safety_claimed") is not False
        or capacity.get("serialized_byte_future_emission_safety_claimed") is not False
    ):
        raise _error("O1C91 Page14 lineage-27 manifest contract")


def _validate_receipt(payload: bytes, bank: bytes) -> None:
    try:
        document = _mapping(
            _v21.load_native_json(payload.decode("utf-8")),
            "O1C90 priority receipt",
        )
        if document.get("schema") != O1C90_PRIORITY_RECEIPT_SCHEMA:
            raise _error("O1C90 priority receipt schema")
        replay = dict(document)
        replay["schema"] = _v22.PRIORITY_STATE_SCHEMA
        _, receipt_bank, _ = _v22._validate_priority_state(
            replay, candidates=PRODUCTION_CANDIDATES
        )
    except (UnicodeDecodeError, json.JSONDecodeError, O1RelationalSearchError) as exc:
        raise _error("O1C90 priority receipt contract") from exc
    if receipt_bank != bank:
        raise _error("O1C90 priority receipt bank linkage")


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
) -> JointScoreSieveV28Result:
    """Validate one native-v25 document and its unchanged v6 lifecycle."""

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
    return JointScoreSieveV28Result(
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
    page14_path: str | Path,
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
        label="O1C91 manifest",
        expected_bytes=manifest_expected_bytes,
        expected_sha256=manifest_expected_sha256,
    )
    receipt, receipt_bytes = _read_exact(
        receipt_path,
        label="O1C90 priority receipt",
        expected_bytes=O1C90_PRIORITY_RECEIPT_BYTES,
        expected_sha256=O1C90_PRIORITY_RECEIPT_SHA256,
    )
    bank, bank_bytes = _read_exact(
        bank_path,
        label="live priority bank",
        expected_bytes=BANK_BYTES,
        expected_sha256=LIVE_BANK_SHA256,
    )
    page14, page14_bytes = _read_page14(page14_path)
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
        page14,
        page14_bytes,
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
    sealed_page14_path: str | Path | None = None,
) -> JointScoreSieveV28Result:
    """Validate a prebuilt native-v25 executable, then launch it exactly once."""

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
            else root / O1C91_MANIFEST_RELATIVE
        )
        receipt = (
            Path(priority_state_receipt_path)
            if priority_state_receipt_path is not None
            else root / O1C90_PRIORITY_RECEIPT_RELATIVE
        )
        page14 = (
            Path(sealed_page14_path)
            if sealed_page14_path is not None
            else root / O1C91_PAGE14_RELATIVE
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
            page14_path=page14,
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
            len(vault_bytes) != PRODUCTION_PAGE14_BYTES
            or vault_sha != PRODUCTION_PAGE14_SHA256
            or vault_bytes != sealed.page14_bytes
        ):
            raise _error("Page14 production seal")
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
            input_vault.sha256 != PRODUCTION_PAGE14_SHA256
            or _candidate_order(field) != PRODUCTION_CANDIDATES
        ):
            raise _error("Page14 parsed production seal")

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
            (manifest, sealed.manifest_path, sealed.manifest_bytes, "O1C91 manifest"),
            (receipt, sealed.receipt_path, sealed.receipt_bytes, "priority receipt"),
            (
                priority_seed_path,
                sealed.bank_path,
                sealed.bank_bytes,
                "priority seed",
            ),
            (page14, sealed.page14_path, sealed.page14_bytes, "sealed Page14"),
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
            raise JointScoreSieveV28Error(
                "joint-score-sieve-v28 execution failed: "
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
        if not message.startswith("joint-score-sieve-v28"):
            message = f"joint-score-sieve-v28 adapter failed: {message}"
        raise _v9.JointScoreSieveExecutionError(
            message, failure_telemetry=telemetry
        ) from exc


__all__ = [
    "JOINT_SCORE_SIEVE_ADAPTER_SCHEMA",
    "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
    "LIVE_BANK_SHA256",
    "JointScoreSieveV28Error",
    "JointScoreSieveV28Result",
    "LiveBankRecord",
    "run_joint_score_sieve",
]
