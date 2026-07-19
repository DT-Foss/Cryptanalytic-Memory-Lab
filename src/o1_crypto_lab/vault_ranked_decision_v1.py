"""Target-free O1C70 suffix-vote ranking with exact grouped singleton bounds.

The module consumes already-canonical public artifacts only.  Ranking polarity
comes from the O1C70 suffix votes; the public APPLE8 potential contributes only
the magnitude tie-breaker obtained from its frozen width-6 grouped bound.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import struct
from typing import Mapping

from .criticality_potential import CriticalityPotentialField
from .joint_score_grouping_v1 import (
    COMPATIBILITY_GROUPING_BOUND_RULE,
    JointScoreCompatibilityGrouping,
    JointScoreGroupingError,
    build_compatibility_grouping,
    compatibility_grouped_upper_bound,
    outward_binary64_sum,
)
from .vault_phase_field_v1 import (
    VaultPhaseField,
    VaultPhaseFieldError,
    validate_production_vault_phase_field,
)


VAULT_RANKED_DECISION_SCHEMA = "o1-vault-ranked-decision-v1"
VAULT_RANKED_DECISION_READER_SCHEMA = "o1-256-cadical-vault-ranked-decision-reader-v1"
VAULT_RANKED_DECISION_OPERATOR = (
    "vault-suffix-vote-strength-then-singleton-grouped-bound-gap"
)
VAULT_RANKED_DECISION_VOTE_RULE = (
    "delta(v)=count(+v)-count(-v);omit-delta-zero;omit-potential-unobserved"
)
VAULT_RANKED_DECISION_BOUND_RULE = (
    "U+(v)=exact-width6-grouped-upper-bound(v=+1);"
    "U-(v)=exact-width6-grouped-upper-bound(v=-1);" + COMPATIBILITY_GROUPING_BOUND_RULE
)
VAULT_RANKED_DECISION_GAP_RULE = (
    "gap(v)=abs(U+(v)-U-(v))-in-exact-binary64-lattice;"
    "round-once-positive-infinity;finite-input-bounds-required;positive-zero"
)
VAULT_RANKED_DECISION_SORT_RULE = (
    "lexicographic:descending-abs-delta;descending-gap;ascending-variable"
)
VAULT_RANKED_DECISION_LITERAL_RULE = "literal(v)=sign(delta(v))*v"
VAULT_RANKED_DECISION_ORDER_ENCODING = "rank-order-concatenated-signed-i32le-literals"
VAULT_RANKED_DECISION_TABLE_ENCODING = (
    "rank-order-records:u32le-variable;i64le-delta;f64le-U+;f64le-U-;f64le-gap"
)

PRODUCTION_VAULT_SHA256 = (
    "cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858"
)
PRODUCTION_SUFFIX_CANONICAL_RECORDS_SHA256 = (
    "cbec487e215b70a22f91b0424f05809a06c0f6cdd5c3fa259bcab0b710e74521"
)
PRODUCTION_VOTE_FIELD_SHA256 = (
    "5d7fd1cfca56c1ab29f9e1490d28e16d3f5def611dad2f52c4ea4015678605fe"
)
PRODUCTION_POTENTIAL_SHA256 = (
    "8c6101b49c7050caf895bd9c496c05bcea9f43a2b27f378d7306be38b00d5390"
)
PRODUCTION_POTENTIAL_SOURCE_SHA256 = (
    "b0ef8533128cbfdbb618c46b686bff0bc20f6b2389251b1ae5a2109729d34f26"
)
PRODUCTION_GROUPING_SHA256 = (
    "3da85bae132d829252a68f0e3fd99220ea7d1ef365042806af810ff02f75f636"
)
PRODUCTION_GROUPING_WIDTH_CAP = 6
PRODUCTION_GROUPING_SERIALIZED_BYTES = 115_700
PRODUCTION_GROUP_COUNT = 2_885
PRODUCTION_FACTOR_COUNT = 7_557
PRODUCTION_OBSERVED_VARIABLE_COUNT = 2_981
PRODUCTION_KEY_VARIABLE_COUNT = 256
PRODUCTION_CANDIDATE_COUNT = 255
PRODUCTION_ZERO_DELTA_VARIABLES = (241,)
PRODUCTION_UNOBSERVED_NONZERO_VARIABLES: tuple[int, ...] = ()
PRODUCTION_ORDER_BYTES = 1_020
PRODUCTION_ORDER_SHA256 = (
    "26c0063f4eed586ef67535cccabacc07d945587a603cbb56dbb3b2225a32a2f5"
)
PRODUCTION_RANK_TABLE_BYTES = 9_180
PRODUCTION_RANK_TABLE_SHA256 = (
    "d3a007ebee7c515289d33be30757f769b2c1fde618fb5c6c312ea9f3509380ae"
)

_SPEC_BYTES = (
    b"o1-vault-ranked-decision-v1\n"
    b"inputs=canonical-vault-suffix-votes;canonical-public-potential;"
    b"canonical-width6-grouping\n"
    b"eligible=nonzero-vote-and-observed-by-potential\n"
    b"delta(v)=count(+v)-count(-v)\n"
    b"U+(v)=exact-width6-grouped-upper-bound-under-singleton-v=+1\n"
    b"U-(v)=exact-width6-grouped-upper-bound-under-singleton-v=-1\n"
    b"gap(v)=absolute-exact-binary64-lattice-difference-of-U+-and-U-;"
    b"round-once-toward-positive-infinity;finite-bounds;positive-zero\n"
    b"sort=descending-abs-delta;descending-gap;ascending-variable\n"
    b"literal(v)=sign(delta(v))*v\n"
    b"order-encoding=concatenated-signed-i32le-literals-in-rank-order\n"
    b"table-encoding=rank-order-u32le-variable,i64le-delta,f64le-U+,"
    b"f64le-U-,f64le-gap\n"
)
VAULT_RANKED_DECISION_SPEC_SHA256 = (
    "974d0f915ef827ecaa453f795a649f78b72bd38be7f413c8eb2c104de58e4543"
)

_INT32_MAX = (1 << 31) - 1
_INT64_MIN = -(1 << 63)
_INT64_MAX = (1 << 63) - 1
_UINT32_MAX = (1 << 32) - 1


class VaultRankedDecisionError(ValueError):
    """A ranking input, canonical projection, or frozen identity differs."""


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _f64le(value: float) -> bytes:
    return struct.pack("<d", value)


def canonical_gap(u_plus: float, u_minus: float) -> float:
    """Round ``abs(u_plus - u_minus)`` once upward from the exact lattice."""

    if (
        isinstance(u_plus, bool)
        or not isinstance(u_plus, float)
        or not math.isfinite(u_plus)
        or isinstance(u_minus, bool)
        or not isinstance(u_minus, float)
        or not math.isfinite(u_minus)
    ):
        raise VaultRankedDecisionError("ranked decision bound differs")
    high, low = max(u_plus, u_minus), min(u_plus, u_minus)
    try:
        gap = outward_binary64_sum((high, -low))
    except JointScoreGroupingError as exc:
        raise VaultRankedDecisionError("ranked decision gap differs") from exc
    if not math.isfinite(gap) or gap < 0.0:
        raise VaultRankedDecisionError("ranked decision gap differs")
    return 0.0 if gap == 0.0 else gap


@dataclass(frozen=True, slots=True)
class VaultRankedDecisionRow:
    """One eligible variable and its complete canonical ranking evidence."""

    variable: int
    delta: int
    u_plus: float
    u_minus: float
    gap: float

    def __post_init__(self) -> None:
        if (
            isinstance(self.variable, bool)
            or not isinstance(self.variable, int)
            or not 1 <= self.variable <= min(_INT32_MAX, _UINT32_MAX)
            or isinstance(self.delta, bool)
            or not isinstance(self.delta, int)
            or not _INT64_MIN <= self.delta <= _INT64_MAX
            or self.delta == 0
            or isinstance(self.u_plus, bool)
            or not isinstance(self.u_plus, float)
            or not math.isfinite(self.u_plus)
            or isinstance(self.u_minus, bool)
            or not isinstance(self.u_minus, float)
            or not math.isfinite(self.u_minus)
            or isinstance(self.gap, bool)
            or not isinstance(self.gap, float)
            or not math.isfinite(self.gap)
            or self.gap < 0.0
            or _f64le(self.gap) != _f64le(canonical_gap(self.u_plus, self.u_minus))
        ):
            raise VaultRankedDecisionError("ranked decision row differs")

    @property
    def literal(self) -> int:
        return self.variable if self.delta > 0 else -self.variable

    @property
    def table_bytes(self) -> bytes:
        return struct.pack(
            "<Iqddd",
            self.variable,
            self.delta,
            self.u_plus,
            self.u_minus,
            self.gap,
        )

    def describe(self) -> dict[str, object]:
        return {
            "variable": self.variable,
            "literal": self.literal,
            "delta": self.delta,
            "u_plus": self.u_plus,
            "u_plus_f64le_hex": _f64le(self.u_plus).hex(),
            "u_minus": self.u_minus,
            "u_minus_f64le_hex": _f64le(self.u_minus).hex(),
            "gap": self.gap,
            "gap_f64le_hex": _f64le(self.gap).hex(),
        }


def _rank_key(row: VaultRankedDecisionRow) -> tuple[int, float, int]:
    return (-abs(row.delta), -row.gap, row.variable)


@dataclass(frozen=True, slots=True)
class VaultRankedDecision:
    """Immutable ranking plus every canonical adapter-facing byte projection."""

    source_vault_sha256: str
    suffix_canonical_records_sha256: str
    vote_field_sha256: str
    potential_sha256: str
    potential_source_sha256: str
    grouping_sha256: str
    grouping_width_cap: int
    key_variable_count: int
    observed_variable_count: int
    zero_delta_variables: tuple[int, ...]
    unobserved_nonzero_variables: tuple[int, ...]
    rows: tuple[VaultRankedDecisionRow, ...]
    spec_bytes: bytes
    spec_sha256: str
    ranked_literals: tuple[int, ...]
    order_bytes: bytes
    order_sha256: str
    rank_table_bytes: bytes
    rank_table_sha256: str

    def __post_init__(self) -> None:
        _validate_decision(self)

    @property
    def candidate_count(self) -> int:
        return len(self.rows)

    def reader_binding(self) -> dict[str, object]:
        """Return the strict JSON-safe mapping consumed by adapters/runners."""

        return {
            "schema": VAULT_RANKED_DECISION_READER_SCHEMA,
            "operator": VAULT_RANKED_DECISION_OPERATOR,
            "source_vault_sha256": self.source_vault_sha256,
            "suffix_canonical_records_sha256": (self.suffix_canonical_records_sha256),
            "vote_field_sha256": self.vote_field_sha256,
            "potential_sha256": self.potential_sha256,
            "potential_source_sha256": self.potential_source_sha256,
            "grouping_sha256": self.grouping_sha256,
            "grouping_width_cap": self.grouping_width_cap,
            "key_variable_count": self.key_variable_count,
            "observed_variable_count": self.observed_variable_count,
            "candidate_count": self.candidate_count,
            "zero_delta_count": len(self.zero_delta_variables),
            "unobserved_nonzero_count": len(self.unobserved_nonzero_variables),
            "vote_rule": VAULT_RANKED_DECISION_VOTE_RULE,
            "bound_rule": VAULT_RANKED_DECISION_BOUND_RULE,
            "gap_rule": VAULT_RANKED_DECISION_GAP_RULE,
            "sort_rule": VAULT_RANKED_DECISION_SORT_RULE,
            "literal_rule": VAULT_RANKED_DECISION_LITERAL_RULE,
            "reader_spec_bytes": len(self.spec_bytes),
            "reader_spec_sha256": self.spec_sha256,
            "order_encoding": VAULT_RANKED_DECISION_ORDER_ENCODING,
            "ranked_literals": list(self.ranked_literals),
            "order_bytes": len(self.order_bytes),
            "order_sha256": self.order_sha256,
            "rank_table_encoding": VAULT_RANKED_DECISION_TABLE_ENCODING,
            "rank_table_rows": len(self.rows),
            "rank_table_bytes": len(self.rank_table_bytes),
            "rank_table_sha256": self.rank_table_sha256,
        }

    def describe(self) -> dict[str, object]:
        """Return complete JSON-safe identities, omissions, and rank rows."""

        return {
            **self.reader_binding(),
            "decision_schema": VAULT_RANKED_DECISION_SCHEMA,
            "zero_delta_variables": list(self.zero_delta_variables),
            "unobserved_nonzero_variables": list(self.unobserved_nonzero_variables),
            "rows": [row.describe() for row in self.rows],
        }


def vault_ranked_decision_spec_bytes() -> bytes:
    """Return the canonical ASCII algorithm specification."""

    if hashlib.sha256(_SPEC_BYTES).hexdigest() != VAULT_RANKED_DECISION_SPEC_SHA256:
        raise VaultRankedDecisionError("ranked decision specification differs")
    return _SPEC_BYTES


def _canonical_artifacts(
    rows: tuple[VaultRankedDecisionRow, ...],
) -> tuple[tuple[int, ...], bytes, str, bytes, str]:
    ranked_literals = tuple(row.literal for row in rows)
    order_bytes = b"".join(struct.pack("<i", literal) for literal in ranked_literals)
    rank_table_bytes = b"".join(row.table_bytes for row in rows)
    return (
        ranked_literals,
        order_bytes,
        hashlib.sha256(order_bytes).hexdigest(),
        rank_table_bytes,
        hashlib.sha256(rank_table_bytes).hexdigest(),
    )


def _validate_decision(decision: VaultRankedDecision) -> None:
    digests = (
        decision.source_vault_sha256,
        decision.suffix_canonical_records_sha256,
        decision.vote_field_sha256,
        decision.potential_sha256,
        decision.potential_source_sha256,
        decision.grouping_sha256,
        decision.spec_sha256,
        decision.order_sha256,
        decision.rank_table_sha256,
    )
    omitted = decision.zero_delta_variables + decision.unobserved_nonzero_variables
    covered = tuple(row.variable for row in decision.rows) + omitted
    canonical = _canonical_artifacts(decision.rows)
    if (
        any(not _is_sha256(digest) for digest in digests)
        or isinstance(decision.grouping_width_cap, bool)
        or not isinstance(decision.grouping_width_cap, int)
        or decision.grouping_width_cap < 1
        or isinstance(decision.key_variable_count, bool)
        or not isinstance(decision.key_variable_count, int)
        or not 1 <= decision.key_variable_count <= _INT32_MAX
        or isinstance(decision.observed_variable_count, bool)
        or not isinstance(decision.observed_variable_count, int)
        or decision.observed_variable_count < 1
        or not isinstance(decision.zero_delta_variables, tuple)
        or not isinstance(decision.unobserved_nonzero_variables, tuple)
        or not isinstance(decision.rows, tuple)
        or any(not isinstance(row, VaultRankedDecisionRow) for row in decision.rows)
        or tuple(sorted(decision.rows, key=_rank_key)) != decision.rows
        or len({row.variable for row in decision.rows}) != len(decision.rows)
        or any(row.variable > decision.key_variable_count for row in decision.rows)
        or tuple(sorted(set(decision.zero_delta_variables)))
        != decision.zero_delta_variables
        or tuple(sorted(set(decision.unobserved_nonzero_variables)))
        != decision.unobserved_nonzero_variables
        or any(
            isinstance(variable, bool)
            or not isinstance(variable, int)
            or not 1 <= variable <= decision.key_variable_count
            for variable in omitted
        )
        or len(set(covered)) != decision.key_variable_count
        or set(covered) != set(range(1, decision.key_variable_count + 1))
        or decision.spec_bytes != _SPEC_BYTES
        or decision.spec_sha256 != VAULT_RANKED_DECISION_SPEC_SHA256
        or decision.spec_sha256 != hashlib.sha256(decision.spec_bytes).hexdigest()
        or decision.ranked_literals != canonical[0]
        or decision.order_bytes != canonical[1]
        or decision.order_sha256 != canonical[2]
        or decision.rank_table_bytes != canonical[3]
        or decision.rank_table_sha256 != canonical[4]
    ):
        raise VaultRankedDecisionError("ranked decision projection differs")


def validate_vault_ranked_decision(
    decision: VaultRankedDecision,
) -> VaultRankedDecision:
    """Revalidate an immutable generic decision and return it unchanged."""

    if not isinstance(decision, VaultRankedDecision):
        raise VaultRankedDecisionError("ranked decision type differs")
    _validate_decision(decision)
    return decision


def _singleton_bounds(
    field: CriticalityPotentialField,
    grouping: JointScoreCompatibilityGrouping,
    variables: tuple[int, ...],
) -> Mapping[int, tuple[float, float]]:
    """Specialize the existing grouped bound exactly for singleton queries."""

    try:
        root = compatibility_grouped_upper_bound(field, grouping)
    except JointScoreGroupingError as exc:
        raise VaultRankedDecisionError("ranked decision grouping differs") from exc
    if not math.isfinite(root):
        raise VaultRankedDecisionError("ranked decision root bound differs")

    requested = set(variables)
    root_maxima = tuple(max(group.energies) for group in grouping.groups)
    incidents: dict[int, list[tuple[int, int]]] = {
        variable: [] for variable in variables
    }
    for group_index, group in enumerate(grouping.groups):
        for local, variable in enumerate(group.variables):
            if variable in requested:
                incidents[variable].append((group_index, local))

    result: dict[int, tuple[float, float]] = {}
    for variable in variables:
        if not incidents[variable]:
            raise VaultRankedDecisionError("ranked decision variable is unobserved")
        plus_maxima = list(root_maxima)
        minus_maxima = list(root_maxima)
        for group_index, local in incidents[variable]:
            group = grouping.groups[group_index]
            bit = 1 << local
            plus_maxima[group_index] = max(
                energy for mask, energy in enumerate(group.energies) if mask & bit
            )
            minus_maxima[group_index] = max(
                energy for mask, energy in enumerate(group.energies) if not mask & bit
            )
        try:
            u_plus = outward_binary64_sum((field.offset, *plus_maxima))
            u_minus = outward_binary64_sum((field.offset, *minus_maxima))
        except JointScoreGroupingError as exc:
            raise VaultRankedDecisionError("ranked decision bound differs") from exc
        if not (math.isfinite(u_plus) and math.isfinite(u_minus)):
            raise VaultRankedDecisionError("ranked decision bound differs")
        result[variable] = (u_plus, u_minus)
    return result


def derive_vault_ranked_decision(
    phase_field: VaultPhaseField,
    field: CriticalityPotentialField,
    grouping: JointScoreCompatibilityGrouping,
) -> VaultRankedDecision:
    """Rank all nonzero, potential-observed suffix votes deterministically."""

    if (
        not isinstance(phase_field, VaultPhaseField)
        or not isinstance(field, CriticalityPotentialField)
        or not isinstance(grouping, JointScoreCompatibilityGrouping)
        or len(phase_field.delta) != phase_field.key_variable_count
        or grouping.potential_sha256 != field.state_sha256
        or grouping.factor_count != len(field.factors)
    ):
        raise VaultRankedDecisionError("ranked decision input differs")

    observed = set(field.observed_variables)
    zero_delta_variables = tuple(
        variable
        for variable, delta in enumerate(phase_field.delta, start=1)
        if delta == 0
    )
    unobserved_nonzero_variables = tuple(
        variable
        for variable, delta in enumerate(phase_field.delta, start=1)
        if delta != 0 and variable not in observed
    )
    variables = tuple(
        variable
        for variable, delta in enumerate(phase_field.delta, start=1)
        if delta != 0 and variable in observed
    )
    bounds = _singleton_bounds(field, grouping, variables)
    rows = tuple(
        sorted(
            (
                VaultRankedDecisionRow(
                    variable=variable,
                    delta=phase_field.delta[variable - 1],
                    u_plus=bounds[variable][0],
                    u_minus=bounds[variable][1],
                    gap=canonical_gap(*bounds[variable]),
                )
                for variable in variables
            ),
            key=_rank_key,
        )
    )
    artifacts = _canonical_artifacts(rows)
    spec_bytes = vault_ranked_decision_spec_bytes()
    return VaultRankedDecision(
        source_vault_sha256=phase_field.source_vault_sha256,
        suffix_canonical_records_sha256=(phase_field.suffix_canonical_records_sha256),
        vote_field_sha256=phase_field.field_sha256,
        potential_sha256=field.state_sha256,
        potential_source_sha256=field.source_sha256,
        grouping_sha256=grouping.sha256,
        grouping_width_cap=grouping.width_cap,
        key_variable_count=phase_field.key_variable_count,
        observed_variable_count=len(field.observed_variables),
        zero_delta_variables=zero_delta_variables,
        unobserved_nonzero_variables=unobserved_nonzero_variables,
        rows=rows,
        spec_bytes=spec_bytes,
        spec_sha256=VAULT_RANKED_DECISION_SPEC_SHA256,
        ranked_literals=artifacts[0],
        order_bytes=artifacts[1],
        order_sha256=artifacts[2],
        rank_table_bytes=artifacts[3],
        rank_table_sha256=artifacts[4],
    )


def _production_field_and_grouping(
    potential_payload: bytes, grouping_payload: bytes | None
) -> tuple[CriticalityPotentialField, JointScoreCompatibilityGrouping]:
    if not isinstance(potential_payload, bytes) or (
        grouping_payload is not None and not isinstance(grouping_payload, bytes)
    ):
        raise VaultRankedDecisionError("production ranking artifact type differs")
    try:
        field = CriticalityPotentialField.from_bytes(potential_payload)
        grouping = build_compatibility_grouping(
            field, width_cap=PRODUCTION_GROUPING_WIDTH_CAP
        )
    except Exception as exc:
        raise VaultRankedDecisionError(
            "production potential or grouping construction differs"
        ) from exc
    if (
        hashlib.sha256(potential_payload).hexdigest() != PRODUCTION_POTENTIAL_SHA256
        or field.to_bytes() != potential_payload
        or field.state_sha256 != PRODUCTION_POTENTIAL_SHA256
        or field.source_sha256 != PRODUCTION_POTENTIAL_SOURCE_SHA256
        or len(field.factors) != PRODUCTION_FACTOR_COUNT
        or len(field.observed_variables) != PRODUCTION_OBSERVED_VARIABLE_COUNT
        or grouping.width_cap != PRODUCTION_GROUPING_WIDTH_CAP
        or grouping.sha256 != PRODUCTION_GROUPING_SHA256
        or len(grouping.serialized) != PRODUCTION_GROUPING_SERIALIZED_BYTES
        or grouping.group_count != PRODUCTION_GROUP_COUNT
        or (grouping_payload is not None and grouping_payload != grouping.serialized)
    ):
        raise VaultRankedDecisionError("production potential or grouping differs")
    return field, grouping


def derive_production_vault_ranked_decision(
    vault_payload: bytes,
    potential_payload: bytes,
    grouping_payload: bytes | None = None,
) -> VaultRankedDecision:
    """Independently rebuild and validate the sealed production ranking."""

    if not isinstance(vault_payload, bytes):
        raise VaultRankedDecisionError("production vault payload type differs")
    try:
        phase_field = validate_production_vault_phase_field(vault_payload)
    except VaultPhaseFieldError as exc:
        raise VaultRankedDecisionError("production suffix votes differ") from exc
    field, grouping = _production_field_and_grouping(
        potential_payload, grouping_payload
    )
    decision = derive_vault_ranked_decision(phase_field, field, grouping)
    return validate_production_vault_ranked_decision(decision)


def validate_production_vault_ranked_decision(
    decision: VaultRankedDecision,
) -> VaultRankedDecision:
    """Fail closed unless every production identity and projection is exact."""

    validate_vault_ranked_decision(decision)
    if (
        decision.source_vault_sha256 != PRODUCTION_VAULT_SHA256
        or decision.suffix_canonical_records_sha256
        != PRODUCTION_SUFFIX_CANONICAL_RECORDS_SHA256
        or decision.vote_field_sha256 != PRODUCTION_VOTE_FIELD_SHA256
        or decision.potential_sha256 != PRODUCTION_POTENTIAL_SHA256
        or decision.potential_source_sha256 != PRODUCTION_POTENTIAL_SOURCE_SHA256
        or decision.grouping_sha256 != PRODUCTION_GROUPING_SHA256
        or decision.grouping_width_cap != PRODUCTION_GROUPING_WIDTH_CAP
        or decision.key_variable_count != PRODUCTION_KEY_VARIABLE_COUNT
        or decision.observed_variable_count != PRODUCTION_OBSERVED_VARIABLE_COUNT
        or decision.candidate_count != PRODUCTION_CANDIDATE_COUNT
        or decision.zero_delta_variables != PRODUCTION_ZERO_DELTA_VARIABLES
        or decision.unobserved_nonzero_variables
        != PRODUCTION_UNOBSERVED_NONZERO_VARIABLES
        or len(decision.order_bytes) != PRODUCTION_ORDER_BYTES
        or decision.order_sha256 != PRODUCTION_ORDER_SHA256
        or len(decision.rank_table_bytes) != PRODUCTION_RANK_TABLE_BYTES
        or decision.rank_table_sha256 != PRODUCTION_RANK_TABLE_SHA256
    ):
        raise VaultRankedDecisionError("sealed production ranking differs")
    return decision


__all__ = [
    "PRODUCTION_CANDIDATE_COUNT",
    "PRODUCTION_FACTOR_COUNT",
    "PRODUCTION_GROUPING_SERIALIZED_BYTES",
    "PRODUCTION_GROUPING_SHA256",
    "PRODUCTION_GROUPING_WIDTH_CAP",
    "PRODUCTION_GROUP_COUNT",
    "PRODUCTION_KEY_VARIABLE_COUNT",
    "PRODUCTION_OBSERVED_VARIABLE_COUNT",
    "PRODUCTION_ORDER_BYTES",
    "PRODUCTION_ORDER_SHA256",
    "PRODUCTION_POTENTIAL_SHA256",
    "PRODUCTION_POTENTIAL_SOURCE_SHA256",
    "PRODUCTION_RANK_TABLE_BYTES",
    "PRODUCTION_RANK_TABLE_SHA256",
    "PRODUCTION_SUFFIX_CANONICAL_RECORDS_SHA256",
    "PRODUCTION_UNOBSERVED_NONZERO_VARIABLES",
    "PRODUCTION_VAULT_SHA256",
    "PRODUCTION_VOTE_FIELD_SHA256",
    "PRODUCTION_ZERO_DELTA_VARIABLES",
    "VAULT_RANKED_DECISION_BOUND_RULE",
    "VAULT_RANKED_DECISION_GAP_RULE",
    "VAULT_RANKED_DECISION_LITERAL_RULE",
    "VAULT_RANKED_DECISION_OPERATOR",
    "VAULT_RANKED_DECISION_ORDER_ENCODING",
    "VAULT_RANKED_DECISION_READER_SCHEMA",
    "VAULT_RANKED_DECISION_SCHEMA",
    "VAULT_RANKED_DECISION_SORT_RULE",
    "VAULT_RANKED_DECISION_SPEC_SHA256",
    "VAULT_RANKED_DECISION_TABLE_ENCODING",
    "VAULT_RANKED_DECISION_VOTE_RULE",
    "VaultRankedDecision",
    "VaultRankedDecisionError",
    "VaultRankedDecisionRow",
    "canonical_gap",
    "derive_production_vault_ranked_decision",
    "derive_vault_ranked_decision",
    "validate_production_vault_ranked_decision",
    "validate_vault_ranked_decision",
    "vault_ranked_decision_spec_bytes",
]
