"""Reversible global max-envelope pair decisions for CaDiCaL 3.0.0."""

from __future__ import annotations

import hashlib
import json
import math
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from .criticality_potential import (
    CriticalityPotentialError,
    CriticalityPotentialField,
)
from .o1_relational_search import (
    NativeGuidedSearchBuild,
    O1RelationalSearchError,
    build_native_guided_search,
)


PAIR_ENVELOPE_RESULT_SCHEMA = "o1-256-cadical-pair-envelope-search-result-v1"
PAIR_ENVELOPE_DECISION_RULE = "pairwise_factorwise_max_envelope"
PAIR_ENVELOPE_DECISION_SCOPE = "explicit_ordered_key_pairs"

_TOP_LEVEL_FIELDS = {
    "schema",
    "cadical_version",
    "variables",
    "conflict_limit",
    "seed",
    "status",
    "key_model_hex",
    "stats",
    "envelope",
    "resources",
}
_STATS_FIELDS = {"conflicts", "decisions", "propagations"}
_RESOURCE_FIELDS = {
    "wall_microseconds",
    "cpu_microseconds",
    "peak_rss_bytes",
}
_ENVELOPE_INTEGER_FIELDS = {
    "factor_count",
    "pair_count",
    "group_width",
    "observed_variables",
    "eligible_decision_variables",
    "requested_decisions",
    "repeated_decisions",
    "queued_decisions",
    "same_sign_queue_skips",
    "opposite_sign_queue_invalidations",
    "zero_gap_fallbacks",
    "assignment_notifications",
    "backtracks",
    "maximum_assigned_variables",
    "maximum_decision_level",
    "envelope_evaluations",
}
_ENVELOPE_FIELDS = _ENVELOPE_INTEGER_FIELDS | {
    "decision_rule",
    "decision_scope",
    "source_sha256",
    "decision_variables_sha256",
    "offset",
    "maximum_score_gap",
}


@dataclass(frozen=True)
class PairEnvelopeSearchResult:
    status: int
    conflict_limit: int
    key_model: bytes | None
    stats: Mapping[str, int]
    envelope: Mapping[str, int | float | str]
    resources: Mapping[str, int]
    raw: Mapping[str, object]

    @property
    def status_name(self) -> str:
        return {0: "UNKNOWN", 10: "SAT", 20: "UNSAT"}[self.status]

    @property
    def pair_envelope(self) -> Mapping[str, int | float | str]:
        """Explicit alias for callers that namespace multiple soft schedulers."""

        return self.envelope


def build_native_pair_envelope_search(
    *, source: str | Path, output: str | Path
) -> NativeGuidedSearchBuild:
    return build_native_guided_search(source=source, output=output)


def write_pair_envelope_potential(
    path: str | Path, field: CriticalityPotentialField
) -> str:
    if not isinstance(field, CriticalityPotentialField):
        raise O1RelationalSearchError("pair-envelope potential differs")
    payload = field.to_bytes()
    Path(path).write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _ordered_decision_variables(variables: Iterable[int]) -> tuple[int, ...]:
    values = tuple(variables)
    if (
        not values
        or len(values) % 2
        or any(
            isinstance(value, bool) or not isinstance(value, int) for value in values
        )
        or len(set(values)) != len(values)
        or any(not 1 <= value <= 256 for value in values)
    ):
        raise O1RelationalSearchError(
            "pair-envelope decision variables must be an even unique ordered key list"
        )
    return values


def write_pair_envelope_decision_variables(
    path: str | Path, variables: Iterable[int]
) -> str:
    values = _ordered_decision_variables(variables)
    payload = "".join(f"{variable}\n" for variable in values).encode("ascii")
    Path(path).write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _read_decision_file(path: str | Path) -> tuple[tuple[int, ...], str, Path]:
    try:
        resolved = Path(path).resolve(strict=True)
        payload = resolved.read_bytes()
        tokens = payload.decode("ascii").split()
        values = _ordered_decision_variables(int(token) for token in tokens)
    except (OSError, UnicodeError, ValueError) as exc:
        raise O1RelationalSearchError(
            "pair-envelope decision-variable file differs"
        ) from exc
    return values, hashlib.sha256(payload).hexdigest(), resolved


def _read_potential_file(
    path: str | Path,
) -> tuple[bytes, CriticalityPotentialField, Path]:
    try:
        resolved = Path(path).resolve(strict=True)
        payload = resolved.read_bytes()
        field = CriticalityPotentialField.from_bytes(payload)
    except (OSError, CriticalityPotentialError) as exc:
        raise O1RelationalSearchError("pair-envelope potential file differs") from exc
    return payload, field, resolved


def _nonnegative_integer_group(
    payload: Mapping[str, object],
    *,
    name: str,
    required_fields: set[str],
) -> dict[str, int]:
    if set(payload) != required_fields:
        raise O1RelationalSearchError(f"pair-envelope {name} fields differ")
    normalized: dict[str, int] = {}
    for field, value in payload.items():
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(f"{name}.{field} differs")
        normalized[str(field)] = value
    return normalized


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def run_pair_envelope_search(
    *,
    executable: str | Path,
    cnf_path: str | Path,
    potential_path: str | Path,
    decision_variables_path: str | Path,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
) -> PairEnvelopeSearchResult:
    if (
        isinstance(conflict_limit, bool)
        or not isinstance(conflict_limit, int)
        or conflict_limit < 1
        or isinstance(seed, bool)
        or not isinstance(seed, int)
        or not 0 <= seed <= 2_000_000_000
        or isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0.0
    ):
        raise O1RelationalSearchError(
            "pair-envelope search limit, seed, or timeout differs"
        )
    decision_values, decision_sha256, decision_path = _read_decision_file(
        decision_variables_path
    )
    potential_bytes, potential_field, resolved_potential_path = _read_potential_file(
        potential_path
    )
    command = [
        str(Path(executable).resolve(strict=True)),
        "--cnf",
        str(Path(cnf_path).resolve(strict=True)),
        "--potential",
        str(resolved_potential_path),
        "--decision-variables",
        str(decision_path),
        "--conflict-limit",
        str(conflict_limit),
        "--seed",
        str(seed),
    ]
    execution_error: OSError | subprocess.TimeoutExpired | None = None
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=float(timeout_seconds),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        execution_error = exc
        completed = None
    try:
        post_decision_values, post_decision_sha256, post_decision_path = (
            _read_decision_file(decision_variables_path)
        )
    except O1RelationalSearchError as exc:
        raise O1RelationalSearchError(
            "pair-envelope decision-variable file changed during execution"
        ) from exc
    if (
        post_decision_path != decision_path
        or post_decision_values != decision_values
        or post_decision_sha256 != decision_sha256
    ):
        raise O1RelationalSearchError(
            "pair-envelope decision-variable file changed during execution"
        )
    try:
        post_bytes, post_field, post_path = _read_potential_file(potential_path)
    except O1RelationalSearchError as exc:
        raise O1RelationalSearchError(
            "pair-envelope potential changed during execution"
        ) from exc
    if (
        post_path != resolved_potential_path
        or post_bytes != potential_bytes
        or post_field != potential_field
    ):
        raise O1RelationalSearchError(
            "pair-envelope potential changed during execution"
        )
    if execution_error is not None:
        raise O1RelationalSearchError(
            "pair-envelope search execution failed"
        ) from execution_error
    if completed is None:
        raise O1RelationalSearchError("pair-envelope search execution failed")
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise O1RelationalSearchError(
            f"pair-envelope search execution failed: {detail}"
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise O1RelationalSearchError("pair-envelope search JSON is invalid") from exc
    if not isinstance(payload, Mapping) or set(payload) != _TOP_LEVEL_FIELDS:
        raise O1RelationalSearchError("pair-envelope result fields differ")

    status = payload["status"]
    variables = payload["variables"]
    reported_limit = payload["conflict_limit"]
    reported_seed = payload["seed"]
    if (
        payload["schema"] != PAIR_ENVELOPE_RESULT_SCHEMA
        or payload["cadical_version"] != "3.0.0"
        or isinstance(variables, bool)
        or not isinstance(variables, int)
        or variables < 256
        or isinstance(reported_limit, bool)
        or not isinstance(reported_limit, int)
        or reported_limit != conflict_limit
        or isinstance(reported_seed, bool)
        or not isinstance(reported_seed, int)
        or reported_seed != seed
        or isinstance(status, bool)
        or status not in (0, 10, 20)
        or not isinstance(payload["stats"], Mapping)
        or not isinstance(payload["envelope"], Mapping)
        or not isinstance(payload["resources"], Mapping)
    ):
        raise O1RelationalSearchError("pair-envelope result contract differs")

    model_hex = payload["key_model_hex"]
    if status == 10:
        if not isinstance(model_hex, str) or len(model_hex) != 64:
            raise O1RelationalSearchError("SAT pair-envelope result lacks key")
        try:
            key_model = bytes.fromhex(model_hex)
        except ValueError as exc:
            raise O1RelationalSearchError("pair-envelope key encoding differs") from exc
    elif model_hex is not None:
        raise O1RelationalSearchError("non-SAT pair-envelope result contains key")
    else:
        key_model = None

    stats = _nonnegative_integer_group(
        payload["stats"], name="stats", required_fields=_STATS_FIELDS
    )
    resources = _nonnegative_integer_group(
        payload["resources"],
        name="resources",
        required_fields=_RESOURCE_FIELDS,
    )
    raw_envelope = payload["envelope"]
    if set(raw_envelope) != _ENVELOPE_FIELDS:
        raise O1RelationalSearchError("pair-envelope envelope fields differ")
    envelope: dict[str, int | float | str] = {}
    for field in _ENVELOPE_INTEGER_FIELDS:
        value = raw_envelope[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(f"envelope.{field} differs")
        envelope[field] = value
    for field in ("offset", "maximum_score_gap"):
        value = raw_envelope[field]
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or (field == "maximum_score_gap" and value < 0.0)
        ):
            raise O1RelationalSearchError(f"envelope.{field} differs")
        envelope[field] = value
    for field in ("source_sha256", "decision_variables_sha256"):
        value = raw_envelope[field]
        if not _is_sha256(value):
            raise O1RelationalSearchError(f"envelope.{field} differs")
        envelope[field] = value
    for field in ("decision_rule", "decision_scope"):
        value = raw_envelope[field]
        if not isinstance(value, str):
            raise O1RelationalSearchError(f"envelope.{field} differs")
        envelope[field] = value

    factor_count = int(envelope["factor_count"])
    observed_variables = int(envelope["observed_variables"])
    if factor_count < 1 or not 1 <= observed_variables <= variables:
        raise O1RelationalSearchError(
            "pair-envelope search consumed an invalid potential"
        )
    if (
        envelope["decision_rule"] != PAIR_ENVELOPE_DECISION_RULE
        or envelope["decision_scope"] != PAIR_ENVELOPE_DECISION_SCOPE
        or envelope["group_width"] != 2
    ):
        raise O1RelationalSearchError(
            "pair-envelope decision rule, scope, or width differs"
        )
    if (
        envelope["source_sha256"] != potential_field.source_sha256
        or factor_count != len(potential_field.factors)
        or envelope["offset"] != potential_field.offset
        or observed_variables != len(potential_field.observed_variables)
    ):
        raise O1RelationalSearchError("pair-envelope potential identity differs")
    if (
        envelope["eligible_decision_variables"] != len(decision_values)
        or envelope["pair_count"] != len(decision_values) // 2
    ):
        raise O1RelationalSearchError(
            "pair-envelope eligible decision-variable count differs"
        )
    if envelope["decision_variables_sha256"] != decision_sha256:
        raise O1RelationalSearchError(
            "pair-envelope decision-variable order hash differs"
        )

    return PairEnvelopeSearchResult(
        status=status,
        conflict_limit=conflict_limit,
        key_model=key_model,
        stats=stats,
        envelope=envelope,
        resources=resources,
        raw=dict(payload),
    )


# Compatibility names parallel to ``criticality_factor_search``.
write_criticality_potential = write_pair_envelope_potential
write_decision_variables = write_pair_envelope_decision_variables


__all__ = [
    "PAIR_ENVELOPE_DECISION_RULE",
    "PAIR_ENVELOPE_DECISION_SCOPE",
    "PAIR_ENVELOPE_RESULT_SCHEMA",
    "PairEnvelopeSearchResult",
    "build_native_pair_envelope_search",
    "run_pair_envelope_search",
    "write_criticality_potential",
    "write_decision_variables",
    "write_pair_envelope_decision_variables",
    "write_pair_envelope_potential",
]
