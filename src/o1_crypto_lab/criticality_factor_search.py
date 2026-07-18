"""Native reversible CaDiCaL decisions from local criticality potentials."""

from __future__ import annotations

import hashlib
import json
import math
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .criticality_potential import CriticalityPotentialField
from .o1_relational_search import (
    NativeGuidedSearchBuild,
    O1RelationalSearchError,
    build_native_guided_search,
)


CRITICALITY_RESULT_SCHEMA = "o1-256-cadical-criticality-search-result-v1"


@dataclass(frozen=True)
class CriticalitySearchResult:
    status: int
    conflict_limit: int
    key_model: bytes | None
    stats: Mapping[str, int]
    potential: Mapping[str, int | float | str]
    resources: Mapping[str, int]
    raw: Mapping[str, object]

    @property
    def status_name(self) -> str:
        return {0: "UNKNOWN", 10: "SAT", 20: "UNSAT"}[self.status]


def build_native_criticality_search(
    *, source: str | Path, output: str | Path
) -> NativeGuidedSearchBuild:
    return build_native_guided_search(source=source, output=output)


def write_criticality_potential(
    path: str | Path, field: CriticalityPotentialField
) -> str:
    payload = field.to_bytes()
    Path(path).write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def run_criticality_search(
    *,
    executable: str | Path,
    cnf_path: str | Path,
    potential_path: str | Path,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
) -> CriticalitySearchResult:
    if (
        isinstance(conflict_limit, bool)
        or not isinstance(conflict_limit, int)
        or conflict_limit < 1
        or isinstance(seed, bool)
        or not isinstance(seed, int)
        or not 0 <= seed <= 2_000_000_000
    ):
        raise O1RelationalSearchError("criticality search limit or seed differs")
    command = [
        str(Path(executable).resolve(strict=True)),
        "--cnf",
        str(Path(cnf_path).resolve(strict=True)),
        "--potential",
        str(Path(potential_path).resolve(strict=True)),
        "--conflict-limit",
        str(conflict_limit),
        "--seed",
        str(seed),
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise O1RelationalSearchError("criticality search execution failed") from exc
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise O1RelationalSearchError(
            f"criticality search execution failed: {detail}"
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise O1RelationalSearchError("criticality search JSON is invalid") from exc
    if not isinstance(payload, Mapping):
        raise O1RelationalSearchError("criticality result must be an object")
    status = payload.get("status")
    model_hex = payload.get("key_model_hex")
    potential = payload.get("potential")
    if (
        payload.get("schema") != CRITICALITY_RESULT_SCHEMA
        or payload.get("cadical_version") != "3.0.0"
        or payload.get("variables", 0) < 256
        or payload.get("conflict_limit") != conflict_limit
        or payload.get("seed") != seed
        or status not in (0, 10, 20)
        or not isinstance(payload.get("stats"), Mapping)
        or not isinstance(potential, Mapping)
        or not isinstance(payload.get("resources"), Mapping)
    ):
        raise O1RelationalSearchError("criticality result contract differs")
    if status == 10:
        if not isinstance(model_hex, str) or len(model_hex) != 64:
            raise O1RelationalSearchError("SAT criticality result lacks key")
        try:
            model = bytes.fromhex(model_hex)
        except ValueError as exc:
            raise O1RelationalSearchError("criticality key encoding differs") from exc
    elif model_hex is not None:
        raise O1RelationalSearchError("non-SAT criticality result contains key")
    else:
        model = None
    stats: dict[str, int] = {}
    resources: dict[str, int] = {}
    for name, destination in (("stats", stats), ("resources", resources)):
        for field, value in payload[name].items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise O1RelationalSearchError(f"{name}.{field} differs")
            destination[str(field)] = value
    normalized_potential: dict[str, int | float | str] = {}
    integer_fields = {
        "factor_count",
        "observed_variables",
        "requested_decisions",
        "repeated_decisions",
        "assignment_notifications",
        "backtracks",
        "maximum_assigned_variables",
        "maximum_decision_level",
        "conditional_factor_evaluations",
    }
    for field, value in potential.items():
        if field in integer_fields:
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise O1RelationalSearchError(f"potential.{field} differs")
        elif field in {"offset", "maximum_abs_support"}:
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise O1RelationalSearchError(f"potential.{field} differs")
        elif field == "source_sha256":
            if not isinstance(value, str) or len(value) != 64:
                raise O1RelationalSearchError("potential.source_sha256 differs")
        else:
            raise O1RelationalSearchError("criticality potential fields differ")
        normalized_potential[str(field)] = value
    if int(normalized_potential.get("factor_count", 0)) < 1:
        raise O1RelationalSearchError("criticality search consumed no factors")
    return CriticalitySearchResult(
        status=status,
        conflict_limit=conflict_limit,
        key_model=model,
        stats=stats,
        potential=normalized_potential,
        resources=resources,
        raw=dict(payload),
    )


__all__ = [
    "CRITICALITY_RESULT_SCHEMA",
    "CriticalitySearchResult",
    "build_native_criticality_search",
    "run_criticality_search",
    "write_criticality_potential",
]
