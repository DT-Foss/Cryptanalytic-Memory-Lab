"""Exact CaDiCaL search driven by a bounded signed relation edge field."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .o1_relational_search import (
    NativeGuidedSearchBuild,
    O1RelationalSearchError,
    build_native_guided_search,
)
from .proof_clause_relations import ClauseRelationField


FACTOR_RESULT_SCHEMA = "o1-256-cadical-factor-search-result-v1"


@dataclass(frozen=True)
class FactorSearchResult:
    status: int
    conflict_limit: int
    key_model: bytes | None
    stats: Mapping[str, int]
    factor: Mapping[str, int]
    resources: Mapping[str, int]
    raw: Mapping[str, object]

    @property
    def status_name(self) -> str:
        return {0: "UNKNOWN", 10: "SAT", 20: "UNSAT"}[self.status]


def build_native_factor_search(
    *, source: str | Path, output: str | Path
) -> NativeGuidedSearchBuild:
    return build_native_guided_search(source=source, output=output)


def write_factor_field(path: str | Path, field: ClauseRelationField) -> str:
    payload = field.factor_file_bytes()
    destination = Path(path)
    destination.write_bytes(payload)
    return __import__("hashlib").sha256(payload).hexdigest()


def run_factor_search(
    *,
    executable: str | Path,
    cnf_path: str | Path,
    factors_path: str | Path,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
) -> FactorSearchResult:
    if (
        isinstance(conflict_limit, bool)
        or not isinstance(conflict_limit, int)
        or conflict_limit < 1
        or isinstance(seed, bool)
        or not isinstance(seed, int)
        or not 0 <= seed <= 2_000_000_000
    ):
        raise O1RelationalSearchError("factor search limit or seed differs")
    command = [
        str(Path(executable).resolve(strict=True)),
        "--cnf",
        str(Path(cnf_path).resolve(strict=True)),
        "--factors",
        str(Path(factors_path).resolve(strict=True)),
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
        raise O1RelationalSearchError("factor-search execution failed") from exc
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise O1RelationalSearchError(f"factor-search execution failed: {detail}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise O1RelationalSearchError("factor-search JSON is invalid") from exc
    if not isinstance(payload, Mapping):
        raise O1RelationalSearchError("factor-search result must be an object")
    status = payload.get("status")
    model_hex = payload.get("key_model_hex")
    if (
        payload.get("schema") != FACTOR_RESULT_SCHEMA
        or payload.get("cadical_version") != "3.0.0"
        or payload.get("variables", 0) < 256
        or payload.get("conflict_limit") != conflict_limit
        or payload.get("seed") != seed
        or status not in (0, 10, 20)
        or not isinstance(payload.get("stats"), Mapping)
        or not isinstance(payload.get("factor"), Mapping)
        or not isinstance(payload.get("resources"), Mapping)
    ):
        raise O1RelationalSearchError("factor-search result contract differs")
    if status == 10:
        if not isinstance(model_hex, str) or len(model_hex) != 64:
            raise O1RelationalSearchError("SAT factor result lacks key model")
        try:
            model = bytes.fromhex(model_hex)
        except ValueError as exc:
            raise O1RelationalSearchError("factor key model is invalid") from exc
    elif model_hex is not None:
        raise O1RelationalSearchError("non-SAT factor result contains key model")
    else:
        model = None
    groups: list[dict[str, int]] = []
    for name in ("stats", "factor", "resources"):
        normalized: dict[str, int] = {}
        for field, value in payload[name].items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise O1RelationalSearchError(f"{name}.{field} must be nonnegative")
            normalized[str(field)] = value
        groups.append(normalized)
    if groups[1].get("edge_count", 0) < 1:
        raise O1RelationalSearchError("factor search consumed no edges")
    return FactorSearchResult(
        status=status,
        conflict_limit=conflict_limit,
        key_model=model,
        stats=groups[0],
        factor=groups[1],
        resources=groups[2],
        raw=dict(payload),
    )


__all__ = [
    "FACTOR_RESULT_SCHEMA",
    "FactorSearchResult",
    "build_native_factor_search",
    "run_factor_search",
    "write_factor_field",
]
