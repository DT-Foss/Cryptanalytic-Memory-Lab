"""Cause-preserving execution evidence for the lifecycle-safe native-v4 sieve.

The native result contract, scoring, lifecycle checks, and 4K conflict ledger
remain byte-for-byte delegated to :mod:`joint_score_sieve_v5`.  This additive
adapter changes only the Python failure boundary: an execution exception keeps
its complete cause/context chain and a bounded structured diagnosis instead of
being reduced to the outer ``O1RelationalSearchError`` message.
"""

from __future__ import annotations

import math
import re
import signal
import subprocess
import time
from pathlib import Path
from typing import Mapping

from . import joint_score_sieve_v5 as _v5
from .joint_score_sieve_v5 import (
    JOINT_SCORE_SIEVE_BOUND_RULE,
    JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE,
    JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA,
    JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES,
    JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS,
    JOINT_SCORE_SIEVE_DECISION_RULE,
    JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA,
    JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS,
    JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET,
    JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
    JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS,
    JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE,
    JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE,
    JOINT_SCORE_SIEVE_RESULT_SCHEMA,
    JOINT_SCORE_SIEVE_STATE_ENCODING,
    JOINT_SCORE_SIEVE_TEARDOWN_RULE,
    JointScoreSieveResult,
    build_native_joint_score_sieve,
    derive_soft_conflict_ledger,
    joint_score_complete,
    joint_score_upper_bound,
    validate_incremental_conflict_ledger,
    validate_native_lifecycle,
    validate_soft_conflict_ledger,
    write_joint_score_sieve_potential,
)


JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA = (
    "o1-256-joint-score-sieve-execution-failure-v1"
)
_WATCHDOG_NUMBERS = re.compile(
    r"\((?P<observed>[0-9]+)\s*>=\s*(?P<threshold>[0-9]+)\s*<\s*"
    r"(?P<limit>[0-9]+)\)"
)


class JointScoreSieveExecutionError(RuntimeError):
    """A v5 failure plus its stable machine-readable process evidence."""

    def __init__(self, message: str, *, failure_telemetry: Mapping[str, object]):
        super().__init__(message)
        self.failure_telemetry = dict(failure_telemetry)

    def describe(self) -> dict[str, object]:
        """Return a detached mapping equal to ``failure_telemetry``."""

        return dict(self.failure_telemetry)


def _stream(value: object) -> bytes | str | None:
    if value is None or isinstance(value, (bytes, str)):
        return value
    return repr(value)


def _exception_chain(exc: BaseException) -> tuple[BaseException, ...]:
    result: list[BaseException] = []
    current: BaseException | None = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        result.append(current)
        if current.__cause__ is not None:
            current = current.__cause__
        elif current.__context__ is not None and not current.__suppress_context__:
            current = current.__context__
        else:
            current = None
    return tuple(result)


def _chain_rows(chain: tuple[BaseException, ...]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for depth, node in enumerate(chain):
        previous = chain[depth - 1] if depth else None
        relationship = (
            "outer"
            if previous is None
            else "cause"
            if previous.__cause__ is node
            else "context"
        )
        rows.append(
            {
                "depth": depth,
                "relationship": relationship,
                "module": type(node).__module__,
                "type": type(node).__qualname__,
                "message": str(node),
                "args_repr": repr(node.args),
            }
        )
    return rows


def _classification(
    exc: BaseException, chain: tuple[BaseException, ...]
) -> tuple[str, str]:
    if any(
        type(node).__name__ == "_JointScoreSieveMemoryLimitExceeded"
        or "physical-footprint watchdog reached its guarded ceiling" in str(node)
        for node in chain
    ):
        return "watchdog_memory", "native_process"
    if any(isinstance(node, subprocess.TimeoutExpired) for node in chain):
        return "timeout", "native_process"
    if any(isinstance(node, OSError) for node in chain[1:]):
        return "launch_or_os", "native_process"
    if str(exc).startswith("joint-score-sieve execution failed:"):
        return "child_exit", "native_process"
    return "adapter_or_parser", "adapter_validation"


def _first_attribute(chain: tuple[BaseException, ...], name: str) -> object | None:
    for node in chain:
        value = getattr(node, name, None)
        if value is not None:
            return value
    return None


def _watchdog_sample(
    chain: tuple[BaseException, ...], *, configured_limit: int | None
) -> list[dict[str, int]]:
    for node in chain:
        match = _WATCHDOG_NUMBERS.search(str(node))
        if match is None:
            continue
        return [
            {
                "observed_bytes": int(match.group("observed")),
                "kill_threshold_bytes": int(match.group("threshold")),
                "configured_limit_bytes": int(match.group("limit")),
            }
        ]
    return [] if configured_limit is None else []


def _failure_telemetry(
    exc: BaseException,
    *,
    elapsed_seconds: float,
    timeout_seconds: float,
    memory_limit_bytes: int | None,
) -> dict[str, object]:
    chain = _exception_chain(exc)
    kind, phase = _classification(exc, chain)
    raw_returncode = _first_attribute(chain, "returncode")
    returncode = (
        raw_returncode
        if isinstance(raw_returncode, int) and not isinstance(raw_returncode, bool)
        else None
    )
    signal_number = -returncode if returncode is not None and returncode < 0 else None
    try:
        signal_name = signal.Signals(signal_number).name if signal_number else None
    except ValueError:
        signal_name = None
    raw_command = _first_attribute(chain, "cmd")
    command = (
        [str(part) for part in raw_command]
        if isinstance(raw_command, (list, tuple))
        else str(raw_command)
        if raw_command is not None
        else None
    )
    guard = JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES
    kill_threshold = (
        memory_limit_bytes - guard if memory_limit_bytes is not None else None
    )
    return {
        "schema": JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA,
        "classification_kind": kind,
        "phase": phase,
        "elapsed_seconds": elapsed_seconds,
        "configured_timeout_seconds": float(timeout_seconds),
        "configured_memory_limit_bytes": memory_limit_bytes,
        "darwin_watchdog_guard_bytes": guard,
        "darwin_watchdog_kill_threshold_bytes": kill_threshold,
        "darwin_watchdog_poll_interval_seconds": (
            JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS
        ),
        "memory_samples": _watchdog_sample(chain, configured_limit=memory_limit_bytes),
        "returncode": returncode,
        "signal_number": signal_number,
        "signal_name": signal_name,
        "command": command,
        "stdout": _stream(
            _first_attribute(chain, "stdout") or _first_attribute(chain, "output")
        ),
        "stderr": _stream(_first_attribute(chain, "stderr")),
        "exception_chain": _chain_rows(chain),
    }


def run_joint_score_sieve(
    *,
    executable: str | Path,
    cnf_path: str | Path,
    potential_path: str | Path,
    threshold: float,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
    memory_limit_bytes: int | None = None,
) -> JointScoreSieveResult:
    """Delegate success to v5 and preserve every runtime failure cause."""

    started = time.perf_counter()
    try:
        return _v5.run_joint_score_sieve(
            executable=executable,
            cnf_path=cnf_path,
            potential_path=potential_path,
            threshold=threshold,
            conflict_limit=conflict_limit,
            seed=seed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
    except Exception as exc:
        elapsed = time.perf_counter() - started
        if not math.isfinite(elapsed) or elapsed < 0.0:
            elapsed = 0.0
        telemetry = _failure_telemetry(
            exc,
            elapsed_seconds=elapsed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
        raise JointScoreSieveExecutionError(
            str(exc), failure_telemetry=telemetry
        ) from exc


__all__ = [
    "JOINT_SCORE_SIEVE_BOUND_RULE",
    "JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE",
    "JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA",
    "JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES",
    "JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS",
    "JOINT_SCORE_SIEVE_DECISION_RULE",
    "JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA",
    "JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA",
    "JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS",
    "JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET",
    "JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT",
    "JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS",
    "JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE",
    "JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE",
    "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
    "JOINT_SCORE_SIEVE_STATE_ENCODING",
    "JOINT_SCORE_SIEVE_TEARDOWN_RULE",
    "JointScoreSieveExecutionError",
    "JointScoreSieveResult",
    "build_native_joint_score_sieve",
    "derive_soft_conflict_ledger",
    "joint_score_complete",
    "joint_score_upper_bound",
    "run_joint_score_sieve",
    "validate_incremental_conflict_ledger",
    "validate_native_lifecycle",
    "validate_soft_conflict_ledger",
    "write_joint_score_sieve_potential",
]
