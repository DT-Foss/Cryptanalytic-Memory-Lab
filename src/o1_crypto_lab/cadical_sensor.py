"""Deterministic paired-assumption CaDiCaL proof telemetry for O1-256.

The native helper loads the immutable public ChaCha20 CNF once and forks a
fresh copy-on-write child for every key-bit polarity.  This module compiles and
validates that helper, streams its newline-delimited records without retaining
the transcript, and reduces exact LRAT antecedent DAGs to fixed-width causal
motifs at declared conflict horizons.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import signal
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Mapping, Sequence

import numpy as np

from .living_inverse import canonical_sha256


STREAM_HEADER_SCHEMA = "o1-256-cadical-paired-proof-stream-header-v1"
PROBE_SCHEMA = "o1-256-cadical-paired-proof-probe-v1"
BUILD_SCHEMA = "o1-256-cadical-native-sensor-build-v1"
PROVENANCE_SCHEMA = "o1-256-cadical-clause-provenance-v1"
PREFIX_SCHEMA = "o1-256-cadical-proof-prefix-summary-v1"
MOTIF_DIMENSIONS = 64
KEY_BITS = 256


class CaDiCaLSensorError(RuntimeError):
    """A native build, probe record, or proof ancestry invariant failed."""


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _integer(value: object, field: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise CaDiCaLSensorError(f"{field} must be an integer >= {minimum}")
    return value


def _signed_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CaDiCaLSensorError(f"{field} must be an integer")
    return value


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise CaDiCaLSensorError(f"{field} must be boolean")
    return value


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise CaDiCaLSensorError(f"{field} must be an object")
    return value


def _integer_list(value: object, field: str) -> tuple[int, ...]:
    if not isinstance(value, list):
        raise CaDiCaLSensorError(f"{field} must be an integer array")
    return tuple(_signed_integer(item, f"{field}[]") for item in value)


@dataclass(frozen=True)
class NativeSensorBuild:
    executable: Path
    compiler: str
    command: tuple[str, ...]
    source_sha256: str
    tracer_header_sha256: str
    cadical_header_sha256: str
    cadical_library_sha256: str
    executable_sha256: str
    compiler_stdout: str
    compiler_stderr: str

    def describe(self) -> dict[str, object]:
        normalized_command = list(self.command)
        try:
            output_index = normalized_command.index("-o") + 1
            normalized_command[output_index] = "<TEMP_OUTPUT>"
        except (ValueError, IndexError):  # pragma: no cover - constructor invariant
            raise CaDiCaLSensorError("native build command lacks output binding")
        return {
            "schema": BUILD_SCHEMA,
            "executable_name": self.executable.name,
            "compiler": self.compiler,
            "command": normalized_command,
            "source_sha256": self.source_sha256,
            "tracer_header_sha256": self.tracer_header_sha256,
            "cadical_header_sha256": self.cadical_header_sha256,
            "cadical_library_sha256": self.cadical_library_sha256,
            "executable_sha256": self.executable_sha256,
            "compiler_stdout": self.compiler_stdout,
            "compiler_stderr": self.compiler_stderr,
        }


def build_native_sensor(
    *,
    source: str | Path,
    tracer_header: str | Path,
    cadical_include: str | Path,
    cadical_library: str | Path,
    output: str | Path,
    expected_cadical_header_sha256: str,
    expected_cadical_library_sha256: str,
    compiler: str = "c++",
    timeout_seconds: float = 60.0,
) -> NativeSensorBuild:
    """Compile the pinned single-threaded COW helper after dependency checks."""

    source_path = Path(source).resolve(strict=True)
    tracer_path = Path(tracer_header).resolve(strict=True)
    include_path = Path(cadical_include).resolve(strict=True)
    library_path = Path(cadical_library).resolve(strict=True)
    header_path = include_path / "cadical.hpp"
    if not header_path.is_file():
        raise CaDiCaLSensorError("CaDiCaL include directory lacks cadical.hpp")
    if sha256_file(header_path) != expected_cadical_header_sha256:
        raise CaDiCaLSensorError("installed cadical.hpp differs from frozen build")
    if sha256_file(library_path) != expected_cadical_library_sha256:
        raise CaDiCaLSensorError("installed libcadical differs from frozen build")
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    command = (
        compiler,
        "-std=c++17",
        "-O3",
        "-DNDEBUG",
        "-Wall",
        "-Wextra",
        "-Werror",
        f"-I{include_path}",
        f"-I{tracer_path.parent}",
        str(source_path),
        str(library_path),
        "-o",
        str(destination),
    )
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CaDiCaLSensorError("native sensor compilation failed to run") from exc
    if completed.returncode != 0 or not destination.is_file():
        raise CaDiCaLSensorError(
            "native sensor compilation failed: "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )
    return NativeSensorBuild(
        executable=destination,
        compiler=compiler,
        command=command,
        source_sha256=sha256_file(source_path),
        tracer_header_sha256=sha256_file(tracer_path),
        cadical_header_sha256=sha256_file(header_path),
        cadical_library_sha256=sha256_file(library_path),
        executable_sha256=sha256_file(destination),
        compiler_stdout=completed.stdout,
        compiler_stderr=completed.stderr,
    )


@dataclass(frozen=True)
class SolverSnapshot:
    conflicts: int
    decisions: int
    propagations: int
    ticks: int

    @classmethod
    def from_mapping(cls, value: object, field: str) -> "SolverSnapshot":
        row = _mapping(value, field)
        if set(row) != {"conflicts", "decisions", "propagations", "ticks"}:
            raise CaDiCaLSensorError(f"{field} fields differ")
        return cls(
            conflicts=_integer(row["conflicts"], f"{field}.conflicts"),
            decisions=_integer(row["decisions"], f"{field}.decisions"),
            propagations=_integer(row["propagations"], f"{field}.propagations"),
            ticks=_integer(row["ticks"], f"{field}.ticks"),
        )

    def describe(self) -> dict[str, int]:
        return {
            "conflicts": self.conflicts,
            "decisions": self.decisions,
            "propagations": self.propagations,
            "ticks": self.ticks,
        }


@dataclass(frozen=True)
class ProofEvent:
    clause_id: int
    redundant: bool
    witness: int
    conclusion_phase: bool
    snapshot: SolverSnapshot
    clause: tuple[int, ...]
    antecedents: tuple[int, ...]

    @classmethod
    def from_mapping(cls, value: object, field: str) -> "ProofEvent":
        row = _mapping(value, field)
        expected = {
            "id",
            "redundant",
            "witness",
            "conclusion_phase",
            "snapshot",
            "clause",
            "antecedents",
        }
        if set(row) != expected:
            raise CaDiCaLSensorError(f"{field} fields differ")
        return cls(
            clause_id=_integer(row["id"], f"{field}.id", 1),
            redundant=_boolean(row["redundant"], f"{field}.redundant"),
            witness=_signed_integer(row["witness"], f"{field}.witness"),
            conclusion_phase=_boolean(
                row["conclusion_phase"], f"{field}.conclusion_phase"
            ),
            snapshot=SolverSnapshot.from_mapping(
                row["snapshot"], f"{field}.snapshot"
            ),
            clause=_integer_list(row["clause"], f"{field}.clause"),
            antecedents=_integer_list(
                row["antecedents"], f"{field}.antecedents"
            ),
        )


@dataclass(frozen=True)
class AssumptionClause:
    clause_id: int
    clause: tuple[int, ...]
    antecedents: tuple[int, ...]

    @classmethod
    def from_mapping(cls, value: object, field: str) -> "AssumptionClause":
        row = _mapping(value, field)
        if set(row) != {"id", "clause", "antecedents"}:
            raise CaDiCaLSensorError(f"{field} fields differ")
        return cls(
            clause_id=_integer(row["id"], f"{field}.id", 1),
            clause=_integer_list(row["clause"], f"{field}.clause"),
            antecedents=_integer_list(
                row["antecedents"], f"{field}.antecedents"
            ),
        )


@dataclass(frozen=True)
class ProbeRecord:
    bit_index: int
    assumed_value: int
    assumption_literal: int
    requested_conflict_horizon: int
    status: int
    reported_status: int
    original_clause_count: int
    last_original_id: int
    reserved_original_ids: int
    stats: Mapping[str, int]
    proof_counters: Mapping[str, int]
    conclusion: Mapping[str, object]
    assumption_clauses: tuple[AssumptionClause, ...]
    resources: Mapping[str, int]
    final_overshoot_conflicts: int
    events: tuple[ProofEvent, ...]
    deterministic_sha256: str

    @classmethod
    def from_mapping(cls, value: object) -> "ProbeRecord":
        row = _mapping(value, "probe")
        expected = {
            "schema",
            "bit_index",
            "assumed_value",
            "assumption_literal",
            "requested_conflict_horizon",
            "status",
            "reported_status",
            "reported_status_clause_id",
            "solve_query_seen",
            "assumptions",
            "original_clause_count",
            "original_literal_count",
            "last_original_id",
            "reserved_original_ids",
            "stats",
            "final_overshoot_conflicts",
            "proof_counters",
            "conclusion",
            "assumption_clauses",
            "resources",
            "events",
        }
        if set(row) != expected or row.get("schema") != PROBE_SCHEMA:
            raise CaDiCaLSensorError("native probe schema or fields differ")
        bit = _integer(row["bit_index"], "bit_index")
        if bit >= KEY_BITS:
            raise CaDiCaLSensorError("probe bit is outside the 256-bit key")
        assumed = _integer(row["assumed_value"], "assumed_value")
        if assumed not in (0, 1):
            raise CaDiCaLSensorError("assumed_value must be zero or one")
        literal = _signed_integer(row["assumption_literal"], "assumption_literal")
        expected_literal = bit + 1 if assumed else -(bit + 1)
        assumptions = _integer_list(row["assumptions"], "assumptions")
        if literal != expected_literal or assumptions != (literal,):
            raise CaDiCaLSensorError("probe assumption binding differs")
        if row["solve_query_seen"] is not True:
            raise CaDiCaLSensorError("CaDiCaL solve query callback was not observed")
        status = _signed_integer(row["status"], "status")
        reported = _signed_integer(row["reported_status"], "reported_status")
        if status not in (0, 10, 20) or reported != status:
            raise CaDiCaLSensorError("solver and tracer status differ")
        stats_row = _mapping(row["stats"], "stats")
        if set(stats_row) != {"conflicts", "decisions", "propagations", "ticks"}:
            raise CaDiCaLSensorError("native statistic fields differ")
        stats = {
            str(name): _signed_integer(count, f"stats.{name}")
            for name, count in stats_row.items()
        }
        for required in ("conflicts", "decisions", "propagations", "ticks"):
            if stats.get(required, -1) < 0:
                raise CaDiCaLSensorError(f"native statistic {required} is unavailable")
        counter_row = _mapping(row["proof_counters"], "proof_counters")
        if set(counter_row) != {
            "deleted",
            "demoted",
            "weakened",
            "strengthened",
            "equivalences",
            "assumption_resets",
        }:
            raise CaDiCaLSensorError("native proof-counter fields differ")
        counters = {
            str(name): _integer(count, f"proof_counters.{name}")
            for name, count in counter_row.items()
        }
        resource_row = _mapping(row["resources"], "resources")
        if set(resource_row) != {
            "solver_cpu_microseconds",
            "solver_wall_microseconds",
            "solver_peak_rss_bytes",
        }:
            raise CaDiCaLSensorError("native resource fields differ")
        resources = {
            str(name): _integer(count, f"resources.{name}")
            for name, count in resource_row.items()
        }
        events_value = row["events"]
        if not isinstance(events_value, list):
            raise CaDiCaLSensorError("probe events must be an array")
        events = tuple(
            ProofEvent.from_mapping(item, f"events[{index}]")
            for index, item in enumerate(events_value)
        )
        horizon = _integer(
            row["requested_conflict_horizon"],
            "requested_conflict_horizon",
            1,
        )
        overshoot = _signed_integer(
            row["final_overshoot_conflicts"], "final_overshoot_conflicts"
        )
        if status == 0 and (
            stats["conflicts"] < horizon
            or overshoot < 0
            or stats["conflicts"] - horizon != overshoot
        ):
            raise CaDiCaLSensorError("native conflict overshoot accounting differs")
        if any(event.snapshot.conflicts > horizon for event in events):
            raise CaDiCaLSensorError("native probe serialized post-horizon events")
        original_count = _integer(
            row["original_clause_count"], "original_clause_count", 1
        )
        last_original = _integer(row["last_original_id"], "last_original_id", 1)
        reserved = _integer(
            row["reserved_original_ids"], "reserved_original_ids", 1
        )
        if original_count != last_original or reserved != original_count:
            raise CaDiCaLSensorError("native original-clause ID boundary differs")
        assumption_clause_value = row["assumption_clauses"]
        if not isinstance(assumption_clause_value, list):
            raise CaDiCaLSensorError("assumption_clauses must be an array")
        assumption_clauses = tuple(
            AssumptionClause.from_mapping(
                item, f"assumption_clauses[{index}]"
            )
            for index, item in enumerate(assumption_clause_value)
        )
        conclusion_row = _mapping(row["conclusion"], "conclusion")
        if set(conclusion_row) != {"type", "clause_ids", "model_size", "trail_size"}:
            raise CaDiCaLSensorError("conclusion fields differ")
        conclusion = {
            "type": _signed_integer(conclusion_row["type"], "conclusion.type"),
            "clause_ids": list(
                _integer_list(conclusion_row["clause_ids"], "conclusion.clause_ids")
            ),
            "model_size": _signed_integer(
                conclusion_row["model_size"], "conclusion.model_size"
            ),
            "trail_size": _signed_integer(
                conclusion_row["trail_size"], "conclusion.trail_size"
            ),
        }
        if status == 0 and not events:
            raise CaDiCaLSensorError("UNKNOWN probe must contain frontier events")
        previous_id = original_count
        previous_snapshot = SolverSnapshot(0, 0, 0, 0)
        for event in events:
            if event.clause_id <= previous_id:
                raise CaDiCaLSensorError("derived proof IDs are not increasing")
            previous_id = event.clause_id
            if not event.conclusion_phase:
                current = event.snapshot
                if (
                    current.conflicts < previous_snapshot.conflicts
                    or current.decisions < previous_snapshot.decisions
                    or current.propagations < previous_snapshot.propagations
                    or current.ticks < previous_snapshot.ticks
                ):
                    raise CaDiCaLSensorError("proof-event work counters regressed")
                previous_snapshot = current
        deterministic = dict(row)
        deterministic.pop("resources")
        return cls(
            bit_index=bit,
            assumed_value=assumed,
            assumption_literal=literal,
            requested_conflict_horizon=horizon,
            status=status,
            reported_status=reported,
            original_clause_count=original_count,
            last_original_id=last_original,
            reserved_original_ids=reserved,
            stats=stats,
            proof_counters=counters,
            conclusion=conclusion,
            assumption_clauses=assumption_clauses,
            resources=resources,
            final_overshoot_conflicts=overshoot,
            events=events,
            deterministic_sha256=canonical_sha256(deterministic),
        )


@dataclass(frozen=True)
class ProbeStreamHeader:
    cadical_version: str
    cnf_path: str
    variables: int
    original_clause_count: int
    first_bit: int
    last_bit: int
    conflict_horizon: int
    seed: int
    branch_isolation: str
    baseline_snapshot: SolverSnapshot
    baseline_events: tuple[ProofEvent, ...]

    @classmethod
    def from_mapping(cls, value: object) -> "ProbeStreamHeader":
        row = _mapping(value, "stream header")
        expected = {
            "schema",
            "probe_schema",
            "cadical_version",
            "cnf_path",
            "variables",
            "original_clause_count",
            "original_literal_count",
            "last_original_id",
            "reserved_original_ids",
            "public_propagation_status",
            "baseline_stats",
            "baseline_events",
            "first_bit",
            "last_bit",
            "conflict_horizon",
            "seed",
            "branch_isolation",
        }
        if (
            set(row) != expected
            or row.get("schema") != STREAM_HEADER_SCHEMA
            or row.get("probe_schema") != PROBE_SCHEMA
            or row.get("cadical_version") != "3.0.0"
            or row.get("branch_isolation") != "single-threaded-posix-fork-cow"
            or row.get("public_propagation_status") != 0
            or not isinstance(row.get("cnf_path"), str)
        ):
            raise CaDiCaLSensorError("native stream header differs")
        clause_count = _integer(
            row["original_clause_count"], "header.original_clause_count", 1
        )
        if (
            row["last_original_id"] != clause_count
            or row["reserved_original_ids"] != clause_count
        ):
            raise CaDiCaLSensorError("native header clause-ID boundary differs")
        baseline_value = row["baseline_events"]
        if not isinstance(baseline_value, list) or not baseline_value:
            raise CaDiCaLSensorError("native stream lacks public baseline events")
        baseline_events = tuple(
            ProofEvent.from_mapping(item, f"baseline_events[{index}]")
            for index, item in enumerate(baseline_value)
        )
        previous_id = clause_count
        for event in baseline_events:
            if event.clause_id <= previous_id:
                raise CaDiCaLSensorError("public baseline proof IDs are not increasing")
            previous_id = event.clause_id
        return cls(
            cadical_version=str(row["cadical_version"]),
            cnf_path=str(row["cnf_path"]),
            variables=_integer(row["variables"], "header.variables", 1),
            original_clause_count=clause_count,
            first_bit=_integer(row["first_bit"], "header.first_bit"),
            last_bit=_integer(row["last_bit"], "header.last_bit"),
            conflict_horizon=_integer(
                row["conflict_horizon"], "header.conflict_horizon", 1
            ),
            seed=_integer(row["seed"], "header.seed"),
            branch_isolation=str(row["branch_isolation"]),
            baseline_snapshot=SolverSnapshot.from_mapping(
                row["baseline_stats"], "header.baseline_stats"
            ),
            baseline_events=baseline_events,
        )


@dataclass(frozen=True)
class NativeProbeStream:
    header: ProbeStreamHeader
    records: Iterator[ProbeRecord]


def iter_native_probe_records(
    *,
    executable: str | Path,
    cnf_path: str | Path,
    first_bit: int,
    last_bit: int,
    conflict_limit: int,
    seed: int,
    timeout_seconds: float,
) -> Iterator[ProbeStreamHeader | ProbeRecord]:
    """Yield one strict header followed by ordered probe records.

    Stdout is consumed one JSON object at a time; the full proof stream is never
    retained in Python or persisted as an unbounded model state.
    """

    command = (
        str(Path(executable).resolve(strict=True)),
        "--cnf",
        str(Path(cnf_path).resolve(strict=True)),
        "--first-bit",
        str(first_bit),
        "--last-bit",
        str(last_bit),
        "--conflict-limit",
        str(conflict_limit),
        "--seed",
        str(seed),
    )
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
            start_new_session=True,
        )
    except OSError as exc:
        raise CaDiCaLSensorError("could not start native paired sensor") from exc
    if process.stdout is None or process.stderr is None:  # pragma: no cover
        process.kill()
        raise CaDiCaLSensorError("native paired sensor pipes are unavailable")
    expired = threading.Event()

    def kill_process_group() -> None:
        expired.set()
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    watchdog = threading.Timer(timeout_seconds, kill_process_group)
    watchdog.daemon = True
    watchdog.start()
    expected_record = 0
    header: ProbeStreamHeader | None = None
    try:
        for line_number, line in enumerate(process.stdout, start=1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CaDiCaLSensorError(
                    f"native sensor emitted invalid JSON at line {line_number}"
                ) from exc
            if line_number == 1:
                header = ProbeStreamHeader.from_mapping(value)
                requested_cnf = str(Path(cnf_path).resolve(strict=True))
                if (
                    header.first_bit != first_bit
                    or header.last_bit != last_bit
                    or header.conflict_horizon != conflict_limit
                    or header.seed != seed
                    or header.cnf_path != requested_cnf
                ):
                    raise CaDiCaLSensorError("native stream request binding differs")
                yield header
                continue
            if header is None:  # pragma: no cover
                raise CaDiCaLSensorError("native stream lacks a header")
            record = ProbeRecord.from_mapping(value)
            expected_bit = first_bit + expected_record // 2
            expected_value = expected_record % 2
            if (
                record.bit_index != expected_bit
                or record.assumed_value != expected_value
                or record.requested_conflict_horizon != conflict_limit
                or record.original_clause_count != header.original_clause_count
            ):
                raise CaDiCaLSensorError("native probe ordering or binding differs")
            baseline_last_id = header.baseline_events[-1].clause_id
            if record.events and record.events[0].clause_id <= baseline_last_id:
                raise CaDiCaLSensorError(
                    "native branch proof IDs overlap the public baseline"
                )
            expected_record += 1
            yield record
        return_code = process.wait()
        stderr = process.stderr.read()
        if expired.is_set():
            raise CaDiCaLSensorError("native paired sensor exceeded timeout")
        expected_count = 2 * (last_bit - first_bit + 1)
        if return_code != 0 or expected_record != expected_count:
            raise CaDiCaLSensorError(
                "native paired sensor failed or stopped early: "
                f"{stderr.strip() or f'{expected_record}/{expected_count} records'}"
            )
        if stderr.strip():
            raise CaDiCaLSensorError("native paired sensor emitted stderr")
    except Exception:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()
        raise
    finally:
        watchdog.cancel()
        process.stdout.close()
        process.stderr.close()


@dataclass(frozen=True)
class ClauseProvenanceIndex:
    variable_count: int
    clause_count: int
    template_clause_count: int
    operation_ids: np.ndarray
    operation_bits: np.ndarray
    key_masks: tuple[int, ...]
    clause_lengths: np.ndarray
    operation_metadata: tuple[Mapping[str, object], ...]
    cnf_sha256: str
    map_sha256: str

    @classmethod
    def load(
        cls, cnf_path: str | Path, map_path: str | Path
    ) -> "ClauseProvenanceIndex":
        cnf = Path(cnf_path)
        sidecar = Path(map_path)
        try:
            document = json.loads(sidecar.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CaDiCaLSensorError("could not load full256 semantic map") from exc
        if not isinstance(document, dict):
            raise CaDiCaLSensorError("full256 semantic map must be an object")
        template_count = _integer(
            document.get("clause_count"), "map.clause_count", 1
        )
        operations_value = document.get("operations")
        if not isinstance(operations_value, list) or not operations_value:
            raise CaDiCaLSensorError("semantic map operations are absent")
        operation_ids = np.full(template_count + 641, -1, dtype=np.int16)
        operation_bits = np.full(template_count + 641, -1, dtype=np.int8)
        operation_metadata: list[Mapping[str, object]] = []
        for expected_id, raw_operation in enumerate(operations_value):
            operation = _mapping(raw_operation, f"operations[{expected_id}]")
            if operation.get("operation_id") != expected_id:
                raise CaDiCaLSensorError("semantic operation IDs are not contiguous")
            operation_metadata.append(operation)
            bit_ranges = operation.get("bit_ranges")
            if not isinstance(bit_ranges, list) or len(bit_ranges) != 32:
                raise CaDiCaLSensorError("semantic operation bit ranges differ")
            for raw_range in bit_ranges:
                bit_range = _mapping(raw_range, "bit_range")
                bit = _integer(bit_range.get("bit"), "bit_range.bit")
                first = _integer(
                    bit_range.get("first_clause"), "bit_range.first_clause", 1
                )
                last = _integer(
                    bit_range.get("last_clause"), "bit_range.last_clause", first
                )
                if last > template_count:
                    raise CaDiCaLSensorError("semantic clause range exceeds template")
                existing = operation_ids[first : last + 1]
                if np.any(existing != -1):
                    raise CaDiCaLSensorError("semantic clause ranges overlap")
                operation_ids[first : last + 1] = expected_id
                operation_bits[first : last + 1] = bit

        key_masks: list[int] = [0]
        lengths: list[int] = [0]
        variable_count = clause_count = -1
        seen_clauses = 0
        try:
            with cnf.open("r", encoding="ascii") as handle:
                for line_number, raw_line in enumerate(handle, start=1):
                    line = raw_line.strip()
                    if not line or line.startswith("c"):
                        continue
                    if line.startswith("p "):
                        fields = line.split()
                        if len(fields) != 4 or fields[:2] != ["p", "cnf"]:
                            raise CaDiCaLSensorError("DIMACS header differs")
                        variable_count = int(fields[2])
                        clause_count = int(fields[3])
                        continue
                    if variable_count < 0:
                        raise CaDiCaLSensorError("DIMACS clause precedes header")
                    values = [int(value) for value in line.split()]
                    if not values or values[-1] != 0 or 0 in values[:-1]:
                        raise CaDiCaLSensorError(
                            f"invalid DIMACS clause at line {line_number}"
                        )
                    clause = values[:-1]
                    mask = 0
                    for literal in clause:
                        variable = abs(literal)
                        if not 1 <= variable <= variable_count:
                            raise CaDiCaLSensorError("DIMACS literal is out of range")
                        if variable <= KEY_BITS:
                            mask |= 1 << (variable - 1)
                    key_masks.append(mask)
                    lengths.append(len(clause))
                    seen_clauses += 1
        except (OSError, UnicodeError, ValueError) as exc:
            if isinstance(exc, CaDiCaLSensorError):
                raise
            raise CaDiCaLSensorError("could not parse public full256 CNF") from exc
        expected_public = template_count + 640
        if clause_count != expected_public or seen_clauses != clause_count:
            raise CaDiCaLSensorError("public CNF clause count differs from map")
        if len(operation_ids) != clause_count + 1:
            raise CaDiCaLSensorError("provenance array length differs")
        operation_ids.setflags(write=False)
        operation_bits.setflags(write=False)
        clause_lengths = np.asarray(lengths, dtype=np.uint8)
        clause_lengths.setflags(write=False)
        return cls(
            variable_count=variable_count,
            clause_count=clause_count,
            template_clause_count=template_count,
            operation_ids=operation_ids,
            operation_bits=operation_bits,
            key_masks=tuple(key_masks),
            clause_lengths=clause_lengths,
            operation_metadata=tuple(operation_metadata),
            cnf_sha256=sha256_file(cnf),
            map_sha256=sha256_file(sidecar),
        )

    def _clause_vector(self, clause_id: int) -> np.ndarray:
        if not 1 <= clause_id <= self.clause_count:
            raise CaDiCaLSensorError("original antecedent ID is out of range")
        vector = np.zeros(MOTIF_DIMENSIONS, dtype=np.float64)
        operation_id = int(self.operation_ids[clause_id])
        if operation_id >= 0:
            operation = self.operation_metadata[operation_id]
            round_value = operation.get("round")
            phase_index = 20 if round_value is None else int(round_value) - 1
            if not 0 <= phase_index <= 20:
                raise CaDiCaLSensorError("semantic round is out of range")
            vector[phase_index] = 1.0
            kind = operation.get("kind")
            if kind == "add32":
                vector[21] = 1.0
            elif kind == "xor32":
                vector[22] = 1.0
            else:
                raise CaDiCaLSensorError("semantic operation kind differs")
            step = operation.get("step_index")
            if isinstance(step, int) and not isinstance(step, bool) and 0 <= step < 4:
                vector[23 + step] = 1.0
            lane = operation.get("destination_lane")
            if isinstance(lane, int) and not isinstance(lane, bool):
                vector[27 + (lane % 8)] = 1.0
            bit = int(self.operation_bits[clause_id])
            if not 0 <= bit < 32:
                raise CaDiCaLSensorError("semantic operation bit differs")
            vector[35 + bit // 4] = 1.0
        else:
            vector[43] = 1.0
        if clause_id > self.template_clause_count:
            public_index = clause_id - self.template_clause_count - 1
            if public_index < 32:
                vector[44] = 1.0
            elif public_index < 128:
                vector[45] = 1.0
            else:
                vector[46] = 1.0
        if self.key_masks[clause_id]:
            vector[47] = 1.0
        length = int(self.clause_lengths[clause_id])
        vector[50 + min(max(length, 1), 5) - 1] = 1.0
        return vector

    def describe(self) -> dict[str, object]:
        return {
            "schema": PROVENANCE_SCHEMA,
            "variable_count": self.variable_count,
            "clause_count": self.clause_count,
            "template_clause_count": self.template_clause_count,
            "operation_count": len(self.operation_metadata),
            "motif_dimensions": MOTIF_DIMENSIONS,
            "cnf_sha256": self.cnf_sha256,
            "map_file_sha256": self.map_sha256,
            "original_key_touch_clause_count": sum(
                bool(mask) for mask in self.key_masks
            ),
        }


@dataclass(frozen=True)
class ProofPrefixSummary:
    horizon: int
    snapshot: SolverSnapshot
    exact_conflict_event_present: bool
    frontier_event_gap: int
    derived_clause_count: int
    redundant_clause_count: int
    derived_literal_count: int
    antecedent_link_count: int
    maximum_ancestry_depth: int
    motif: np.ndarray
    key_touch: np.ndarray
    summary_sha256: str

    def describe(self, *, include_vectors: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": PREFIX_SCHEMA,
            "horizon": self.horizon,
            "snapshot": self.snapshot.describe(),
            "exact_conflict_event_present": self.exact_conflict_event_present,
            "frontier_event_gap": self.frontier_event_gap,
            "derived_clause_count": self.derived_clause_count,
            "redundant_clause_count": self.redundant_clause_count,
            "derived_literal_count": self.derived_literal_count,
            "antecedent_link_count": self.antecedent_link_count,
            "maximum_ancestry_depth": self.maximum_ancestry_depth,
            "motif_l1": float(np.abs(self.motif).sum()),
            "key_touch_l1": float(np.abs(self.key_touch).sum()),
            "summary_sha256": self.summary_sha256,
        }
        if include_vectors:
            value["motif"] = self.motif.tolist()
            value["key_touch"] = self.key_touch.tolist()
        return value


def _derived_local_vector(event: ProofEvent, depth: int) -> np.ndarray:
    vector = np.zeros(MOTIF_DIMENSIONS, dtype=np.float64)
    variables = tuple(abs(literal) for literal in event.clause)
    if any(variable <= KEY_BITS for variable in variables):
        vector[47] = 1.0
    if any(385 <= variable <= 896 for variable in variables):
        vector[48] = 1.0
    if any(variable >= 897 for variable in variables):
        vector[49] = 1.0
    length = len(event.clause)
    vector[50 + min(max(length, 1), 5) - 1] = 1.0
    if event.redundant:
        vector[55] = 1.0
    if event.witness:
        vector[56] = 1.0
    if depth <= 1:
        vector[57] = 1.0
    elif depth <= 3:
        vector[58] = 1.0
    elif depth <= 7:
        vector[59] = 1.0
    else:
        vector[60] = 1.0
    antecedents = len(event.antecedents)
    if antecedents <= 1:
        vector[61] = 1.0
    elif antecedents <= 4:
        vector[62] = 1.0
    else:
        vector[63] = 1.0
    return vector


def summarize_probe_prefixes(
    record: ProbeRecord,
    provenance: ClauseProvenanceIndex,
    horizons: Sequence[int],
    *,
    baseline_events: Sequence[ProofEvent] = (),
) -> dict[int, ProofPrefixSummary]:
    """Reduce one proof DAG to complete closed prefixes at conflict cutoffs."""

    ordered_horizons = tuple(sorted(set(horizons)))
    if (
        not ordered_horizons
        or ordered_horizons[0] < 1
        or ordered_horizons[-1] > record.requested_conflict_horizon
        or int(record.stats["conflicts"]) < ordered_horizons[-1]
    ):
        raise CaDiCaLSensorError("proof horizons are invalid for this probe")
    if provenance.clause_count != record.original_clause_count:
        raise CaDiCaLSensorError("probe and semantic provenance clause counts differ")

    node_depth: dict[int, int] = {}
    node_key_mask: dict[int, int] = {}
    node_vector: dict[int, np.ndarray] = {}
    original_vector_cache: dict[int, np.ndarray] = {}
    motif_total = np.zeros(MOTIF_DIMENSIONS, dtype=np.float64)
    key_touch_total = np.zeros(KEY_BITS, dtype=np.float64)
    derived_count = redundant_count = literal_count = link_count = maximum_depth = 0
    last_snapshot: SolverSnapshot | None = None
    seen_exact: set[int] = set()
    results: dict[int, ProofPrefixSummary] = {}
    horizon_index = 0

    def antecedent_vector(clause_id: int) -> np.ndarray:
        cached = original_vector_cache.get(clause_id)
        if cached is None:
            cached = provenance._clause_vector(clause_id)
            original_vector_cache[clause_id] = cached
        return cached

    def derive_node(event: ProofEvent) -> tuple[int, int, np.ndarray]:
        if (
            event.clause_id <= provenance.clause_count
            or event.clause_id in node_depth
        ):
            raise CaDiCaLSensorError("proof DAG contains a duplicate derived ID")
        antecedent_vectors: list[np.ndarray] = []
        ancestry_mask = 0
        parent_depth = 0
        for raw_antecedent in event.antecedents:
            antecedent = abs(raw_antecedent)
            if not antecedent:
                continue
            if antecedent <= provenance.clause_count:
                antecedent_vectors.append(antecedent_vector(antecedent))
                ancestry_mask |= provenance.key_masks[antecedent]
            else:
                if antecedent not in node_depth:
                    raise CaDiCaLSensorError(
                        "derived proof antecedent precedes no recorded clause"
                    )
                antecedent_vectors.append(node_vector[antecedent])
                ancestry_mask |= node_key_mask[antecedent]
                parent_depth = max(parent_depth, node_depth[antecedent])
        direct_mask = 0
        for literal in event.clause:
            variable = abs(literal)
            if variable <= KEY_BITS:
                direct_mask |= 1 << (variable - 1)
        depth = parent_depth + 1
        local = _derived_local_vector(event, depth)
        if antecedent_vectors:
            vector = local + np.mean(antecedent_vectors, axis=0)
        else:
            vector = local
        mask = ancestry_mask | direct_mask
        node_depth[event.clause_id] = depth
        node_key_mask[event.clause_id] = mask
        node_vector[event.clause_id] = vector
        return depth, mask, vector

    for event in baseline_events:
        if event.conclusion_phase:
            continue
        derive_node(event)

    def finalize(horizon: int) -> None:
        if last_snapshot is None or last_snapshot.conflicts > horizon:
            raise CaDiCaLSensorError(f"proof stream lacks a closed conflict-{horizon} prefix")
        frontier_event_gap = horizon - last_snapshot.conflicts
        exact_conflict_event_present = horizon in seen_exact
        motif = motif_total / max(derived_count, 1)
        key_touch = key_touch_total / max(derived_count, 1)
        motif = np.asarray(motif, dtype=np.float32)
        key_touch = np.asarray(key_touch, dtype=np.float32)
        motif.setflags(write=False)
        key_touch.setflags(write=False)
        unsigned = {
            "horizon": horizon,
            "snapshot": last_snapshot.describe(),
            "exact_conflict_event_present": exact_conflict_event_present,
            "frontier_event_gap": frontier_event_gap,
            "derived_clause_count": derived_count,
            "redundant_clause_count": redundant_count,
            "derived_literal_count": literal_count,
            "antecedent_link_count": link_count,
            "maximum_ancestry_depth": maximum_depth,
            "motif_float32le_sha256": hashlib.sha256(
                motif.astype("<f4", copy=False).tobytes(order="C")
            ).hexdigest(),
            "key_touch_float32le_sha256": hashlib.sha256(
                key_touch.astype("<f4", copy=False).tobytes(order="C")
            ).hexdigest(),
        }
        results[horizon] = ProofPrefixSummary(
            horizon=horizon,
            snapshot=last_snapshot,
            exact_conflict_event_present=exact_conflict_event_present,
            frontier_event_gap=frontier_event_gap,
            derived_clause_count=derived_count,
            redundant_clause_count=redundant_count,
            derived_literal_count=literal_count,
            antecedent_link_count=link_count,
            maximum_ancestry_depth=maximum_depth,
            motif=motif,
            key_touch=key_touch,
            summary_sha256=canonical_sha256(unsigned),
        )

    for event in record.events:
        if event.conclusion_phase:
            continue
        conflict = event.snapshot.conflicts
        while (
            horizon_index < len(ordered_horizons)
            and conflict > ordered_horizons[horizon_index]
        ):
            finalize(ordered_horizons[horizon_index])
            horizon_index += 1
        if horizon_index >= len(ordered_horizons):
            break
        if conflict > ordered_horizons[-1]:
            break

        depth, mask, vector = derive_node(event)
        motif_total += vector / math.sqrt(depth)
        touched = mask.bit_count()
        if touched:
            weight = 1.0 / touched
            remaining = mask
            while remaining:
                least = remaining & -remaining
                key_touch_total[least.bit_length() - 1] += weight
                remaining ^= least
        derived_count += 1
        redundant_count += int(event.redundant)
        literal_count += len(event.clause)
        link_count += len(event.antecedents)
        maximum_depth = max(maximum_depth, depth)
        last_snapshot = event.snapshot
        if conflict in ordered_horizons:
            seen_exact.add(conflict)

    while horizon_index < len(ordered_horizons):
        finalize(ordered_horizons[horizon_index])
        horizon_index += 1
    return results


def paired_records(
    records: Iterator[ProbeStreamHeader | ProbeRecord],
) -> tuple[ProbeStreamHeader, Iterator[tuple[ProbeRecord, ProbeRecord]]]:
    """Split a strict native stream into its header and ordered bit pairs."""

    try:
        first = next(records)
    except StopIteration as exc:
        raise CaDiCaLSensorError("native probe stream is empty") from exc
    if not isinstance(first, ProbeStreamHeader):
        raise CaDiCaLSensorError("native probe stream does not start with a header")

    def iterator() -> Iterator[tuple[ProbeRecord, ProbeRecord]]:
        while True:
            try:
                zero = next(records)
            except StopIteration:
                return
            try:
                one = next(records)
            except StopIteration as exc:
                raise CaDiCaLSensorError("native probe stream ends mid-pair") from exc
            if not isinstance(zero, ProbeRecord) or not isinstance(one, ProbeRecord):
                raise CaDiCaLSensorError("native stream contains an extra header")
            if (
                zero.bit_index != one.bit_index
                or zero.assumed_value != 0
                or one.assumed_value != 1
            ):
                raise CaDiCaLSensorError("native paired probe order differs")
            yield zero, one

    return first, iterator()


def pair_commitment(zero: ProbeRecord, one: ProbeRecord) -> str:
    return canonical_sha256(
        {
            "bit_index": zero.bit_index,
            "zero": zero.deterministic_sha256,
            "one": one.deterministic_sha256,
        }
    )


def branch_difficulty(summary: ProofPrefixSummary) -> float:
    """Fixed label-free geometric work score at a closed conflict cutoff."""

    snapshot_value = summary.snapshot
    return math.fsum(
        (
            math.log1p(snapshot_value.decisions),
            math.log1p(snapshot_value.propagations),
            math.log1p(snapshot_value.ticks),
            0.25 * math.log1p(summary.derived_literal_count),
            0.25 * math.log1p(summary.antecedent_link_count),
            0.25 * math.log1p(summary.frontier_event_gap),
        )
    )
