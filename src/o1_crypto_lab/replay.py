"""Read-only replay adapter for stored O1-O sessions.

Only metadata and execution-result envelopes are read. Generated programs are never
imported or executed, and stdout/stderr payloads are omitted from the evidence
stream. Their byte counts and unsalted content fingerprints are integrity metadata,
not a confidentiality mechanism.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .events import EvidenceEvent, EventKind, OutcomeDimension, OutcomeStatus
from .types import InformationLabel


class ReplayError(ValueError):
    pass


_TASK_DIRECTORY = re.compile(r"^(\d+)_")
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _safe_file(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ReplayError(f"session member escapes root: {relative}") from exc
    if not candidate.is_file():
        raise FileNotFoundError(candidate)
    return candidate


def _load_json_bytes(path: Path) -> tuple[dict[str, object], bytes]:
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ReplayError(f"expected JSON object: {path.name}")
    return value, raw


@dataclass(frozen=True)
class ReplayTask:
    task_id: str
    meta_sha256: str
    execution_sha256: str | None
    compiles: OutcomeStatus
    verified: OutcomeStatus
    process: OutcomeStatus
    capability: OutcomeStatus = OutcomeStatus.UNKNOWN
    mission: OutcomeStatus = OutcomeStatus.UNKNOWN
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    stdout_sha256: str = _EMPTY_SHA256
    stderr_sha256: str = _EMPTY_SHA256

    def describe(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "meta_sha256": self.meta_sha256,
            "execution_sha256": self.execution_sha256,
            "outcomes": {
                "compiles": self.compiles.value,
                "verified": self.verified.value,
                "process": self.process.value,
                "capability": self.capability.value,
                "mission": self.mission.value,
            },
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
        }


@dataclass(frozen=True)
class AdaptiveTraceSummary:
    source_sha256: str
    services_discovered: int
    tools_generated: int
    tools_succeeded: int
    adaptive_retries: int
    retry_successes: int
    chained_tools: int

    def describe(self) -> dict[str, object]:
        return {
            "source_artifact": "engagement_report.json",
            "source_sha256": self.source_sha256,
            "services_discovered": self.services_discovered,
            "tools_generated": self.tools_generated,
            "tools_succeeded": self.tools_succeeded,
            "adaptive_retries": self.adaptive_retries,
            "retry_successes": self.retry_successes,
            "chained_tools": self.chained_tools,
            "edge_fidelity": "aggregate counts; parent task ids were not stored",
        }


@dataclass(frozen=True)
class ReplayReport:
    session_id: str
    source_root: str
    source_snapshot_sha256: str
    tasks: tuple[ReplayTask, ...]
    events: tuple[EvidenceEvent, ...]
    adaptive_trace: AdaptiveTraceSummary | None = None

    def build_target_model(self):
        """Stream normalized events into a bounded neutral TargetModel state."""

        from .orchestrator import CryptanalyticTargetModel, ExperimentProposal

        model = CryptanalyticTargetModel(self.source_snapshot_sha256)
        for event in self.events:
            proposal = ExperimentProposal(
                name=event.event_id,
                family=f"replay/{event.dimension.value.lower()}/{event.kind.value.lower()}",
                expected_information_gain=0.0,
                work_units=1,
                labels=frozenset(event.labels),
            )
            model.record_observation(proposal)
        return model

    def describe(self, *, include_events: bool = False) -> dict[str, object]:
        counts: dict[str, dict[str, int]] = {}
        for dimension, values in {
            "compiles": [task.compiles for task in self.tasks],
            "verified": [task.verified for task in self.tasks],
            "process": [task.process for task in self.tasks],
            "capability": [task.capability for task in self.tasks],
            "mission": [task.mission for task in self.tasks],
        }.items():
            counts[dimension] = {
                status.value: sum(value is status for value in values)
                for status in OutcomeStatus
            }
        target_model = self.build_target_model()
        result: dict[str, object] = {
            "schema": "o1-o-session-replay-v2",
            "session_id": self.session_id,
            "source_root": self.source_root,
            "source_snapshot_sha256": self.source_snapshot_sha256,
            "task_count": len(self.tasks),
            "event_count": len(self.events),
            "outcome_counts": counts,
            "tasks": [task.describe() for task in self.tasks],
            "adaptive_trace": (
                None if self.adaptive_trace is None else self.adaptive_trace.describe()
            ),
            "target_model_ingest": {
                "mode": "neutral typed observations; no success reward inferred",
                "observations": target_model.observations,
                "family_attempts": dict(sorted(target_model.family_attempts.items())),
                "state_sha256": target_model.state_sha256(),
                "bounded_control_state": True,
            },
            "semantic_contract": {
                "process_success_is_not_capability_success": True,
                "capability_success_is_not_mission_success": True,
                "stdout_stderr_redacted": True,
                "stdout_stderr_raw_omitted": True,
                "stdout_stderr_hashes_are_unsalted_fingerprints": True,
                "generated_code_executed": False,
            },
        }
        if include_events:
            result["events"] = [event.describe() for event in self.events]
        return result


class O1OSessionReplay:
    """Normalize an existing O1-O run into a deterministic evidence stream."""

    def __init__(self, session_root: str | Path) -> None:
        self.root = Path(session_root).resolve()
        if not self.root.is_dir():
            raise FileNotFoundError(self.root)

    @staticmethod
    def _boolean_status(value: object) -> OutcomeStatus:
        if value is True:
            return OutcomeStatus.POSITIVE
        if value is False:
            return OutcomeStatus.NEGATIVE
        return OutcomeStatus.UNKNOWN

    @staticmethod
    def _process_status(execution: dict[str, object] | None) -> OutcomeStatus:
        if execution is None:
            return OutcomeStatus.UNKNOWN
        exit_code = execution.get("exit_code")
        status_value = execution.get("status", "")
        if exit_code is not None and (
            not isinstance(exit_code, int) or isinstance(exit_code, bool)
        ):
            raise ReplayError("execution exit_code must be an integer or null")
        if not isinstance(status_value, str):
            raise ReplayError("execution status must be a string")
        status = status_value.lower()
        if exit_code == 0 and status in {"success", "ok", "completed"}:
            return OutcomeStatus.POSITIVE
        if isinstance(exit_code, int) or status:
            return OutcomeStatus.NEGATIVE
        return OutcomeStatus.UNKNOWN

    @staticmethod
    def _event(
        *,
        session_id: str,
        task_id: str,
        kind: EventKind,
        address: str,
        dimension: OutcomeDimension,
        status: OutcomeStatus,
        source_artifact: str,
        source_sha256: str,
    ) -> EvidenceEvent:
        value = {
            OutcomeStatus.POSITIVE: 1.0,
            OutcomeStatus.NEGATIVE: -1.0,
            OutcomeStatus.UNKNOWN: 0.0,
        }[status]
        confidence = 1.0 if status is not OutcomeStatus.UNKNOWN else 0.0
        return EvidenceEvent(
            session_id=session_id,
            source_task=task_id,
            kind=kind,
            address=address,
            dimension=dimension,
            status=status,
            confidence=confidence,
            value=value,
            source_artifact=source_artifact,
            source_sha256=source_sha256,
            labels=(InformationLabel.INTERNAL_TRAIN, InformationLabel.TRAIN_LABEL),
        )

    @staticmethod
    def _nonnegative_int(value: object, *, field: str) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ReplayError(
                f"engagement field {field} must be a non-negative integer"
            )
        return value

    @staticmethod
    def _output_bytes(execution: dict[str, object] | None, *, field: str) -> bytes:
        if execution is None:
            return b""
        value = execution.get(field, "")
        if not isinstance(value, str):
            raise ReplayError(f"execution {field} must be a string")
        return value.encode("utf-8")

    @classmethod
    def _adaptive_summary(
        cls, report: dict[str, object], *, source_sha256: str
    ) -> AdaptiveTraceSummary:
        services = report.get("services_discovered", [])
        if not isinstance(services, list):
            raise ReplayError("services_discovered must be an array")
        return AdaptiveTraceSummary(
            source_sha256=source_sha256,
            services_discovered=len(services),
            tools_generated=cls._nonnegative_int(
                report.get("tools_generated"), field="tools_generated"
            ),
            tools_succeeded=cls._nonnegative_int(
                report.get("tools_succeeded"), field="tools_succeeded"
            ),
            adaptive_retries=cls._nonnegative_int(
                report.get("adaptive_retries"), field="adaptive_retries"
            ),
            retry_successes=cls._nonnegative_int(
                report.get("retry_successes"), field="retry_successes"
            ),
            chained_tools=cls._nonnegative_int(
                report.get("chained_tools"), field="chained_tools"
            ),
        )

    @staticmethod
    def _count_event(
        *,
        session_id: str,
        address: str,
        value: int,
        dimension: OutcomeDimension,
        source_sha256: str,
    ) -> EvidenceEvent:
        return EvidenceEvent(
            session_id=session_id,
            source_task="SESSION",
            kind=EventKind.OBSERVATION,
            address=address,
            dimension=dimension,
            status=OutcomeStatus.UNKNOWN,
            confidence=1.0,
            value=float(value),
            source_artifact="engagement_report.json",
            source_sha256=source_sha256,
            labels=(InformationLabel.INTERNAL_TRAIN, InformationLabel.TRAIN_LABEL),
        )

    def _task_directories(self) -> Iterable[tuple[str, Path]]:
        seen: set[str] = set()
        for child in sorted(self.root.iterdir(), key=lambda item: item.name):
            match = _TASK_DIRECTORY.match(child.name)
            if not match or not child.is_dir():
                continue
            task_id = match.group(1)
            if task_id in seen:
                raise ReplayError(f"duplicate task id: {task_id}")
            seen.add(task_id)
            resolved = child.resolve()
            try:
                resolved.relative_to(self.root)
            except ValueError as exc:
                raise ReplayError(
                    f"task directory escapes session: {child.name}"
                ) from exc
            yield task_id, resolved

    def replay(self) -> ReplayReport:
        session_path = _safe_file(self.root, "session.json")
        session, session_raw = _load_json_bytes(session_path)
        session_id = str(session.get("session_id") or self.root.name)
        tasks: list[ReplayTask] = []
        events: list[EvidenceEvent] = []
        snapshot_parts = [("session.json", _sha256_bytes(session_raw))]
        adaptive_trace = None

        engagement_path = self.root / "engagement_report.json"
        if engagement_path.exists():
            safe_engagement = _safe_file(self.root, "engagement_report.json")
            engagement, engagement_raw = _load_json_bytes(safe_engagement)
            engagement_sha = _sha256_bytes(engagement_raw)
            snapshot_parts.append(("engagement_report.json", engagement_sha))
            adaptive_trace = self._adaptive_summary(
                engagement, source_sha256=engagement_sha
            )
            for field, value, dimension in (
                (
                    "services_discovered",
                    adaptive_trace.services_discovered,
                    OutcomeDimension.GENERATION,
                ),
                (
                    "tools_generated",
                    adaptive_trace.tools_generated,
                    OutcomeDimension.GENERATION,
                ),
                (
                    "tools_succeeded",
                    adaptive_trace.tools_succeeded,
                    OutcomeDimension.PROCESS,
                ),
                (
                    "adaptive_retries",
                    adaptive_trace.adaptive_retries,
                    OutcomeDimension.PROCESS,
                ),
                (
                    "retry_successes",
                    adaptive_trace.retry_successes,
                    OutcomeDimension.PROCESS,
                ),
                (
                    "chained_tools",
                    adaptive_trace.chained_tools,
                    OutcomeDimension.PROCESS,
                ),
            ):
                events.append(
                    self._count_event(
                        session_id=session_id,
                        address=f"session/{field}",
                        value=value,
                        dimension=dimension,
                        source_sha256=engagement_sha,
                    )
                )

        for task_id, task_root in self._task_directories():
            relative_root = task_root.relative_to(self.root).as_posix()
            logical_meta = f"tasks/{task_id}/meta.json"
            logical_execution = f"tasks/{task_id}/execution_result.json"
            meta_path = _safe_file(self.root, f"{relative_root}/meta.json")
            meta, meta_raw = _load_json_bytes(meta_path)
            declared_id = str(meta.get("task_id", task_id))
            if declared_id != task_id:
                raise ReplayError(
                    f"task id mismatch for {relative_root}: {declared_id} != {task_id}"
                )
            meta_sha = _sha256_bytes(meta_raw)
            snapshot_parts.append((f"{relative_root}/meta.json", meta_sha))

            execution_path = task_root / "execution_result.json"
            execution: dict[str, object] | None = None
            execution_sha: str | None = None
            if execution_path.exists():
                safe_execution = _safe_file(
                    self.root, f"{relative_root}/execution_result.json"
                )
                execution, execution_raw = _load_json_bytes(safe_execution)
                execution_sha = _sha256_bytes(execution_raw)
                snapshot_parts.append(
                    (f"{relative_root}/execution_result.json", execution_sha)
                )

            compiles = self._boolean_status(meta.get("compiles"))
            verified = self._boolean_status(meta.get("verified"))
            process = self._process_status(execution)
            stdout = self._output_bytes(execution, field="stdout")
            stderr = self._output_bytes(execution, field="stderr")
            task = ReplayTask(
                task_id=task_id,
                meta_sha256=meta_sha,
                execution_sha256=execution_sha,
                compiles=compiles,
                verified=verified,
                process=process,
                stdout_bytes=len(stdout),
                stderr_bytes=len(stderr),
                stdout_sha256=_sha256_bytes(stdout),
                stderr_sha256=_sha256_bytes(stderr),
            )
            tasks.append(task)
            events.extend(
                [
                    self._event(
                        session_id=session_id,
                        task_id=task_id,
                        kind=EventKind.ACTION,
                        address=f"task/{task_id}/generated",
                        dimension=OutcomeDimension.GENERATION,
                        status=compiles,
                        source_artifact=logical_meta,
                        source_sha256=meta_sha,
                    ),
                    self._event(
                        session_id=session_id,
                        task_id=task_id,
                        kind=EventKind.SUPPORT,
                        address=f"task/{task_id}/structural_verification",
                        dimension=OutcomeDimension.GENERATION,
                        status=verified,
                        source_artifact=logical_meta,
                        source_sha256=meta_sha,
                    ),
                ]
            )
            if execution_sha is not None:
                events.append(
                    self._event(
                        session_id=session_id,
                        task_id=task_id,
                        kind=EventKind.RESULT,
                        address=f"task/{task_id}/process",
                        dimension=OutcomeDimension.PROCESS,
                        status=process,
                        source_artifact=logical_execution,
                        source_sha256=execution_sha,
                    )
                )

        if not tasks:
            raise ReplayError("session contains no task directories")
        snapshot_payload = "\n".join(
            f"{digest}  {name}" for name, digest in sorted(snapshot_parts)
        ).encode("utf-8")
        return ReplayReport(
            session_id=session_id,
            source_root=str(self.root),
            source_snapshot_sha256=_sha256_bytes(snapshot_payload),
            tasks=tuple(tasks),
            events=tuple(events),
            adaptive_trace=adaptive_trace,
        )
