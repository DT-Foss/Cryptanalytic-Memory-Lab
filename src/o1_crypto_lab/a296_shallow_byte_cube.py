"""Direct A296 H1/2/4/8 byte-cube transfer onto a full-256 relation.

The measurement boundary accepts only the public ChaCha20 view.  Candidate
scores are frozen before the caller may compare them with a known consumed
target byte.
"""

from __future__ import annotations

import hashlib
import json
import math
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence, cast

import numpy as np

from .a291_a296_fap_transfer import (
    A291_HORIZONS,
    exact_a291_selected_channel_scores,
    load_frozen_a291_model,
)
from .full256_cnf import KEY_FIRST_VARIABLE, write_full256_instance
from .living_inverse import PublicTargetView, canonical_sha256
from .shape532 import RAW_CHANNELS, RawCell


A296_HELPER_SHA256 = (
    "d536dd2a7d22b4e4f587f44333861b303fb3fdf100b395ac1d911f4e93cd43a3"
)
A296_CANDIDATES = 256
A296_STAGES = A296_CANDIDATES * len(A291_HORIZONS)


class A296ByteCubeError(RuntimeError):
    """The exact helper, public boundary, or complete shallow cube differs."""


@dataclass(frozen=True)
class A296ByteCubeMeasurement:
    byte_index: int
    scores: np.ndarray
    score_sha256: str
    stdout_sha256: str
    instance_sha256: str
    helper_sha256: str
    wall_seconds: float

    def __post_init__(self) -> None:
        if not 0 <= self.byte_index < 32:
            raise A296ByteCubeError("byte_index must be in 0..31")
        if self.scores.shape != (A296_CANDIDATES,) or not np.isfinite(
            self.scores
        ).all():
            raise A296ByteCubeError("A296 scores must be finite float64[256]")
        self.scores.setflags(write=False)

    def describe(self) -> dict[str, object]:
        order = candidate_order(self.scores)
        return {
            "schema": "o1-256-a296-shallow-byte-cube-measurement-v1",
            "byte_index": self.byte_index,
            "horizons": list(A291_HORIZONS),
            "candidate_count": A296_CANDIDATES,
            "other_key_bits_assigned": 0,
            "target_key_inputs": 0,
            "scores": self.scores.tolist(),
            "score_sha256": self.score_sha256,
            "candidate_order": order,
            "candidate_order_uint8_sha256": hashlib.sha256(bytes(order)).hexdigest(),
            "stdout_sha256": self.stdout_sha256,
            "instance_sha256": self.instance_sha256,
            "helper_sha256": self.helper_sha256,
            "wall_seconds": self.wall_seconds,
        }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def key_byte_reader_mapping(byte_index: int) -> tuple[int, ...]:
    """Map one key byte into the unchanged twenty-literal A291 helper ABI."""

    if isinstance(byte_index, bool) or not isinstance(byte_index, int):
        raise A296ByteCubeError("byte_index must be an integer")
    if not 0 <= byte_index < 32:
        raise A296ByteCubeError("byte_index must be in 0..31")
    start = byte_index * 8
    candidate_bits = tuple(range(start, start + 8))
    auxiliary_bits = tuple(
        bit for bit in range(256) if bit not in candidate_bits
    )[:12]
    mapping_bits = (*auxiliary_bits, *candidate_bits)
    mapping = tuple(KEY_FIRST_VARIABLE + bit for bit in mapping_bits)
    if len(mapping) != 20 or len(set(mapping)) != 20:
        raise AssertionError("A296 twenty-literal mapping construction failed")
    return mapping


def _native_arguments(
    *, helper: Path, cnf: Path, byte_index: int, watchdog_seconds: float
) -> tuple[str, ...]:
    mapping = key_byte_reader_mapping(byte_index)
    assumptions = tuple(mapping[index] for index in range(19, 11, -1))
    order = tuple(f"{candidate:08b}" for candidate in range(A296_CANDIDATES))
    return (
        str(helper),
        "--cnf",
        str(cnf),
        "--mode",
        f"O1C_A296_FULL256_BYTE_{byte_index:02d}",
        "--assumption-one-literals",
        ",".join(str(value) for value in assumptions),
        "--model-one-literals",
        ",".join(str(value) for value in mapping),
        "--cell-order",
        ",".join(order),
        "--conflict-horizons",
        ",".join(str(value) for value in A291_HORIZONS),
        "--watchdog-seconds",
        format(watchdog_seconds, ".17g"),
    )


def _finite(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise A296ByteCubeError(f"{field} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise A296ByteCubeError(f"{field} must be finite")
    return result


def _stage_to_raw(row: Mapping[str, object]) -> Mapping[str, float]:
    metrics = row.get("metrics_stage_delta")
    if row.get("metric_names") != [
        "conflicts",
        "decisions",
        "search_propagations",
    ] or not isinstance(metrics, list) or len(metrics) != 3:
        raise A296ByteCubeError("A296 native metric ABI differs")
    lengths_raw = row.get("learned_clause_lengths_stage")
    if not isinstance(lengths_raw, list):
        raise A296ByteCubeError("A296 learned clause lengths differ")
    lengths = np.asarray(
        [_finite(value, "learned_clause_lengths_stage[]") for value in lengths_raw],
        dtype=np.float64,
    )
    values = {
        "conflicts": _finite(metrics[0], "conflicts"),
        "decisions": _finite(metrics[1], "decisions"),
        "search_propagations": _finite(metrics[2], "search_propagations"),
        "active_variables_delta": _finite(
            row.get("active_variables_delta"), "active_variables_delta"
        ),
        "irredundant_clauses_delta": _finite(
            row.get("irredundant_clauses_delta"), "irredundant_clauses_delta"
        ),
        "redundant_clauses_delta": _finite(
            row.get("redundant_clauses_delta"), "redundant_clauses_delta"
        ),
        "learned_clause_accepted_stage": _finite(
            row.get("learned_clause_accepted_stage"),
            "learned_clause_accepted_stage",
        ),
        "learned_clause_offered_stage": _finite(
            row.get("learned_clause_offered_stage"), "learned_clause_offered_stage"
        ),
        "learned_clause_rejected_large_stage": _finite(
            row.get("learned_clause_rejected_large_stage"),
            "learned_clause_rejected_large_stage",
        ),
        "learned_literal_count_stage": _finite(
            row.get("learned_literal_count_stage"), "learned_literal_count_stage"
        ),
        "learned_clause_length_mean": float(lengths.mean()) if len(lengths) else 0.0,
        "learned_clause_length_std": float(lengths.std()) if len(lengths) else 0.0,
        "learned_clause_length_max": float(lengths.max()) if len(lengths) else 0.0,
    }
    if set(values) != set(RAW_CHANNELS):
        raise AssertionError("A296 RawCell construction differs")
    return values


def parse_a296_native_cube(stdout: str) -> tuple[RawCell, ...]:
    """Parse one exact helper transcript into the canonical 256-cell cube."""

    cells: list[dict[int, Mapping[str, float]]] = [
        {} for _ in range(A296_CANDIDATES)
    ]
    cell_rows = 0
    summary: Mapping[str, object] | None = None
    for line in stdout.splitlines():
        if line.startswith("FRESH_CI_STAGE "):
            row = cast(
                Mapping[str, object], json.loads(line.removeprefix("FRESH_CI_STAGE "))
            )
            candidate = row.get("cell_index")
            horizon = row.get("horizon")
            prefix = row.get("prefix8")
            if (
                isinstance(candidate, bool)
                or not isinstance(candidate, int)
                or not 0 <= candidate < A296_CANDIDATES
                or horizon not in A291_HORIZONS
                or prefix != f"{candidate:08b}"
                or row.get("status") != "unknown"
                or row.get("terminal") is not False
                or row.get("model_bits_bit0_through_bit19") != []
                or horizon in cells[candidate]
            ):
                raise A296ByteCubeError("A296 stage cover or UNKNOWN gate differs")
            cells[candidate][cast(int, horizon)] = _stage_to_raw(row)
        elif line.startswith("FRESH_CI_CELL "):
            row = cast(
                Mapping[str, object], json.loads(line.removeprefix("FRESH_CI_CELL "))
            )
            if (
                row.get("cell_index") != cell_rows
                or row.get("prefix8") != f"{cell_rows:08b}"
                or row.get("stages_run") != len(A291_HORIZONS)
                or row.get("final_status") != "unknown"
                or row.get("terminal_stage_index") is not None
            ):
                raise A296ByteCubeError("A296 cell completion gate differs")
            cell_rows += 1
        elif line.startswith("FRESH_CI_SUMMARY "):
            if summary is not None:
                raise A296ByteCubeError("duplicate A296 summary")
            summary = cast(
                Mapping[str, object],
                json.loads(line.removeprefix("FRESH_CI_SUMMARY ")),
            )
        elif line:
            raise A296ByteCubeError(f"unexpected A296 output: {line[:120]}")
    if (
        cell_rows != A296_CANDIDATES
        or summary is None
        or summary.get("cells") != A296_CANDIDATES
        or summary.get("stages_emitted") != A296_STAGES
        or summary.get("unknown_cells") != A296_CANDIDATES
        or summary.get("sat_cells") != 0
        or summary.get("unsat_cells") != 0
        or summary.get("conflict_horizons") != list(A291_HORIZONS)
        or summary.get("learned_clause_maximum_size") != 64
        or summary.get("bounded_variable_addition_enabled") is not False
        or any(set(cell) != set(A291_HORIZONS) for cell in cells)
    ):
        raise A296ByteCubeError("A296 complete-cube summary gate differs")
    return tuple(cast(RawCell, cell) for cell in cells)


def measure_public_a296_byte_cube(
    *,
    public: PublicTargetView,
    byte_index: int,
    helper: str | Path,
    template: str | Path,
    semantic_map: str | Path,
    workspace: str | Path,
    watchdog_seconds: float = 2.0,
    external_timeout_seconds: float = 900.0,
) -> A296ByteCubeMeasurement:
    """Measure and score one byte without accepting a target key or label."""

    if not isinstance(public, PublicTargetView):
        raise TypeError("public must be PublicTargetView")
    public.validate()
    if public.block_count != 1:
        raise A296ByteCubeError("A296 byte cube requires one public block")
    helper_path = Path(helper).resolve(strict=True)
    template_path = Path(template).resolve(strict=True)
    map_path = Path(semantic_map).resolve(strict=True)
    workspace_path = Path(workspace).resolve(strict=True)
    helper_sha = _sha256_file(helper_path)
    if helper_sha != A296_HELPER_SHA256:
        raise A296ByteCubeError("A296 exact native helper hash differs")
    if (
        isinstance(watchdog_seconds, bool)
        or not math.isfinite(watchdog_seconds)
        or watchdog_seconds <= 0.0
        or not math.isfinite(external_timeout_seconds)
        or external_timeout_seconds <= 0.0
    ):
        raise A296ByteCubeError("A296 timeouts must be finite and positive")
    with tempfile.TemporaryDirectory(prefix="a296-byte-cube-", dir=workspace_path) as raw:
        instance_path = Path(raw) / "public.cnf"
        instance = write_full256_instance(
            template_path,
            map_path,
            instance_path,
            counter=public.counter_schedule[0],
            nonce=public.nonce,
            output=public.output_blocks[0],
            verify_template=False,
        )
        if (
            instance.key_unit_clause_count != 0
            or instance.assumption_unit_clause_count != 0
            or instance.public_unit_clause_count != 640
        ):
            raise A296ByteCubeError("A296 public CNF contains target-key input")
        command = _native_arguments(
            helper=helper_path,
            cnf=instance_path,
            byte_index=byte_index,
            watchdog_seconds=watchdog_seconds,
        )
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=external_timeout_seconds,
                env={"LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise A296ByteCubeError("A296 native cube did not complete") from exc
        wall_seconds = time.perf_counter() - started
        if completed.returncode != 0 or completed.stderr:
            raise A296ByteCubeError(
                "A296 native cube failed: "
                + (completed.stderr.strip() or f"return code {completed.returncode}")
            )
        cells = parse_a296_native_cube(completed.stdout)
    model = load_frozen_a291_model()
    scores = exact_a291_selected_channel_scores(
        cells,
        means=model.means,
        scales=model.scales,
        coefficients=model.coefficients,
    )
    score_sha = canonical_sha256(scores.tolist())
    return A296ByteCubeMeasurement(
        byte_index=byte_index,
        scores=scores,
        score_sha256=score_sha,
        stdout_sha256=hashlib.sha256(completed.stdout.encode("utf-8")).hexdigest(),
        instance_sha256=instance.instance_sha256,
        helper_sha256=helper_sha,
        wall_seconds=wall_seconds,
    )


def candidate_order(scores: Sequence[float] | np.ndarray) -> list[int]:
    values = np.asarray(scores, dtype=np.float64)
    if values.shape != (A296_CANDIDATES,) or not np.isfinite(values).all():
        raise A296ByteCubeError("candidate scores must be finite float64[256]")
    return sorted(
        range(A296_CANDIDATES),
        key=lambda candidate: (-float(values[candidate]), candidate),
    )


def revealed_byte_rank(
    scores: Sequence[float] | np.ndarray, target_byte: int
) -> int:
    """Evaluate one already-frozen score field against a consumed target byte."""

    if (
        isinstance(target_byte, bool)
        or not isinstance(target_byte, int)
        or not 0 <= target_byte < 256
    ):
        raise A296ByteCubeError("target_byte must be in 0..255")
    return candidate_order(scores).index(target_byte) + 1


__all__ = [
    "A296ByteCubeError",
    "A296ByteCubeMeasurement",
    "A296_CANDIDATES",
    "A296_HELPER_SHA256",
    "A296_STAGES",
    "candidate_order",
    "key_byte_reader_mapping",
    "measure_public_a296_byte_cube",
    "parse_a296_native_cube",
    "revealed_byte_rank",
]
