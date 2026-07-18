"""Exact CaDiCaL completion driven by a frozen 256-bit O1 soft field.

The native adapter never turns O1 predictions into unit clauses.  It presents
their sign and confidence order as reversible CDCL decisions, so the exact
ChaCha relation can learn conflicts and repair wrong O1 choices.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Mapping, Sequence

import numpy as np

from .chacha_trace import chacha20_block
from .living_inverse import KEY_BITS, PublicTargetView, key_bits


GUIDED_RESULT_SCHEMA = "o1-256-cadical-guided-search-result-v1"
CADICAL_VERSION = "3.0.0"
CADICAL_HEADER_SHA256 = (
    "b7111690c61935b9c096d3701be59b3c3d26c555eab8e070f19eb2a97dc5d38c"
)
CADICAL_LIBRARY_SHA256 = (
    "44cae3728485b4fd5736ce7cb986021236652daeda9cca227a2c4ac17d3a8a7f"
)
SearchMode = Literal["internal", "phase", "guided"]


class O1RelationalSearchError(RuntimeError):
    """A frozen field, native build, or exact guided-search result differs."""


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class NativeGuidedSearchBuild:
    executable: Path
    command: tuple[str, ...]
    source_sha256: str
    cadical_header_sha256: str
    cadical_library_sha256: str
    executable_sha256: str

    def describe(self) -> dict[str, object]:
        command = list(self.command)
        output_index = command.index("-o") + 1
        command[output_index] = "<TEMP_OUTPUT>"
        return {
            "source_sha256": self.source_sha256,
            "cadical_header_sha256": self.cadical_header_sha256,
            "cadical_library_sha256": self.cadical_library_sha256,
            "executable_sha256": self.executable_sha256,
            "command": command,
        }


@dataclass(frozen=True)
class GuidedSearchResult:
    mode: SearchMode
    status: int
    conflict_limit: int
    guided_bits: int
    key_model: bytes | None
    stats: Mapping[str, int]
    guided: Mapping[str, int]
    resources: Mapping[str, int]
    raw: Mapping[str, object]

    @property
    def status_name(self) -> str:
        return {0: "UNKNOWN", 10: "SAT", 20: "UNSAT"}[self.status]


def build_native_guided_search(
    *,
    source: str | Path,
    output: str | Path,
    cadical_include: str | Path = "/opt/homebrew/opt/cadical/include",
    cadical_library: str | Path = "/opt/homebrew/opt/cadical/lib/libcadical.a",
    compiler: str = "c++",
    timeout_seconds: float = 60.0,
) -> NativeGuidedSearchBuild:
    source_path = Path(source).resolve(strict=True)
    include_path = Path(cadical_include).resolve(strict=True)
    library_path = Path(cadical_library).resolve(strict=True)
    header_path = include_path / "cadical.hpp"
    destination = Path(output).resolve()
    if shutil.which(compiler) is None or not header_path.is_file():
        raise O1RelationalSearchError("C++ or CaDiCaL development files are absent")
    header_sha = sha256_file(header_path)
    library_sha = sha256_file(library_path)
    if header_sha != CADICAL_HEADER_SHA256 or library_sha != CADICAL_LIBRARY_SHA256:
        raise O1RelationalSearchError("installed CaDiCaL 3.0.0 bytes differ")
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
        str(source_path),
        str(library_path),
        "-o",
        str(destination),
    )
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise O1RelationalSearchError("native guided-search build failed") from exc
    if completed.returncode or not destination.is_file():
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise O1RelationalSearchError(f"native guided-search build failed: {detail}")
    return NativeGuidedSearchBuild(
        executable=destination,
        command=command,
        source_sha256=sha256_file(source_path),
        cadical_header_sha256=header_sha,
        cadical_library_sha256=library_sha,
        executable_sha256=sha256_file(destination),
    )


def _scores(value: Sequence[float] | np.ndarray) -> np.ndarray:
    result = np.asarray(value, dtype=np.float64)
    if result.shape != (KEY_BITS,) or not bool(np.isfinite(result).all()):
        raise O1RelationalSearchError("hint scores must be finite float64[256]")
    return result


def write_hint_scores(path: str | Path, scores: Sequence[float] | np.ndarray) -> str:
    values = _scores(scores)
    payload = "".join(
        f"{index} {float(score):.17g}\n" for index, score in enumerate(values)
    ).encode("ascii")
    destination = Path(path)
    destination.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def repair_radius_scores(
    base_scores: Sequence[float] | np.ndarray,
    truth: Sequence[int] | np.ndarray,
    *,
    wrong_count: int,
) -> np.ndarray:
    """Keep O1 confidence order while flipping the weakest truth phases."""

    values = _scores(base_scores)
    labels = np.asarray(truth)
    if (
        labels.shape != (KEY_BITS,)
        or not bool(np.all((labels == 0) | (labels == 1)))
        or isinstance(wrong_count, bool)
        or not isinstance(wrong_count, int)
        or not 0 <= wrong_count <= KEY_BITS
    ):
        raise O1RelationalSearchError("repair truth or wrong_count differs")
    magnitudes = np.maximum(np.abs(values), np.float64(2.0**-40))
    signs = np.where(labels.astype(bool), 1.0, -1.0)
    weakest = np.lexsort((np.arange(KEY_BITS), magnitudes))[:wrong_count]
    signs[weakest] *= -1.0
    result = magnitudes * signs
    result.setflags(write=False)
    return result


def run_guided_search(
    *,
    executable: str | Path,
    cnf_path: str | Path,
    mode: SearchMode,
    conflict_limit: int,
    guided_bits: int | None = None,
    seed: int = 0,
    hint_path: str | Path | None = None,
    timeout_seconds: float = 60.0,
) -> GuidedSearchResult:
    if mode not in ("internal", "phase", "guided"):
        raise O1RelationalSearchError("search mode differs")
    if (
        isinstance(conflict_limit, bool)
        or not isinstance(conflict_limit, int)
        or conflict_limit < 1
        or isinstance(seed, bool)
        or not isinstance(seed, int)
        or not 0 <= seed <= 2_000_000_000
    ):
        raise O1RelationalSearchError("search limit or seed differs")
    expected_guided_bits = 0 if mode == "internal" else guided_bits
    if (
        isinstance(expected_guided_bits, bool)
        or not isinstance(expected_guided_bits, int)
        or not 0 <= expected_guided_bits <= KEY_BITS
    ):
        raise O1RelationalSearchError("phase/guided mode requires guided_bits")
    command = [
        str(Path(executable).resolve(strict=True)),
        "--cnf",
        str(Path(cnf_path).resolve(strict=True)),
        "--mode",
        mode,
        "--conflict-limit",
        str(conflict_limit),
        "--guided-bits",
        str(expected_guided_bits),
        "--seed",
        str(seed),
    ]
    if mode == "internal":
        if hint_path is not None:
            raise O1RelationalSearchError("internal mode must not receive hints")
    else:
        if hint_path is None:
            raise O1RelationalSearchError("phase/guided mode requires hints")
        command.extend(["--hints", str(Path(hint_path).resolve(strict=True))])
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise O1RelationalSearchError("guided-search execution failed") from exc
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise O1RelationalSearchError(f"guided-search execution failed: {detail}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise O1RelationalSearchError("guided-search JSON is invalid") from exc
    if not isinstance(payload, Mapping):
        raise O1RelationalSearchError("guided-search result must be an object")
    status = payload.get("status")
    model_hex = payload.get("key_model_hex")
    if (
        payload.get("schema") != GUIDED_RESULT_SCHEMA
        or payload.get("mode") != mode
        or payload.get("cadical_version") != CADICAL_VERSION
        or payload.get("variables", 0) < KEY_BITS
        or payload.get("conflict_limit") != conflict_limit
        or payload.get("guided_bits") != expected_guided_bits
        or payload.get("seed") != seed
        or status not in (0, 10, 20)
        or not isinstance(payload.get("stats"), Mapping)
        or not isinstance(payload.get("guided"), Mapping)
        or not isinstance(payload.get("resources"), Mapping)
    ):
        raise O1RelationalSearchError("guided-search result contract differs")
    if status == 10:
        if not isinstance(model_hex, str) or len(model_hex) != 64:
            raise O1RelationalSearchError("SAT result lacks a 256-bit model")
        try:
            model = bytes.fromhex(model_hex)
        except ValueError as exc:
            raise O1RelationalSearchError("SAT model hex is invalid") from exc
    elif model_hex is not None:
        raise O1RelationalSearchError("non-SAT result contains a key model")
    else:
        model = None
    integer_groups: list[dict[str, int]] = []
    for name in ("stats", "guided", "resources"):
        group = payload[name]
        normalized: dict[str, int] = {}
        for field, value in group.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise O1RelationalSearchError(f"{name}.{field} must be nonnegative")
            normalized[str(field)] = value
        integer_groups.append(normalized)
    return GuidedSearchResult(
        mode=mode,
        status=status,
        conflict_limit=conflict_limit,
        guided_bits=expected_guided_bits,
        key_model=model,
        stats=integer_groups[0],
        guided=integer_groups[1],
        resources=integer_groups[2],
        raw=dict(payload),
    )


def model_matches_public(model: bytes, public: PublicTargetView) -> bool:
    public.validate()
    if public.block_count != 1 or not isinstance(model, bytes) or len(model) != 32:
        raise O1RelationalSearchError("model verification requires one public block")
    return (
        chacha20_block(model, public.counter_schedule[0], public.nonce)
        == public.output_blocks[0]
    )


def model_hamming_distance(model: bytes, truth: bytes) -> int:
    return int(np.count_nonzero(key_bits(model) != key_bits(truth)))


__all__ = [
    "CADICAL_HEADER_SHA256",
    "CADICAL_LIBRARY_SHA256",
    "GUIDED_RESULT_SCHEMA",
    "GuidedSearchResult",
    "NativeGuidedSearchBuild",
    "O1RelationalSearchError",
    "build_native_guided_search",
    "model_hamming_distance",
    "model_matches_public",
    "repair_radius_scores",
    "run_guided_search",
    "sha256_file",
    "write_hint_scores",
]
