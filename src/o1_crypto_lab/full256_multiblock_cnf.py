"""Canonical shared-key composition of exact one-block Full256 CNFs.

Every input instance is first verified against the frozen single-block template.
The 256 key variables remain shared; every public or internal variable is moved
into a disjoint block-local range.  The output order is deliberately simple:
for each block, the original template clauses followed by its 640 public units.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Mapping, Protocol, Sequence, cast

from .chacha_trace import UINT32_MASK
from .full256_cnf import (
    PUBLIC_UNIT_CLAUSES,
    Full256CNFError,
    InstanceWriteReport,
    load_full256_template_map,
    verify_full256_instance,
    verify_full256_template,
)
from .living_inverse import canonical_json_bytes


MULTIBLOCK_CNF_SCHEMA = "o1-256-chacha20-shared-key-multiblock-cnf-v1"
MULTIBLOCK_CNF_VERIFICATION_SCHEMA = (
    "o1-256-chacha20-shared-key-multiblock-cnf-verification-v1"
)
MULTIBLOCK_REMAP_RULE = "key-v1..256-shared;v>=257->v+block_index*(32128-256)"
SINGLE_BLOCK_VARIABLE_COUNT = 32_128
SINGLE_BLOCK_TEMPLATE_CLAUSE_COUNT = 187_370
SHARED_KEY_VARIABLE_COUNT = 256
BLOCK_VARIABLE_STRIDE = SINGLE_BLOCK_VARIABLE_COUNT - SHARED_KEY_VARIABLE_COUNT
MINIMUM_BLOCK_COUNT = 1
MAXIMUM_BLOCK_COUNT = 16


class Full256MultiblockCNFError(Full256CNFError):
    """A source instance, remap, report, or immutable output differs."""


class _Digest(Protocol):
    def update(self, value: bytes) -> None: ...

    def hexdigest(self) -> str: ...


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _block_count(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not MINIMUM_BLOCK_COUNT <= value <= MAXIMUM_BLOCK_COUNT
    ):
        raise Full256MultiblockCNFError("multiblock count must be in 1..16")
    return value


def multiblock_variable_count(block_count: int) -> int:
    """Return the exact declared variable count for ``block_count`` blocks."""

    count = _block_count(block_count)
    return SINGLE_BLOCK_VARIABLE_COUNT + (count - 1) * BLOCK_VARIABLE_STRIDE


def multiblock_clause_count(block_count: int) -> int:
    """Return the exact clause count for canonical public-only inputs."""

    return _block_count(block_count) * (
        SINGLE_BLOCK_TEMPLATE_CLAUSE_COUNT + PUBLIC_UNIT_CLAUSES
    )


def remap_full256_variable(variable: int, block_index: int) -> int:
    """Map one single-block variable into the shared-key multiblock space."""

    if (
        isinstance(variable, bool)
        or not isinstance(variable, int)
        or not 1 <= variable <= SINGLE_BLOCK_VARIABLE_COUNT
        or isinstance(block_index, bool)
        or not isinstance(block_index, int)
        or not 0 <= block_index < MAXIMUM_BLOCK_COUNT
    ):
        raise Full256MultiblockCNFError("multiblock variable remap differs")
    if variable <= SHARED_KEY_VARIABLE_COUNT:
        return variable
    return variable + block_index * BLOCK_VARIABLE_STRIDE


def remap_full256_literal(literal: int, block_index: int) -> int:
    """Remap a nonzero signed literal while retaining its polarity."""

    if isinstance(literal, bool) or not isinstance(literal, int) or literal == 0:
        raise Full256MultiblockCNFError("multiblock literal remap differs")
    variable = remap_full256_variable(abs(literal), block_index)
    return variable if literal > 0 else -variable


@dataclass(frozen=True)
class Full256MultiblockBlockReport:
    block_index: int
    counter: int
    nonce_hex: str
    output_sha256: str
    source_instance_sha256: str
    source_instance_bytes: int
    source_public_unit_sha256: str
    remapped_block_sha256: str
    remapped_public_unit_sha256: str
    remapped_block_bytes: int
    variable_count: int
    clause_count: int
    public_unit_clause_count: int

    def __post_init__(self) -> None:
        if (
            isinstance(self.block_index, bool)
            or not isinstance(self.block_index, int)
            or not 0 <= self.block_index < MAXIMUM_BLOCK_COUNT
            or isinstance(self.counter, bool)
            or not isinstance(self.counter, int)
            or not 0 <= self.counter <= UINT32_MASK
            or not isinstance(self.nonce_hex, str)
            or len(self.nonce_hex) != 24
            or any(character not in "0123456789abcdef" for character in self.nonce_hex)
            or any(
                not _is_sha256(value)
                for value in (
                    self.output_sha256,
                    self.source_instance_sha256,
                    self.source_public_unit_sha256,
                    self.remapped_block_sha256,
                    self.remapped_public_unit_sha256,
                )
            )
            or isinstance(self.source_instance_bytes, bool)
            or not isinstance(self.source_instance_bytes, int)
            or self.source_instance_bytes <= 0
            or isinstance(self.remapped_block_bytes, bool)
            or not isinstance(self.remapped_block_bytes, int)
            or self.remapped_block_bytes <= 0
            or self.variable_count
            != remap_full256_variable(SINGLE_BLOCK_VARIABLE_COUNT, self.block_index)
            or self.clause_count
            != SINGLE_BLOCK_TEMPLATE_CLAUSE_COUNT + PUBLIC_UNIT_CLAUSES
            or self.public_unit_clause_count != PUBLIC_UNIT_CLAUSES
        ):
            raise Full256MultiblockCNFError("multiblock per-block report differs")

    def describe(self) -> dict[str, object]:
        return {
            "block_index": self.block_index,
            "counter": self.counter,
            "nonce_hex": self.nonce_hex,
            "output_sha256": self.output_sha256,
            "source_instance_sha256": self.source_instance_sha256,
            "source_instance_bytes": self.source_instance_bytes,
            "source_public_unit_sha256": self.source_public_unit_sha256,
            "remapped_block_sha256": self.remapped_block_sha256,
            "remapped_public_unit_sha256": self.remapped_public_unit_sha256,
            "remapped_block_bytes": self.remapped_block_bytes,
            "variable_count": self.variable_count,
            "clause_count": self.clause_count,
            "public_unit_clause_count": self.public_unit_clause_count,
        }


@dataclass(frozen=True)
class Full256MultiblockCNFReport:
    schema: str
    template_sha256: str
    template_map_sha256: str
    remap_rule: str
    block_count: int
    shared_key_variable_count: int
    block_variable_stride: int
    variable_count: int
    clause_count: int
    public_unit_clause_count: int
    key_unit_clause_count: int
    assumption_unit_clause_count: int
    ordered_source_sha256: str
    body_sha256: str
    instance_sha256: str
    instance_bytes: int
    blocks: tuple[Full256MultiblockBlockReport, ...]

    def __post_init__(self) -> None:
        count = _block_count(self.block_count)
        if (
            self.schema != MULTIBLOCK_CNF_SCHEMA
            or not _is_sha256(self.template_sha256)
            or not _is_sha256(self.template_map_sha256)
            or self.remap_rule != MULTIBLOCK_REMAP_RULE
            or self.shared_key_variable_count != SHARED_KEY_VARIABLE_COUNT
            or self.block_variable_stride != BLOCK_VARIABLE_STRIDE
            or self.variable_count != multiblock_variable_count(count)
            or self.clause_count != multiblock_clause_count(count)
            or self.public_unit_clause_count != count * PUBLIC_UNIT_CLAUSES
            or isinstance(self.key_unit_clause_count, bool)
            or self.key_unit_clause_count != 0
            or isinstance(self.assumption_unit_clause_count, bool)
            or self.assumption_unit_clause_count != 0
            or not _is_sha256(self.ordered_source_sha256)
            or not _is_sha256(self.body_sha256)
            or not _is_sha256(self.instance_sha256)
            or isinstance(self.instance_bytes, bool)
            or not isinstance(self.instance_bytes, int)
            or self.instance_bytes <= 0
            or not isinstance(self.blocks, tuple)
            or len(self.blocks) != count
            or tuple(block.block_index for block in self.blocks) != tuple(range(count))
            or len({block.source_instance_sha256 for block in self.blocks}) != count
            or any(block.nonce_hex != self.blocks[0].nonce_hex for block in self.blocks)
            or any(
                block.counter != self.blocks[0].counter + block.block_index
                for block in self.blocks
            )
            or self.blocks[-1].counter > UINT32_MASK
            or self.ordered_source_sha256 != _ordered_source_digest(self.blocks)
        ):
            raise Full256MultiblockCNFError("multiblock aggregate report differs")

    def describe(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "template_sha256": self.template_sha256,
            "template_map_sha256": self.template_map_sha256,
            "remap_rule": self.remap_rule,
            "block_count": self.block_count,
            "shared_key_variable_count": self.shared_key_variable_count,
            "block_variable_stride": self.block_variable_stride,
            "variable_count": self.variable_count,
            "clause_count": self.clause_count,
            "public_unit_clause_count": self.public_unit_clause_count,
            "key_unit_clause_count": self.key_unit_clause_count,
            "assumption_unit_clause_count": self.assumption_unit_clause_count,
            "ordered_source_sha256": self.ordered_source_sha256,
            "body_sha256": self.body_sha256,
            "instance_sha256": self.instance_sha256,
            "instance_bytes": self.instance_bytes,
            "blocks": [block.describe() for block in self.blocks],
        }


@dataclass(frozen=True)
class _SourceInstance:
    path: Path
    report: Mapping[str, object]
    fingerprint: tuple[int, int, int, int]


def _fingerprint(path: Path) -> tuple[int, int, int, int]:
    stat = path.stat(follow_symlinks=False)
    if not path.is_file():
        raise Full256MultiblockCNFError("multiblock input is not a regular file")
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)


def _load_canonical_mapping(path: Path, field: str) -> dict[str, object]:
    raw = path.read_bytes()

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise Full256MultiblockCNFError(f"duplicate {field} JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise Full256MultiblockCNFError(f"{field} is not valid JSON") from exc
    if not isinstance(value, dict) or raw != canonical_json_bytes(value) + b"\n":
        raise Full256MultiblockCNFError(f"{field} is not canonical JSON")
    return value


def _instance_report_mapping(
    report: InstanceWriteReport | Mapping[str, object] | str | Path,
) -> dict[str, object]:
    if isinstance(report, InstanceWriteReport):
        return report.describe()
    if isinstance(report, (str, Path)):
        return _load_canonical_mapping(
            Path(report).resolve(strict=True), "instance report"
        )
    if not isinstance(report, Mapping):
        raise Full256MultiblockCNFError("source instance report differs")
    return dict(report)


def _report_from_mapping(value: Mapping[str, object]) -> Full256MultiblockCNFReport:
    fields = {
        "schema",
        "template_sha256",
        "template_map_sha256",
        "remap_rule",
        "block_count",
        "shared_key_variable_count",
        "block_variable_stride",
        "variable_count",
        "clause_count",
        "public_unit_clause_count",
        "key_unit_clause_count",
        "assumption_unit_clause_count",
        "ordered_source_sha256",
        "body_sha256",
        "instance_sha256",
        "instance_bytes",
        "blocks",
    }
    raw_blocks = value.get("blocks")
    if set(value) != fields or not isinstance(raw_blocks, list):
        raise Full256MultiblockCNFError("multiblock report fields differ")
    block_fields = {
        "block_index",
        "counter",
        "nonce_hex",
        "output_sha256",
        "source_instance_sha256",
        "source_instance_bytes",
        "source_public_unit_sha256",
        "remapped_block_sha256",
        "remapped_public_unit_sha256",
        "remapped_block_bytes",
        "variable_count",
        "clause_count",
        "public_unit_clause_count",
    }
    blocks: list[Full256MultiblockBlockReport] = []
    for raw in raw_blocks:
        if not isinstance(raw, Mapping) or set(raw) != block_fields:
            raise Full256MultiblockCNFError("multiblock block report fields differ")
        blocks.append(Full256MultiblockBlockReport(**dict(raw)))  # type: ignore[arg-type]
    payload = dict(value)
    payload["blocks"] = tuple(blocks)
    return Full256MultiblockCNFReport(**payload)  # type: ignore[arg-type]


def _report_value(
    report: Full256MultiblockCNFReport | Mapping[str, object] | str | Path,
) -> Full256MultiblockCNFReport:
    if isinstance(report, Full256MultiblockCNFReport):
        return report
    if isinstance(report, (str, Path)):
        return _report_from_mapping(
            _load_canonical_mapping(
                Path(report).resolve(strict=True), "multiblock report"
            )
        )
    if not isinstance(report, Mapping):
        raise Full256MultiblockCNFError("multiblock report differs")
    return _report_from_mapping(report)


def _ordered_source_digest(
    blocks: Sequence[Full256MultiblockBlockReport],
) -> str:
    digest = hashlib.sha256(b"O1-FULL256-MULTIBLOCK-SOURCES-V1\0")
    for block in blocks:
        digest.update(block.block_index.to_bytes(2, "little"))
        digest.update(bytes.fromhex(block.source_instance_sha256))
        digest.update(bytes.fromhex(block.source_public_unit_sha256))
    return digest.hexdigest()


def _validate_public_only_report(report: Mapping[str, object]) -> None:
    if (
        report.get("public_unit_clause_count") != PUBLIC_UNIT_CLAUSES
        or report.get("key_unit_clause_count") != 0
        or report.get("key_unit_clause_sha256") is not None
        or report.get("assumption_unit_clause_count") != 0
        or report.get("assumption_unit_clause_sha256") is not None
        or report.get("assumptions") != []
        or report.get("key_fixed_for_self_test") is not False
        or report.get("fixed_key_sha256") is not None
        or report.get("variable_count") != SINGLE_BLOCK_VARIABLE_COUNT
        or report.get("clause_count")
        != SINGLE_BLOCK_TEMPLATE_CLAUSE_COUNT + PUBLIC_UNIT_CLAUSES
    ):
        raise Full256MultiblockCNFError(
            "multiblock sources must contain exactly 640 public units and no key units"
        )


def _prepare_sources(
    instances: Sequence[
        tuple[
            str | Path,
            InstanceWriteReport | Mapping[str, object] | str | Path,
        ]
    ],
    *,
    template: Path,
    map_path: Path,
) -> tuple[_SourceInstance, ...]:
    if isinstance(instances, (str, bytes)):
        raise Full256MultiblockCNFError("multiblock source inventory differs")
    rows = tuple(instances)
    _block_count(len(rows))
    sources: list[_SourceInstance] = []
    seen: set[Path] = set()
    for raw in rows:
        if not isinstance(raw, tuple) or len(raw) != 2:
            raise Full256MultiblockCNFError("multiblock source row differs")
        path = Path(raw[0]).resolve(strict=True)
        if path in seen or path in (template, map_path):
            raise Full256MultiblockCNFError("multiblock source paths differ")
        seen.add(path)
        report = _instance_report_mapping(raw[1])
        verify_full256_instance(path, template, map_path, report)
        _validate_public_only_report(report)
        sources.append(_SourceInstance(path, report, _fingerprint(path)))
    first_counter = sources[0].report.get("counter")
    first_nonce = sources[0].report.get("nonce_hex")
    if (
        isinstance(first_counter, bool)
        or not isinstance(first_counter, int)
        or not 0 <= first_counter <= UINT32_MASK
        or not isinstance(first_nonce, str)
        or len(first_nonce) != 24
        or first_counter + len(sources) - 1 > UINT32_MASK
        or any(
            source.report.get("counter") != first_counter + index
            or source.report.get("nonce_hex") != first_nonce
            for index, source in enumerate(sources)
        )
    ):
        raise Full256MultiblockCNFError(
            "multiblock counters must be contiguous with one shared nonce"
        )
    return tuple(sources)


def _parse_clause(raw: bytes, *, block_index: int) -> bytes:
    if not raw.endswith(b"\n"):
        raise Full256MultiblockCNFError("source clause lacks final newline")
    try:
        fields = raw.decode("ascii").strip().split()
        values = [int(field) for field in fields]
    except (UnicodeDecodeError, ValueError) as exc:
        raise Full256MultiblockCNFError("source clause encoding differs") from exc
    if not values or values[-1] != 0 or 0 in values[:-1]:
        raise Full256MultiblockCNFError("source clause terminator differs")
    remapped = [remap_full256_literal(value, block_index) for value in values[:-1]]
    return (" ".join(str(value) for value in (*remapped, 0)) + "\n").encode("ascii")


def _stream_remapped_blocks(
    sources: Sequence[_SourceInstance],
    *,
    artifact_digest: _Digest,
    destination: IO[bytes] | None = None,
    expected: IO[bytes] | None = None,
) -> tuple[tuple[Full256MultiblockBlockReport, ...], str, int]:
    if (destination is None) == (expected is None):
        raise AssertionError("exactly one multiblock stream target is required")
    body_digest = hashlib.sha256()
    body_bytes = 0
    block_reports: list[Full256MultiblockBlockReport] = []
    expected_source_header = (
        f"p cnf {SINGLE_BLOCK_VARIABLE_COUNT} "
        f"{SINGLE_BLOCK_TEMPLATE_CLAUSE_COUNT + PUBLIC_UNIT_CLAUSES}\n"
    ).encode("ascii")
    for block_index, source in enumerate(sources):
        source_digest = hashlib.sha256()
        block_digest = hashlib.sha256()
        public_digest = hashlib.sha256()
        remapped_bytes = 0
        with source.path.open("rb") as handle:
            header = handle.readline()
            source_digest.update(header)
            if header != expected_source_header:
                raise Full256MultiblockCNFError("source instance header differs")
            for clause_index in range(
                SINGLE_BLOCK_TEMPLATE_CLAUSE_COUNT + PUBLIC_UNIT_CLAUSES
            ):
                raw = handle.readline()
                if not raw:
                    raise Full256MultiblockCNFError("source instance ended early")
                source_digest.update(raw)
                remapped = _parse_clause(raw, block_index=block_index)
                if destination is not None:
                    destination.write(remapped)
                else:
                    assert expected is not None
                    if expected.readline() != remapped:
                        raise Full256MultiblockCNFError(
                            "multiblock clause stream differs"
                        )
                artifact_digest.update(remapped)
                body_digest.update(remapped)
                block_digest.update(remapped)
                remapped_bytes += len(remapped)
                body_bytes += len(remapped)
                if clause_index >= SINGLE_BLOCK_TEMPLATE_CLAUSE_COUNT:
                    public_digest.update(remapped)
            if handle.read(1):
                raise Full256MultiblockCNFError(
                    "source instance contains trailing bytes"
                )
        if (
            source_digest.hexdigest() != source.report.get("instance_sha256")
            or _fingerprint(source.path) != source.fingerprint
        ):
            raise Full256MultiblockCNFError(
                "source instance changed while composing multiblock CNF"
            )
        block_reports.append(
            Full256MultiblockBlockReport(
                block_index=block_index,
                counter=cast(int, source.report["counter"]),
                nonce_hex=str(source.report["nonce_hex"]),
                output_sha256=str(source.report["output_sha256"]),
                source_instance_sha256=str(source.report["instance_sha256"]),
                source_instance_bytes=cast(int, source.report["instance_bytes"]),
                source_public_unit_sha256=str(
                    source.report["public_unit_clause_sha256"]
                ),
                remapped_block_sha256=block_digest.hexdigest(),
                remapped_public_unit_sha256=public_digest.hexdigest(),
                remapped_block_bytes=remapped_bytes,
                variable_count=remap_full256_variable(
                    SINGLE_BLOCK_VARIABLE_COUNT, block_index
                ),
                clause_count=SINGLE_BLOCK_TEMPLATE_CLAUSE_COUNT + PUBLIC_UNIT_CLAUSES,
                public_unit_clause_count=PUBLIC_UNIT_CLAUSES,
            )
        )
    return tuple(block_reports), body_digest.hexdigest(), body_bytes


def _temporary_output(destination: Path) -> tuple[int, Path]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(destination)
    descriptor, raw = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    return descriptor, Path(raw)


def _publish_temporary(temporary: Path, destination: Path) -> tuple[int, int]:
    metadata = temporary.stat()
    identity = (metadata.st_dev, metadata.st_ino)
    linked = False
    try:
        os.link(temporary, destination, follow_symlinks=False)
        linked = True
        temporary.unlink()
        parent = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except Exception:
        if linked:
            _remove_if_owned(destination, identity)
        raise
    return identity


def _remove_if_present(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _remove_if_owned(path: Path, identity: tuple[int, int]) -> None:
    try:
        metadata = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return
    if (metadata.st_dev, metadata.st_ino) == identity:
        path.unlink()


def _make_report(
    *,
    document: Mapping[str, object],
    blocks: tuple[Full256MultiblockBlockReport, ...],
    body_sha256: str,
    instance_sha256: str,
    instance_bytes: int,
) -> Full256MultiblockCNFReport:
    count = len(blocks)
    return Full256MultiblockCNFReport(
        schema=MULTIBLOCK_CNF_SCHEMA,
        template_sha256=str(document["dimacs_sha256"]),
        template_map_sha256=str(document["map_sha256"]),
        remap_rule=MULTIBLOCK_REMAP_RULE,
        block_count=count,
        shared_key_variable_count=SHARED_KEY_VARIABLE_COUNT,
        block_variable_stride=BLOCK_VARIABLE_STRIDE,
        variable_count=multiblock_variable_count(count),
        clause_count=multiblock_clause_count(count),
        public_unit_clause_count=count * PUBLIC_UNIT_CLAUSES,
        key_unit_clause_count=0,
        assumption_unit_clause_count=0,
        ordered_source_sha256=_ordered_source_digest(blocks),
        body_sha256=body_sha256,
        instance_sha256=instance_sha256,
        instance_bytes=instance_bytes,
        blocks=blocks,
    )


def write_full256_multiblock_cnf(
    template_path: str | Path,
    map_path: str | Path,
    instances: Sequence[
        tuple[
            str | Path,
            InstanceWriteReport | Mapping[str, object] | str | Path,
        ]
    ],
    destination_path: str | Path,
    *,
    report_path: str | Path | None = None,
) -> Full256MultiblockCNFReport:
    """Verify, remap, stream, and atomically publish ordered public instances."""

    template = Path(template_path).resolve(strict=True)
    sidecar = Path(map_path).resolve(strict=True)
    destination = Path(destination_path).resolve()
    report_destination = None if report_path is None else Path(report_path).resolve()
    if destination in (template, sidecar) or report_destination in (
        template,
        sidecar,
        destination,
    ):
        raise Full256MultiblockCNFError("multiblock output paths collide")
    template_fingerprint = _fingerprint(template)
    map_fingerprint = _fingerprint(sidecar)
    verification = verify_full256_template(template, sidecar)
    document = load_full256_template_map(sidecar)
    if (
        document.get("variable_count") != SINGLE_BLOCK_VARIABLE_COUNT
        or document.get("clause_count") != SINGLE_BLOCK_TEMPLATE_CLAUSE_COUNT
        or verification.get("ok") is not True
    ):
        raise Full256MultiblockCNFError("single-block template contract differs")
    sources = _prepare_sources(instances, template=template, map_path=sidecar)
    if destination in {source.path for source in sources}:
        raise Full256MultiblockCNFError("multiblock output collides with a source")

    descriptor, temporary = _temporary_output(destination)
    report_temporary: Path | None = None
    published: dict[Path, tuple[int, int]] = {}
    try:
        artifact_digest = hashlib.sha256()
        header = (
            f"p cnf {multiblock_variable_count(len(sources))} "
            f"{multiblock_clause_count(len(sources))}\n"
        ).encode("ascii")
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(header)
            artifact_digest.update(header)
            blocks, body_sha256, body_bytes = _stream_remapped_blocks(
                sources, artifact_digest=artifact_digest, destination=handle
            )
            handle.flush()
            os.fsync(handle.fileno())
        if temporary.stat().st_size != len(header) + body_bytes:
            raise Full256MultiblockCNFError("multiblock output byte count differs")
        if (
            _fingerprint(template) != template_fingerprint
            or _fingerprint(sidecar) != map_fingerprint
        ):
            raise Full256MultiblockCNFError(
                "template inputs changed while composing multiblock CNF"
            )
        report = _make_report(
            document=document,
            blocks=blocks,
            body_sha256=body_sha256,
            instance_sha256=artifact_digest.hexdigest(),
            instance_bytes=temporary.stat().st_size,
        )
        if report_destination is not None:
            report_descriptor, report_temporary = _temporary_output(report_destination)
            with os.fdopen(report_descriptor, "wb") as handle:
                handle.write(canonical_json_bytes(report.describe()) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
        published[destination] = _publish_temporary(temporary, destination)
        if report_destination is not None and report_temporary is not None:
            published[report_destination] = _publish_temporary(
                report_temporary, report_destination
            )
            report_temporary = None
        return report
    except Exception:
        _remove_if_present(temporary)
        if report_temporary is not None:
            _remove_if_present(report_temporary)
        for path, identity in published.items():
            _remove_if_owned(path, identity)
        raise


def verify_full256_multiblock_cnf(
    instance_path: str | Path,
    template_path: str | Path,
    map_path: str | Path,
    instances: Sequence[
        tuple[
            str | Path,
            InstanceWriteReport | Mapping[str, object] | str | Path,
        ]
    ],
    report: Full256MultiblockCNFReport | Mapping[str, object] | str | Path,
) -> dict[str, object]:
    """Recompute every source/remap/report binding and compare every clause."""

    target = Path(instance_path).resolve(strict=True)
    template = Path(template_path).resolve(strict=True)
    sidecar = Path(map_path).resolve(strict=True)
    template_fingerprint = _fingerprint(template)
    map_fingerprint = _fingerprint(sidecar)
    expected_report = _report_value(report)
    verify_full256_template(template, sidecar)
    document = load_full256_template_map(sidecar)
    sources = _prepare_sources(instances, template=template, map_path=sidecar)
    if len(sources) != expected_report.block_count:
        raise Full256MultiblockCNFError("multiblock verification source count differs")
    digest = hashlib.sha256()
    with target.open("rb") as handle:
        header = handle.readline()
        expected_header = (
            f"p cnf {multiblock_variable_count(len(sources))} "
            f"{multiblock_clause_count(len(sources))}\n"
        ).encode("ascii")
        if header != expected_header:
            raise Full256MultiblockCNFError("multiblock DIMACS header differs")
        digest.update(header)
        blocks, body_sha256, body_bytes = _stream_remapped_blocks(
            sources, artifact_digest=digest, expected=handle
        )
        if handle.read(1):
            raise Full256MultiblockCNFError("multiblock DIMACS has trailing bytes")
    if target.stat().st_size != len(header) + body_bytes:
        raise Full256MultiblockCNFError("multiblock DIMACS byte count differs")
    actual = _make_report(
        document=document,
        blocks=blocks,
        body_sha256=body_sha256,
        instance_sha256=digest.hexdigest(),
        instance_bytes=target.stat().st_size,
    )
    if (
        _fingerprint(template) != template_fingerprint
        or _fingerprint(sidecar) != map_fingerprint
    ):
        raise Full256MultiblockCNFError(
            "template inputs changed while verifying multiblock CNF"
        )
    if actual != expected_report:
        raise Full256MultiblockCNFError("multiblock report binding differs")
    return {
        "schema": MULTIBLOCK_CNF_VERIFICATION_SCHEMA,
        "ok": True,
        "block_count": actual.block_count,
        "variable_count": actual.variable_count,
        "clause_count": actual.clause_count,
        "public_unit_clause_count": actual.public_unit_clause_count,
        "key_unit_clause_count": 0,
        "assumption_unit_clause_count": 0,
        "instance_sha256": actual.instance_sha256,
        "body_sha256": actual.body_sha256,
        "ordered_source_sha256": actual.ordered_source_sha256,
    }


__all__ = [
    "BLOCK_VARIABLE_STRIDE",
    "Full256MultiblockBlockReport",
    "Full256MultiblockCNFError",
    "Full256MultiblockCNFReport",
    "MAXIMUM_BLOCK_COUNT",
    "MULTIBLOCK_CNF_SCHEMA",
    "MULTIBLOCK_CNF_VERIFICATION_SCHEMA",
    "MULTIBLOCK_REMAP_RULE",
    "SHARED_KEY_VARIABLE_COUNT",
    "SINGLE_BLOCK_TEMPLATE_CLAUSE_COUNT",
    "SINGLE_BLOCK_VARIABLE_COUNT",
    "multiblock_clause_count",
    "multiblock_variable_count",
    "remap_full256_literal",
    "remap_full256_variable",
    "verify_full256_multiblock_cnf",
    "write_full256_multiblock_cnf",
]
