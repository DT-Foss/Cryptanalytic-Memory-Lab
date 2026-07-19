"""Zero-call O1C-0074 preparation of the O1C-0073 causal attic.

This command consumes only manifested, sealed clause-vault artifacts.  It does
not import a native adapter, solver, public-target broker, truth key, or reveal
surface.  The original 202-clause vault remains the immutable rank source; the
311 O1C-0073 novel clauses become a separate vault-v1 rollover chunk; and a
new schema binds the deterministic 256-clause active projection.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import Mapping, Sequence

from .causal_attic_v1 import (
    ACTIVE_PROJECTION_SCHEMA,
    CausalAttic,
    CausalAtticError,
    ParsedVaultTelemetry,
    build_causal_attic,
    canonical_json_bytes,
    parse_self_scoping_vault,
    parse_vault_telemetry,
    sha256_bytes,
)


ATTEMPT_ID = "O1C-0074"
PREPARATION_SCHEMA = "o1-256-apple8-causal-attic-preparation-v1"
MANIFEST_SCHEMA = "o1-256-apple8-causal-attic-manifest-v1"
ARTIFACT_SET_SCHEMA = "o1-256-apple8-causal-attic-artifact-set-v1"

RETAINED_CHUNK_NAME = "retained-source.vault"
NOVEL_CHUNK_NAME = "novel-rollover.vault"
ACTIVE_PROJECTION_NAME = "active-projection.bin"
OCCURRENCES_NAME = "witness-occurrences.json"
RELATIONS_NAME = "subsumption-relations.json"
MANIFEST_NAME = "causal-attic-manifest.json"

ACTIVE_CLAUSE_LIMIT = 256

DEFAULT_CAPSULE_RELATIVE = Path(
    "runs/20260719_215617_O1C-0073_apple8-vault-release-contrast-v1"
)
RETAINED_VAULT_RELATIVE = Path("vault-imported.bin")
CURRENT_TELEMETRY_RELATIVE = Path("episodes/00/vault_telemetry.json")
DEFAULT_RETAINED_TELEMETRY_RELATIVES = (
    Path(
        "runs/20260719_135856_O1C-0066_apple8-episodic-vault-v1/"
        "episodes/00/vault_telemetry.json"
    ),
    Path(
        "runs/20260719_135856_O1C-0066_apple8-episodic-vault-v1/"
        "episodes/01/vault_telemetry.json"
    ),
    Path(
        "runs/20260719_161838_O1C-0068_apple8-complementary-phase-v1/"
        "episodes/00/vault_telemetry.json"
    ),
)

EXPECTED_RETAINED_VAULT_SHA256 = (
    "cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858"
)
EXPECTED_CURRENT_TELEMETRY_SHA256 = (
    "d8889755e1856cd3d57ef33921023913499a55591dcf726a2db58c16c3d5688b"
)
EXPECTED_RETAINED_TELEMETRY_SHA256 = (
    "4c5b296976ab854e6ddbe503c1aaa38b99304cfdbf4bdad183c8e8285702b86e",
    "eef1e17c32b2d9e5caefd22abdcc803a3ff13fe9e29c2bdc16b59ad2b6e075af",
    "8192b43013472e6394fed9887cd03e324d16156f21e459540bd112c34a00055e",
)
EXPECTED_RETAINED_AGGREGATE_SHA256 = (
    "72d788d52064f4d67ea4355069df0420ecfb100656a985691ff82000794dd0e9"
)
EXPECTED_NOVEL_AGGREGATE_SHA256 = (
    "5cbe1f9c402679ba607564cc9fcec56df513144200b624ecd9b6face5fc7d58f"
)
EXPECTED_NOVEL_VAULT_SHA256 = (
    "79be5483c7f8a0494fa72233715f81dca480c8b6aad79f43f31e6635cac88bc6"
)
EXPECTED_UNION_AGGREGATE_SHA256 = (
    "a01e51d30b4d713ca7e354830c563591f27d90acd2707f81f403a613b79d4c43"
)
EXPECTED_UNION_VAULT_SHA256 = (
    "51b19ce9eef9b4de263e8cf850c415bec13266676c227904be35cb73c4a8d36a"
)
EXPECTED_ACTIVE_AGGREGATE_SHA256 = (
    "dd601f9bd60b143d31136a1c8144be4ef0656638d6c3e114a4fa3e41a7d80fc7"
)
EXPECTED_ACTIVE_VAULT_SHA256 = (
    "fb7528bf1cccf76e57dfa34dd8d5b13a9c96b331dad9ebf4443e7caa45d6f2b7"
)


class O1C74PreparationError(RuntimeError):
    """A sealed input, release contract, or atomic output invariant differs."""


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _regular_file(path: Path, field: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise O1C74PreparationError(f"{field} is unreadable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise O1C74PreparationError(f"{field} is not a sealed regular file")
    return path


def _parse_artifact_manifest(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise O1C74PreparationError("artifact manifest encoding differs") from exc
    entries: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise O1C74PreparationError("artifact manifest row differs")
        digest = line[:64]
        relative = line[66:]
        if (
            any(character not in "0123456789abcdef" for character in digest)
            or not relative
            or relative.startswith("/")
            or ".." in Path(relative).parts
            or relative in entries
        ):
            raise O1C74PreparationError("artifact manifest row differs")
        entries[relative] = digest
    if not entries:
        raise O1C74PreparationError("artifact manifest is empty")
    return entries


def _read_manifested(path: str | Path) -> tuple[bytes, str, str]:
    artifact = _regular_file(Path(path), "sealed artifact")
    capsule: Path | None = None
    for candidate in artifact.parents:
        manifest_candidate = candidate / "artifacts.sha256"
        if manifest_candidate.exists():
            capsule = candidate
            break
    if capsule is None:
        raise O1C74PreparationError("sealed artifact lacks a capsule manifest")
    manifest_path = _regular_file(capsule / "artifacts.sha256", "artifact manifest")
    try:
        relative = artifact.relative_to(capsule).as_posix()
        manifest_payload = manifest_path.read_bytes()
        payload = artifact.read_bytes()
    except (OSError, ValueError) as exc:
        raise O1C74PreparationError("sealed artifact read failed") from exc
    entries = _parse_artifact_manifest(manifest_payload)
    expected = entries.get(relative)
    observed = sha256_bytes(payload)
    if expected is None or expected != observed:
        raise O1C74PreparationError("sealed artifact digest differs")
    return payload, observed, sha256_bytes(manifest_payload)


def _validate_release_contract(
    attic: CausalAttic,
    *,
    retained_telemetry_sha256: tuple[str, ...],
    current: ParsedVaultTelemetry,
) -> None:
    retained = attic.retained_chunk
    novel = attic.novel_chunk
    union = attic.union_vault
    active = attic.active_projection
    selected_retained = tuple(
        index for index in attic.selected_union_indices if index < retained.clause_count
    )
    facts = {
        "retained_sha256": retained.sha256,
        "retained_clause_count": retained.clause_count,
        "retained_literal_count": retained.literal_count,
        "retained_serialized_bytes": retained.serialized_bytes,
        "retained_aggregate_sha256": retained.clause_aggregate_sha256,
        "retained_telemetry_sha256": retained_telemetry_sha256,
        "current_telemetry_sha256": current.artifact_sha256,
        "current_occurrence_count": len(current.occurrences),
        "novel_sha256": novel.sha256,
        "novel_clause_count": novel.clause_count,
        "novel_literal_count": novel.literal_count,
        "novel_serialized_bytes": novel.serialized_bytes,
        "novel_aggregate_sha256": novel.clause_aggregate_sha256,
        "union_sha256": union.sha256,
        "union_clause_count": union.clause_count,
        "union_literal_count": union.literal_count,
        "union_serialized_bytes": union.serialized_bytes,
        "union_aggregate_sha256": union.clause_aggregate_sha256,
        "occurrence_count": len(attic.occurrences),
        "duplicate_occurrence_count": attic.duplicate_occurrence_count,
        "subsumption_pair_count": len(attic.relations),
        "undominated_clause_count": len(attic.undominated_indices),
        "active_sha256": active.sha256,
        "active_clause_count": active.clause_count,
        "active_literal_count": active.literal_count,
        "active_serialized_bytes": active.serialized_bytes,
        "active_aggregate_sha256": active.clause_aggregate_sha256,
        "active_unique_coverage": attic.unique_coverage_count,
        "active_occurrence_coverage": attic.occurrence_coverage_count,
        "selected_retained_indices": selected_retained,
    }
    expected = {
        "retained_sha256": EXPECTED_RETAINED_VAULT_SHA256,
        "retained_clause_count": 202,
        "retained_literal_count": 599_728,
        "retained_serialized_bytes": 2_399_911,
        "retained_aggregate_sha256": EXPECTED_RETAINED_AGGREGATE_SHA256,
        "retained_telemetry_sha256": EXPECTED_RETAINED_TELEMETRY_SHA256,
        "current_telemetry_sha256": EXPECTED_CURRENT_TELEMETRY_SHA256,
        "current_occurrence_count": 313,
        "novel_sha256": EXPECTED_NOVEL_VAULT_SHA256,
        "novel_clause_count": 311,
        "novel_literal_count": 798_046,
        "novel_serialized_bytes": 3_193_619,
        "novel_aggregate_sha256": EXPECTED_NOVEL_AGGREGATE_SHA256,
        "union_sha256": EXPECTED_UNION_VAULT_SHA256,
        "union_clause_count": 513,
        "union_literal_count": 1_397_774,
        "union_serialized_bytes": 5_593_339,
        "union_aggregate_sha256": EXPECTED_UNION_AGGREGATE_SHA256,
        "occurrence_count": 515,
        "duplicate_occurrence_count": 2,
        "subsumption_pair_count": 8,
        "undominated_clause_count": 508,
        "active_sha256": EXPECTED_ACTIVE_VAULT_SHA256,
        "active_clause_count": 256,
        "active_literal_count": 654_753,
        "active_serialized_bytes": 2_620_227,
        "active_aggregate_sha256": EXPECTED_ACTIVE_AGGREGATE_SHA256,
        "active_unique_coverage": 261,
        "active_occurrence_coverage": 263,
        "selected_retained_indices": (9, 123, 144),
    }
    if facts != expected:
        raise O1C74PreparationError("O1C-0074 release contract differs")


def _artifact_row(payload: bytes, role: str) -> dict[str, object]:
    return {
        "role": role,
        "serialized_bytes": len(payload),
        "sha256": sha256_bytes(payload),
    }


def _durable_write(path: Path, payload: bytes) -> None:
    try:
        with path.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise O1C74PreparationError("causal-attic artifact write failed") from exc


def _publish_directory(output_dir: Path, files: Mapping[str, bytes]) -> None:
    if output_dir.exists():
        raise O1C74PreparationError("causal-attic output already exists")
    try:
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        parent = output_dir.parent.resolve(strict=True)
    except OSError as exc:
        raise O1C74PreparationError("causal-attic output parent differs") from exc
    if output_dir.name in ("", ".", ".."):
        raise O1C74PreparationError("causal-attic output name differs")
    stage = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}.", suffix=".tmp", dir=parent)
    )
    try:
        for name, payload in files.items():
            if Path(name).name != name:
                raise O1C74PreparationError("causal-attic artifact name differs")
            _durable_write(stage / name, payload)
        os.replace(stage, output_dir)
        directory_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def prepare_o1c74_causal_attic(
    *,
    capsule_dir: str | Path,
    retained_telemetry_paths: Sequence[str | Path],
    output_dir: str | Path,
    enforce_release_contract: bool = True,
) -> dict[str, object]:
    """Validate sealed artifacts and atomically publish the zero-call attic."""

    if not isinstance(enforce_release_contract, bool):
        raise O1C74PreparationError("release-contract flag differs")
    capsule = Path(capsule_dir)
    retained_paths = tuple(Path(path) for path in retained_telemetry_paths)
    if not retained_paths:
        raise O1C74PreparationError("retained witness telemetry is empty")

    retained_payload, retained_sha, retained_manifest_sha = _read_manifested(
        capsule / RETAINED_VAULT_RELATIVE
    )
    current_payload, current_sha, current_manifest_sha = _read_manifested(
        capsule / CURRENT_TELEMETRY_RELATIVE
    )
    if retained_manifest_sha != current_manifest_sha:
        raise O1C74PreparationError("O1C-0073 capsule manifest differs")
    try:
        retained_vault = parse_self_scoping_vault(retained_payload)
        current = parse_vault_telemetry(
            current_payload,
            stream_id="o1c73-current",
            expected_sha256=current_sha,
        )
    except CausalAtticError as exc:
        raise O1C74PreparationError(str(exc)) from exc
    if (
        current.input_identity != retained_vault.identity
        or current.input_vault_sha256 != retained_vault.sha256
        or current.input_clause_count != retained_vault.clause_count
        or current.input_literal_count != retained_vault.literal_count
        or current.input_serialized_bytes != retained_vault.serialized_bytes
        or current.input_clause_aggregate_sha256
        != retained_vault.clause_aggregate_sha256
    ):
        raise O1C74PreparationError("O1C-0073 telemetry input vault differs")

    retained_streams: list[ParsedVaultTelemetry] = []
    retained_manifest_hashes: list[str] = []
    for ordinal, path in enumerate(retained_paths):
        payload, digest, manifest_digest = _read_manifested(path)
        try:
            parsed = parse_vault_telemetry(
                payload,
                stream_id=f"retained-genesis-{ordinal:02d}",
                expected_sha256=digest,
            )
        except CausalAtticError as exc:
            raise O1C74PreparationError(str(exc)) from exc
        if parsed.input_identity != retained_vault.identity:
            raise O1C74PreparationError("retained telemetry identity differs")
        retained_streams.append(parsed)
        retained_manifest_hashes.append(manifest_digest)
    retained_occurrences = tuple(
        occurrence
        for stream in retained_streams
        for occurrence in stream.new_occurrences
    )
    try:
        attic = build_causal_attic(
            retained_vault,
            retained_occurrences=retained_occurrences,
            current_occurrences=current.occurrences,
            active_limit=ACTIVE_CLAUSE_LIMIT,
        )
    except CausalAtticError as exc:
        raise O1C74PreparationError(str(exc)) from exc
    if enforce_release_contract:
        _validate_release_contract(
            attic,
            retained_telemetry_sha256=tuple(
                stream.artifact_sha256 for stream in retained_streams
            ),
            current=current,
        )

    occurrence_payload = canonical_json_bytes(attic.occurrence_document())
    relation_payload = canonical_json_bytes(attic.relation_document())
    artifacts = {
        RETAINED_CHUNK_NAME: retained_payload,
        NOVEL_CHUNK_NAME: attic.novel_chunk.serialized,
        ACTIVE_PROJECTION_NAME: attic.active_projection.serialized,
        OCCURRENCES_NAME: occurrence_payload,
        RELATIONS_NAME: relation_payload,
    }
    artifact_rows = {
        RETAINED_CHUNK_NAME: _artifact_row(
            artifacts[RETAINED_CHUNK_NAME], "immutable-rank-source-vault-v1-chunk"
        ),
        NOVEL_CHUNK_NAME: _artifact_row(
            artifacts[NOVEL_CHUNK_NAME], "immutable-novel-vault-v1-rollover-chunk"
        ),
        ACTIVE_PROJECTION_NAME: _artifact_row(
            artifacts[ACTIVE_PROJECTION_NAME], "active-projection-encoding"
        ),
        OCCURRENCES_NAME: _artifact_row(
            artifacts[OCCURRENCES_NAME], "compact-witness-occurrence-ledger"
        ),
        RELATIONS_NAME: _artifact_row(
            artifacts[RELATIONS_NAME], "strict-subsumption-closure"
        ),
    }
    manifest: dict[str, object] = {
        "schema": MANIFEST_SCHEMA,
        "preparation_schema": PREPARATION_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "zero_call": {
            "native_solver_calls": 0,
            "science_calls": 0,
            "truth_key_bytes_read": False,
            "reveal_calls": 0,
        },
        "rank_source_vault_sha256": retained_sha,
        "active_projection_schema": ACTIVE_PROJECTION_SCHEMA,
        "active_projection_is_cumulative_vault_v1": False,
        "source_artifacts": {
            "o1c73_capsule_manifest_sha256": retained_manifest_sha,
            "o1c73_current_telemetry": current.source_description(),
            "retained_witness_streams": [
                stream.source_description() for stream in retained_streams
            ],
            "retained_capsule_manifest_sha256": retained_manifest_hashes,
        },
        "attic": attic.describe(),
        "artifact_set": {
            "schema": ARTIFACT_SET_SCHEMA,
            "artifacts": artifact_rows,
            "artifact_count": len(artifact_rows),
        },
    }
    manifest_payload = canonical_json_bytes(manifest)
    files = {**artifacts, MANIFEST_NAME: manifest_payload}
    _publish_directory(Path(output_dir), files)
    return manifest


def _parser() -> argparse.ArgumentParser:
    root = lab_root()
    parser = argparse.ArgumentParser(
        description="Prepare O1C-0074's zero-call causal attic from sealed artifacts"
    )
    parser.add_argument(
        "--capsule",
        default=(root / DEFAULT_CAPSULE_RELATIVE).as_posix(),
    )
    parser.add_argument(
        "--retained-telemetry",
        action="append",
        dest="retained_telemetry",
        help="Manifested retained-clause genesis telemetry; repeat in lineage order",
    )
    parser.add_argument("--output-dir", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    retained = (
        tuple(args.retained_telemetry)
        if args.retained_telemetry
        else tuple(
            (lab_root() / relative).as_posix()
            for relative in DEFAULT_RETAINED_TELEMETRY_RELATIVES
        )
    )
    try:
        manifest = prepare_o1c74_causal_attic(
            capsule_dir=args.capsule,
            retained_telemetry_paths=retained,
            output_dir=args.output_dir,
        )
    except (O1C74PreparationError, CausalAtticError) as exc:
        print(f"{ATTEMPT_ID}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(manifest, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ACTIVE_CLAUSE_LIMIT",
    "ACTIVE_PROJECTION_NAME",
    "DEFAULT_CAPSULE_RELATIVE",
    "DEFAULT_RETAINED_TELEMETRY_RELATIVES",
    "MANIFEST_NAME",
    "NOVEL_CHUNK_NAME",
    "O1C74PreparationError",
    "OCCURRENCES_NAME",
    "RELATIONS_NAME",
    "RETAINED_CHUNK_NAME",
    "lab_root",
    "main",
    "prepare_o1c74_causal_attic",
]
