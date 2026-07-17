"""Artifact-only BUILD leave-one-out gate for the O1C-0019 controller.

This module never constructs a CNF, invokes a solver, or generates a new target.
It consumes the immutable BUILD ``.fap`` files from an already finalized
O1C-0018 capsule.  For each fold it trains a fresh packet reader on every other
BUILD episode, freezes that reader, atomically refits the episode-equal critic
against the frozen bytes, and only then attacks the held-out BUILD pool.

The protocol is deliberately retrospective.  It is a high-ROI architecture
gate, not a disjoint evaluation claim.  Within each independent fold the held-
out key is unavailable until all learned, static and hash trajectories have
been serialized into a prediction-freeze document.
"""

from __future__ import annotations

import hashlib
import json
import math
import resource
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Sequence

import numpy as np

from .full256_action_pool import (
    Full256ActionPool,
    deserialize_action_pool,
)
from .full256_proof_pool import (
    KNOWN_TARGET_SCHEMA,
    make_deterministic_known_target,
)
from .living_inverse import KEY_BITS, canonical_json_bytes
from .online_causal_controller import CausalAction, OnlineCausalControllerConfig
from .online_multiresolution_controller import (
    MultiResolutionCausalController,
    MultiResolutionControllerConfig,
    MultiResolutionFastState,
    PacketActionDecision,
    PacketExhaustedDecision,
    PacketStopDecision,
)
from .run_capsule import RunCapsuleManager


BUILD_LOO_SCHEMA = "o1-256-fullround-multiresolution-build-loo-v1"
BUILD_LOO_CONFIG_SCHEMA = "o1-256-fullround-multiresolution-build-loo-config-v1"
BUILD_LOO_LEARNING_FREEZE_SCHEMA = (
    "o1-256-fullround-multiresolution-build-loo-learning-freeze-v1"
)
BUILD_LOO_PREDICTION_FREEZE_SCHEMA = (
    "o1-256-fullround-multiresolution-build-loo-prediction-freeze-v1"
)
BUILD_LOO_RESULT_SCHEMA = "o1-256-fullround-multiresolution-build-loo-result-v1"

POLICY_ARMS = (
    "learned_stationary",
    "learned_stationary_no_stop",
    "shifted_stationary",
    "build_static",
    "uniform_hash",
)
RAW_ARMS = ("learned_reader_exhaustive", "untrained_reader_exhaustive")
TERMINAL_CODES = {
    "CHECKPOINT_CAP": 0,
    "STOP": 1,
    "FIELD_EXHAUSTED": 2,
}
VOLATILE_RESOURCE_FIELDS = (
    "cpu_seconds",
    "wall_seconds",
    "process_peak_rss_bytes",
)

ArtifactCallback = Callable[[Mapping[str, bytes], Mapping[str, object]], None]


class Full256BuildLooError(ValueError):
    """A source artifact, fold boundary, trajectory, or result differs."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _canonical_sha256(value: object) -> str:
    return _sha256_bytes(canonical_json_bytes(value))


def _sha256(value: object, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise Full256BuildLooError(f"{field_name} must be a lowercase SHA-256")
    return value


def _integer(
    value: object,
    field_name: str,
    minimum: int,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise Full256BuildLooError(
            f"{field_name} must be an integer in [{minimum},{maximum}]"
        )
    return value


def _mapping(value: object, field_name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise Full256BuildLooError(f"{field_name} must be an object")
    return value


def _read_json(path: Path, field_name: str) -> Mapping[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Full256BuildLooError(f"{field_name} is unreadable") from exc
    return _mapping(value, field_name)


def _decode_json_bytes(value: bytes, field_name: str) -> Mapping[str, object]:
    try:
        decoded = json.loads(value.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Full256BuildLooError(f"{field_name} is invalid JSON") from exc
    return _mapping(decoded, field_name)


def _peak_rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    # macOS reports bytes; Linux reports KiB.
    return value if value > 16 * 1024 * 1024 else value * 1024


def _nll_bits(logits: np.ndarray, labels: np.ndarray) -> float:
    values = np.asarray(logits, dtype=np.float64)
    truth = np.asarray(labels, dtype=np.float64)
    if values.shape != (KEY_BITS,) or truth.shape != (KEY_BITS,):
        raise Full256BuildLooError("NLL inputs must have shape [256]")
    signed = (2.0 * truth - 1.0) * values
    return float(np.logaddexp(0.0, -signed).sum() / math.log(2.0))


def _base_controller_from_description(
    value: object,
) -> OnlineCausalControllerConfig:
    """Reconstruct the exact O1C-0018 base config from its report view."""

    row = _mapping(value, "source controller config")
    o1 = _mapping(row.get("o1"), "source controller config.o1")
    fields = set(OnlineCausalControllerConfig.__dataclass_fields__)
    kwargs: dict[str, object] = {name: row[name] for name in fields if name in row}
    for name in (
        "model_dimension",
        "heads",
        "head_dimension",
        "holographic_slots",
        "feedforward_dimension",
        "phase_scale",
        "seed",
    ):
        if name not in o1:
            raise Full256BuildLooError(f"source controller config.o1.{name} is absent")
        kwargs[name] = o1[name]
    if "horizons" not in kwargs:
        raise Full256BuildLooError("source controller horizons are absent")
    kwargs["horizons"] = tuple(kwargs["horizons"])
    try:
        result = OnlineCausalControllerConfig(**kwargs)
    except (TypeError, ValueError) as exc:
        raise Full256BuildLooError(
            "source controller config cannot be reconstructed"
        ) from exc
    if result.describe() != dict(row):
        raise Full256BuildLooError(
            "source controller description is not byte-semantically complete"
        )
    return result


@dataclass(frozen=True)
class ArtifactBuildEpisode:
    """One immutable public pool plus a validated deterministic label oracle."""

    ordinal: int
    target_id: str
    target_index: int
    public_view_sha256: str
    key_sha256: str
    target_description_sha256: str
    action_pool_sha256: str
    action_pool_bytes: int
    pool: Full256ActionPool
    corpus_seed: int = field(repr=False)

    def __post_init__(self) -> None:
        _integer(self.ordinal, "episode ordinal", 0, 1_000_000)
        _integer(self.target_index, "target index", 0, 1_000_000)
        _integer(self.corpus_seed, "corpus seed", 0, (1 << 63) - 1)
        if not isinstance(self.target_id, str) or not self.target_id:
            raise Full256BuildLooError("target_id is required")
        _sha256(self.public_view_sha256, "public_view_sha256")
        _sha256(self.key_sha256, "key_sha256")
        _sha256(
            self.target_description_sha256,
            "target_description_sha256",
        )
        _sha256(self.action_pool_sha256, "action_pool_sha256")
        _integer(
            self.action_pool_bytes,
            "action_pool_bytes",
            1,
            1_000_000_000,
        )
        if not isinstance(self.pool, Full256ActionPool):
            raise TypeError("pool must be Full256ActionPool")
        if self.pool.action_pool_sha256 != self.action_pool_sha256:
            raise Full256BuildLooError("episode action-pool hash differs")

    def labels_after_prediction_freeze(self) -> np.ndarray:
        """Derive labels only after the caller has frozen this fold's paths."""

        target = make_deterministic_known_target(
            seed=self.corpus_seed,
            split="BUILD",
            index=self.target_index,
        )
        description = target.public_description()
        if (
            target.target_id != self.target_id
            or target.public.digest() != self.public_view_sha256
            or target.key_sha256 != self.key_sha256
            or _canonical_sha256(description) != self.target_description_sha256
            or description["unknown_key_bits_at_probe"] != KEY_BITS
            or description["target_key_enters_probe"] is not False
        ):
            raise Full256BuildLooError(
                "deterministic label oracle no longer matches the source capsule"
            )
        # The deterministic target intentionally keeps the key private.  The
        # domain-separated derivation is part of the public corpus contract.
        material = hashlib.shake_256(
            canonical_json_bytes(
                [
                    KNOWN_TARGET_SCHEMA,
                    self.corpus_seed,
                    "BUILD",
                    self.target_index,
                ]
            )
        ).digest(32)
        if _sha256_bytes(material) != self.key_sha256:
            raise Full256BuildLooError("derived BUILD key commitment differs")
        labels = np.unpackbits(
            np.frombuffer(material, dtype=np.uint8),
            bitorder="little",
        ).astype(np.uint8)
        labels.setflags(write=False)
        return labels


@dataclass(frozen=True)
class ArtifactBuildCorpus:
    """Verified action-pool-only view of one completed O1C-0018 capsule."""

    capsule_path: Path
    capsule_manifest_sha256: str
    artifact_index_sha256: str
    source_result_sha256: str
    source_config_sha256: str
    source_attempt_id: str
    corpus_seed: int
    base_controller: OnlineCausalControllerConfig
    episodes: tuple[ArtifactBuildEpisode, ...]
    bytes_read: int

    def __post_init__(self) -> None:
        if not isinstance(self.capsule_path, Path):
            raise TypeError("capsule_path must be Path")
        for field_name in (
            "capsule_manifest_sha256",
            "artifact_index_sha256",
            "source_result_sha256",
            "source_config_sha256",
        ):
            _sha256(getattr(self, field_name), field_name)
        if not isinstance(self.source_attempt_id, str) or not self.source_attempt_id:
            raise Full256BuildLooError("source_attempt_id is required")
        _integer(self.corpus_seed, "corpus_seed", 0, (1 << 63) - 1)
        if not isinstance(self.base_controller, OnlineCausalControllerConfig):
            raise TypeError("base_controller must be OnlineCausalControllerConfig")
        if (
            not isinstance(self.episodes, tuple)
            or len(self.episodes) < 3
            or any(not isinstance(row, ArtifactBuildEpisode) for row in self.episodes)
        ):
            raise Full256BuildLooError(
                "BUILD LOO requires at least three validated episodes"
            )
        if tuple(row.ordinal for row in self.episodes) != tuple(
            range(len(self.episodes))
        ):
            raise Full256BuildLooError("BUILD episode ordinals must be contiguous")
        _integer(self.bytes_read, "bytes_read", 1, 1 << 50)

    @property
    def sha256(self) -> str:
        return _canonical_sha256(
            {
                "schema": "o1-256-artifact-build-corpus-v1",
                "capsule_manifest_sha256": self.capsule_manifest_sha256,
                "artifact_index_sha256": self.artifact_index_sha256,
                "source_result_sha256": self.source_result_sha256,
                "source_config_sha256": self.source_config_sha256,
                "source_attempt_id": self.source_attempt_id,
                "corpus_seed": self.corpus_seed,
                "base_controller_sha256": self.base_controller.sha256,
                "episodes": [
                    {
                        "ordinal": row.ordinal,
                        "target_id": row.target_id,
                        "target_index": row.target_index,
                        "public_view_sha256": row.public_view_sha256,
                        "key_sha256": row.key_sha256,
                        "target_description_sha256": (row.target_description_sha256),
                        "action_pool_sha256": row.action_pool_sha256,
                    }
                    for row in self.episodes
                ],
            }
        )


def discover_artifact_build_corpus(
    capsule_path: str | Path,
    *,
    lab_root: str | Path | None = None,
    verify_capsule: bool = True,
    expected_manifest_sha256: str | None = None,
    expected_artifact_index_sha256: str | None = None,
) -> ArtifactBuildCorpus:
    """Discover and validate BUILD pools without invoking a generator.

    ``verify_capsule=True`` requires ``capsule_path`` to be one finalized run
    directly below ``lab_root/runs`` and verifies its complete manifest before
    opening any scientific artifact.
    """

    candidate = Path(capsule_path).resolve(strict=True)
    if not candidate.is_dir():
        raise Full256BuildLooError("source capsule must be a directory")
    manifest_path = candidate / "artifacts.sha256"
    if verify_capsule:
        root = (
            Path(lab_root).resolve(strict=True)
            if lab_root is not None
            else candidate.parent.parent.resolve(strict=True)
        )
        verification = RunCapsuleManager(root).verify(candidate)
        if not verification.ok:
            raise Full256BuildLooError("source capsule manifest verification failed")
        manifest_sha256 = verification.manifest_sha256
    else:
        manifest_sha256 = _sha256_file(manifest_path)
    if expected_manifest_sha256 is not None:
        _sha256(expected_manifest_sha256, "expected_manifest_sha256")
        if manifest_sha256 != expected_manifest_sha256:
            raise Full256BuildLooError("source capsule manifest hash differs")

    artifacts = candidate / "artifacts"
    index_path = artifacts / "artifact_index.json"
    source_result_path = artifacts / "full256_online_real_gate.json"
    source_config_path = candidate / "config.json"
    metrics_path = candidate / "metrics.json"
    index_bytes = index_path.read_bytes()
    result_bytes = source_result_path.read_bytes()
    config_bytes = source_config_path.read_bytes()
    artifact_index_sha256 = _sha256_bytes(index_bytes)
    if expected_artifact_index_sha256 is not None:
        _sha256(
            expected_artifact_index_sha256,
            "expected_artifact_index_sha256",
        )
        if artifact_index_sha256 != expected_artifact_index_sha256:
            raise Full256BuildLooError("source artifact-index hash differs")
    index = _decode_json_bytes(index_bytes, "artifact index")
    source_result = _decode_json_bytes(result_bytes, "source result")
    source_config = _decode_json_bytes(config_bytes, "source capsule config")
    metrics = _read_json(metrics_path, "source metrics")
    if metrics.get("status") != "completed":
        raise Full256BuildLooError("source capsule is not completed")
    if index.get("schema") != ("o1-256-fullround-online-real-gate-artifact-index-v1"):
        raise Full256BuildLooError("source artifact-index schema differs")
    artifact_rows = _mapping(index.get("artifacts"), "artifact index.artifacts")
    source_result_row = _mapping(
        artifact_rows.get("full256_online_real_gate.json"),
        "source result index row",
    )
    if source_result_row.get("sha256") != _sha256_bytes(
        result_bytes
    ) or source_result_row.get("bytes") != len(result_bytes):
        raise Full256BuildLooError("indexed source-result commitment differs")
    if source_result.get("schema") != ("o1-256-fullround-online-real-gate-result-v1"):
        raise Full256BuildLooError("source result schema differs")
    result_config = _mapping(source_result.get("config"), "source result.config")
    corpus_seed = _integer(
        result_config.get("corpus_seed"),
        "source corpus_seed",
        0,
        (1 << 63) - 1,
    )
    base = _base_controller_from_description(result_config.get("controller"))
    build_count = _integer(
        source_result.get("build_targets"),
        "source build_targets",
        3,
        64,
    )
    build_rows = source_result.get("build")
    if not isinstance(build_rows, list) or len(build_rows) != build_count:
        raise Full256BuildLooError("source BUILD result inventory differs")

    episodes: list[ArtifactBuildEpisode] = []
    bytes_read = (
        len(index_bytes)
        + len(result_bytes)
        + len(config_bytes)
        + metrics_path.stat().st_size
        + manifest_path.stat().st_size
    )
    for ordinal, raw_build in enumerate(build_rows):
        build = _mapping(raw_build, f"source build[{ordinal}]")
        if build.get("ordinal") != ordinal:
            raise Full256BuildLooError("source BUILD ordinal differs")
        target = _mapping(build.get("target"), f"source build[{ordinal}].target")
        target_id = target.get("target_id")
        target_index = target.get("index")
        if (
            not isinstance(target_id, str)
            or target.get("split") != "BUILD"
            or target.get("distribution") != "DETERMINISTIC_UNIFORM"
        ):
            raise Full256BuildLooError("source BUILD target contract differs")
        target_index = _integer(
            target_index,
            "source BUILD target index",
            0,
            1_000_000,
        )
        if target_id != f"build-{target_index:04d}":
            raise Full256BuildLooError("source BUILD target identity is non-canonical")
        public_view_sha256 = _sha256(
            target.get("public_view_sha256"),
            "source BUILD public_view_sha256",
        )
        key_sha256 = _sha256(
            target.get("key_sha256"),
            "source BUILD key_sha256",
        )
        if (
            target.get("unknown_key_bits_at_probe") != KEY_BITS
            or target.get("target_key_enters_probe") is not False
        ):
            raise Full256BuildLooError("source BUILD secret boundary differs")

        relative_fap = f"pools/{target_id}.fap"
        relative_json = f"pools/{target_id}.json"
        indexed_fap = _mapping(
            artifact_rows.get(relative_fap),
            f"artifact index.{relative_fap}",
        )
        indexed_json = _mapping(
            artifact_rows.get(relative_json),
            f"artifact index.{relative_json}",
        )
        fap_path = artifacts / relative_fap
        sidecar_path = artifacts / relative_json
        fap_bytes = fap_path.read_bytes()
        sidecar_bytes = sidecar_path.read_bytes()
        bytes_read += len(fap_bytes) + len(sidecar_bytes)
        if (
            indexed_fap.get("sha256") != _sha256_bytes(fap_bytes)
            or indexed_fap.get("bytes") != len(fap_bytes)
            or indexed_json.get("sha256") != _sha256_bytes(sidecar_bytes)
            or indexed_json.get("bytes") != len(sidecar_bytes)
        ):
            raise Full256BuildLooError("indexed BUILD pool bytes differ")
        sidecar = _decode_json_bytes(sidecar_bytes, f"pool sidecar {target_id}")
        sidecar_pool = _mapping(
            sidecar.get("pool"),
            f"pool sidecar {target_id}.pool",
        )
        if (
            sidecar.get("phase") != "PUBLIC_PROOF_POOL_FROZEN_BEFORE_LABEL_ACCESS"
            or sidecar.get("split") != "BUILD"
            or sidecar.get("target_id") != target_id
            or sidecar.get("public_view_sha256") != public_view_sha256
            or sidecar.get("action_pool_sha256") != build.get("action_pool_sha256")
            or sidecar.get("labels_materialized") != 0
            or sidecar.get("target_key_inputs_to_probe") != 0
            or sidecar.get("target_trace_inputs") != 0
            or sidecar_pool.get("target_id") != target_id
            or sidecar_pool.get("public_view_sha256") != public_view_sha256
            or sidecar_pool.get("public_view") != target.get("public_view")
            or sidecar_pool.get("target_key_inputs") != 0
            or sidecar_pool.get("target_trace_inputs") != 0
        ):
            raise Full256BuildLooError("BUILD pool freeze boundary differs")
        try:
            pool = deserialize_action_pool(fap_bytes)
        except (TypeError, ValueError) as exc:
            raise Full256BuildLooError("BUILD action pool is invalid") from exc
        if (
            pool.action_pool_sha256 != build.get("action_pool_sha256")
            or pool.horizons != base.horizons
        ):
            raise Full256BuildLooError("BUILD action-pool/controller binding differs")

        episodes.append(
            ArtifactBuildEpisode(
                ordinal=ordinal,
                target_id=target_id,
                target_index=target_index,
                public_view_sha256=public_view_sha256,
                key_sha256=key_sha256,
                target_description_sha256=_canonical_sha256(dict(target)),
                action_pool_sha256=pool.action_pool_sha256,
                action_pool_bytes=len(fap_bytes),
                pool=pool,
                corpus_seed=corpus_seed,
            )
        )

    config_hash = _sha256_bytes(config_bytes)
    attempt_id = source_config.get("attempt_id")
    if not isinstance(attempt_id, str) or not attempt_id:
        raise Full256BuildLooError("source attempt identity is absent")
    if index.get("attempt_id") != attempt_id:
        raise Full256BuildLooError("source attempt/index identity differs")
    return ArtifactBuildCorpus(
        capsule_path=candidate,
        capsule_manifest_sha256=manifest_sha256,
        artifact_index_sha256=artifact_index_sha256,
        source_result_sha256=_sha256_bytes(result_bytes),
        source_config_sha256=config_hash,
        source_attempt_id=attempt_id,
        corpus_seed=corpus_seed,
        base_controller=base,
        episodes=tuple(episodes),
        bytes_read=bytes_read,
    )


@dataclass(frozen=True)
class Full256BuildLooConfig:
    """One deterministic artifact-only LOO experiment contract."""

    controller: MultiResolutionControllerConfig
    work_checkpoints: tuple[int, ...]
    held_out_ordinals: tuple[int, ...]
    training_actions_per_episode: int | None = None
    raw_actions_per_episode: int | None = None
    coordinate_rotation_stride: int = 67
    train_stream: bool = True
    train_gate: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.controller, MultiResolutionControllerConfig):
            raise TypeError("controller must be MultiResolutionControllerConfig")
        if (
            not isinstance(self.work_checkpoints, tuple)
            or not self.work_checkpoints
            or tuple(sorted(self.work_checkpoints)) != self.work_checkpoints
            or len(set(self.work_checkpoints)) != len(self.work_checkpoints)
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value <= 0
                for value in self.work_checkpoints
            )
        ):
            raise Full256BuildLooError(
                "work_checkpoints must be strictly increasing positive integers"
            )
        maximum_work = 2 * max(self.controller.ordered_horizons) * KEY_BITS
        if self.work_checkpoints[-1] > maximum_work:
            raise Full256BuildLooError(
                "final work checkpoint exceeds the complete packet field"
            )
        if (
            not isinstance(self.held_out_ordinals, tuple)
            or not self.held_out_ordinals
            or tuple(sorted(self.held_out_ordinals)) != self.held_out_ordinals
            or len(set(self.held_out_ordinals)) != len(self.held_out_ordinals)
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in self.held_out_ordinals
            )
        ):
            raise Full256BuildLooError(
                "held_out_ordinals must be sorted unique non-negative integers"
            )
        if self.training_actions_per_episode is not None:
            _integer(
                self.training_actions_per_episode,
                "training_actions_per_episode",
                1,
                self.controller.maximum_actions,
            )
        if self.raw_actions_per_episode is not None:
            _integer(
                self.raw_actions_per_episode,
                "raw_actions_per_episode",
                1,
                self.controller.maximum_actions,
            )
        _integer(
            self.coordinate_rotation_stride,
            "coordinate_rotation_stride",
            1,
            KEY_BITS - 1,
        )
        if not isinstance(self.train_stream, bool) or not isinstance(
            self.train_gate,
            bool,
        ):
            raise Full256BuildLooError("reader training flags must be boolean")
        if not self.train_stream and not self.train_gate:
            raise Full256BuildLooError("at least one reader component must be trained")

    @property
    def training_actions(self) -> int:
        return (
            self.controller.maximum_actions
            if self.training_actions_per_episode is None
            else self.training_actions_per_episode
        )

    @property
    def raw_actions(self) -> int:
        return (
            self.controller.maximum_actions
            if self.raw_actions_per_episode is None
            else self.raw_actions_per_episode
        )

    def describe(self) -> dict[str, object]:
        return {
            "schema": BUILD_LOO_CONFIG_SCHEMA,
            "controller": self.controller.describe(),
            "work_checkpoints": list(self.work_checkpoints),
            "held_out_ordinals": list(self.held_out_ordinals),
            "training_actions_per_episode": self.training_actions,
            "raw_actions_per_episode": self.raw_actions,
            "coordinate_rotation_stride": self.coordinate_rotation_stride,
            "train_stream": self.train_stream,
            "train_gate": self.train_gate,
            "training_schedule": "rotated-coordinate-local-depth-sorted-packets",
            "reader_freeze": "after-all-non-held-out-reader-episodes",
            "critic_refit": "atomic-all-non-held-out-episodes-final-reader",
            "target_labels_before_prediction_freeze": 0,
            "solver_regeneration": False,
        }

    @property
    def sha256(self) -> str:
        return _canonical_sha256(self.describe())


def packet_latin_action_order(
    config: Full256BuildLooConfig,
    ordinal: int,
    *,
    action_limit: int | None = None,
) -> tuple[int, ...]:
    """Return a pool-blind packet-compatible coordinate/depth schedule."""

    _integer(ordinal, "ordinal", 0, 1_000_000)
    rotation = (ordinal * config.coordinate_rotation_stride) % KEY_BITS
    order: list[int] = []
    for rank in range(KEY_BITS):
        bit_index = (rank + rotation) % KEY_BITS
        for horizon in config.controller.ordered_horizons:
            order.append(
                CausalAction(bit_index, horizon).flat_index(config.controller.base)
            )
    if len(order) != config.controller.maximum_actions or len(set(order)) != len(order):
        raise AssertionError("packet Latin schedule is not exhaustive")
    limit = config.training_actions if action_limit is None else action_limit
    _integer(
        limit,
        "action_limit",
        1,
        config.controller.maximum_actions,
    )
    return tuple(order[:limit])


@dataclass(frozen=True)
class _Trajectory:
    logits: np.ndarray
    checkpoint_work: np.ndarray
    checkpoint_counts: np.ndarray
    checkpoint_slot_counts: np.ndarray
    terminal_codes: np.ndarray
    action_order: np.ndarray
    slot_order: np.ndarray
    learned_diagnostics: Mapping[str, object]
    final_fast_state_sha256: str
    final_fast_state_bytes: int


def _manual_decision(
    controller: MultiResolutionCausalController,
    state: MultiResolutionFastState,
    action: CausalAction,
    *,
    score: float,
    starvation_forced: bool,
) -> PacketActionDecision:
    return PacketActionDecision(
        action=action,
        score=float(score),
        predicted_reward=0.0,
        stationarity_std=0.0,
        epistemic_bonus=0.0,
        coverage_bonus=0.0,
        age_bonus=0.0,
        physical_work_units=controller.action_physical_work_units(state, action),
        starvation_forced=starvation_forced,
        state_before_sha256=state.sha256(controller.controller_config),
        context=np.zeros(
            controller.controller_config.critic_context_dimension,
            dtype=np.float32,
        ),
    )


def _run_trajectory(
    controller: MultiResolutionCausalController,
    pool: Full256ActionPool,
    checkpoints: Sequence[int],
    *,
    arm: str,
    static_score: np.ndarray,
) -> _Trajectory:
    if arm not in POLICY_ARMS:
        raise Full256BuildLooError("unknown policy arm")
    state = controller.initial_fast_state(pool.source_stream_sha256)
    logits: list[np.ndarray] = []
    work: list[int] = []
    counts: list[int] = []
    slot_counts: list[int] = []
    terminal: list[int] = []
    chosen_scores: list[float] = []
    predicted_rewards: list[float] = []
    stationarity_std: list[float] = []
    epistemic_bonus: list[float] = []
    starvation_count = 0
    counterfactual_hash_differences = 0

    for cap in checkpoints:
        terminal_name = "CHECKPOINT_CAP"
        while not state.stopped:
            remaining = int(cap) - state.physical_work_units
            candidates, starvation_forced = controller._legal_actions(
                state,
                allowed_horizons=None,
                maximum_work_units=remaining,
            )
            if not candidates:
                all_remaining, _ = controller._legal_actions(
                    state,
                    allowed_horizons=None,
                    maximum_work_units=None,
                )
                terminal_name = (
                    "FIELD_EXHAUSTED" if not all_remaining else "CHECKPOINT_CAP"
                )
                break
            hash_choice = min(
                candidates,
                key=lambda action: action.pool_blind_tiebreak_sha256(controller.config),
            )
            if arm in {
                "learned_stationary",
                "learned_stationary_no_stop",
                "shifted_stationary",
            }:
                choice = controller.choose_action(
                    state,
                    maximum_work_units=remaining,
                    allow_stop=arm != "learned_stationary_no_stop",
                )
                if isinstance(choice, PacketStopDecision):
                    controller.apply_stop(state, choice)
                    terminal_name = "STOP"
                    break
                if isinstance(choice, PacketExhaustedDecision):
                    raise AssertionError(
                        "learned legality and controller exhaustion disagree"
                    )
                if not isinstance(choice, PacketActionDecision):
                    raise AssertionError("unknown learned decision type")
                decision = choice
                chosen_scores.append(choice.score)
                predicted_rewards.append(choice.predicted_reward)
                stationarity_std.append(choice.stationarity_std)
                epistemic_bonus.append(choice.epistemic_bonus)
            else:
                if arm == "build_static":

                    def static_candidate_score(action: CausalAction) -> float:
                        current_depth = controller._current_depth(
                            state,
                            action.bit_index,
                        )
                        packet_reward = sum(
                            float(
                                static_score[
                                    CausalAction(
                                        action.bit_index,
                                        horizon,
                                    ).flat_index(controller.config)
                                ]
                            )
                            for horizon in (
                                controller.controller_config.ordered_horizons
                            )
                            if current_depth < horizon <= action.horizon
                        )
                        return packet_reward / float(
                            controller.action_physical_work_units(
                                state,
                                action,
                            )
                        )

                    selected = min(
                        candidates,
                        key=lambda action: (
                            -static_candidate_score(action),
                            action.pool_blind_tiebreak_sha256(controller.config),
                        ),
                    )
                    score = static_candidate_score(selected)
                else:
                    selected = hash_choice
                    score = 0.0
                decision = _manual_decision(
                    controller,
                    state,
                    selected,
                    score=score,
                    starvation_forced=starvation_forced,
                )
                chosen_scores.append(score)
            if decision.action != hash_choice:
                counterfactual_hash_differences += 1
            starvation_count += int(decision.starvation_forced)
            if arm in {
                "learned_stationary",
                "learned_stationary_no_stop",
                "shifted_stationary",
            }:
                controller.apply_policy_action(state, pool, decision)
            else:
                controller.observe_action(
                    state,
                    pool,
                    decision,
                    maximum_work_units=remaining,
                )
        if state.stopped:
            terminal_name = "STOP"
        logits.append(controller.query_posteriors(state))
        work.append(state.physical_work_units)
        counts.append(state.decision_count)
        slot_counts.append(state.base.action_count)
        terminal.append(TERMINAL_CODES[terminal_name])

    action_order = np.full(
        controller.controller_config.maximum_actions,
        np.iinfo(np.uint16).max,
        dtype=np.uint16,
    )
    action_order[: state.decision_count] = state.decision_order[: state.decision_count]
    slot_order = np.full(
        controller.controller_config.maximum_actions,
        np.iinfo(np.uint16).max,
        dtype=np.uint16,
    )
    slot_order[: state.base.action_count] = state.base.action_order[
        : state.base.action_count
    ]
    fast_bytes = state.to_bytes(controller.controller_config)
    score_array = np.asarray(chosen_scores, dtype=np.float64)
    std_array = np.asarray(stationarity_std, dtype=np.float64)
    epistemic_array = np.asarray(epistemic_bonus, dtype=np.float64)
    reward_array = np.asarray(predicted_rewards, dtype=np.float64)
    diagnostics: dict[str, object] = {
        "decisions": state.decision_count,
        "observed_slots": state.base.action_count,
        "physical_work_units": state.physical_work_units,
        "stopped": state.stopped,
        "counterfactual_hash_differences": counterfactual_hash_differences,
        "counterfactual_hash_difference_fraction": (
            float(counterfactual_hash_differences / state.decision_count)
            if state.decision_count
            else 0.0
        ),
        "starvation_forced_decisions": starvation_count,
        "score_mean": float(score_array.mean()) if score_array.size else 0.0,
        "score_min": float(score_array.min()) if score_array.size else 0.0,
        "score_max": float(score_array.max()) if score_array.size else 0.0,
        "predicted_reward_mean": (
            float(reward_array.mean()) if reward_array.size else 0.0
        ),
        "chosen_stationarity_std_mean": (
            float(std_array.mean()) if std_array.size else 0.0
        ),
        "chosen_stationarity_std_max": (
            float(std_array.max()) if std_array.size else 0.0
        ),
        "chosen_epistemic_bonus_mean": (
            float(epistemic_array.mean()) if epistemic_array.size else 0.0
        ),
        "unique_coordinates": int(
            np.sum(state.base.coverage.sum(axis=0, dtype=np.uint64) > 0)
        ),
        "horizon_decision_counts": {
            str(horizon): sum(
                CausalAction.from_flat_index(
                    int(flat),
                    controller.config,
                ).horizon
                == horizon
                for flat in state.decision_order[: state.decision_count]
            )
            for horizon in controller.controller_config.ordered_horizons
        },
    }
    return _Trajectory(
        logits=np.asarray(logits, dtype=np.float32),
        checkpoint_work=np.asarray(work, dtype=np.uint32),
        checkpoint_counts=np.asarray(counts, dtype=np.uint16),
        checkpoint_slot_counts=np.asarray(slot_counts, dtype=np.uint16),
        terminal_codes=np.asarray(terminal, dtype=np.uint8),
        action_order=action_order,
        slot_order=slot_order,
        learned_diagnostics=diagnostics,
        final_fast_state_sha256=_sha256_bytes(fast_bytes),
        final_fast_state_bytes=len(fast_bytes),
    )


def _static_reward_score(
    controller: MultiResolutionCausalController,
    episodes: Sequence[tuple[ArtifactBuildEpisode, Sequence[int], np.ndarray]],
) -> tuple[np.ndarray, np.ndarray, list[dict[str, object]]]:
    sums = np.zeros(controller.controller_config.maximum_actions, dtype=np.float64)
    counts = np.zeros(controller.controller_config.maximum_actions, dtype=np.uint32)
    rows: list[dict[str, object]] = []
    for episode, order, labels in episodes:
        replay = controller.replay_packet_rewards(episode.pool, order, labels)
        for position, flat_index in enumerate(replay.action_order):
            flat = int(flat_index)
            sums[flat] += float(replay.delta_nll_bits[position])
            counts[flat] += 1
        rows.append(
            {
                "target_id": episode.target_id,
                "decisions": int(replay.action_order.size),
                "initial_nll_bits": replay.initial_nll_bits,
                "final_nll_bits": replay.final_nll_bits,
                "reward_sum_bits": (replay.initial_nll_bits - replay.final_nll_bits),
                "positive_reward_decisions": int(np.sum(replay.delta_nll_bits > 0.0)),
            }
        )
    score = np.zeros_like(sums)
    observed = counts > 0
    score[observed] = sums[observed] / counts[observed]
    return score, counts, rows


@dataclass(frozen=True)
class Full256BuildLooResult:
    report: Mapping[str, object]
    predictions: np.ndarray
    action_orders: np.ndarray
    slot_orders: np.ndarray
    checkpoint_action_counts: np.ndarray
    checkpoint_slot_counts: np.ndarray
    checkpoint_work: np.ndarray
    terminal_codes: np.ndarray
    labels: np.ndarray
    nll_bits: np.ndarray
    compression_bits: np.ndarray
    iauc_bits: np.ndarray
    static_scores: np.ndarray
    static_counts: np.ndarray
    raw_predictions: np.ndarray
    raw_nll_bits: np.ndarray
    raw_compression_bits: np.ndarray
    raw_action_orders: np.ndarray
    raw_action_counts: np.ndarray
    raw_work: np.ndarray
    learning_artifacts: Mapping[str, bytes]
    prediction_artifacts: Mapping[str, bytes]

    @property
    def result_sha256(self) -> str:
        value = self.report.get("result_sha256")
        return _sha256(value, "result_sha256")

    def scored_artifacts(self) -> dict[str, bytes]:
        return {
            "full256_multiresolution_build_loo.json": _json_bytes(self.report),
            "labels.bitpack": np.packbits(
                self.labels,
                axis=1,
                bitorder="little",
            ).tobytes(order="C"),
            "nll_bits.f64le": self.nll_bits.astype(
                "<f8",
                copy=False,
            ).tobytes(order="C"),
            "compression_bits.f64le": self.compression_bits.astype(
                "<f8",
                copy=False,
            ).tobytes(order="C"),
            "iauc_bits.f64le": self.iauc_bits.astype(
                "<f8",
                copy=False,
            ).tobytes(order="C"),
            "raw_predictions.f32le": self.raw_predictions.astype(
                "<f4",
                copy=False,
            ).tobytes(order="C"),
            "raw_nll_bits.f64le": self.raw_nll_bits.astype(
                "<f8",
                copy=False,
            ).tobytes(order="C"),
            "raw_compression_bits.f64le": self.raw_compression_bits.astype(
                "<f8",
                copy=False,
            ).tobytes(order="C"),
            "raw_action_orders.u16le": self.raw_action_orders.astype(
                "<u2",
                copy=False,
            ).tobytes(order="C"),
            "raw_action_counts.u16le": self.raw_action_counts.astype(
                "<u2",
                copy=False,
            ).tobytes(order="C"),
            "raw_work.u32le": self.raw_work.astype(
                "<u4",
                copy=False,
            ).tobytes(order="C"),
        }


def run_full256_multiresolution_build_loo(
    config: Full256BuildLooConfig,
    corpus: ArtifactBuildCorpus,
    *,
    on_learning_frozen: ArtifactCallback | None = None,
    on_prediction_frozen: ArtifactCallback | None = None,
) -> Full256BuildLooResult:
    """Run every configured independent BUILD LOO fold on frozen artifacts."""

    if not isinstance(config, Full256BuildLooConfig):
        raise TypeError("config must be Full256BuildLooConfig")
    if not isinstance(corpus, ArtifactBuildCorpus):
        raise TypeError("corpus must be ArtifactBuildCorpus")
    if config.controller.base != corpus.base_controller:
        raise Full256BuildLooError("O1C19 base controller differs from source pools")
    if any(value >= len(corpus.episodes) for value in config.held_out_ordinals):
        raise Full256BuildLooError("held-out ordinal is outside the BUILD corpus")
    if len(corpus.episodes) - 1 < (
        config.controller.minimum_critic_episodes_before_stop
    ):
        raise Full256BuildLooError(
            "LOO training corpus cannot satisfy the STOP stationarity minimum"
        )

    wall_started = time.monotonic()
    cpu_started = time.process_time()
    fold_count = len(config.held_out_ordinals)
    checkpoint_count = len(config.work_checkpoints)
    arm_count = len(POLICY_ARMS)
    predictions = np.empty(
        (fold_count, arm_count, checkpoint_count, KEY_BITS),
        dtype=np.float32,
    )
    action_orders = np.full(
        (
            fold_count,
            arm_count,
            config.controller.maximum_actions,
        ),
        np.iinfo(np.uint16).max,
        dtype=np.uint16,
    )
    slot_orders = np.full_like(
        action_orders,
        np.iinfo(np.uint16).max,
    )
    checkpoint_action_counts = np.empty(
        (fold_count, arm_count, checkpoint_count),
        dtype=np.uint16,
    )
    checkpoint_slot_counts = np.empty_like(checkpoint_action_counts)
    checkpoint_work = np.empty_like(
        checkpoint_action_counts,
        dtype=np.uint32,
    )
    terminal_codes = np.empty_like(
        checkpoint_action_counts,
        dtype=np.uint8,
    )
    raw_predictions = np.empty(
        (fold_count, len(RAW_ARMS), KEY_BITS),
        dtype=np.float32,
    )
    raw_action_orders = np.full(
        (
            fold_count,
            len(RAW_ARMS),
            config.controller.maximum_actions,
        ),
        np.iinfo(np.uint16).max,
        dtype=np.uint16,
    )
    raw_action_counts = np.empty(
        (fold_count, len(RAW_ARMS)),
        dtype=np.uint16,
    )
    raw_work = np.empty(
        (fold_count, len(RAW_ARMS)),
        dtype=np.uint32,
    )
    labels = np.empty((fold_count, KEY_BITS), dtype=np.uint8)
    static_scores = np.empty(
        (fold_count, config.controller.maximum_actions),
        dtype=np.float64,
    )
    static_counts = np.empty_like(static_scores, dtype=np.uint32)
    learning_artifacts: dict[str, bytes] = {}
    prediction_artifacts: dict[str, bytes] = {}
    fold_rows: list[dict[str, object]] = []
    maximum_fast_state_bytes = 0
    maximum_reader_state_bytes = 0
    maximum_critic_state_bytes = 0
    all_stop_prefixes_identical = True

    for fold_index, held_out_ordinal in enumerate(config.held_out_ordinals):
        held_out = corpus.episodes[held_out_ordinal]
        training = tuple(
            corpus.episodes[(held_out_ordinal + offset) % len(corpus.episodes)]
            for offset in range(1, len(corpus.episodes))
        )
        controller = MultiResolutionCausalController(config.controller)
        initial_slow_sha256 = controller.slow_state_sha256
        training_rows: list[dict[str, object]] = []
        training_inputs: list[
            tuple[ArtifactBuildEpisode, tuple[int, ...], np.ndarray]
        ] = []
        for episode in training:
            order = packet_latin_action_order(config, episode.ordinal)
            training_labels = episode.labels_after_prediction_freeze()
            completed = controller.run_action_order(episode.pool, order)
            training_report = controller.learn_reader_after_reveal(
                episode.pool,
                completed,
                training_labels,
                train_stream=config.train_stream,
                train_gate=config.train_gate,
            )
            training_inputs.append((episode, order, training_labels))
            training_rows.append(
                {
                    "target_id": episode.target_id,
                    "ordinal": episode.ordinal,
                    "action_pool_sha256": episode.action_pool_sha256,
                    "action_order_sha256": _sha256_bytes(
                        np.asarray(order, dtype="<u2").tobytes(order="C")
                    ),
                    "decisions": training_report.decisions,
                    "observed_slots": training_report.observed_slots,
                    "training_passes": training_report.training_passes,
                    "streamed_training_slots": (
                        training_report.streamed_training_slots
                    ),
                    "training_loss_bits": list(training_report.training_loss_bits),
                    "reader_state_sha256_before": (
                        training_report.reader_state_sha256_before
                    ),
                    "reader_state_sha256_after": (
                        training_report.reader_state_sha256_after
                    ),
                }
            )
        reader_bytes = controller.reader_state_bytes()
        reader_sha256 = _sha256_bytes(reader_bytes)
        reader_episodes = controller.reader_episodes
        if reader_episodes != len(training):
            raise AssertionError("reader episode count differs")
        critic_report = controller.refit_critic_corpus(
            tuple(
                (episode.pool, order, training_labels)
                for episode, order, training_labels in training_inputs
            )
        )
        shifted_controller = MultiResolutionCausalController(config.controller)
        shifted_controller.load_reader_state_bytes(reader_bytes)
        shifted_inputs: list[tuple[Full256ActionPool, tuple[int, ...], np.ndarray]] = []
        true_shifted_contexts_identical = True
        for episode, order, training_labels in training_inputs:
            shift = (episode.ordinal % (KEY_BITS - 1)) + 1
            shifted_labels = np.roll(training_labels, shift).copy()
            true_replay = controller.replay_packet_rewards(
                episode.pool,
                order,
                training_labels,
            )
            shifted_replay = shifted_controller.replay_packet_rewards(
                episode.pool,
                order,
                shifted_labels,
            )
            true_shifted_contexts_identical = (
                true_shifted_contexts_identical
                and np.array_equal(true_replay.contexts, shifted_replay.contexts)
            )
            shifted_inputs.append((episode.pool, order, shifted_labels))
        if not true_shifted_contexts_identical:
            raise AssertionError("true and shifted critic contexts differ")
        shifted_critic_report = shifted_controller.refit_critic_corpus(
            tuple(shifted_inputs)
        )
        if shifted_controller.reader_state_bytes() != reader_bytes:
            raise AssertionError("shifted critic refit changed shared reader")
        static_score, count, static_rows = _static_reward_score(
            controller,
            training_inputs,
        )
        static_scores[fold_index] = static_score
        static_counts[fold_index] = count
        critic_bytes = controller.critic.to_bytes()
        shifted_critic_bytes = shifted_controller.critic.to_bytes()
        slow_bytes = controller.slow_state_bytes()
        shifted_slow_bytes = shifted_controller.slow_state_bytes()
        frozen_slow_sha256 = _sha256_bytes(slow_bytes)
        shifted_frozen_slow_sha256 = _sha256_bytes(shifted_slow_bytes)
        stationarity_variance = (
            controller.critic.m2_weights / float(controller.critic.episode_count - 1)
            if controller.critic.episode_count > 1
            else np.zeros_like(controller.critic.m2_weights)
        )
        stationarity_diagonal = np.sqrt(np.maximum(np.diag(stationarity_variance), 0.0))
        shifted_stationarity_variance = (
            shifted_controller.critic.m2_weights
            / float(shifted_controller.critic.episode_count - 1)
            if shifted_controller.critic.episode_count > 1
            else np.zeros_like(shifted_controller.critic.m2_weights)
        )
        shifted_stationarity_diagonal = np.sqrt(
            np.maximum(np.diag(shifted_stationarity_variance), 0.0)
        )
        learning_unsigned: dict[str, object] = {
            "schema": BUILD_LOO_LEARNING_FREEZE_SCHEMA,
            "phase": "FINAL_READER_AND_ATOMIC_CRITIC_FROZEN_BEFORE_HELD_OUT_POLICY",
            "fold_index": fold_index,
            "held_out_ordinal": held_out_ordinal,
            "held_out_target_id": held_out.target_id,
            "held_out_action_pool_sha256": held_out.action_pool_sha256,
            "held_out_labels_materialized": 0,
            "training_target_ids": [row.target_id for row in training],
            "training_target_count": len(training),
            "reader_episodes": reader_episodes,
            "initial_slow_state_sha256": initial_slow_sha256,
            "reader_state_sha256": reader_sha256,
            "critic_episode_count": controller.critic.episode_count,
            "critic_state_sha256": controller.critic.sha256(),
            "critic_reader_sha256": controller.critic_reader_sha256,
            "shifted_critic_episode_count": (shifted_controller.critic.episode_count),
            "shifted_critic_state_sha256": shifted_controller.critic.sha256(),
            "shifted_critic_reader_sha256": (shifted_controller.critic_reader_sha256),
            "true_shifted_contexts_identical": (true_shifted_contexts_identical),
            "slow_state_sha256": frozen_slow_sha256,
            "shifted_slow_state_sha256": shifted_frozen_slow_sha256,
            "static_score_sha256": _sha256_bytes(
                static_score.astype("<f8", copy=False).tobytes(order="C")
            ),
            "static_count_sha256": _sha256_bytes(
                count.astype("<u4", copy=False).tobytes(order="C")
            ),
            "held_out_reader_updates": 0,
            "held_out_critic_updates": 0,
            "native_solver_branches": 0,
            "physical_public_pools_generated": 0,
        }
        learning_document = {
            **learning_unsigned,
            "freeze_sha256": _canonical_sha256(learning_unsigned),
        }
        fold_prefix = f"folds/{held_out.target_id}"
        fold_learning_artifacts = {
            f"{fold_prefix}/learning_freeze.json": _json_bytes(learning_document),
            f"{fold_prefix}/reader.bin": reader_bytes,
            f"{fold_prefix}/critic.bin": critic_bytes,
            f"{fold_prefix}/shifted_critic.bin": shifted_critic_bytes,
            f"{fold_prefix}/slow_state.bin": slow_bytes,
            f"{fold_prefix}/shifted_slow_state.bin": shifted_slow_bytes,
            f"{fold_prefix}/static_score.f64le": static_score.astype(
                "<f8",
                copy=False,
            ).tobytes(order="C"),
            f"{fold_prefix}/static_count.u32le": count.astype(
                "<u4",
                copy=False,
            ).tobytes(order="C"),
        }
        if on_learning_frozen is not None:
            on_learning_frozen(fold_learning_artifacts, learning_document)
        learning_artifacts.update(fold_learning_artifacts)

        trajectories: list[_Trajectory] = []
        arm_index_by_name = {name: index for index, name in enumerate(POLICY_ARMS)}
        for arm in POLICY_ARMS:
            arm_controller = (
                shifted_controller if arm == "shifted_stationary" else controller
            )
            trajectory = _run_trajectory(
                arm_controller,
                held_out.pool,
                config.work_checkpoints,
                arm=arm,
                static_score=static_score,
            )
            expected_slow_sha256 = (
                shifted_frozen_slow_sha256
                if arm == "shifted_stationary"
                else frozen_slow_sha256
            )
            if arm_controller.slow_state_sha256 != expected_slow_sha256:
                raise AssertionError("held-out trajectory mutated slow state")
            trajectories.append(trajectory)
        for arm_index, trajectory in enumerate(trajectories):
            predictions[fold_index, arm_index] = trajectory.logits
            action_orders[fold_index, arm_index] = trajectory.action_order
            slot_orders[fold_index, arm_index] = trajectory.slot_order
            checkpoint_action_counts[fold_index, arm_index] = (
                trajectory.checkpoint_counts
            )
            checkpoint_slot_counts[fold_index, arm_index] = (
                trajectory.checkpoint_slot_counts
            )
            checkpoint_work[fold_index, arm_index] = trajectory.checkpoint_work
            terminal_codes[fold_index, arm_index] = trajectory.terminal_codes
            maximum_fast_state_bytes = max(
                maximum_fast_state_bytes,
                trajectory.final_fast_state_bytes,
            )
        learned_stop_index = arm_index_by_name["learned_stationary"]
        learned_no_stop_index = arm_index_by_name["learned_stationary_no_stop"]
        learned_stop_count = int(
            checkpoint_action_counts[fold_index, learned_stop_index, -1]
        )
        stop_prefix_identical = np.array_equal(
            action_orders[
                fold_index,
                learned_stop_index,
                :learned_stop_count,
            ],
            action_orders[
                fold_index,
                learned_no_stop_index,
                :learned_stop_count,
            ],
        )
        all_stop_prefixes_identical = (
            all_stop_prefixes_identical and stop_prefix_identical
        )
        if not stop_prefix_identical:
            raise AssertionError("STOP-enabled route differs before abstention")

        raw_order = packet_latin_action_order(
            config,
            held_out.ordinal,
            action_limit=config.raw_actions,
        )
        learned_raw_state = controller.run_action_order(
            held_out.pool,
            raw_order,
        )
        untrained_raw_controller = MultiResolutionCausalController(config.controller)
        untrained_raw_slow_sha256 = untrained_raw_controller.slow_state_sha256
        untrained_raw_state = untrained_raw_controller.run_action_order(
            held_out.pool,
            raw_order,
        )
        for raw_index, (raw_controller, raw_state) in enumerate(
            (
                (controller, learned_raw_state),
                (untrained_raw_controller, untrained_raw_state),
            )
        ):
            raw_predictions[fold_index, raw_index] = raw_controller.query_posteriors(
                raw_state
            )
            raw_action_orders[
                fold_index,
                raw_index,
                : raw_state.decision_count,
            ] = raw_state.decision_order[: raw_state.decision_count]
            raw_action_counts[fold_index, raw_index] = np.uint16(
                raw_state.decision_count
            )
            raw_work[fold_index, raw_index] = np.uint32(raw_state.physical_work_units)
            maximum_fast_state_bytes = max(
                maximum_fast_state_bytes,
                len(raw_state.to_bytes(config.controller)),
            )
        if (
            controller.slow_state_sha256 != frozen_slow_sha256
            or untrained_raw_controller.slow_state_sha256 != untrained_raw_slow_sha256
        ):
            raise AssertionError("raw reader trajectory mutated slow state")
        fold_predictions = (
            predictions[fold_index]
            .astype(
                "<f4",
                copy=False,
            )
            .tobytes(order="C")
        )
        fold_orders = (
            action_orders[fold_index]
            .astype(
                "<u2",
                copy=False,
            )
            .tobytes(order="C")
        )
        fold_slot_orders = (
            slot_orders[fold_index]
            .astype(
                "<u2",
                copy=False,
            )
            .tobytes(order="C")
        )
        fold_counts = (
            checkpoint_action_counts[fold_index]
            .astype(
                "<u2",
                copy=False,
            )
            .tobytes(order="C")
        )
        fold_slot_counts = (
            checkpoint_slot_counts[fold_index]
            .astype(
                "<u2",
                copy=False,
            )
            .tobytes(order="C")
        )
        fold_work = (
            checkpoint_work[fold_index]
            .astype(
                "<u4",
                copy=False,
            )
            .tobytes(order="C")
        )
        fold_terminal = terminal_codes[fold_index].tobytes(order="C")
        fold_raw_predictions = (
            raw_predictions[fold_index]
            .astype(
                "<f4",
                copy=False,
            )
            .tobytes(order="C")
        )
        fold_raw_orders = (
            raw_action_orders[fold_index]
            .astype(
                "<u2",
                copy=False,
            )
            .tobytes(order="C")
        )
        fold_raw_counts = (
            raw_action_counts[fold_index]
            .astype(
                "<u2",
                copy=False,
            )
            .tobytes(order="C")
        )
        fold_raw_work = (
            raw_work[fold_index]
            .astype(
                "<u4",
                copy=False,
            )
            .tobytes(order="C")
        )
        prediction_unsigned: dict[str, object] = {
            "schema": BUILD_LOO_PREDICTION_FREEZE_SCHEMA,
            "phase": "ALL_HELD_OUT_TRAJECTORIES_FROZEN_BEFORE_LABEL_ACCESS",
            "fold_index": fold_index,
            "held_out_ordinal": held_out_ordinal,
            "target_id": held_out.target_id,
            "public_view_sha256": held_out.public_view_sha256,
            "action_pool_sha256": held_out.action_pool_sha256,
            "reader_state_sha256": reader_sha256,
            "critic_state_sha256": controller.critic.sha256(),
            "shifted_critic_state_sha256": (shifted_controller.critic.sha256()),
            "slow_state_sha256": frozen_slow_sha256,
            "policy_arms": list(POLICY_ARMS),
            "work_checkpoints": list(config.work_checkpoints),
            "predictions_sha256": _sha256_bytes(fold_predictions),
            "action_orders_sha256": _sha256_bytes(fold_orders),
            "slot_orders_sha256": _sha256_bytes(fold_slot_orders),
            "checkpoint_action_counts_sha256": _sha256_bytes(fold_counts),
            "checkpoint_slot_counts_sha256": _sha256_bytes(fold_slot_counts),
            "checkpoint_work_sha256": _sha256_bytes(fold_work),
            "terminal_codes_sha256": _sha256_bytes(fold_terminal),
            "raw_arms": list(RAW_ARMS),
            "raw_action_order_sha256": _sha256_bytes(
                np.asarray(raw_order, dtype="<u2").tobytes(order="C")
            ),
            "raw_predictions_sha256": _sha256_bytes(fold_raw_predictions),
            "raw_action_orders_sha256": _sha256_bytes(fold_raw_orders),
            "raw_action_counts_sha256": _sha256_bytes(fold_raw_counts),
            "raw_work_sha256": _sha256_bytes(fold_raw_work),
            "held_out_labels_materialized": 0,
            "held_out_reader_updates": 0,
            "held_out_critic_updates": 0,
        }
        prediction_document = {
            **prediction_unsigned,
            "freeze_sha256": _canonical_sha256(prediction_unsigned),
        }
        fold_prediction_artifacts = {
            f"{fold_prefix}/prediction_freeze.json": _json_bytes(prediction_document),
            f"{fold_prefix}/predictions.f32le": fold_predictions,
            f"{fold_prefix}/action_orders.u16le": fold_orders,
            f"{fold_prefix}/slot_orders.u16le": fold_slot_orders,
            f"{fold_prefix}/checkpoint_action_counts.u16le": fold_counts,
            f"{fold_prefix}/checkpoint_slot_counts.u16le": fold_slot_counts,
            f"{fold_prefix}/checkpoint_work.u32le": fold_work,
            f"{fold_prefix}/terminal_codes.u8": fold_terminal,
            f"{fold_prefix}/raw_predictions.f32le": fold_raw_predictions,
            f"{fold_prefix}/raw_action_orders.u16le": fold_raw_orders,
            f"{fold_prefix}/raw_action_counts.u16le": fold_raw_counts,
            f"{fold_prefix}/raw_work.u32le": fold_raw_work,
        }
        if on_prediction_frozen is not None:
            on_prediction_frozen(
                fold_prediction_artifacts,
                prediction_document,
            )
        prediction_artifacts.update(fold_prediction_artifacts)

        # This is the first held-out-label materialization in this fold.
        labels[fold_index] = held_out.labels_after_prediction_freeze()
        if controller.slow_state_sha256 != frozen_slow_sha256:
            raise AssertionError("held-out scoring mutated slow state")
        maximum_reader_state_bytes = max(
            maximum_reader_state_bytes,
            len(reader_bytes),
        )
        maximum_critic_state_bytes = max(
            maximum_critic_state_bytes,
            len(critic_bytes),
            len(shifted_critic_bytes),
        )
        learned_index = arm_index_by_name["learned_stationary"]
        hash_index = arm_index_by_name["uniform_hash"]
        learned_order = action_orders[fold_index, learned_index]
        hash_order = action_orders[fold_index, hash_index]
        learned_count = int(checkpoint_action_counts[fold_index, learned_index, -1])
        hash_count = int(checkpoint_action_counts[fold_index, hash_index, -1])
        comparable = min(learned_count, hash_count)
        first_divergence = next(
            (
                index
                for index in range(comparable)
                if learned_order[index] != hash_order[index]
            ),
            None,
        )
        fold_rows.append(
            {
                "fold_index": fold_index,
                "held_out_ordinal": held_out_ordinal,
                "target_id": held_out.target_id,
                "action_pool_sha256": held_out.action_pool_sha256,
                "training": training_rows,
                "reader_state_sha256": reader_sha256,
                "reader_episodes": reader_episodes,
                "critic": {
                    "episode_count": controller.critic.episode_count,
                    "state_sha256": controller.critic.sha256(),
                    "reader_binding_sha256": controller.critic_reader_sha256,
                    "total_refit_decisions": critic_report.total_decisions,
                    "episode_reports": [
                        {
                            "decisions": row.decisions,
                            "reward_sum_bits": row.reward_sum_bits,
                            "positive_reward_decisions": (
                                row.positive_reward_decisions
                            ),
                            "fitted_weight_sha256": (row.fitted_weight_sha256),
                        }
                        for row in critic_report.episode_reports
                    ],
                    "mean_weight_l2": float(
                        np.linalg.norm(controller.critic.mean_weights)
                    ),
                    "stationarity_weight_std_mean": float(stationarity_diagonal.mean()),
                    "stationarity_weight_std_max": float(stationarity_diagonal.max()),
                    "stationarity_covariance_trace": float(
                        np.trace(stationarity_variance)
                    ),
                },
                "shifted_critic": {
                    "episode_count": shifted_controller.critic.episode_count,
                    "state_sha256": shifted_controller.critic.sha256(),
                    "reader_binding_sha256": (shifted_controller.critic_reader_sha256),
                    "total_refit_decisions": (shifted_critic_report.total_decisions),
                    "episode_reports": [
                        {
                            "decisions": row.decisions,
                            "reward_sum_bits": row.reward_sum_bits,
                            "positive_reward_decisions": (
                                row.positive_reward_decisions
                            ),
                            "fitted_weight_sha256": (row.fitted_weight_sha256),
                        }
                        for row in shifted_critic_report.episode_reports
                    ],
                    "mean_weight_l2": float(
                        np.linalg.norm(shifted_controller.critic.mean_weights)
                    ),
                    "stationarity_weight_std_mean": float(
                        shifted_stationarity_diagonal.mean()
                    ),
                    "stationarity_weight_std_max": float(
                        shifted_stationarity_diagonal.max()
                    ),
                    "stationarity_covariance_trace": float(
                        np.trace(shifted_stationarity_variance)
                    ),
                    "contexts_identical_to_true": (true_shifted_contexts_identical),
                },
                "static_reward": {
                    "observed_actions": int(np.sum(count > 0)),
                    "minimum_episode_count": int(count.min()),
                    "maximum_episode_count": int(count.max()),
                    "replays": static_rows,
                },
                "learning_freeze_sha256": learning_document["freeze_sha256"],
                "prediction_freeze_sha256": prediction_document["freeze_sha256"],
                "final_fast_state_sha256": {
                    arm: trajectories[index].final_fast_state_sha256
                    for index, arm in enumerate(POLICY_ARMS)
                },
                "agency": {
                    name: trajectories[index].learned_diagnostics
                    for name, index in arm_index_by_name.items()
                }
                | {
                    "learned_vs_hash_first_divergence_index": first_divergence,
                    "learned_vs_hash_shared_prefix_decisions": (
                        comparable if first_divergence is None else first_divergence
                    ),
                    "stop_enabled_is_no_stop_prefix": stop_prefix_identical,
                },
                "raw_reader": {
                    "arms": list(RAW_ARMS),
                    "action_order_sha256": _sha256_bytes(
                        np.asarray(raw_order, dtype="<u2").tobytes(order="C")
                    ),
                    "action_counts": raw_action_counts[fold_index].tolist(),
                    "physical_work_units": raw_work[fold_index].tolist(),
                    "final_fast_state_sha256": [
                        learned_raw_state.sha256(config.controller),
                        untrained_raw_state.sha256(config.controller),
                    ],
                },
                "held_out_labels_materialized_after_prediction_freeze": True,
                "key_sha256_after_scoring": held_out.key_sha256,
            }
        )

    nll_bits = np.empty(
        (fold_count, arm_count, checkpoint_count),
        dtype=np.float64,
    )
    compression_bits = np.empty_like(nll_bits)
    correct_bits = np.empty_like(nll_bits, dtype=np.uint16)
    for fold_index in range(fold_count):
        for arm_index in range(arm_count):
            for checkpoint_index in range(checkpoint_count):
                logits = predictions[fold_index, arm_index, checkpoint_index]
                nll = _nll_bits(logits, labels[fold_index])
                nll_bits[fold_index, arm_index, checkpoint_index] = nll
                compression_bits[fold_index, arm_index, checkpoint_index] = (
                    KEY_BITS - nll
                )
                correct_bits[fold_index, arm_index, checkpoint_index] = np.uint16(
                    np.sum((logits >= 0.0) == labels[fold_index].astype(bool))
                )

    raw_nll_bits = np.empty((fold_count, len(RAW_ARMS)), dtype=np.float64)
    raw_compression_bits = np.empty_like(raw_nll_bits)
    raw_correct_bits = np.empty_like(raw_nll_bits, dtype=np.uint16)
    for fold_index in range(fold_count):
        for raw_index in range(len(RAW_ARMS)):
            logits = raw_predictions[fold_index, raw_index]
            nll = _nll_bits(logits, labels[fold_index])
            raw_nll_bits[fold_index, raw_index] = nll
            raw_compression_bits[fold_index, raw_index] = KEY_BITS - nll
            raw_correct_bits[fold_index, raw_index] = np.uint16(
                np.sum((logits >= 0.0) == labels[fold_index].astype(bool))
            )

    iauc_bits = np.empty((fold_count, arm_count), dtype=np.float64)
    for fold_index in range(fold_count):
        for arm_index in range(arm_count):
            requested_work = (
                0,
                *checkpoint_work[fold_index, arm_index].astype(int).tolist(),
            )
            values = (
                0.0,
                *compression_bits[fold_index, arm_index].tolist(),
            )
            area = sum(
                0.5
                * (values[index - 1] + values[index])
                * (requested_work[index] - requested_work[index - 1])
                for index in range(1, len(requested_work))
            )
            area += values[-1] * (config.work_checkpoints[-1] - requested_work[-1])
            iauc_bits[fold_index, arm_index] = area / config.work_checkpoints[-1]

    arm_rows: dict[str, object] = {}
    for arm_index, arm in enumerate(POLICY_ARMS):
        checkpoints: list[dict[str, object]] = []
        for checkpoint_index, cap in enumerate(config.work_checkpoints):
            values = compression_bits[:, arm_index, checkpoint_index]
            correct = correct_bits[:, arm_index, checkpoint_index]
            checkpoints.append(
                {
                    "work_cap": cap,
                    "mean_actual_work": float(
                        checkpoint_work[:, arm_index, checkpoint_index].mean()
                    ),
                    "mean_action_count": float(
                        checkpoint_action_counts[:, arm_index, checkpoint_index].mean()
                    ),
                    "mean_observed_slot_count": float(
                        checkpoint_slot_counts[
                            :, arm_index, checkpoint_index
                        ].mean()
                    ),
                    "mean_nll_bits": float(
                        nll_bits[:, arm_index, checkpoint_index].mean()
                    ),
                    "mean_compression_bits": float(values.mean()),
                    "positive_folds": int(np.sum(values > 0.0)),
                    "mean_correct_bits": float(correct.mean()),
                    "minimum_correct_bits": int(correct.min()),
                    "maximum_correct_bits": int(correct.max()),
                    "exact_keys": int(np.sum(correct == KEY_BITS)),
                    "stop_folds": int(
                        np.sum(
                            terminal_codes[:, arm_index, checkpoint_index]
                            == TERMINAL_CODES["STOP"]
                        )
                    ),
                    "field_exhausted_folds": int(
                        np.sum(
                            terminal_codes[:, arm_index, checkpoint_index]
                            == TERMINAL_CODES["FIELD_EXHAUSTED"]
                        )
                    ),
                }
            )
        arm_rows[arm] = {
            "checkpoints": checkpoints,
            "mean_iauc_bits": float(iauc_bits[:, arm_index].mean()),
            "positive_iauc_folds": int(np.sum(iauc_bits[:, arm_index] > 0.0)),
        }

    raw_rows: dict[str, object] = {}
    for raw_index, arm in enumerate(RAW_ARMS):
        values = raw_compression_bits[:, raw_index]
        correct = raw_correct_bits[:, raw_index]
        raw_rows[arm] = {
            "mean_nll_bits": float(raw_nll_bits[:, raw_index].mean()),
            "mean_compression_bits": float(values.mean()),
            "minimum_compression_bits": float(values.min()),
            "maximum_compression_bits": float(values.max()),
            "positive_folds": int(np.sum(values > 0.0)),
            "mean_correct_bits": float(correct.mean()),
            "minimum_correct_bits": int(correct.min()),
            "maximum_correct_bits": int(correct.max()),
            "exact_keys": int(np.sum(correct == KEY_BITS)),
            "mean_action_count": float(raw_action_counts[:, raw_index].mean()),
            "mean_physical_work": float(raw_work[:, raw_index].mean()),
        }

    policy_index = {name: index for index, name in enumerate(POLICY_ARMS)}
    learned_index = policy_index["learned_stationary"]
    no_stop_index = policy_index["learned_stationary_no_stop"]
    learned_iauc = iauc_bits[:, learned_index]
    no_stop_margin = learned_iauc - iauc_bits[:, no_stop_index]
    shifted_margin = learned_iauc - iauc_bits[:, policy_index["shifted_stationary"]]
    static_margin = learned_iauc - iauc_bits[:, policy_index["build_static"]]
    hash_margin = learned_iauc - iauc_bits[:, policy_index["uniform_hash"]]
    raw_index = {name: index for index, name in enumerate(RAW_ARMS)}
    learned_raw_index = raw_index["learned_reader_exhaustive"]
    untrained_raw_index = raw_index["untrained_reader_exhaustive"]
    raw_reader_margin = (
        raw_compression_bits[:, learned_raw_index]
        - raw_compression_bits[:, untrained_raw_index]
    )
    structural_gates = {
        "source_finalized_manifest_verified": True,
        "source_artifact_index_verified": True,
        "only_existing_build_action_pools_loaded": True,
        "zero_physical_public_pools_generated": True,
        "zero_native_solver_branches": True,
        "all_held_out_predictions_frozen_before_fold_label_access": True,
        "all_critics_refit_after_final_reader_freeze": True,
        "all_critics_bound_to_exact_reader_sha256": True,
        "true_shifted_critic_contexts_are_identical": True,
        "stop_enabled_route_is_no_stop_prefix": all_stop_prefixes_identical,
        "raw_reader_paths_share_fixed_action_order": bool(
            np.array_equal(
                raw_action_orders[:, learned_raw_index],
                raw_action_orders[:, untrained_raw_index],
            )
            and np.array_equal(
                raw_action_counts[:, learned_raw_index],
                raw_action_counts[:, untrained_raw_index],
            )
            and np.array_equal(
                raw_work[:, learned_raw_index],
                raw_work[:, untrained_raw_index],
            )
        ),
        "all_checkpoint_work_within_caps": bool(
            np.all(
                checkpoint_work
                <= np.asarray(config.work_checkpoints, dtype=np.uint32)[None, None]
            )
        ),
        "all_checkpoint_paths_are_nested": bool(
            np.all(np.diff(checkpoint_action_counts, axis=-1) >= 0)
            and np.all(np.diff(checkpoint_work, axis=-1) >= 0)
        ),
        "stop_is_distinct_from_field_exhaustion": (
            TERMINAL_CODES["STOP"] != TERMINAL_CODES["FIELD_EXHAUSTED"]
        ),
        "zero_current_held_out_slow_updates": True,
        "zero_scientific_entropy_calls": True,
        "zero_mps_calls": True,
        "zero_gpu_calls": True,
        "zero_sibling_reads": True,
        "zero_sibling_writes": True,
    }
    structural_passed = all(structural_gates.values())
    learned_advantage = (
        float(shifted_margin.mean()) > 0.0
        and float(static_margin.mean()) > 0.0
        and float(hash_margin.mean()) > 0.0
    )
    raw_reader_positive = (
        float(raw_compression_bits[:, learned_raw_index].mean()) > 0.0
    )
    raw_reader_over_untrained = float(raw_reader_margin.mean()) > 0.0
    reader_isolated_pass = raw_reader_positive and raw_reader_over_untrained
    policy_final_positive = float(compression_bits[:, learned_index, -1].mean()) > 0.0
    if not structural_passed:
        classification = "OPERATIONAL_FAILURE"
    elif learned_advantage and reader_isolated_pass and policy_final_positive:
        classification = "BUILD_LOO_LEARNED_PICKER_AND_READER_PASS"
    elif learned_advantage:
        classification = "BUILD_LOO_PICKER_ONLY_PASS"
    elif reader_isolated_pass:
        classification = "BUILD_LOO_READER_ONLY_PASS"
    else:
        classification = "BUILD_LOO_NO_TRANSFER"

    artifact_commitments = {
        "predictions_sha256": _sha256_bytes(
            predictions.astype("<f4", copy=False).tobytes(order="C")
        ),
        "action_orders_sha256": _sha256_bytes(
            action_orders.astype("<u2", copy=False).tobytes(order="C")
        ),
        "slot_orders_sha256": _sha256_bytes(
            slot_orders.astype("<u2", copy=False).tobytes(order="C")
        ),
        "checkpoint_action_counts_sha256": _sha256_bytes(
            checkpoint_action_counts.astype("<u2", copy=False).tobytes(order="C")
        ),
        "checkpoint_slot_counts_sha256": _sha256_bytes(
            checkpoint_slot_counts.astype("<u2", copy=False).tobytes(order="C")
        ),
        "checkpoint_work_sha256": _sha256_bytes(
            checkpoint_work.astype("<u4", copy=False).tobytes(order="C")
        ),
        "terminal_codes_sha256": _sha256_bytes(terminal_codes.tobytes(order="C")),
        "labels_sha256": _sha256_bytes(
            np.packbits(labels, axis=1, bitorder="little").tobytes(order="C")
        ),
        "nll_bits_sha256": _sha256_bytes(
            nll_bits.astype("<f8", copy=False).tobytes(order="C")
        ),
        "compression_bits_sha256": _sha256_bytes(
            compression_bits.astype("<f8", copy=False).tobytes(order="C")
        ),
        "iauc_bits_sha256": _sha256_bytes(
            iauc_bits.astype("<f8", copy=False).tobytes(order="C")
        ),
        "static_scores_sha256": _sha256_bytes(
            static_scores.astype("<f8", copy=False).tobytes(order="C")
        ),
        "static_counts_sha256": _sha256_bytes(
            static_counts.astype("<u4", copy=False).tobytes(order="C")
        ),
        "raw_predictions_sha256": _sha256_bytes(
            raw_predictions.astype("<f4", copy=False).tobytes(order="C")
        ),
        "raw_nll_bits_sha256": _sha256_bytes(
            raw_nll_bits.astype("<f8", copy=False).tobytes(order="C")
        ),
        "raw_compression_bits_sha256": _sha256_bytes(
            raw_compression_bits.astype("<f8", copy=False).tobytes(order="C")
        ),
        "raw_action_orders_sha256": _sha256_bytes(
            raw_action_orders.astype("<u2", copy=False).tobytes(order="C")
        ),
        "raw_action_counts_sha256": _sha256_bytes(
            raw_action_counts.astype("<u2", copy=False).tobytes(order="C")
        ),
        "raw_work_sha256": _sha256_bytes(
            raw_work.astype("<u4", copy=False).tobytes(order="C")
        ),
    }
    resources = {
        "cpu_seconds": time.process_time() - cpu_started,
        "wall_seconds": time.monotonic() - wall_started,
        "process_peak_rss_bytes": _peak_rss_bytes(),
        "source_artifact_bytes_read": corpus.bytes_read,
        "existing_build_pools_loaded": len(corpus.episodes),
        "physical_public_pools_generated": 0,
        "native_solver_branches": 0,
        "scientific_entropy_calls": 0,
        "mps_calls": 0,
        "gpu_calls": 0,
        "sibling_reads": 0,
        "sibling_writes": 0,
        "maximum_serialized_fast_state_bytes": maximum_fast_state_bytes,
        "maximum_reader_state_bytes": maximum_reader_state_bytes,
        "maximum_critic_state_bytes": maximum_critic_state_bytes,
    }
    report_unsigned: dict[str, object] = {
        "schema": BUILD_LOO_RESULT_SCHEMA,
        "classification": classification,
        "claim_boundary": {
            "retrospective_build_leave_one_out": True,
            "disjoint_evaluation_claimed": False,
            "exact_key_recovery_claimed": bool(
                np.any(correct_bits[:, :, -1] == KEY_BITS)
                or np.any(raw_correct_bits == KEY_BITS)
            ),
            "native_solver_speedup_claimed": False,
            "logical_artifact_replay_only": True,
            "unknown_key_bits_at_held_out_probe": KEY_BITS,
        },
        "result_commitment": {
            "scope": "all report fields except volatile execution resources",
            "excluded_resource_fields": list(VOLATILE_RESOURCE_FIELDS),
        },
        "config": config.describe(),
        "source": {
            "attempt_id": corpus.source_attempt_id,
            "capsule_manifest_sha256": corpus.capsule_manifest_sha256,
            "artifact_index_sha256": corpus.artifact_index_sha256,
            "source_result_sha256": corpus.source_result_sha256,
            "source_config_sha256": corpus.source_config_sha256,
            "artifact_corpus_sha256": corpus.sha256,
            "build_pool_sha256": [row.action_pool_sha256 for row in corpus.episodes],
        },
        "policy_arms": list(POLICY_ARMS),
        "raw_arms": list(RAW_ARMS),
        "terminal_codes": dict(TERMINAL_CODES),
        "work_checkpoints": list(config.work_checkpoints),
        "folds": fold_rows,
        "arms": arm_rows,
        "raw_reader_arms": raw_rows,
        "margins": {
            "learned_minus_shifted_mean_iauc_bits": float(shifted_margin.mean()),
            "learned_stop_minus_no_stop_mean_iauc_bits": float(no_stop_margin.mean()),
            "learned_minus_static_mean_iauc_bits": float(static_margin.mean()),
            "learned_minus_hash_mean_iauc_bits": float(hash_margin.mean()),
            "learned_over_all_policy_controls_folds": int(
                np.sum(
                    (shifted_margin > 0.0) & (static_margin > 0.0) & (hash_margin > 0.0)
                )
            ),
            "learned_final_mean_compression_bits": float(
                compression_bits[:, learned_index, -1].mean()
            ),
            "raw_learned_minus_untrained_mean_compression_bits": float(
                raw_reader_margin.mean()
            ),
            "raw_learned_mean_compression_bits": float(
                raw_compression_bits[:, learned_raw_index].mean()
            ),
        },
        "gates": {
            **structural_gates,
            "structural_gate_passed": structural_passed,
            "learned_picker_over_all_controls": learned_advantage,
            "learned_policy_positive_final_compression": policy_final_positive,
            "raw_learned_reader_positive_compression": raw_reader_positive,
            "raw_learned_reader_over_untrained": raw_reader_over_untrained,
            "reader_isolated_gate_passed": reader_isolated_pass,
            "success_gate_passed": (
                structural_passed
                and learned_advantage
                and reader_isolated_pass
                and policy_final_positive
            ),
        },
        "iauc_convention": (
            "trapezoids at each arm-fold actual cumulative physical-work "
            "coordinate, then hold the final posterior through the indivisible "
            "tail to the common final cap; normalize by that cap"
        ),
        "artifact_commitments": artifact_commitments,
        "resources": resources,
        "next_action": (
            "If BUILD LOO transfers, freeze this architecture and attack one "
            "never-trained disjoint full-256 pool. Otherwise preserve per-fold "
            "agency/stationarity breadcrumbs and change the packet reader or "
            "credit model without regenerating these pools."
        ),
    }
    scientific_unsigned = dict(report_unsigned)
    scientific_unsigned["resources"] = {
        key: value
        for key, value in resources.items()
        if key not in VOLATILE_RESOURCE_FIELDS
    }
    report = {
        **report_unsigned,
        "execution_report_sha256": _canonical_sha256(report_unsigned),
        "result_sha256": _canonical_sha256(scientific_unsigned),
    }
    return Full256BuildLooResult(
        report=report,
        predictions=predictions,
        action_orders=action_orders,
        slot_orders=slot_orders,
        checkpoint_action_counts=checkpoint_action_counts,
        checkpoint_slot_counts=checkpoint_slot_counts,
        checkpoint_work=checkpoint_work,
        terminal_codes=terminal_codes,
        labels=labels,
        nll_bits=nll_bits,
        compression_bits=compression_bits,
        iauc_bits=iauc_bits,
        static_scores=static_scores,
        static_counts=static_counts,
        raw_predictions=raw_predictions,
        raw_nll_bits=raw_nll_bits,
        raw_compression_bits=raw_compression_bits,
        raw_action_orders=raw_action_orders,
        raw_action_counts=raw_action_counts,
        raw_work=raw_work,
        learning_artifacts=learning_artifacts,
        prediction_artifacts=prediction_artifacts,
    )


__all__ = [
    "BUILD_LOO_CONFIG_SCHEMA",
    "BUILD_LOO_LEARNING_FREEZE_SCHEMA",
    "BUILD_LOO_PREDICTION_FREEZE_SCHEMA",
    "BUILD_LOO_RESULT_SCHEMA",
    "BUILD_LOO_SCHEMA",
    "POLICY_ARMS",
    "RAW_ARMS",
    "TERMINAL_CODES",
    "VOLATILE_RESOURCE_FIELDS",
    "ArtifactBuildCorpus",
    "ArtifactBuildEpisode",
    "Full256BuildLooConfig",
    "Full256BuildLooError",
    "Full256BuildLooResult",
    "discover_artifact_build_corpus",
    "packet_latin_action_order",
    "run_full256_multiresolution_build_loo",
]
