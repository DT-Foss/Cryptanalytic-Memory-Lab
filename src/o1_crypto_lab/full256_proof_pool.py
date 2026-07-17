"""Deterministic full-round known-key proof pools for online O1 learning.

This module owns the narrow bridge from one standard ChaCha20 public view to the
immutable ``[H,256,2,330]`` raw action pool consumed by
``OnlineCausalController``.  The probe API accepts no key, label, target trace,
reader, or policy callback.  The deterministic key oracle remains outside that
boundary and may reveal labels only after the pool commitment exists.
"""

from __future__ import annotations

import hashlib
import math
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

import numpy as np

from .cadical_sensor import build_native_sensor, sha256_file
from .causal_bitfield import CausalBitfieldPlan
from .chacha_trace import chacha20_block
from .full256_action_pool import Full256ActionPool, serialize_action_pool
from .full256_cnf import verify_full256_template, write_full256_instance
from .full256_paired_sensor import NativeDependencyConfig
from .full256_probe_core import Full256ProbeCoreConfig, run_full256_probe_core
from .living_inverse import KEY_BITS, PublicTargetView, canonical_json_bytes


PROOF_POOL_SCHEMA = "o1-256-fullround-proof-pool-v1"
PROOF_POOL_SOURCE_SCHEMA = "o1-256-fullround-proof-pool-source-v1"
KNOWN_TARGET_SCHEMA = "o1-256-deterministic-known-fullround-target-v1"
ALLOWED_KNOWN_SPLITS = frozenset({"BUILD", "DEVELOPMENT", "EVALUATION"})


class Full256ProofPoolError(ValueError):
    """A deterministic target, public probe, source, or pool differs."""


def _sha256(value: object, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise Full256ProofPoolError(f"{field_name} must be lowercase SHA-256")
    return value


def _positive_int(value: object, field_name: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise Full256ProofPoolError(
            f"{field_name} must be an integer in [1,{maximum}]"
        )
    return value


def _positive_float(value: object, field_name: str, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0.0 < float(value) <= maximum
    ):
        raise Full256ProofPoolError(
            f"{field_name} must be finite in (0,{maximum}]"
        )
    return float(value)


@dataclass(frozen=True)
class Full256ProofPoolSource:
    """Pinned O1C-0011 template and semantic-map lineage."""

    capsule: str
    manifest_sha256: str
    template: str
    template_sha256: str
    semantic_map: str
    semantic_map_sha256: str
    expected_variable_count: int
    expected_template_clause_count: int
    expected_public_clause_count: int

    def __post_init__(self) -> None:
        for field_name in ("capsule", "template", "semantic_map"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise Full256ProofPoolError(f"source.{field_name} is required")
        for field_name in (
            "manifest_sha256",
            "template_sha256",
            "semantic_map_sha256",
        ):
            _sha256(getattr(self, field_name), f"source.{field_name}")
        for field_name in (
            "expected_variable_count",
            "expected_template_clause_count",
            "expected_public_clause_count",
        ):
            _positive_int(getattr(self, field_name), f"source.{field_name}", 10_000_000)

    def describe(self) -> dict[str, object]:
        return {
            "schema": PROOF_POOL_SOURCE_SCHEMA,
            "capsule": self.capsule,
            "manifest_sha256": self.manifest_sha256,
            "template": self.template,
            "template_sha256": self.template_sha256,
            "semantic_map": self.semantic_map,
            "semantic_map_sha256": self.semantic_map_sha256,
            "expected_variable_count": self.expected_variable_count,
            "expected_template_clause_count": self.expected_template_clause_count,
            "expected_public_clause_count": self.expected_public_clause_count,
        }


@dataclass(frozen=True)
class Full256ProofPoolConfig:
    """Fixed public-probe build contract shared by every known target."""

    source: Full256ProofPoolSource
    native: NativeDependencyConfig
    state_plan: CausalBitfieldPlan = field(default_factory=CausalBitfieldPlan)
    probe_seed: int = 0
    timeout_seconds: float = 240.0
    maximum_state_bytes: int = 18_000

    def __post_init__(self) -> None:
        if not isinstance(self.source, Full256ProofPoolSource):
            raise Full256ProofPoolError("source must be Full256ProofPoolSource")
        if not isinstance(self.native, NativeDependencyConfig):
            raise Full256ProofPoolError("native must be NativeDependencyConfig")
        if not isinstance(self.state_plan, CausalBitfieldPlan):
            raise Full256ProofPoolError("state_plan must be CausalBitfieldPlan")
        if len(self.state_plan.horizons) != 3:
            raise Full256ProofPoolError("proof pools require exactly three horizons")
        if (
            isinstance(self.probe_seed, bool)
            or not isinstance(self.probe_seed, int)
            or not 0 <= self.probe_seed <= 2_000_000_000
        ):
            raise Full256ProofPoolError("probe_seed is outside the native range")
        _positive_float(self.timeout_seconds, "timeout_seconds", 3600.0)
        if (
            isinstance(self.maximum_state_bytes, bool)
            or not isinstance(self.maximum_state_bytes, int)
            or self.maximum_state_bytes < self.state_plan.serialized_state_bytes
        ):
            raise Full256ProofPoolError("maximum_state_bytes cannot fit the state")

    def describe(self) -> dict[str, object]:
        return {
            "schema": PROOF_POOL_SCHEMA,
            "source": self.source.describe(),
            "native": {
                "compiler": self.native.compiler,
                "include_directory": self.native.include_directory,
                "static_library": self.native.static_library,
                "cadical_header_sha256": self.native.cadical_header_sha256,
                "cadical_library_sha256": self.native.cadical_library_sha256,
            },
            "state_plan": self.state_plan.describe(),
            "probe_seed": self.probe_seed,
            "timeout_seconds": self.timeout_seconds,
            "maximum_state_bytes": self.maximum_state_bytes,
            "accepted_target_key_bytes": 0,
            "accepted_target_labels": 0,
            "accepted_target_trace_fields": 0,
        }


@dataclass(frozen=True)
class DeterministicKnownTarget:
    """A reproducible full-round target whose secret stays outside the probe API."""

    target_id: str
    split: str
    index: int
    public: PublicTargetView
    _key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.target_id, str) or not self.target_id:
            raise Full256ProofPoolError("target_id is required")
        if self.split not in ALLOWED_KNOWN_SPLITS:
            raise Full256ProofPoolError("known target split differs")
        if isinstance(self.index, bool) or not isinstance(self.index, int) or self.index < 0:
            raise Full256ProofPoolError("known target index must be non-negative")
        if not isinstance(self.public, PublicTargetView):
            raise Full256ProofPoolError("known target public view differs")
        self.public.validate()
        if self.public.block_count != 1:
            raise Full256ProofPoolError("known target requires one public block")
        if not isinstance(self._key, bytes) or len(self._key) != 32:
            raise Full256ProofPoolError("known target key must contain 256 bits")

    @property
    def key_sha256(self) -> str:
        return hashlib.sha256(self._key).hexdigest()

    def labels_after_pool_freeze(
        self,
        frozen_pool: FrozenFull256ProofPool,
    ) -> np.ndarray:
        """Materialize labels only against this target's exact frozen pool."""

        if not isinstance(frozen_pool, FrozenFull256ProofPool):
            raise Full256ProofPoolError(
                "labels require a FrozenFull256ProofPool receipt"
            )
        if (
            frozen_pool.target_id != self.target_id
            or frozen_pool.public.digest() != self.public.digest()
            or frozen_pool.public.describe() != self.public.describe()
        ):
            raise Full256ProofPoolError(
                "frozen pool does not belong to this known target"
            )
        _sha256(frozen_pool.action_pool_sha256, "action_pool_sha256")
        labels = np.unpackbits(
            np.frombuffer(self._key, dtype=np.uint8), bitorder="little"
        ).astype(np.uint8)
        labels.setflags(write=False)
        return labels

    def public_description(self) -> dict[str, object]:
        return {
            "schema": KNOWN_TARGET_SCHEMA,
            "target_id": self.target_id,
            "split": self.split,
            "index": self.index,
            "distribution": "DETERMINISTIC_UNIFORM",
            "public_view": self.public.describe(),
            "public_view_sha256": self.public.digest(),
            "key_sha256": self.key_sha256,
            "unknown_key_bits_at_probe": KEY_BITS,
            "target_key_enters_probe": False,
        }


def make_deterministic_known_target(
    *, seed: int, split: str, index: int
) -> DeterministicKnownTarget:
    """Derive a domain-separated standard full-round known target."""

    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed < 1 << 63:
        raise Full256ProofPoolError("known-target seed must be uint63")
    if split not in ALLOWED_KNOWN_SPLITS:
        raise Full256ProofPoolError("known target split differs")
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise Full256ProofPoolError("known target index must be non-negative")
    material = hashlib.shake_256(
        canonical_json_bytes([KNOWN_TARGET_SCHEMA, seed, split, index])
    ).digest(48)
    key = material[:32]
    counter = int.from_bytes(material[32:36], "little")
    nonce = material[36:48]
    public = PublicTargetView(
        counter_schedule=(counter,),
        nonce=nonce,
        output_blocks=(chacha20_block(key, counter, nonce),),
    )
    public.validate()
    return DeterministicKnownTarget(
        target_id=f"{split.lower()}-{index:04d}",
        split=split,
        index=index,
        public=public,
        _key=key,
    )


@dataclass(frozen=True)
class FrozenFull256ProofPool:
    """Public-only action pool and provenance frozen before any label access."""

    target_id: str
    public: PublicTargetView
    action_pool: Full256ActionPool
    action_pool_bytes: bytes
    instance: Mapping[str, object]
    probe: Mapping[str, object]
    resources: Mapping[str, object]

    def __post_init__(self) -> None:
        if not isinstance(self.target_id, str) or not self.target_id:
            raise Full256ProofPoolError("frozen target_id is required")
        if not isinstance(self.public, PublicTargetView):
            raise Full256ProofPoolError("frozen public view differs")
        self.public.validate()
        if not isinstance(self.action_pool, Full256ActionPool):
            raise Full256ProofPoolError("frozen action pool differs")
        if (
            not isinstance(self.action_pool_bytes, bytes)
            or serialize_action_pool(self.action_pool) != self.action_pool_bytes
        ):
            raise Full256ProofPoolError("frozen action-pool bytes differ")
        if not isinstance(self.instance, Mapping) or not isinstance(self.probe, Mapping):
            raise Full256ProofPoolError("frozen proof provenance differs")
        if not isinstance(self.resources, Mapping):
            raise Full256ProofPoolError("frozen proof resources differ")

    @property
    def action_pool_sha256(self) -> str:
        return hashlib.sha256(self.action_pool_bytes).hexdigest()

    def describe(self, *, include_resources: bool = True) -> dict[str, object]:
        result = {
            "schema": PROOF_POOL_SCHEMA,
            "target_id": self.target_id,
            "public_view": self.public.describe(),
            "public_view_sha256": self.public.digest(),
            "action_pool": self.action_pool.describe(),
            "action_pool_bytes": len(self.action_pool_bytes),
            "action_pool_sha256": self.action_pool_sha256,
            "instance": dict(self.instance),
            "probe": dict(self.probe),
            "label_access_phase": "AFTER_ACTION_POOL_FREEZE",
            "target_key_inputs": 0,
            "target_trace_inputs": 0,
        }
        if include_resources:
            result["resources"] = dict(self.resources)
        return result


class Full256ProofPoolBuilder:
    """Verified source/native builder whose live probe surface is public-only."""

    def __init__(
        self,
        *,
        root: str | Path,
        config: Full256ProofPoolConfig,
        workspace: str | Path,
    ) -> None:
        if not isinstance(config, Full256ProofPoolConfig):
            raise TypeError("config must be Full256ProofPoolConfig")
        self.root = Path(root).resolve(strict=True)
        self.config = config
        self.workspace = Path(workspace).resolve(strict=True)
        if not self.workspace.is_dir():
            raise Full256ProofPoolError("workspace must be an existing directory")
        runs_root = (self.root / "runs").resolve(strict=True)
        self.source_capsule = (self.root / config.source.capsule).resolve(strict=True)
        if not self.source_capsule.is_relative_to(runs_root):
            raise Full256ProofPoolError("proof-pool source escapes finalized runs")
        self.manifest = (self.source_capsule / "artifacts.sha256").resolve(strict=True)
        self.template = (self.source_capsule / config.source.template).resolve(
            strict=True
        )
        self.semantic_map = (
            self.source_capsule / config.source.semantic_map
        ).resolve(strict=True)
        if not self.template.is_relative_to(
            self.source_capsule
        ) or not self.semantic_map.is_relative_to(self.source_capsule):
            raise Full256ProofPoolError("proof-pool source member escapes capsule")
        self._verify_sources()
        verification = verify_full256_template(self.template, self.semantic_map)
        if (
            verification.get("variable_count")
            != config.source.expected_variable_count
            or verification.get("clause_count")
            != config.source.expected_template_clause_count
        ):
            raise Full256ProofPoolError("full-round template dimensions differ")
        self.native_executable = self.workspace / "cadical_pair_sensor_o1c18"
        self.native_build = build_native_sensor(
            source=self.root / "native/cadical_pair_sensor.cpp",
            tracer_header=self.root / "native/cadical_tracer_3_0_0.hpp",
            cadical_include=config.native.include_directory,
            cadical_library=config.native.static_library,
            output=self.native_executable,
            expected_cadical_header_sha256=config.native.cadical_header_sha256,
            expected_cadical_library_sha256=config.native.cadical_library_sha256,
            compiler=config.native.compiler,
        )

    def _verify_sources(self) -> None:
        actual = {
            "manifest": sha256_file(self.manifest),
            "template": sha256_file(self.template),
            "semantic_map": sha256_file(self.semantic_map),
        }
        expected = {
            "manifest": self.config.source.manifest_sha256,
            "template": self.config.source.template_sha256,
            "semantic_map": self.config.source.semantic_map_sha256,
        }
        if actual != expected:
            raise Full256ProofPoolError("proof-pool source hashes differ")

    def verify_sources_unchanged(self) -> None:
        self._verify_sources()

    def probe_public(
        self, *, target_id: str, public: PublicTargetView
    ) -> FrozenFull256ProofPool:
        """Freeze one complete public pool; this signature cannot accept a key."""

        if not isinstance(target_id, str) or not target_id:
            raise Full256ProofPoolError("target_id is required")
        if not isinstance(public, PublicTargetView):
            raise Full256ProofPoolError("public must be PublicTargetView")
        public.validate()
        if public.block_count != 1:
            raise Full256ProofPoolError("proof pool requires one public block")
        with tempfile.TemporaryDirectory(
            prefix=f"o1c0018-{target_id}-", dir=self.workspace
        ) as temporary:
            instance_path = Path(temporary) / "public_attacker_instance.cnf"
            instance = write_full256_instance(
                self.template,
                self.semantic_map,
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
                or instance.variable_count
                != self.config.source.expected_variable_count
                or instance.clause_count
                != self.config.source.expected_public_clause_count
            ):
                raise Full256ProofPoolError("generated public instance boundary differs")
            core = run_full256_probe_core(
                Full256ProbeCoreConfig(
                    public_cnf=instance_path,
                    semantic_map=self.semantic_map,
                    native_executable=self.native_executable,
                    state_plan=self.config.state_plan,
                    seed=self.config.probe_seed,
                    timeout_seconds=self.config.timeout_seconds,
                    sentinel_reruns=0,
                    maximum_state_bytes=self.config.maximum_state_bytes,
                    expected_public_cnf_sha256=instance.instance_sha256,
                    expected_semantic_map_sha256=(
                        self.config.source.semantic_map_sha256
                    ),
                    expected_variable_count=(
                        self.config.source.expected_variable_count
                    ),
                    expected_clause_count=(
                        self.config.source.expected_public_clause_count
                    ),
                )
            )
            if not core.success_gate_passed:
                raise Full256ProofPoolError("full-round probe-core gate failed")
            # Solver timing/RSS counters are operational telemetry, not part of
            # the scientific observation.  Zero them before freezing the pool so
            # identical public evidence has identical bytes across machines and
            # runs; the real counters remain available through ``resources``.
            scientific_pool = Full256ActionPool(
                horizons=core.action_pool.horizons,
                branch_features=core.action_pool.branch_features,
                final_resources=np.zeros_like(core.action_pool.final_resources),
                pair_sha256=core.action_pool.pair_sha256,
                source_stream_sha256=core.action_pool.source_stream_sha256,
            )
            pool_bytes = serialize_action_pool(scientific_pool)
            frozen = FrozenFull256ProofPool(
                target_id=target_id,
                public=public,
                action_pool=scientific_pool,
                action_pool_bytes=pool_bytes,
                instance=instance.describe(),
                probe={
                    "result_sha256": core.report["result_sha256"],
                    "source_stream_sha256": core.action_pool.source_stream_sha256,
                    "event_index_sha256": core.event_index["event_index_sha256"],
                    "gates": core.report["gates"],
                    "operational_final_resources_removed_from_pool": True,
                },
                resources=core.report["resources"],
            )
        self._verify_sources()
        return frozen


__all__ = [
    "ALLOWED_KNOWN_SPLITS",
    "KNOWN_TARGET_SCHEMA",
    "PROOF_POOL_SCHEMA",
    "DeterministicKnownTarget",
    "FrozenFull256ProofPool",
    "Full256ProofPoolBuilder",
    "Full256ProofPoolConfig",
    "Full256ProofPoolError",
    "Full256ProofPoolSource",
    "make_deterministic_known_target",
]
