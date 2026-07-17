from __future__ import annotations

import hashlib
import inspect
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import numpy as np

from o1_crypto_lab.causal_bitfield import CausalBitfieldPlan
from o1_crypto_lab.full256_action_pool import (
    BRANCH_FEATURES,
    Full256ActionPool,
    serialize_action_pool,
)
from o1_crypto_lab.full256_paired_sensor import NativeDependencyConfig
from o1_crypto_lab.full256_proof_pool import (
    FrozenFull256ProofPool,
    Full256ProofPoolBuilder,
    Full256ProofPoolConfig,
    Full256ProofPoolError,
    Full256ProofPoolSource,
    make_deterministic_known_target,
)


SHA_A = "a" * 64


def _pool() -> Full256ActionPool:
    generator = np.random.Generator(np.random.PCG64(180018))
    features = generator.normal(
        0.0, 0.1, (3, 256, 2, BRANCH_FEATURES)
    ).astype(np.float32)
    resources = np.zeros((256, 2, 3), dtype=np.uint64)
    return Full256ActionPool(
        horizons=(64, 96, 65),
        branch_features=features,
        final_resources=resources,
        pair_sha256=tuple(
            hashlib.sha256(f"pair-{index}".encode("ascii")).hexdigest()
            for index in range(256)
        ),
        source_stream_sha256=hashlib.sha256(b"stream").hexdigest(),
    )


class DeterministicKnownTargetTests(unittest.TestCase):
    def test_target_is_domain_separated_fullround_and_labels_open_after_freeze(
        self,
    ) -> None:
        first = make_deterministic_known_target(seed=180018, split="BUILD", index=0)
        repeated = make_deterministic_known_target(
            seed=180018, split="BUILD", index=0
        )
        evaluation = make_deterministic_known_target(
            seed=180018, split="EVALUATION", index=0
        )

        self.assertEqual(first.public.digest(), repeated.public.digest())
        self.assertEqual(first.key_sha256, repeated.key_sha256)
        self.assertNotEqual(first.public.digest(), evaluation.public.digest())
        self.assertNotEqual(first.key_sha256, evaluation.key_sha256)
        self.assertEqual(first.public.block_count, 1)

        with self.assertRaisesRegex(Full256ProofPoolError, "action_pool_sha256"):
            first.labels_after_pool_freeze("not-a-hash")
        labels = first.labels_after_pool_freeze(SHA_A)
        self.assertEqual(labels.shape, (256,))
        self.assertEqual(labels.dtype, np.uint8)
        self.assertFalse(labels.flags.writeable)
        self.assertEqual(
            np.packbits(labels, bitorder="little").tobytes(), first._key
        )

        public = first.public_description()
        self.assertFalse(public["target_key_enters_probe"])
        self.assertEqual(public["unknown_key_bits_at_probe"], 256)
        self.assertNotIn("key", public)
        self.assertNotIn(first._key.hex(), repr(public))

    def test_target_validation_rejects_overlap_primitives(self) -> None:
        with self.assertRaisesRegex(Full256ProofPoolError, "split"):
            make_deterministic_known_target(seed=1, split="SEALED", index=0)
        with self.assertRaisesRegex(Full256ProofPoolError, "index"):
            make_deterministic_known_target(seed=1, split="BUILD", index=-1)
        with self.assertRaisesRegex(Full256ProofPoolError, "uint63"):
            make_deterministic_known_target(seed=-1, split="BUILD", index=0)


class FrozenProofPoolTests(unittest.TestCase):
    def test_snapshot_binds_canonical_pool_and_contains_no_secret_input(self) -> None:
        target = make_deterministic_known_target(
            seed=180018, split="DEVELOPMENT", index=1
        )
        pool = _pool()
        payload = serialize_action_pool(pool)
        frozen = FrozenFull256ProofPool(
            target_id=target.target_id,
            public=target.public,
            action_pool=pool,
            action_pool_bytes=payload,
            instance={"instance_sha256": "b" * 64},
            probe={"result_sha256": "c" * 64},
            resources={"native_cpu_seconds": 1.0},
        )

        self.assertEqual(
            frozen.action_pool_sha256, hashlib.sha256(payload).hexdigest()
        )
        report = frozen.describe()
        self.assertEqual(report["target_key_inputs"], 0)
        self.assertEqual(report["target_trace_inputs"], 0)
        self.assertEqual(report["label_access_phase"], "AFTER_ACTION_POOL_FREEZE")
        self.assertNotIn(target._key.hex(), repr(report))

        with self.assertRaisesRegex(Full256ProofPoolError, "bytes differ"):
            FrozenFull256ProofPool(
                target_id=target.target_id,
                public=target.public,
                action_pool=pool,
                action_pool_bytes=payload + b"x",
                instance={},
                probe={},
                resources={},
            )


class ProofPoolBuilderTests(unittest.TestCase):
    def _fixture(
        self, root: Path
    ) -> tuple[Full256ProofPoolConfig, Path, Path, Path, Path]:
        source = root / "runs" / "source"
        source.mkdir(parents=True)
        manifest = source / "artifacts.sha256"
        template = source / "artifacts" / "cnf" / "full.cnf"
        semantic_map = source / "artifacts" / "cnf" / "full.map.json"
        template.parent.mkdir(parents=True)
        manifest.write_bytes(b"manifest\n")
        template.write_bytes(b"template\n")
        semantic_map.write_bytes(b"map\n")
        workspace = root / "workspace"
        workspace.mkdir()
        source_config = Full256ProofPoolSource(
            capsule="runs/source",
            manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
            template="artifacts/cnf/full.cnf",
            template_sha256=hashlib.sha256(template.read_bytes()).hexdigest(),
            semantic_map="artifacts/cnf/full.map.json",
            semantic_map_sha256=hashlib.sha256(semantic_map.read_bytes()).hexdigest(),
            expected_variable_count=32128,
            expected_template_clause_count=187370,
            expected_public_clause_count=188010,
        )
        native = NativeDependencyConfig(
            compiler="c++",
            include_directory="/pinned/include",
            static_library="/pinned/libcadical.a",
            cadical_header_sha256="d" * 64,
            cadical_library_sha256="e" * 64,
        )
        config = Full256ProofPoolConfig(
            source=source_config,
            native=native,
            state_plan=CausalBitfieldPlan(),
        )
        return config, workspace, manifest, template, semantic_map

    @staticmethod
    def _fake_build(**kwargs: object) -> SimpleNamespace:
        output = Path(kwargs["output"])
        output.write_bytes(b"native")
        output.chmod(0o700)
        return SimpleNamespace(executable=output, executable_sha256="f" * 64)

    def test_builder_probe_surface_is_public_only_and_returns_raw_pool(self) -> None:
        parameters = inspect.signature(Full256ProofPoolBuilder.probe_public).parameters
        self.assertEqual(set(parameters), {"self", "target_id", "public"})
        self.assertNotIn("key", parameters)
        self.assertNotIn("labels", parameters)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, workspace, _manifest, _template, _map = self._fixture(root)
            pool = _pool()
            instance = SimpleNamespace(
                key_unit_clause_count=0,
                assumption_unit_clause_count=0,
                public_unit_clause_count=640,
                variable_count=32128,
                clause_count=188010,
                instance_sha256="1" * 64,
                describe=lambda: {"instance_sha256": "1" * 64},
            )
            core = SimpleNamespace(
                success_gate_passed=True,
                action_pool=pool,
                report={
                    "result_sha256": "2" * 64,
                    "gates": {"success_gate_passed": True},
                    "resources": {"native_branch_count": 512},
                },
                event_index={"event_index_sha256": "3" * 64},
            )
            target = make_deterministic_known_target(
                seed=180018, split="BUILD", index=0
            )
            captured_config = None

            def fake_core(value: object) -> SimpleNamespace:
                nonlocal captured_config
                captured_config = value
                return core

            with (
                mock.patch(
                    "o1_crypto_lab.full256_proof_pool.verify_full256_template",
                    return_value={"variable_count": 32128, "clause_count": 187370},
                ),
                mock.patch(
                    "o1_crypto_lab.full256_proof_pool.build_native_sensor",
                    side_effect=self._fake_build,
                ),
                mock.patch(
                    "o1_crypto_lab.full256_proof_pool.write_full256_instance",
                    return_value=instance,
                ),
                mock.patch(
                    "o1_crypto_lab.full256_proof_pool.run_full256_probe_core",
                    side_effect=fake_core,
                ),
            ):
                builder = Full256ProofPoolBuilder(
                    root=root, config=config, workspace=workspace
                )
                frozen = builder.probe_public(
                    target_id=target.target_id, public=target.public
                )

            self.assertEqual(frozen.action_pool_bytes, serialize_action_pool(pool))
            self.assertEqual(frozen.public.digest(), target.public.digest())
            self.assertIsNotNone(captured_config)
            assert captured_config is not None
            fields = vars(captured_config)
            self.assertFalse(any("key" in name or "label" in name for name in fields))
            self.assertEqual(captured_config.sentinel_reruns, 0)
            self.assertEqual(captured_config.expected_clause_count, 188010)

    def test_builder_detects_source_mutation_after_probe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, workspace, manifest, _template, _map = self._fixture(root)
            with (
                mock.patch(
                    "o1_crypto_lab.full256_proof_pool.verify_full256_template",
                    return_value={"variable_count": 32128, "clause_count": 187370},
                ),
                mock.patch(
                    "o1_crypto_lab.full256_proof_pool.build_native_sensor",
                    side_effect=self._fake_build,
                ),
            ):
                builder = Full256ProofPoolBuilder(
                    root=root, config=config, workspace=workspace
                )
            manifest.write_bytes(b"changed\n")
            with self.assertRaisesRegex(Full256ProofPoolError, "source hashes"):
                builder.verify_sources_unchanged()


if __name__ == "__main__":
    unittest.main()
