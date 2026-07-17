from __future__ import annotations

import hashlib
import inspect
import itertools
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np

import o1_crypto_lab.full256_polyphase_replication as replication
from o1_crypto_lab.causal_orientation_reader import (
    deserialize_orientation_reader,
    serialize_orientation_reader,
)
from o1_crypto_lab.full256_broker import ENTROPY_BYTES, Full256TargetBroker
from o1_crypto_lab.full256_polyphase_replication import (
    Full256PolyphaseReplicationError,
    load_full256_polyphase_replication_config,
    run_full256_polyphase_replication,
)
from o1_crypto_lab.full256_probe_core import READER_FEATURES
from o1_crypto_lab.living_inverse import KEY_BITS, PublicTargetView


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/full256_polyphase_replication_v1.json"
CONFIG_V2 = ROOT / "configs/full256_polyphase_replication_v2.json"
CONFIG_V1_SHA256 = "5084c24909cc344cb37587b3eb544f107ce3676b40fdbbb72f9df2643cc470c7"

PRIMARY_H96_SHA256 = "796e79ec932b990a59ecbc34216c4878b9279bae3bb136fe0832e580bcb2e9f8"
PRIMARY_H65_SHA256 = "b7dd365753bf2ca131c2c263f3c04e5e644d9d438feaf17a5a313790dcf8409d"
PRIMARY_H65_CANDIDATE_SHA256 = (
    "318d9d94fd5419522f26fcf054d0953b0d001c63dd38951e159077128f38b5d4"
)
SHUFFLED_H96_SHA256 = "6dd8b6c09c4593228cfafe545bdff4c6e6b9953ba013fff35f97ac87c8ab3cb1"
SHUFFLED_H96_CANDIDATE_SHA256 = (
    "05bf33a58b93f201af509bfc458751a146f974f824999d79395e1685450da44c"
)
SHUFFLED_H65_SHA256 = "d9077567e1ffd6b73d673fdca22626495fb213057c0a203a0cd1c264d15b00d6"
SHUFFLED_H65_CANDIDATE_SHA256 = (
    "7ee43dddded426a1fb5ff883df960248d4dacbef20342baff2ed72e63560fadd"
)


def _canonical_config():
    return load_full256_polyphase_replication_config(CONFIG)


class Full256PolyphaseReplicationConfigTests(unittest.TestCase):
    def test_v1_config_remains_byte_identical(self) -> None:
        self.assertEqual(
            hashlib.sha256(CONFIG.read_bytes()).hexdigest(), CONFIG_V1_SHA256
        )

    def test_canonical_config_freezes_the_exact_32_target_operator(self) -> None:
        raw, config = _canonical_config()

        self.assertEqual(raw["attempt_id"], "O1C-0015")
        self.assertEqual(config.attempt_id, "O1C-0015")
        self.assertEqual(config.corpus.sealed_targets, 32)
        self.assertEqual(config.reader.arms, ("horizon_1", "horizon_2"))
        self.assertEqual(config.reader.ensemble_weights, (0.5, 0.5))
        self.assertEqual(
            config.reader.ridge_lambdas, (0.001, 0.01, 0.1, 1.0, 10.0, 100.0)
        )
        self.assertEqual(config.reader.temperatures, (0.5, 1.0, 2.0, 4.0, 8.0))
        self.assertEqual(config.reader.logit_scales, (0.0, 0.25, 0.5, 1.0))
        self.assertEqual(config.decision.directional_minimum_positive_targets, 18)
        self.assertEqual(config.decision.strong_minimum_positive_targets, 22)
        self.assertEqual(config.budgets.maximum_fresh_random_targets, 32)
        self.assertEqual(config.budgets.maximum_native_solver_branches, 17_920)
        self.assertEqual(config.maximum_live_target_state_bytes, 67_584)
        self.assertEqual(
            tuple(config.controls.transforms),
            ("output_bit_flip", "wrong_nonce", "output_byte_rotate"),
        )

    def test_v2_changes_only_attempt_slug_and_three_soft_resource_ceilings(
        self,
    ) -> None:
        raw_v1, config_v1 = load_full256_polyphase_replication_config(CONFIG)
        raw_v2, config_v2 = load_full256_polyphase_replication_config(CONFIG_V2)

        self.assertEqual(raw_v2["attempt_id"], "O1C-0016")
        self.assertEqual(config_v2.attempt_id, "O1C-0016")
        self.assertEqual(raw_v2["slug"], "full256-polyphase-blind-replication-v2")
        self.assertEqual(config_v2.budgets.maximum_cpu_seconds, 3_000)
        self.assertEqual(config_v2.budgets.maximum_wall_seconds, 3_000)
        self.assertEqual(config_v2.budgets.maximum_resident_memory_mib, 768)

        allowed_differences = {
            ("attempt_id",),
            ("slug",),
            ("budgets", "maximum_cpu_seconds"),
            ("budgets", "maximum_wall_seconds"),
            ("budgets", "maximum_resident_memory_mib"),
            ("controls",),
            ("next_action",),
        }

        def differing_paths(left, right, prefix=()):
            if isinstance(left, dict) and isinstance(right, dict):
                paths = set()
                for key in left.keys() | right.keys():
                    if key not in left or key not in right:
                        paths.add((*prefix, key))
                    else:
                        paths.update(
                            differing_paths(left[key], right[key], (*prefix, key))
                        )
                return paths
            return {prefix} if left != right else set()

        self.assertEqual(differing_paths(raw_v1, raw_v2), allowed_differences)
        self.assertEqual(config_v1.corpus, config_v2.corpus)
        self.assertEqual(raw_v1["controls"], raw_v2["controls"][:-1])
        self.assertIn(
            "326bc30a1499f6479d306df43b17ec390c020832bb5d1816fa8ab9f7f9660314",
            raw_v2["controls"][-1],
        )
        self.assertIn("runtime-only provenance", raw_v2["controls"][-1])
        self.assertIn("no O1C-0015 public views", raw_v2["controls"][-1])
        self.assertIn(
            "Never reuse any revealed O1C-0015 or O1C-0016 target",
            raw_v2["next_action"],
        )
        self.assertEqual(config_v1.reader, config_v2.reader)
        self.assertEqual(config_v1.controls, config_v2.controls)
        self.assertEqual(config_v1.decision, config_v2.decision)
        self.assertEqual(config_v1.state_plan, config_v2.state_plan)
        self.assertEqual(config_v1.source, config_v2.source)
        self.assertEqual(config_v1.design_lineage, config_v2.design_lineage)
        self.assertEqual(config_v1.maximum_state_bytes, config_v2.maximum_state_bytes)
        self.assertEqual(
            config_v1.maximum_live_target_state_bytes,
            config_v2.maximum_live_target_state_bytes,
        )
        for field in (
            "maximum_persistent_artifact_bytes",
            "maximum_native_solver_branches",
            "maximum_mps_calls",
            "maximum_gpu_calls",
            "maximum_sibling_reads",
            "maximum_sibling_writes",
            "maximum_fresh_random_targets",
        ):
            self.assertEqual(
                getattr(config_v1.budgets, field),
                getattr(config_v2.budgets, field),
            )

    def test_reader_pins_and_o1c0014_lineage_boundary_are_explicit(self) -> None:
        raw, config = _canonical_config()

        self.assertEqual(config.source.primary_reader_sha256, PRIMARY_H96_SHA256)
        self.assertEqual(config.reader.primary_h65_reader_sha256, PRIMARY_H65_SHA256)
        self.assertEqual(
            config.reader.primary_h65_candidate_sha256,
            PRIMARY_H65_CANDIDATE_SHA256,
        )
        self.assertEqual(config.reader.shuffled_h96_reader_sha256, SHUFFLED_H96_SHA256)
        self.assertEqual(
            config.reader.shuffled_h96_candidate_sha256,
            SHUFFLED_H96_CANDIDATE_SHA256,
        )
        self.assertEqual(config.reader.shuffled_h65_reader_sha256, SHUFFLED_H65_SHA256)
        self.assertEqual(
            config.reader.shuffled_h65_candidate_sha256,
            SHUFFLED_H65_CANDIDATE_SHA256,
        )
        self.assertIn("O1C-0013", config.source.capsule)
        self.assertNotIn("O1C-0014", json.dumps(raw["source"], sort_keys=True))
        self.assertIn("O1C-0014", config.design_lineage.capsule)
        self.assertEqual(
            set(raw["design_lineage"]),
            {"capsule", "manifest_sha256", "result", "result_sha256"},
        )
        reconstruction_source = inspect.getsource(
            replication._reconstruct_polyphase_readers
        )
        self.assertNotIn("design_lineage", reconstruction_source)
        self.assertNotIn("O1C-0014", reconstruction_source)

    def test_config_rejects_search_or_protocol_drift(self) -> None:
        raw, _config = _canonical_config()
        variants: list[dict[str, object]] = []

        unknown = json.loads(json.dumps(raw))
        unknown["unreviewed_extension"] = True
        variants.append(unknown)
        for mutate in (
            lambda row: row["corpus"].__setitem__("sealed_targets", 31),
            lambda row: row["reader"].__setitem__("arms", ["horizon_2", "horizon_1"]),
            lambda row: row["reader"].__setitem__("ensemble_weights", [0.4, 0.6]),
            lambda row: row["decision"].__setitem__(
                "directional_minimum_positive_targets", 17
            ),
            lambda row: row["budgets"].__setitem__(
                "maximum_native_solver_branches", 17_919
            ),
        ):
            candidate = json.loads(json.dumps(raw))
            mutate(candidate)
            variants.append(candidate)

        with tempfile.TemporaryDirectory() as temporary:
            for index, value in enumerate(variants):
                path = Path(temporary) / f"config-{index}.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                with (
                    self.subTest(index=index),
                    self.assertRaises(Full256PolyphaseReplicationError),
                ):
                    load_full256_polyphase_replication_config(path)


class Full256PolyphaseReplicationPrimitiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        _raw, cls.config = _canonical_config()
        cls.bundle = replication._source_bundle(
            ROOT, cls.config.source, cls.config.design_lineage
        )
        primary_payload = cls.bundle.primary_reader.read_bytes()
        cls.primary_h96 = deserialize_orientation_reader(primary_payload)
        cls.primary_h65, cls.shuffled_h96, cls.shuffled_h65 = (
            replication._reconstruct_polyphase_readers(
                cls.bundle,
                cls.config.source,
                cls.config.reader,
                cls.primary_h96,
            )
        )
        feature_bytes = cls.bundle.build_cal_features.read_bytes()
        cls.features = np.frombuffer(feature_bytes, dtype="<f4").reshape(
            6, KEY_BITS, READER_FEATURES
        )[0]

    def test_h96_is_byte_identical_and_h65_reconstruction_is_pinned(self) -> None:
        primary_payload = self.bundle.primary_reader.read_bytes()
        self.assertEqual(
            hashlib.sha256(primary_payload).hexdigest(), PRIMARY_H96_SHA256
        )
        self.assertEqual(
            serialize_orientation_reader(self.primary_h96), primary_payload
        )

        expected = (
            (
                self.primary_h65,
                PRIMARY_H65_SHA256,
                PRIMARY_H65_CANDIDATE_SHA256,
                "horizon_2",
                1.0,
            ),
            (
                self.shuffled_h96,
                SHUFFLED_H96_SHA256,
                SHUFFLED_H96_CANDIDATE_SHA256,
                "horizon_1",
                0.0,
            ),
            (
                self.shuffled_h65,
                SHUFFLED_H65_SHA256,
                SHUFFLED_H65_CANDIDATE_SHA256,
                "horizon_2",
                1.0,
            ),
        )
        for reader, reader_sha, candidate_sha, arm, scale in expected:
            with self.subTest(arm=arm, reader_sha=reader_sha):
                payload = serialize_orientation_reader(reader)
                self.assertEqual(hashlib.sha256(payload).hexdigest(), reader_sha)
                self.assertEqual(reader.candidate_sha256, candidate_sha)
                self.assertEqual(reader.arm, arm)
                self.assertEqual(reader.ridge_lambda, 0.001)
                self.assertEqual(reader.temperature, 0.5)
                self.assertEqual(reader.logit_scale, scale)
                self.assertEqual(
                    serialize_orientation_reader(
                        deserialize_orientation_reader(payload)
                    ),
                    payload,
                )

    def test_equal_logit_ensemble_formula_and_swap_complement_are_exact(self) -> None:
        output = replication._ensemble_outputs(
            self.primary_h96, self.primary_h65, self.features
        )
        expected_logits = (
            np.float32(0.5) * output.h96_logits + np.float32(0.5) * output.h65_logits
        ).astype(np.float32)
        expected_probabilities = 0.5 + 0.5 * np.tanh(
            0.5 * expected_logits.astype(np.float64)
        )
        np.testing.assert_array_equal(output.ensemble_logits, expected_logits)
        np.testing.assert_array_equal(output.probabilities, expected_probabilities)

        swapped = replication._ensemble_outputs(
            self.primary_h96, self.primary_h65, -self.features
        )
        np.testing.assert_array_equal(swapped.ensemble_logits, -output.ensemble_logits)
        np.testing.assert_array_equal(
            swapped.probabilities + output.probabilities,
            np.ones(KEY_BITS, dtype=np.float64),
        )

        matched = replication._ensemble_outputs(
            self.shuffled_h96, self.shuffled_h65, self.features
        )
        np.testing.assert_array_equal(
            matched.h96_logits, np.zeros(KEY_BITS, dtype=np.float32)
        )
        np.testing.assert_array_equal(
            matched.ensemble_logits,
            (np.float32(0.5) * matched.h65_logits).astype(np.float32),
        )

    def test_three_state_decision_obeys_all_32_target_boundaries(self) -> None:
        decide = replication._replication_decision
        threshold = replication.DECISION_THRESHOLD

        directional = decide(
            primary_compressions=(0.2,) * 18 + (-0.1,) * 14,
            h96_compressions=(0.01,) * 32,
            shuffled_compressions=(-0.2,) * 32,
            conditional_null_z=threshold - 1e-9,
            paired_conditional_null_z=threshold + 1.0,
        )
        self.assertEqual(directional["classification"], "DIRECTIONAL_REPLICATION")

        strong = decide(
            primary_compressions=(0.2,) * 22 + (-0.01,) * 10,
            h96_compressions=(0.01,) * 32,
            shuffled_compressions=(-0.2,) * 32,
            conditional_null_z=threshold,
            paired_conditional_null_z=threshold,
        )
        self.assertEqual(strong["classification"], "STRONG_REPLICATION")

        cases = (
            ((0.2,) * 17 + (-0.1,) * 15, (0.01,) * 32, (-0.2,) * 32),
            ((0.2,) * 22 + (-0.01,) * 10, (-0.01,) * 32, (-0.2,) * 32),
            ((0.1,) * 32, (0.01,) * 32, (0.2,) * 32),
        )
        for primary, h96, shuffled in cases:
            with self.subTest(primary=primary[:2], h96=h96[0], shuffled=shuffled[0]):
                decision = decide(
                    primary_compressions=primary,
                    h96_compressions=h96,
                    shuffled_compressions=shuffled,
                    conditional_null_z=99.0,
                    paired_conditional_null_z=99.0,
                )
                self.assertEqual(decision["classification"], "NOT_REPLICATED")
                if h96[0] < 0.0:
                    self.assertFalse(
                        decision["directional_gates"][
                            "h96_baseline_mean_compression_positive"
                        ]
                    )


class Full256PolyphaseReplicationOrchestrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.workspace_root = Path(self.temporary.name)
        self.run_index = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _fake_native_build(**_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(
            describe=lambda: {
                "schema": "synthetic-native-build-v1",
                "executable_name": "cadical_pair_sensor",
                "executable_sha256": "6" * 64,
            }
        )

    @staticmethod
    def _snapshot(**kwargs: object) -> SimpleNamespace:
        target_id = str(kwargs["target_id"])
        public = kwargs["public"]
        state_plan = kwargs["state_plan"]
        assert isinstance(public, PublicTargetView)
        public.validate()
        public_digest = public.digest()
        feature_raw = hashlib.shake_256(
            b"o1c0015-test-features\0" + bytes.fromhex(public_digest)
        ).digest(KEY_BITS * READER_FEATURES)
        features = np.frombuffer(feature_raw, dtype=np.uint8).astype(np.float32)
        features = ((features - np.float32(127.5)) / np.float32(128.0)).reshape(
            KEY_BITS, READER_FEATURES
        )
        features = np.ascontiguousarray(features, dtype=np.float32)
        state = hashlib.shake_256(
            b"o1c0015-test-state\0"
            + target_id.encode("ascii")
            + bytes.fromhex(public_digest)
        ).digest(state_plan.serialized_state_bytes)
        identity = hashlib.sha256(target_id.encode("ascii")).hexdigest()
        return SimpleNamespace(
            target_id=target_id,
            public=public,
            state_bytes=state,
            state_sha256=hashlib.sha256(state).hexdigest(),
            reader_features=features,
            reader_features_sha256=hashlib.sha256(
                features.astype("<f4", copy=False).tobytes(order="C")
            ).hexdigest(),
            instance={"instance_sha256": identity},
            probe={
                "result_sha256": identity,
                "event_index_sha256": hashlib.sha256(
                    (target_id + "-events").encode("ascii")
                ).hexdigest(),
            },
            resources={
                "native_cpu_seconds": 0.01,
                "native_peak_rss_bytes": 1_024,
                "conservative_process_group_peak_rss_bytes": 4_096,
            },
        )

    @staticmethod
    def _uniform_ensemble(*_args: object, **_kwargs: object):
        zeros = np.zeros(KEY_BITS, dtype=np.float32)
        return replication._EnsembleOutput(
            h96_scores=zeros.copy(),
            h65_scores=zeros.copy(),
            h96_logits=zeros.copy(),
            h65_logits=zeros.copy(),
            ensemble_logits=zeros.copy(),
            h96_probabilities=np.full(KEY_BITS, 0.5, dtype=np.float64),
            h65_probabilities=np.full(KEY_BITS, 0.5, dtype=np.float64),
            probabilities=np.full(KEY_BITS, 0.5, dtype=np.float64),
        )

    @staticmethod
    def _entropy_payload(index: int) -> bytes:
        return hashlib.shake_256(
            b"o1c0015-test-sealed-target\0" + index.to_bytes(4, "little")
        ).digest(ENTROPY_BYTES)

    def _run(
        self,
        *,
        maximum_cpu_seconds: float | None = None,
        maximum_persistent_artifact_bytes: int | None = None,
        attempt_id: str = "O1C-0015",
    ):
        config_path = CONFIG_V2 if attempt_id == "O1C-0016" else CONFIG
        _raw, config = load_full256_polyphase_replication_config(config_path)
        config = replace(config, reader=replace(config.reader, decoy_count=7))
        if maximum_cpu_seconds is not None:
            config = replace(
                config,
                budgets=replace(
                    config.budgets,
                    maximum_cpu_seconds=maximum_cpu_seconds,
                ),
            )
        if maximum_persistent_artifact_bytes is not None:
            config = replace(
                config,
                budgets=replace(
                    config.budgets,
                    maximum_persistent_artifact_bytes=(
                        maximum_persistent_artifact_bytes
                    ),
                ),
            )
        self.run_index += 1
        workspace = self.workspace_root / f"workspace-{self.run_index}"
        events: list[str] = []
        entropy_payloads: list[bytes] = []
        prediction_artifacts: dict[str, bytes] = {}

        def entropy_source(size: int) -> bytes:
            self.assertEqual(size, ENTROPY_BYTES)
            index = len(entropy_payloads)
            payload = self._entropy_payload(index)
            entropy_payloads.append(payload)
            events.append(f"entropy-{index}")
            return payload

        def on_protocol_frozen(
            artifacts: dict[str, bytes], document: dict[str, object]
        ) -> None:
            events.append("protocol-freeze")
            self.assertEqual(len(entropy_payloads), 0)
            self.assertEqual(
                document["phase"],
                "FROZEN_PROTOCOL_VERIFIED_BEFORE_FRESH_TARGET_ENTROPY",
            )
            self.assertEqual(document["fresh_target_entropy_calls"], 0)
            self.assertEqual(document["attempt_id"], attempt_id)
            self.assertEqual(document["ensemble_logit_weights"], [0.5, 0.5])
            for name in (
                "source/o1c0013_h96_exact.bin",
                "reconstructed/primary_h65.bin",
                "reconstructed/shuffled_h96.bin",
                "reconstructed/shuffled_h65.bin",
            ):
                self.assertIn(name, artifacts)

        def on_predictions_frozen(
            artifacts: dict[str, bytes], document: dict[str, object]
        ) -> None:
            events.append("predictions-freeze")
            self.assertEqual(len(entropy_payloads), 32)
            self.assertNotIn("reveal", events)
            self.assertEqual(
                document["phase"], "ALL_PREDICTIONS_FROZEN_BEFORE_ANY_REVEAL"
            )
            self.assertEqual(document["pre_reveal_resources"]["sweep_attempts"], 35)
            self.assertEqual(
                document["pre_reveal_resources"]["native_solver_branches"], 17_920
            )
            self.assertEqual(
                document["pre_reveal_resource_gates"]["native_branches_under_budget"],
                True,
            )
            prediction_artifacts.update(artifacts)
            publication_names = sorted(
                name for name in artifacts if name.endswith("/publication.json")
            )
            self.assertEqual(len(publication_names), 32)
            for name in publication_names:
                publication = json.loads(artifacts[name])
                self.assertFalse(publication["public_view"]["target_key_included"])
                self.assertFalse(publication["public_view"]["target_trace_included"])
                prefix = name.removesuffix("publication.json")
                for suffix in (
                    "h96_logits.f32le",
                    "h65_logits.f32le",
                    "ensemble_logits.f32le",
                    "h96_probabilities.f64le",
                    "h65_probabilities.f64le",
                    "probabilities.f64le",
                    "shuffled_h96_logits.f32le",
                    "shuffled_h65_logits.f32le",
                    "shuffled_ensemble_logits.f32le",
                    "shuffled_h96_probabilities.f64le",
                    "shuffled_h65_probabilities.f64le",
                    "shuffled_probabilities.f64le",
                    "prediction_freeze.json",
                ):
                    self.assertIn(prefix + suffix, artifacts)
            for suffix in (
                "/h96_probabilities.f64le",
                "/h65_probabilities.f64le",
                "/probabilities.f64le",
                "/shuffled_h96_probabilities.f64le",
                "/shuffled_h65_probabilities.f64le",
                "/shuffled_probabilities.f64le",
            ):
                self.assertEqual(
                    sum(
                        name.startswith("controls/") and name.endswith(suffix)
                        for name in artifacts
                    ),
                    3,
                )
            for entropy in entropy_payloads:
                key = entropy[:32]
                salt = entropy[48:80]
                for payload in artifacts.values():
                    self.assertNotIn(b'"key_hex"', payload)
                    self.assertNotIn(b'"salt_hex"', payload)
                    self.assertNotIn(key, payload)
                    self.assertNotIn(salt, payload)
                    self.assertNotIn(key.hex().encode("ascii"), payload)
                    self.assertNotIn(salt.hex().encode("ascii"), payload)

        original_reveal = Full256TargetBroker.reveal

        def tracked_reveal(broker: Full256TargetBroker, receipt: object):
            events.append("reveal")
            return original_reveal(broker, receipt)

        self.last_events = events
        monotonic = itertools.count(10)
        usage = SimpleNamespace(ru_utime=0.0, ru_stime=0.0)
        with (
            patch.object(
                replication,
                "verify_full256_template",
                return_value={
                    "schema": "synthetic-template-verification-v1",
                    "ok": True,
                    "variable_count": config.source.foundation.expected_variable_count,
                    "clause_count": (
                        config.source.foundation.expected_template_clause_count
                    ),
                },
            ),
            patch.object(
                replication, "build_native_sensor", side_effect=self._fake_native_build
            ),
            patch.object(replication, "_probe_public", side_effect=self._snapshot),
            patch.object(
                replication, "_ensemble_outputs", side_effect=self._uniform_ensemble
            ),
            patch.object(
                replication.time,
                "monotonic",
                side_effect=lambda: float(next(monotonic)),
            ),
            patch.object(
                replication.time,
                "process_time",
                side_effect=(2.0, 2.25, 2.5, 3.0),
            ),
            patch.object(replication.resource, "getrusage", return_value=usage),
            patch.object(replication, "_peak_rss_bytes", return_value=4_096),
            patch.object(Full256TargetBroker, "reveal", new=tracked_reveal),
        ):
            result = run_full256_polyphase_replication(
                config,
                lab_root=ROOT,
                working_directory=workspace,
                on_protocol_frozen=on_protocol_frozen,
                on_predictions_frozen=on_predictions_frozen,
                sealed_entropy_source=entropy_source,
                sealed_entropy_source_id="test.deterministic-v1",
                attempt_id=attempt_id,
            )
        return result, events, entropy_payloads, prediction_artifacts

    def test_attempt_identity_propagates_into_protocol_and_target_ids(self) -> None:
        result, _events, _entropy, _artifacts = self._run(attempt_id="O1C-0016")

        self.assertEqual(result.report["protocol_freeze"]["attempt_id"], "O1C-0016")
        self.assertTrue(
            all(
                row["target_id"].startswith("o1c0016-replication-")
                for row in result.report["sealed_evaluation"]["per_target"]
            )
        )

    def test_runtime_attempt_cannot_differ_from_loaded_config(self) -> None:
        _raw, config = _canonical_config()

        with self.assertRaisesRegex(
            Full256PolyphaseReplicationError,
            "runtime attempt identity differs from loaded config",
        ):
            run_full256_polyphase_replication(
                config,
                lab_root=ROOT,
                working_directory=self.workspace_root / "identity-mismatch-work",
                on_protocol_frozen=lambda *_args: None,
                on_predictions_frozen=lambda *_args: None,
                attempt_id="O1C-0016",
            )

    def test_resource_failure_after_prediction_persistence_never_reveals(self) -> None:
        with self.assertRaisesRegex(
            Full256PolyphaseReplicationError,
            "pre-reveal polyphase resource budget exceeded",
        ):
            self._run(maximum_cpu_seconds=0.1)

        self.assertIn("predictions-freeze", self.last_events)
        self.assertNotIn("reveal", self.last_events)

    def test_post_reveal_budget_failure_returns_complete_truth_artifacts(self) -> None:
        result, events, _entropy, _artifacts = self._run(
            maximum_persistent_artifact_bytes=1
        )

        self.assertEqual(events.count("reveal"), 32)
        self.assertFalse(result.success_gate_passed)
        self.assertFalse(result.report["gates"]["persistent_artifacts_under_budget"])
        self.assertIn("sealed_reveals.json", result.final_artifacts)
        self.assertIn("sealed_evaluation.json", result.final_artifacts)

    def test_exact_frozen_lifecycle_counts_and_output_only_boundary(self) -> None:
        result, events, entropy_payloads, artifacts = self._run()
        resources = result.report["resources"]
        gates = result.report["gates"]
        attacker = result.report["attacker_contract"]

        self.assertLess(events.index("protocol-freeze"), events.index("entropy-0"))
        self.assertLess(events.index("predictions-freeze"), events.index("reveal"))
        self.assertEqual(len(entropy_payloads), 32)
        self.assertEqual(events.count("reveal"), 32)
        self.assertEqual(resources["fresh_target_entropy_calls"], 32)
        self.assertEqual(resources["fresh_random_targets"], 32)
        self.assertEqual(resources["sweep_attempts"], 35)
        self.assertEqual(resources["native_solver_branches"], 17_920)
        self.assertEqual(resources["target_controls_executed"], 3)
        self.assertEqual(resources["reader_refits"], 0)
        self.assertEqual(resources["reader_hyperparameter_changes"], 0)
        self.assertEqual(resources["source_build_cal_reader_reconstructions"], 3)
        self.assertEqual(len(result.report["sealed_evaluation"]["per_target"]), 32)
        self.assertEqual(len(result.report["sealed_evaluation"]["target_controls"]), 3)
        self.assertEqual(
            result.report["sealed_evaluation"][
                "uniform_random_baseline_total_nll_bits"
            ],
            8_192.0,
        )
        self.assertEqual(attacker["unknown_target_key_bits"], 256)
        self.assertEqual(attacker["target_internal_trace_inputs"], 0)
        self.assertEqual(attacker["key_unit_clauses"], 0)
        self.assertEqual(attacker["paired_assumption_branches_per_sweep"], 512)
        self.assertTrue(gates["protocol_frozen_before_fresh_target_entropy"])
        self.assertTrue(gates["all_predictions_frozen_before_any_reveal"])
        self.assertTrue(gates["sealed_assumption_swap_complements"])
        self.assertTrue(gates["source_capsules_unchanged"])
        self.assertTrue(result.success_gate_passed)
        self.assertTrue(artifacts)

    def test_scientifically_negative_result_is_a_valid_lifecycle_outcome(self) -> None:
        result, _events, _entropy, _artifacts = self._run()
        sealed = result.report["sealed_evaluation"]

        self.assertEqual(sealed["decision"]["classification"], "NOT_REPLICATED")
        self.assertEqual(
            sealed["conditional_uniform_key_null"]["independent_secret_bits"], 8_192
        )
        self.assertEqual(
            sealed["primary_minus_shuffled_conditional_null"][
                "independent_secret_bits"
            ],
            8_192,
        )
        self.assertTrue(result.success_gate_passed)
        self.assertFalse(result.report["claim_boundary"]["replication_claimed"])
        self.assertFalse(
            result.report["claim_boundary"]["polyphase_architecture_promoted"]
        )
        self.assertEqual(
            sealed["architecture_promotion"]["classification"], "DO_NOT_PROMOTE"
        )
        self.assertFalse(sealed["architecture_promotion"]["passed"])
        self.assertEqual(sealed["exact_keys"], 0)

    def test_artifacts_are_fixed_point_and_accounted_exactly(self) -> None:
        first, _events, _entropy, _artifacts = self._run()
        second, _events, _entropy, _artifacts = self._run()

        self.assertEqual(first.report, second.report)
        self.assertEqual(first.reader_freeze_artifacts, second.reader_freeze_artifacts)
        self.assertEqual(
            first.prediction_freeze_artifacts,
            second.prediction_freeze_artifacts,
        )
        self.assertEqual(first.final_artifacts, second.final_artifacts)
        actual = sum(
            len(payload)
            for group in (
                first.reader_freeze_artifacts,
                first.prediction_freeze_artifacts,
                first.final_artifacts,
            )
            for payload in group.values()
        )
        self.assertEqual(first.report["resources"]["persistent_artifact_bytes"], actual)
        self.assertTrue(first.report["gates"]["persistent_artifacts_under_budget"])

    def test_mismatched_h96_source_hash_is_rejected_before_entropy_or_build(
        self,
    ) -> None:
        _raw, config = _canonical_config()
        config = replace(
            config,
            source=replace(config.source, primary_reader_sha256="0" * 64),
        )

        with (
            patch.object(
                replication,
                "build_native_sensor",
                side_effect=AssertionError("native build reached after hash mismatch"),
            ),
            patch.object(
                replication,
                "_probe_public",
                side_effect=AssertionError("probe reached after hash mismatch"),
            ),
            self.assertRaisesRegex(
                Full256PolyphaseReplicationError,
                "source hash differs|source.*hash differs|immutable.*hash differs",
            ),
        ):
            run_full256_polyphase_replication(
                config,
                lab_root=ROOT,
                working_directory=self.workspace_root / "hash-mismatch-work",
                on_protocol_frozen=lambda *_args: None,
                on_predictions_frozen=lambda *_args: None,
                sealed_entropy_source=lambda _size: (_ for _ in ()).throw(
                    AssertionError("entropy reached after hash mismatch")
                ),
                sealed_entropy_source_id="test.must-not-run-v1",
            )


if __name__ == "__main__":
    unittest.main()
