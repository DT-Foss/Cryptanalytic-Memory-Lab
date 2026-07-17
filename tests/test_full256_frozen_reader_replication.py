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

import o1_crypto_lab.full256_frozen_reader_replication as replication
from o1_crypto_lab.causal_orientation_reader import (
    deserialize_orientation_reader,
    serialize_orientation_reader,
)
from o1_crypto_lab.full256_broker import ENTROPY_BYTES, Full256TargetBroker
from o1_crypto_lab.full256_frozen_reader_replication import (
    Full256FrozenReaderReplicationError,
    load_full256_frozen_reader_replication_config,
    run_full256_frozen_reader_replication,
)
from o1_crypto_lab.full256_probe_core import READER_FEATURES
from o1_crypto_lab.living_inverse import KEY_BITS, PublicTargetView


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/full256_frozen_reader_replication_v1.json"

MANIFEST_SHA256 = "a0d4df5c01f7de3c65a429f9589e46d784f802bc1f8e0aa90dffb011be46922c"
RESULT_FILE_SHA256 = "38674b9c49e2463471a35fddb8d0b7d2218567cab7251e8a275e74ccace156a5"
RESULT_COMMITMENT = "a70610d3d589e97048c6045747c0821e5669c5dc89e420df79b0fca43476d4cd"
EVALUATION_FILE_SHA256 = (
    "869020e3393b60dfb1c312bb6943b15e9601eb67c6f59344161d9a5c4b95be22"
)
EVALUATION_COMMITMENT = (
    "11d3cdfffb6cb078f7d8a54e56ff827d3c9a4237df32632274c2176e7e5efa38"
)
READER_FREEZE_FILE_SHA256 = (
    "f8c99cbb376a2d9adc04ac3cc6dcda85b91ea49765808c4ce33b0e62f236bbbf"
)
READER_FREEZE_COMMITMENT = (
    "2d96c4582076818d1d101a10527535de8ed5be1f2e928658a14427043645a5e5"
)
PRIMARY_READER_SHA256 = (
    "796e79ec932b990a59ecbc34216c4878b9279bae3bb136fe0832e580bcb2e9f8"
)
SHUFFLED_READER_SHA256 = (
    "87bd132c44be5c788444088465780f227315dddde84ac42f5474092c664e19d0"
)


def _canonical_config():
    return load_full256_frozen_reader_replication_config(CONFIG)


def _source_path(raw: dict[str, object], suffix: str) -> Path:
    matches: list[Path] = []

    def visit(node: object) -> None:
        if not isinstance(node, dict):
            return
        capsule = node.get("capsule")
        if isinstance(capsule, str):
            for value in node.values():
                if isinstance(value, str) and value.endswith(suffix):
                    candidate = ROOT / capsule / value
                    if candidate.is_file():
                        matches.append(candidate)
        for value in node.values():
            visit(value)

    visit(raw["source"])
    if len(matches) != 1:
        raise AssertionError(
            f"expected one resolvable source member ending in {suffix!r}"
        )
    return matches[0]


class Full256FrozenReaderReplicationConfigTests(unittest.TestCase):
    def test_canonical_config_is_an_eight_key_fixed_reader_protocol(self) -> None:
        raw, config = _canonical_config()

        self.assertEqual(raw["attempt_id"], "O1C-0014")
        self.assertEqual(config.corpus.sealed_targets, 8)
        self.assertEqual(set(raw["reader"]), {"decoy_count", "decoy_seed"})
        self.assertEqual(config.reader.decoy_count, 1_000_000)
        self.assertEqual(config.budgets.maximum_fresh_random_targets, 8)
        self.assertEqual(config.budgets.maximum_native_solver_branches, 5_632)
        self.assertEqual(config.maximum_live_target_state_bytes, 58_368)
        self.assertEqual(
            tuple(config.controls.transforms),
            ("output_bit_flip", "wrong_nonce", "output_byte_rotate"),
        )

    def test_canonical_config_pins_every_o1c0013_commitment(self) -> None:
        raw, _config = _canonical_config()
        flattened = json.dumps(raw["source"], sort_keys=True)
        for commitment in (
            MANIFEST_SHA256,
            RESULT_FILE_SHA256,
            RESULT_COMMITMENT,
            EVALUATION_FILE_SHA256,
            EVALUATION_COMMITMENT,
            READER_FREEZE_FILE_SHA256,
            READER_FREEZE_COMMITMENT,
            PRIMARY_READER_SHA256,
            SHUFFLED_READER_SHA256,
        ):
            self.assertIn(commitment, flattened)

    def test_config_rejects_unknown_and_reader_selection_fields(self) -> None:
        raw, _config = _canonical_config()
        variants = []
        top_level = dict(raw)
        top_level["unreviewed_extension"] = True
        variants.append(top_level)
        for field, value in (
            ("arms", ["horizon_1"]),
            ("ridge_lambdas", [0.001]),
            ("temperatures", [0.5]),
            ("logit_scales", [1.0]),
        ):
            candidate = json.loads(json.dumps(raw))
            candidate["reader"][field] = value
            variants.append(candidate)

        with tempfile.TemporaryDirectory() as temporary:
            for index, value in enumerate(variants):
                path = Path(temporary) / f"config-{index}.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                with (
                    self.subTest(index=index),
                    self.assertRaises(Full256FrozenReaderReplicationError),
                ):
                    load_full256_frozen_reader_replication_config(path)

    def test_runtime_module_exposes_no_fitting_or_selection_surface(self) -> None:
        forbidden = {
            "fit_causal_orientation_reader",
            "select_causal_orientation_reader",
            "MultiKeyReaderConfig",
            "_fit_reader",
            "_select_reader",
        }
        self.assertFalse(forbidden & set(vars(replication)))
        source = inspect.getsource(replication)
        self.assertNotIn("fit_causal_orientation_reader(", source)


class Full256FrozenReaderReplicationPrimitiveTests(unittest.TestCase):
    def test_both_pinned_readers_roundtrip_byte_identically(self) -> None:
        raw, _config = _canonical_config()
        for suffix, expected_hash in (
            ("frozen_reader.bin", PRIMARY_READER_SHA256),
            ("shuffled_key_reader.bin", SHUFFLED_READER_SHA256),
        ):
            payload = _source_path(raw, suffix).read_bytes()
            self.assertEqual(hashlib.sha256(payload).hexdigest(), expected_hash)
            reader = deserialize_orientation_reader(payload)
            self.assertEqual(serialize_orientation_reader(reader), payload)

    def test_three_state_decision_obeys_every_preregistered_boundary(self) -> None:
        decide = replication._replication_decision
        threshold = 1.6448536269514722

        directional = decide(
            primary_compressions=(0.2, 0.2, 0.2, 0.2, 0.2, -0.1, -0.1, -0.1),
            shuffled_compressions=(-0.2,) * 8,
            conditional_null_z=threshold - 1e-9,
            paired_conditional_null_z=threshold + 1.0,
        )
        self.assertEqual(directional["classification"], "DIRECTIONAL_REPLICATION")

        strong = decide(
            primary_compressions=(0.2,) * 7 + (-0.01,),
            shuffled_compressions=(-0.2,) * 8,
            conditional_null_z=threshold,
            paired_conditional_null_z=threshold,
        )
        self.assertEqual(strong["classification"], "STRONG_REPLICATION")

        cases = (
            ((-0.1,) * 8, (-0.2,) * 8),
            ((0.1,) * 4 + (-0.1,) * 4, (-0.2,) * 8),
            ((0.1,) * 8, (0.2,) * 8),
        )
        for primary, shuffled in cases:
            with self.subTest(primary=primary, shuffled=shuffled):
                decision = decide(
                    primary_compressions=primary,
                    shuffled_compressions=shuffled,
                    conditional_null_z=99.0,
                    paired_conditional_null_z=99.0,
                )
                self.assertEqual(decision["classification"], "NOT_REPLICATED")


class Full256FrozenReaderReplicationOrchestrationTests(unittest.TestCase):
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
            b"o1c0014-test-features\0" + bytes.fromhex(public_digest)
        ).digest(KEY_BITS * READER_FEATURES)
        features = np.frombuffer(feature_raw, dtype=np.uint8).astype(np.float32)
        features = ((features - np.float32(127.5)) / np.float32(128.0)).reshape(
            KEY_BITS, READER_FEATURES
        )
        features = np.ascontiguousarray(features, dtype=np.float32)
        state = hashlib.shake_256(
            b"o1c0014-test-state\0"
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
    def _entropy_payload(index: int) -> bytes:
        return hashlib.shake_256(
            b"o1c0014-test-sealed-target\0" + index.to_bytes(4, "little")
        ).digest(ENTROPY_BYTES)

    def _run(self):
        _raw, config = _canonical_config()
        # The stream-rank implementation is covered elsewhere.  Keep this
        # lifecycle suite fast while preserving every O1C-0014 sweep and gate.
        config = replace(config, reader=replace(config.reader, decoy_count=7))
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
            self.assertTrue(
                any(name.endswith("frozen_reader.bin") for name in artifacts)
            )
            self.assertTrue(
                any(name.endswith("shuffled_key_reader.bin") for name in artifacts)
            )

        def on_predictions_frozen(
            artifacts: dict[str, bytes], document: dict[str, object]
        ) -> None:
            events.append("predictions-freeze")
            self.assertEqual(len(entropy_payloads), 8)
            self.assertNotIn("reveal", events)
            self.assertEqual(
                document["phase"], "ALL_PREDICTIONS_FROZEN_BEFORE_ANY_REVEAL"
            )
            prediction_artifacts.update(artifacts)
            publication_names = sorted(
                name for name in artifacts if name.endswith("/publication.json")
            )
            self.assertEqual(len(publication_names), 8)
            for name in publication_names:
                publication = json.loads(artifacts[name])
                self.assertFalse(publication["public_view"]["target_key_included"])
                self.assertFalse(publication["public_view"]["target_trace_included"])
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

        monotonic = itertools.count(10)
        usage = SimpleNamespace(ru_utime=0.0, ru_stime=0.0)
        with (
            patch.object(
                replication,
                "verify_full256_template",
                return_value={
                    "schema": "synthetic-template-verification-v1",
                    "ok": True,
                    "variable_count": (
                        config.source.foundation.expected_variable_count
                    ),
                    "clause_count": (
                        config.source.foundation.expected_template_clause_count
                    ),
                },
            ),
            patch.object(
                replication,
                "build_native_sensor",
                side_effect=self._fake_native_build,
            ),
            patch.object(replication, "_probe_public", side_effect=self._snapshot),
            patch.object(
                replication.time,
                "monotonic",
                side_effect=lambda: float(next(monotonic)),
            ),
            patch.object(replication.time, "process_time", side_effect=(2.0, 3.0)),
            patch.object(replication.resource, "getrusage", return_value=usage),
            patch.object(replication, "_peak_rss_bytes", return_value=4_096),
            patch.object(Full256TargetBroker, "reveal", new=tracked_reveal),
        ):
            result = run_full256_frozen_reader_replication(
                config,
                lab_root=ROOT,
                working_directory=workspace,
                on_protocol_frozen=on_protocol_frozen,
                on_predictions_frozen=on_predictions_frozen,
                sealed_entropy_source=entropy_source,
                sealed_entropy_source_id="test.deterministic-v1",
            )
        return result, events, entropy_payloads, prediction_artifacts

    def test_exact_frozen_lifecycle_counts_and_output_only_boundary(self) -> None:
        result, events, entropy_payloads, artifacts = self._run()
        resources = result.report["resources"]
        gates = result.report["gates"]

        self.assertLess(events.index("protocol-freeze"), events.index("entropy-0"))
        self.assertLess(events.index("predictions-freeze"), events.index("reveal"))
        self.assertEqual(len(entropy_payloads), 8)
        self.assertEqual(events.count("reveal"), 8)
        self.assertEqual(resources["fresh_target_entropy_calls"], 8)
        self.assertEqual(resources["fresh_random_targets"], 8)
        self.assertEqual(resources["sweep_attempts"], 11)
        self.assertEqual(resources["native_solver_branches"], 5_632)
        self.assertEqual(resources["target_controls_executed"], 3)
        self.assertEqual(resources["reader_refits"], 0)
        self.assertEqual(resources["reader_hyperparameter_changes"], 0)
        self.assertEqual(len(result.report["sealed_evaluation"]["per_target"]), 8)
        self.assertEqual(len(result.report["sealed_evaluation"]["target_controls"]), 3)
        self.assertTrue(gates["protocol_frozen_before_fresh_target_entropy"])
        self.assertTrue(gates["all_predictions_frozen_before_any_reveal"])
        self.assertTrue(gates["source_capsules_unchanged"])
        self.assertTrue(result.success_gate_passed)
        self.assertTrue(artifacts)

    def test_negative_replication_is_a_successful_lifecycle_outcome(self) -> None:
        result, _events, _entropy, _artifacts = self._run()
        decision = result.report["sealed_evaluation"]["decision"]

        self.assertEqual(decision["classification"], "NOT_REPLICATED")
        self.assertTrue(result.success_gate_passed)
        self.assertFalse(result.report["claim_boundary"]["replication_claimed"])

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

    def test_escaping_reader_member_is_rejected_before_entropy_or_probe(self) -> None:
        _raw, config = _canonical_config()
        source_fields = set(config.source.__dataclass_fields__)
        primary_path_field = next(
            name for name in source_fields if "primary" in name and "sha256" not in name
        )
        escaped_source = replace(
            config.source, **{primary_path_field: "../../README.md"}
        )
        escaped_config = replace(config, source=escaped_source)

        with (
            patch.object(
                replication,
                "build_native_sensor",
                side_effect=AssertionError("native build reached before containment"),
            ),
            patch.object(
                replication,
                "_probe_public",
                side_effect=AssertionError("probe reached before containment"),
            ),
            self.assertRaisesRegex(
                Full256FrozenReaderReplicationError,
                "escapes.*capsule|outside.*capsule|capsule.*outside",
            ),
        ):
            run_full256_frozen_reader_replication(
                escaped_config,
                lab_root=ROOT,
                working_directory=self.workspace_root / "containment-work",
                on_protocol_frozen=lambda *_args: None,
                on_predictions_frozen=lambda *_args: None,
                sealed_entropy_source=lambda _size: (_ for _ in ()).throw(
                    AssertionError("entropy reached before containment")
                ),
                sealed_entropy_source_id="test.must-not-run-v1",
            )

    def test_mismatched_reader_hash_is_rejected_before_entropy_or_build(self) -> None:
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
            self.assertRaisesRegex(
                Full256FrozenReaderReplicationError,
                "source hash differs|reader.*hash differs",
            ),
        ):
            run_full256_frozen_reader_replication(
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
