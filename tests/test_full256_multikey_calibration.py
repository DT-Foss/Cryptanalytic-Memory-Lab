from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np

import o1_crypto_lab.full256_multikey_calibration as calibration
from o1_crypto_lab.causal_bitfield import CausalBitfieldPlan
from o1_crypto_lab.full256_broker import ENTROPY_BYTES, Full256TargetBroker
from o1_crypto_lab.full256_multikey_calibration import (
    CONFIG_SCHEMA,
    Full256MultiKeyCalibrationConfig,
    Full256MultiKeyCalibrationError,
    MultiKeyControlConfig,
    MultiKeyCorpusConfig,
    MultiKeyFoundationSource,
    MultiKeyProbeConfig,
    MultiKeyReaderConfig,
    _known_target,
    _stream_decoy_rank,
    load_full256_multikey_calibration_config,
    run_full256_multikey_calibration,
)
from o1_crypto_lab.full256_paired_sensor import (
    NativeDependencyConfig,
    SensorBudgetConfig,
)
from o1_crypto_lab.full256_probe_core import READER_FEATURES, Full256ProbeCoreError
from o1_crypto_lab.living_inverse import KEY_BITS, PublicTargetView


def _config_document() -> dict[str, object]:
    plan = CausalBitfieldPlan()
    maximum_live = (
        plan.serialized_state_bytes + KEY_BITS * READER_FEATURES * 4 + KEY_BITS * 4
    )
    return {
        "schema": CONFIG_SCHEMA,
        "attempt_id": "O1C-0013",
        "slug": "full256-multikey-causal-calibration-v1",
        "claim_level": "TEST",
        "hypothesis": "synthetic orchestration contract",
        "prediction": "all lifecycle gates pass",
        "controls": ["sealed lifecycle", "output-only target"],
        "budgets": {
            "maximum_cpu_seconds": 100.0,
            "maximum_wall_seconds": 100.0,
            "maximum_resident_memory_mib": 128.0,
            "maximum_persistent_artifact_bytes": 10_000_000,
            # 2 BUILD + 2 CAL + 1 sealed + 1 declared control.
            "maximum_native_solver_branches": 6 * 512,
            "maximum_mps_calls": 0,
            "maximum_gpu_calls": 0,
            "maximum_sibling_reads": 0,
            "maximum_sibling_writes": 0,
            "maximum_fresh_random_targets": 1,
        },
        "next_action": "freeze and reveal",
        "source": {
            "capsule": "runs/foundation",
            "manifest_sha256": "1" * 64,
            "template": "artifacts/cnf/template.cnf",
            "template_sha256": "2" * 64,
            "semantic_map": "artifacts/cnf/template.map.json",
            "semantic_map_sha256": "3" * 64,
            "expected_variable_count": 32_128,
            "expected_template_clause_count": 187_370,
            "expected_public_clause_count": 188_010,
        },
        "native": {
            "compiler": "c++",
            "include_directory": "/synthetic/include",
            "static_library": "/synthetic/libcadical.a",
            "cadical_header_sha256": "4" * 64,
            "cadical_library_sha256": "5" * 64,
        },
        "probe": {
            "seed": 0,
            "timeout_seconds": 10.0,
            "sentinel_bit": 173,
            "sentinel_reruns_per_sweep": 0,
        },
        "state_plan": {
            "horizons": list(plan.horizons),
            "horizon_weights": list(plan.horizon_weights),
            "unary_clip": plan.unary_clip,
            "interaction_clip": plan.interaction_clip,
            "holographic_clip": plan.holographic_clip,
            "readout_temperature": plan.readout_temperature,
            "phase_seed": plan.phase_seed,
        },
        "corpus": {
            "seed": 13_0013,
            "build_targets": 2,
            "calibration_targets": 2,
            "sealed_targets": 1,
        },
        "reader": {
            "arms": ["horizon_0"],
            "ridge_lambdas": [1.0],
            "temperatures": [1.0],
            "shrinkages": [0.0],
            "decoy_count": 7,
            "decoy_seed": 0xC0FFEE,
        },
        "target_controls": {
            "transforms": ["output_bit_flip"],
            "run_only_if_calibration_compression_positive": True,
        },
        "maximum_state_bytes": 18_000,
        "maximum_live_target_state_bytes": maximum_live,
    }


def _write_config(directory: Path, value: dict[str, object]) -> Path:
    path = directory / "config.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


class Full256MultiKeyConfigTests(unittest.TestCase):
    def test_strict_config_binds_branch_and_live_state_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw, config = load_full256_multikey_calibration_config(
                _write_config(Path(temporary), _config_document())
            )

        self.assertEqual(raw["schema"], CONFIG_SCHEMA)
        self.assertEqual(config.corpus.build_targets, 2)
        self.assertEqual(config.corpus.calibration_targets, 2)
        self.assertEqual(config.corpus.sealed_targets, 1)
        self.assertEqual(config.state_plan.serialized_state_bytes, 17_408)
        self.assertEqual(config.maximum_live_target_state_bytes, 58_368)
        self.assertEqual(config.budgets.maximum_native_solver_branches, 3_072)

    def test_unknown_field_is_rejected(self) -> None:
        document = _config_document()
        document["unreviewed_extension"] = True
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                Full256MultiKeyCalibrationError, "config fields differ"
            ):
                load_full256_multikey_calibration_config(
                    _write_config(Path(temporary), document)
                )

    def test_declared_branch_budget_must_cover_all_possible_sweeps(self) -> None:
        document = _config_document()
        budgets = dict(document["budgets"])
        budgets["maximum_native_solver_branches"] = 3_071
        document["budgets"] = budgets
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                Full256MultiKeyCalibrationError, "branch count exceeds budget"
            ):
                load_full256_multikey_calibration_config(
                    _write_config(Path(temporary), document)
                )

    def test_live_state_must_include_feature_bank_and_logits(self) -> None:
        document = _config_document()
        document["maximum_live_target_state_bytes"] = 18_432
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                Full256MultiKeyCalibrationError, "reader feature bank"
            ):
                load_full256_multikey_calibration_config(
                    _write_config(Path(temporary), document)
                )

    def test_unhashable_control_entry_is_rejected_as_protocol_error(self) -> None:
        document = _config_document()
        controls = dict(document["target_controls"])
        controls["transforms"] = [{}]
        document["target_controls"] = controls
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                Full256MultiKeyCalibrationError,
                "target control transforms differ",
            ):
                load_full256_multikey_calibration_config(
                    _write_config(Path(temporary), document)
                )


class Full256MultiKeyPrimitiveTests(unittest.TestCase):
    def test_known_build_and_calibration_targets_are_deterministic_and_disjoint(
        self,
    ) -> None:
        build = [
            _known_target(seed=71, split="BUILD", index=index) for index in range(4)
        ]
        calibration_targets = [
            _known_target(seed=71, split="CALIBRATION", index=index)
            for index in range(3)
        ]
        replay = _known_target(seed=71, split="BUILD", index=2)

        self.assertEqual(replay, build[2])
        self.assertEqual(len({target.key for target in build}), len(build))
        self.assertEqual(len({target.public.digest() for target in build}), len(build))
        self.assertFalse(
            {target.key for target in build}
            & {target.key for target in calibration_targets}
        )
        self.assertFalse(
            {target.public.digest() for target in build}
            & {target.public.digest() for target in calibration_targets}
        )

    def test_uniform_decoys_report_the_full_tie_interval_conservatively(self) -> None:
        result = _stream_decoy_rank(
            np.full(KEY_BITS, 0.5, dtype=np.float64),
            np.zeros(KEY_BITS, dtype=np.uint8),
            decoy_count=7,
            seed=123,
        )

        self.assertEqual(result["strictly_better_decoys"], 0)
        self.assertEqual(result["equal_score_decoys"], 7)
        self.assertEqual(result["rank_lower_one_based"], 1)
        self.assertEqual(result["rank_upper_one_based"], 8)
        self.assertEqual(result["rank_midpoint_one_based"], 4.5)
        self.assertEqual(result["rank_one_based"], 8)


class Full256MultiKeyOrchestrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.runs = self.root / "runs"
        self.capsule = self.runs / "foundation"
        cnf = self.capsule / "artifacts/cnf"
        cnf.mkdir(parents=True)
        self.template = cnf / "template.cnf"
        self.semantic_map = cnf / "template.map.json"
        self.manifest = self.capsule / "artifacts.sha256"
        self.template.write_bytes(b"p cnf 1 0\n")
        self.semantic_map.write_bytes(b"{}\n")
        self.manifest.write_bytes(b"synthetic immutable manifest\n")
        self.workspace_counter = 0
        self.entropy = bytes((37 * index + 11) & 0xFF for index in range(ENTROPY_BYTES))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _config(
        self,
        *,
        force_controls: bool = False,
        persistent_budget: int = 10_000_000,
    ) -> Full256MultiKeyCalibrationConfig:
        plan = CausalBitfieldPlan()
        source = MultiKeyFoundationSource(
            capsule="runs/foundation",
            manifest_sha256=hashlib.sha256(self.manifest.read_bytes()).hexdigest(),
            template="artifacts/cnf/template.cnf",
            template_sha256=hashlib.sha256(self.template.read_bytes()).hexdigest(),
            semantic_map="artifacts/cnf/template.map.json",
            semantic_map_sha256=hashlib.sha256(
                self.semantic_map.read_bytes()
            ).hexdigest(),
            expected_variable_count=32_128,
            expected_template_clause_count=187_370,
            expected_public_clause_count=188_010,
        )
        return Full256MultiKeyCalibrationConfig(
            source=source,
            native=NativeDependencyConfig(
                compiler="c++",
                include_directory="/synthetic/include",
                static_library="/synthetic/libcadical.a",
                cadical_header_sha256="4" * 64,
                cadical_library_sha256="5" * 64,
            ),
            probe=MultiKeyProbeConfig(
                seed=0,
                timeout_seconds=10.0,
                sentinel_bit=173,
                sentinel_reruns_per_sweep=0,
            ),
            state_plan=plan,
            corpus=MultiKeyCorpusConfig(
                seed=13_0013,
                build_targets=2,
                calibration_targets=2,
                sealed_targets=1,
            ),
            reader=MultiKeyReaderConfig(
                arms=("horizon_0",),
                ridge_lambdas=(1.0,),
                temperatures=(1.0,),
                shrinkages=(0.0,),
                decoy_count=7,
                decoy_seed=0xC0FFEE,
            ),
            controls=MultiKeyControlConfig(
                transforms=("output_bit_flip",),
                run_only_if_calibration_compression_positive=not force_controls,
            ),
            budgets=SensorBudgetConfig(
                maximum_cpu_seconds=100.0,
                maximum_wall_seconds=100.0,
                maximum_resident_memory_mib=128.0,
                maximum_persistent_artifact_bytes=persistent_budget,
                maximum_native_solver_branches=3_072,
                maximum_mps_calls=0,
                maximum_gpu_calls=0,
                maximum_sibling_reads=0,
                maximum_sibling_writes=0,
                maximum_fresh_random_targets=1,
            ),
            maximum_state_bytes=18_000,
            maximum_live_target_state_bytes=(
                plan.serialized_state_bytes
                + KEY_BITS * READER_FEATURES * 4
                + KEY_BITS * 4
            ),
        )

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
    def _snapshot(
        *,
        target_id: str,
        public: PublicTargetView,
        state_plan: CausalBitfieldPlan,
    ) -> calibration._ProbeSnapshot:
        public.validate()
        public_digest = public.digest()
        feature_raw = hashlib.shake_256(
            b"o1c0013-test-features\0" + bytes.fromhex(public_digest)
        ).digest(KEY_BITS * READER_FEATURES)
        features = np.frombuffer(feature_raw, dtype=np.uint8).astype(np.float32)
        features = ((features - np.float32(127.5)) / np.float32(128.0)).reshape(
            KEY_BITS, READER_FEATURES
        )
        features = np.ascontiguousarray(features, dtype=np.float32)
        state = hashlib.shake_256(
            b"o1c0013-test-state\0"
            + target_id.encode("ascii")
            + bytes.fromhex(public_digest)
        ).digest(state_plan.serialized_state_bytes)
        state_sha = hashlib.sha256(state).hexdigest()
        feature_sha = hashlib.sha256(
            features.astype("<f4", copy=False).tobytes(order="C")
        ).hexdigest()
        identity = hashlib.sha256(target_id.encode("ascii")).hexdigest()
        return calibration._ProbeSnapshot(
            target_id=target_id,
            public=public,
            state_bytes=state,
            state_sha256=state_sha,
            reader_features=features,
            reader_features_sha256=feature_sha,
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

    def _run(
        self,
        config: Full256MultiKeyCalibrationConfig,
        *,
        early_control: bool = False,
    ) -> tuple[
        calibration.Full256MultiKeyCalibrationResult,
        list[str],
        dict[str, bytes],
        list[int],
    ]:
        events: list[str] = []
        prediction_artifacts: dict[str, bytes] = {}
        reloaded_reader_ids: set[int] = set()
        reloaded_inference_ids: list[int] = []
        self.workspace_counter += 1
        workspace = self.root / f"workspace-{self.workspace_counter}"

        def entropy_source(size: int) -> bytes:
            events.append("entropy")
            self.assertEqual(size, ENTROPY_BYTES)
            return self.entropy

        def on_reader_frozen(
            artifacts: Mapping[str, bytes],
            document: Mapping[str, object],
        ) -> None:
            events.append("reader-freeze")
            self.assertNotIn("entropy", events)
            self.assertEqual(document["fresh_target_entropy_calls"], 0)
            self.assertIn("frozen_reader.bin", artifacts)

        def on_predictions_frozen(
            artifacts: Mapping[str, bytes],
            document: Mapping[str, object],
        ) -> None:
            events.append("predictions-freeze")
            self.assertNotIn("reveal", events)
            self.assertEqual(
                document["phase"], "ALL_PREDICTIONS_FROZEN_BEFORE_ANY_REVEAL"
            )
            prediction_artifacts.update(artifacts)

        def fake_probe(**kwargs: object) -> calibration._ProbeSnapshot:
            target_id = str(kwargs["target_id"])
            public = kwargs["public"]
            state_plan = kwargs["state_plan"]
            self.assertIsInstance(public, PublicTargetView)
            self.assertIsInstance(state_plan, CausalBitfieldPlan)
            if early_control and "-control-" in target_id:
                raise Full256ProbeCoreError(
                    "paired branch reached SAT/UNSAT before the frozen horizon"
                )
            return self._snapshot(
                target_id=target_id,
                public=public,
                state_plan=state_plan,
            )

        original_reveal = Full256TargetBroker.reveal

        def tracked_reveal(
            broker: Full256TargetBroker, receipt: object
        ) -> dict[str, object]:
            events.append("reveal")
            return original_reveal(broker, receipt)

        original_deserialize = calibration.deserialize_orientation_reader

        def tracked_deserialize(payload: bytes):
            reader = original_deserialize(payload)
            reloaded_reader_ids.add(id(reader))
            return reader

        original_reader_outputs = calibration._reader_outputs

        def tracked_reader_outputs(reader, features):
            if id(reader) in reloaded_reader_ids:
                reloaded_inference_ids.append(id(reader))
            return original_reader_outputs(reader, features)

        monotonic_ticks = iter(float(value) for value in range(10, 100))
        process_ticks = iter((2.0, 3.0))
        usage = SimpleNamespace(ru_utime=0.0, ru_stime=0.0)
        with (
            patch.object(
                calibration,
                "verify_full256_template",
                return_value={
                    "schema": "synthetic-template-verification-v1",
                    "ok": True,
                    "variable_count": config.source.expected_variable_count,
                    "clause_count": config.source.expected_template_clause_count,
                },
            ),
            patch.object(
                calibration, "build_native_sensor", side_effect=self._fake_native_build
            ),
            patch.object(calibration, "_probe_public", side_effect=fake_probe),
            patch.object(
                calibration,
                "deserialize_orientation_reader",
                side_effect=tracked_deserialize,
            ),
            patch.object(
                calibration, "_reader_outputs", side_effect=tracked_reader_outputs
            ),
            patch.object(
                calibration.time,
                "monotonic",
                side_effect=lambda: next(monotonic_ticks),
            ),
            patch.object(
                calibration.time,
                "process_time",
                side_effect=lambda: next(process_ticks),
            ),
            patch.object(calibration.resource, "getrusage", return_value=usage),
            patch.object(calibration, "_peak_rss_bytes", return_value=4_096),
            patch.object(Full256TargetBroker, "reveal", new=tracked_reveal),
        ):
            result = run_full256_multikey_calibration(
                config,
                lab_root=self.root,
                working_directory=workspace,
                on_reader_frozen=on_reader_frozen,
                on_predictions_frozen=on_predictions_frozen,
                sealed_entropy_source=entropy_source,
                sealed_entropy_source_id="test.deterministic-v1",
            )
        return result, events, prediction_artifacts, reloaded_inference_ids

    def test_freezes_precede_entropy_and_reveal_and_target_artifacts_are_output_only(
        self,
    ) -> None:
        result, events, artifacts, reloaded_inference_ids = self._run(self._config())

        self.assertLess(events.index("reader-freeze"), events.index("entropy"))
        self.assertLess(events.index("predictions-freeze"), events.index("reveal"))
        self.assertEqual(events.count("entropy"), 1)
        self.assertTrue(reloaded_inference_ids)
        self.assertTrue(result.success_gate_passed)
        self.assertTrue(
            result.report["gates"]["reader_frozen_before_fresh_target_entropy"]
        )
        self.assertTrue(
            result.report["gates"]["all_predictions_frozen_before_any_reveal"]
        )
        self.assertTrue(result.report["gates"]["sealed_assumption_swap_complements"])
        self.assertEqual(
            result.report["state_contract"]["live_target_state_bytes"], 58_368
        )

        names = set(artifacts)
        self.assertFalse(any("reveal" in name for name in names))
        self.assertFalse(any("evaluation" in name for name in names))
        publication_name = next(
            name for name in names if name.endswith("/publication.json")
        )
        publication = json.loads(artifacts[publication_name])
        public_view = publication["public_view"]
        self.assertFalse(public_view["target_key_included"])
        self.assertFalse(public_view["target_trace_included"])
        true_key = self.entropy[:32]
        salt = self.entropy[48:80]
        for payload in artifacts.values():
            self.assertNotIn(true_key, payload)
            self.assertNotIn(salt, payload)
            self.assertNotIn(true_key.hex().encode("ascii"), payload)
            self.assertNotIn(salt.hex().encode("ascii"), payload)

        index = json.loads(result.reader_freeze_artifacts["build_cal_index.json"])
        build_hashes = {
            row["key_sha256"] for row in index["rows"] if row["split"] == "BUILD"
        }
        calibration_hashes = {
            row["key_sha256"] for row in index["rows"] if row["split"] == "CALIBRATION"
        }
        self.assertFalse(build_hashes & calibration_hashes)
        self.assertTrue(result.report["gates"]["build_calibration_disjoint"])

    def test_uniform_calibration_closes_control_gate_and_bills_only_real_sweeps(
        self,
    ) -> None:
        result, _events, artifacts, _reloaded = self._run(self._config())
        resources = result.report["resources"]

        self.assertFalse(
            result.report["prediction_set_freeze"]["target_controls_gate_open"]
        )
        self.assertEqual(resources["sweep_attempts"], 5)
        self.assertEqual(resources["native_solver_branches"], 5 * 512)
        self.assertEqual(resources["target_controls_executed"], 0)
        self.assertEqual(resources["target_controls_resolved_early"], 0)
        self.assertFalse(any(name.startswith("controls/") for name in artifacts))
        self.assertEqual(resources["fresh_target_entropy_calls"], 1)

    def test_forced_control_is_persisted_and_billed(self) -> None:
        result, _events, artifacts, _reloaded = self._run(
            self._config(force_controls=True)
        )
        resources = result.report["resources"]

        self.assertTrue(
            result.report["prediction_set_freeze"]["target_controls_gate_open"]
        )
        self.assertEqual(resources["sweep_attempts"], 6)
        self.assertEqual(resources["native_solver_branches"], 6 * 512)
        self.assertEqual(resources["target_controls_executed"], 1)
        self.assertTrue(
            any(
                name.startswith("controls/") and name.endswith("/public_view.json")
                for name in artifacts
            )
        )

    def test_early_resolved_control_still_persists_public_view_and_branch_bill(
        self,
    ) -> None:
        result, _events, artifacts, _reloaded = self._run(
            self._config(force_controls=True), early_control=True
        )
        resources = result.report["resources"]
        controls = result.report["sealed_evaluation"]["target_controls"]

        self.assertEqual(resources["sweep_attempts"], 6)
        self.assertEqual(resources["native_solver_branches"], 6 * 512)
        self.assertEqual(resources["target_controls_executed"], 0)
        self.assertEqual(resources["target_controls_resolved_early"], 1)
        self.assertEqual(
            controls[0]["status"], "relation-resolved-before-frozen-horizon"
        )
        self.assertIn("public_view_sha256", controls[0])
        self.assertNotIn("error", controls[0])
        self.assertTrue(
            any(
                name.startswith("controls/") and name.endswith("/public_view.json")
                for name in artifacts
            )
        )

    def test_deterministic_entropy_clock_and_resources_reproduce_full_report(
        self,
    ) -> None:
        first, _events, _artifacts, _reloaded = self._run(self._config())
        second, _events, _artifacts, _reloaded = self._run(self._config())

        self.assertEqual(first.report, second.report)
        self.assertEqual(first.reader_freeze_artifacts, second.reader_freeze_artifacts)
        self.assertEqual(
            first.prediction_freeze_artifacts,
            second.prediction_freeze_artifacts,
        )
        self.assertEqual(first.final_artifacts, second.final_artifacts)

    def test_persistent_artifact_accounting_is_exact_and_under_budget(self) -> None:
        result, _events, _artifacts, _reloaded = self._run(self._config())
        resources = result.report["resources"]
        actual = sum(
            len(payload)
            for group in (
                result.reader_freeze_artifacts,
                result.prediction_freeze_artifacts,
                result.final_artifacts,
            )
            for payload in group.values()
        )

        self.assertEqual(resources["persistent_artifact_bytes"], actual)
        self.assertTrue(result.report["gates"]["persistent_artifacts_under_budget"])

    def test_persistent_artifact_budget_is_enforced(self) -> None:
        with self.assertRaisesRegex(
            Full256MultiKeyCalibrationError, "persistent_artifacts_under_budget"
        ):
            self._run(self._config(persistent_budget=1))

    def test_foundation_members_cannot_escape_the_finalized_capsule(self) -> None:
        escaped = self.root / "outside-template.cnf"
        escaped.write_bytes(b"outside capsule\n")
        config = self._config()
        source = replace(
            config.source,
            template="../../outside-template.cnf",
            template_sha256=hashlib.sha256(escaped.read_bytes()).hexdigest(),
        )
        config = replace(config, source=source)

        with (
            patch.object(
                calibration,
                "build_native_sensor",
                side_effect=AssertionError("build reached before containment gate"),
            ),
            self.assertRaisesRegex(
                Full256MultiKeyCalibrationError,
                "escapes.*capsule|outside.*capsule|capsule.*outside",
            ),
        ):
            run_full256_multikey_calibration(
                config,
                lab_root=self.root,
                working_directory=self.root / "containment-work",
                on_reader_frozen=lambda *_args: None,
                on_predictions_frozen=lambda *_args: None,
                sealed_entropy_source=lambda _size: self.entropy,
                sealed_entropy_source_id="test.deterministic-v1",
            )

    def test_pinned_template_dimensions_are_rechecked_before_native_build(self) -> None:
        config = self._config()
        with (
            patch.object(
                calibration,
                "verify_full256_template",
                return_value={
                    "schema": "synthetic-template-verification-v1",
                    "ok": True,
                    "variable_count": config.source.expected_variable_count,
                    "clause_count": config.source.expected_template_clause_count + 1,
                },
            ),
            patch.object(
                calibration,
                "build_native_sensor",
                side_effect=AssertionError("native build reached after count mismatch"),
            ),
            self.assertRaisesRegex(
                Full256MultiKeyCalibrationError,
                "template dimensions differ",
            ),
        ):
            run_full256_multikey_calibration(
                config,
                lab_root=self.root,
                working_directory=self.root / "dimension-work",
                on_reader_frozen=lambda *_args: None,
                on_predictions_frozen=lambda *_args: None,
                sealed_entropy_source=lambda _size: self.entropy,
                sealed_entropy_source_id="test.deterministic-v1",
            )


if __name__ == "__main__":
    unittest.main()
