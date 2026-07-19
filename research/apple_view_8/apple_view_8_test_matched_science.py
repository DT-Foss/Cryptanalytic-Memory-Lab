from __future__ import annotations

import json
import os
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import cast
from unittest.mock import patch

from o1_crypto_lab.joint_score_sieve_v3 import JointScoreSieveResult

import apple_view_8_matched_science as matched_module
from apple_view_8_matched_science import (
    ATTEMPT_ID,
    BOUND_TOLERANCE,
    CONFLICT_LIMIT,
    MEMORY_LIMIT_BYTES,
    PREFLIGHT_SCHEMA,
    SEED,
    TIMEOUT_SECONDS,
    AppleView8MatchedError,
    bind_terminal_o1c61,
    classify_incremental_effect,
    config_preflight,
    finalize_capsule,
    invoke_native_once,
    invoke_native_once_terminal,
    load_config,
    public_model_then_truth_diagnostic,
)


ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "research/apple_view_8/apple_view_8_matched_config.template.json"


def _raw_native(
    *,
    status: int = 0,
    trail_prunes: int = 0,
    model_prunes: int = 0,
    root: float = 100.0,
    minimum: float = 100.0,
    maximum_assigned: int = 10,
    conflicts: int = 512,
    propagations: int = 0,
) -> dict[str, object]:
    return {
        "schema": "o1-256-cadical-joint-score-sieve-result-v2",
        "status": status,
        "stats": {
            "conflicts": conflicts,
            "decisions": 0,
            "propagations": propagations,
        },
        "sieve": {
            "trail_threshold_prunes": trail_prunes,
            "model_threshold_prunes": model_prunes,
            "threshold_prunes": trail_prunes + model_prunes,
            "maximum_assigned_variables": maximum_assigned,
            "root_upper_bound": root,
            "minimum_upper_bound": minimum,
        },
    }


def _ledger(
    *,
    requested: int = 512,
    before: int = 0,
    solve: int = 513,
) -> dict[str, int]:
    cumulative = before + solve
    return {
        "conflicts": cumulative,
        "conflicts_before_solve": before,
        "solve_conflicts": solve,
        "decisions": 0,
        "propagations": 0,
        "requested_conflicts": requested,
        "unused_requested_conflicts": max(requested - solve, 0),
        "conflict_limit_overshoot": max(solve - requested, 0),
        "billed_conflicts": solve,
    }


def _native(*, status: int = 0, key: bytes | None = None) -> JointScoreSieveResult:
    return JointScoreSieveResult(
        status=status,
        conflict_limit=CONFLICT_LIMIT,
        threshold=3.0,
        key_model=key,
        stats=_ledger(solve=0),
        sieve={},
        resources={},
        raw={},
    )


class AppleView8MatchedScienceTests(unittest.TestCase):
    def test_unbound_template_preflight_is_pure_waiting_and_load_refuses(self) -> None:
        before = tuple(
            sorted(
                path.relative_to(TEMPLATE.parent).as_posix()
                for path in TEMPLATE.parent.iterdir()
                if path.is_file()
            )
        )
        result = config_preflight(TEMPLATE)
        after = tuple(
            sorted(
                path.relative_to(TEMPLATE.parent).as_posix()
                for path in TEMPLATE.parent.iterdir()
                if path.is_file()
            )
        )
        self.assertEqual(before, after)
        self.assertEqual(result["schema"], PREFLIGHT_SCHEMA)
        self.assertEqual(
            result["status"], "WAITING_FOR_IMMUTABLE_O1C61_SOURCE_BINDING"
        )
        self.assertFalse(result["ready_for_science"])
        self.assertEqual(result["native_solver_calls"], 0)
        self.assertEqual(result["files_written"], 0)
        with self.assertRaises(AppleView8MatchedError, msg="unbound science config"):
            load_config(TEMPLATE)

    def test_template_tamper_fails_before_binding_or_writes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="apple8-config-") as raw:
            path = Path(raw) / "tampered.json"
            value = json.loads(TEMPLATE.read_text("utf-8"))
            value["consequences"]["augmentation_clause_count"] = 14_391
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(AppleView8MatchedError, msg="frozen count"):
                config_preflight(path)

    def test_real_o1c61_bind_succeeds_and_missing_source_key_fails(self) -> None:
        baseline_result = (
            ROOT
            / "research/O1C0061_MULTIBLOCK_JOINT_SCORE_SIEVE_SOFT_STOP_RESULT_20260719.json"
        )
        baseline_capsule = (
            ROOT
            / "runs/20260719_091954_O1C-0061_multiblock-joint-score-sieve-soft-stop-v1"
        )
        with tempfile.TemporaryDirectory(
            prefix="apple8-bind-", dir=TEMPLATE.parent
        ) as raw:
            destination = Path(raw) / "bound.json"
            with (
                patch.object(
                    matched_module, "_git_commit", return_value="a" * 40
                ),
                patch.object(matched_module, "_commit_bound"),
            ):
                document = bind_terminal_o1c61(
                    TEMPLATE,
                    baseline_result,
                    baseline_capsule,
                    destination,
                )
            self.assertTrue(document["ready_for_science"])
            self.assertTrue(destination.is_file())
            self.assertEqual(
                cast(Mapping[str, object], document["baseline"])["result_sha256"],
                "100cde7911d9297170b63b2a095a4f0b7710b241bf25f1c8964fccca76758d7c",
            )
        missing = dict(matched_module.FROZEN_BASELINE_SOURCE_HASHES)
        missing.pop("full256_cnf")
        with self.assertRaises(AppleView8MatchedError, msg="missing source key"):
            matched_module._validate_frozen_baseline_source_hashes(missing)

    def test_classification_promotes_each_strict_semantic_effect(self) -> None:
        baseline = _raw_native()
        cases = (
            _raw_native(trail_prunes=1),
            _raw_native(minimum=99.5),
        )
        expected_gate = (
            "positive_additional_safe_trail_prunes_at_matched_work",
            "smaller_remaining_gap_at_matched_work",
        )
        for augmented, gate in zip(cases, expected_gate, strict=True):
            classification, report = classify_incremental_effect(
                baseline_native=baseline,
                augmented_native=augmented,
                baseline_ledger=_ledger(),
                augmented_ledger=_ledger(),
                baseline_exact_public_recovery=False,
                augmented_public_model_verified=False,
            )
            self.assertEqual(
                classification,
                "APPLE_VIEW_0008_STRICT_INCREMENTAL_EFFECT_NO_RECOVERY",
            )
            gates = cast(Mapping[str, bool], report["strict_effect_gates"])
            self.assertTrue(gates[gate])
            self.assertFalse(report["event_volume_used_for_promotion"])

    def test_event_volume_late_models_and_equal_semantics_do_not_promote(self) -> None:
        baseline = _raw_native(propagations=1)
        augmented = _raw_native(
            model_prunes=50, maximum_assigned=11, propagations=10_000_000
        )
        classification, report = classify_incremental_effect(
            baseline_native=baseline,
            augmented_native=augmented,
            baseline_ledger=_ledger(),
            augmented_ledger=_ledger(),
            baseline_exact_public_recovery=False,
            augmented_public_model_verified=False,
        )
        self.assertEqual(classification, "APPLE_VIEW_0008_NO_INCREMENTAL_EFFECT")
        gates = cast(Mapping[str, bool], report["strict_effect_gates"])
        self.assertFalse(any(gates.values()))
        self.assertFalse(report["event_volume_used_for_promotion"])

    def test_public_collision_is_exact_and_lost_baseline_exact_is_not_progress(self) -> None:
        exact, exact_report = classify_incremental_effect(
            baseline_native=_raw_native(status=10),
            augmented_native=_raw_native(status=10),
            baseline_ledger=_ledger(solve=20),
            augmented_ledger=_ledger(solve=1),
            baseline_exact_public_recovery=True,
            augmented_public_model_verified=True,
        )
        self.assertEqual(exact, "APPLE_VIEW_0008_EXACT_PUBLIC_FULL256_RECOVERY")
        self.assertTrue(exact_report["augmented_public_model_verified"])

        lost, lost_report = classify_incremental_effect(
            baseline_native=_raw_native(status=10),
            augmented_native=_raw_native(trail_prunes=20, minimum=90.0),
            baseline_ledger=_ledger(),
            augmented_ledger=_ledger(),
            baseline_exact_public_recovery=True,
            augmented_public_model_verified=False,
        )
        self.assertEqual(lost, "APPLE_VIEW_0008_NO_INCREMENTAL_EFFECT")
        self.assertTrue(lost_report["lost_baseline_exact_recovery"])

    def test_matched_root_bound_mismatch_fails_closed(self) -> None:
        with self.assertRaises(AppleView8MatchedError, msg="root mismatch"):
            classify_incremental_effect(
                baseline_native=_raw_native(root=100.0),
                augmented_native=_raw_native(root=100.0 + 10 * BOUND_TOLERANCE),
                baseline_ledger=_ledger(),
                augmented_ledger=_ledger(),
                baseline_exact_public_recovery=False,
                augmented_public_model_verified=False,
            )

    def test_soft_stop_overshoot_one_and_early_finish_are_valid(self) -> None:
        classification, report = classify_incremental_effect(
            baseline_native=_raw_native(),
            augmented_native=_raw_native(minimum=90.0),
            baseline_ledger=_ledger(),
            augmented_ledger=_ledger(solve=400),
            baseline_exact_public_recovery=False,
            augmented_public_model_verified=False,
        )
        self.assertEqual(classification, "APPLE_VIEW_0008_NO_INCREMENTAL_EFFECT")
        work = cast(Mapping[str, object], report["work"])
        self.assertFalse(work["billed_work_matched"])
        self.assertEqual(
            cast(Mapping[str, object], work["baseline"])["conflict_limit_overshoot"],
            1,
        )

    def test_soft_stop_overshoot_two_and_missing_ledger_fail_closed(self) -> None:
        invalid = _ledger(solve=514)
        missing = _ledger()
        del missing["billed_conflicts"]
        for ledger in (invalid, missing):
            with self.assertRaises(AppleView8MatchedError, msg="invalid ledger"):
                classify_incremental_effect(
                    baseline_native=_raw_native(),
                    augmented_native=_raw_native(),
                    baseline_ledger=_ledger(),
                    augmented_ledger=ledger,
                    baseline_exact_public_recovery=False,
                    augmented_public_model_verified=False,
                )

    def test_public_model_diagnostic_strictly_precedes_truth_and_accepts_collision(
        self,
    ) -> None:
        model = b"m" * 32
        truth = b"t" * 32
        order: list[str] = []

        def verify_public(value: bytes) -> bool:
            order.append("public")
            return value == model

        def read_truth() -> bytes:
            order.append("truth")
            return truth

        public, observed_truth, equals = public_model_then_truth_diagnostic(
            _native(status=10, key=model),
            verify_public_model=verify_public,
            read_truth_key=read_truth,
        )
        self.assertEqual(order, ["public", "truth"])
        self.assertTrue(public)
        self.assertEqual(observed_truth, truth)
        self.assertFalse(equals)

        blocked_order: list[str] = []

        def reject_public(_: bytes) -> bool:
            blocked_order.append("public")
            return False

        def forbidden_truth() -> bytes:
            blocked_order.append("truth")
            return truth

        with self.assertRaises(AppleView8MatchedError, msg="public failure"):
            public_model_then_truth_diagnostic(
                _native(status=10, key=model),
                verify_public_model=reject_public,
                read_truth_key=forbidden_truth,
            )
        self.assertEqual(blocked_order, ["public"])

    def test_no_model_and_sat_without_model_never_read_truth(self) -> None:
        for status in (0, 20):
            callbacks: list[str] = []
            ledger = [False]
            observed = public_model_then_truth_diagnostic(
                _native(status=status),
                verify_public_model=lambda _: callbacks.append("public") or True,
                read_truth_key=lambda: callbacks.append("truth") or b"t" * 32,
                public_diagnostic_ledger=ledger,
            )
            self.assertEqual(observed, (False, None, None))
            self.assertEqual(callbacks, [])
            self.assertEqual(ledger, [True])

        sat_callbacks: list[str] = []
        sat_ledger = [False]
        with self.assertRaises(AppleView8MatchedError, msg="SAT without model"):
            public_model_then_truth_diagnostic(
                _native(status=10),
                verify_public_model=lambda _: sat_callbacks.append("public") or True,
                read_truth_key=lambda: sat_callbacks.append("truth") or b"t" * 32,
                public_diagnostic_ledger=sat_ledger,
            )
        self.assertEqual(sat_callbacks, [])
        self.assertEqual(sat_ledger, [True])

    def test_native_adapter_is_exactly_one_matched_call(self) -> None:
        calls: list[dict[str, object]] = []
        expected = _native()

        def fake_runner(**kwargs: object) -> JointScoreSieveResult:
            calls.append(dict(kwargs))
            return expected

        result = invoke_native_once(
            executable=Path("native"),
            cnf=Path("augmented.cnf"),
            potential=Path("baseline.potential"),
            threshold=14.5,
            conflict_limit=CONFLICT_LIMIT,
            seed=SEED,
            timeout_seconds=TIMEOUT_SECONDS,
            memory_limit_bytes=MEMORY_LIMIT_BYTES,
            runner=fake_runner,
        )
        self.assertIs(result, expected)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["conflict_limit"], 512)
        self.assertEqual(calls[0]["seed"], 0)
        self.assertEqual(calls[0]["timeout_seconds"], 180.0)
        self.assertEqual(calls[0]["memory_limit_bytes"], 805_306_368)

    def test_post_intent_exception_consumes_call_without_retry_or_truth(self) -> None:
        calls = 0

        def explode(**_: object) -> JointScoreSieveResult:
            nonlocal calls
            calls += 1
            raise TimeoutError("synthetic")

        result, failure = invoke_native_once_terminal(
            executable=Path("native"),
            cnf=Path("augmented.cnf"),
            potential=Path("baseline.potential"),
            threshold=14.5,
            conflict_limit=CONFLICT_LIMIT,
            seed=SEED,
            timeout_seconds=TIMEOUT_SECONDS,
            memory_limit_bytes=MEMORY_LIMIT_BYTES,
            runner=explode,
        )
        self.assertEqual(calls, 1)
        self.assertIsNone(result)
        self.assertIsNotNone(failure)
        assert failure is not None
        self.assertEqual(failure["native_calls_consumed"], 1)
        self.assertFalse(failure["retry_authorized"])
        self.assertFalse(failure["truth_key_bytes_read"])

    def test_terminal_capsule_converges_manifest_and_becomes_immutable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="apple8-terminal-") as raw:
            root = Path(raw)
            capsule = root / "capsule"
            capsule.mkdir()
            (capsule / "native_call_intent.json").write_text("{}\n", encoding="ascii")
            authoritative = root / "result.json"
            result: dict[str, object] = {
                "classification": "APPLE_VIEW_0008_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT",
                "claim_boundary": {
                    "truth_key_bytes_read_after_public_diagnostic": False
                },
                "resources": {
                    "native_solver_calls": 1,
                    "persistent_artifact_bytes": 0,
                },
            }
            finalize_capsule(
                capsule=capsule,
                authoritative_result=authoritative,
                result=result,
                maximum_persistent_bytes=1_000_000,
            )
            self.assertTrue((capsule / "artifacts.sha256").is_file())
            self.assertTrue(authoritative.is_file())
            self.assertEqual(capsule.stat().st_mode & 0o777, 0o555)
            self.assertEqual(
                (capsule / "result.json").stat().st_mode & 0o777, 0o444
            )
            self.assertEqual(
                cast(
                    Mapping[str, object],
                    cast(
                        Mapping[str, object],
                        json.loads(authoritative.read_text("ascii")),
                    )["resources"],
                )["persistent_artifact_bytes"],
                cast(Mapping[str, object], result["resources"])[
                    "persistent_artifact_bytes"
                ],
            )
            for path in sorted(
                capsule.rglob("*"), key=lambda item: len(item.parts), reverse=True
            ):
                os.chmod(path, 0o755 if path.is_dir() else 0o644)
            os.chmod(capsule, 0o755)

    def test_publication_failure_recovers_into_one_call_terminal_failure(self) -> None:
        with tempfile.TemporaryDirectory(prefix="apple8-publication-") as raw:
            root = Path(raw)
            capsule = root / "capsule"
            capsule.mkdir()
            (capsule / "native_call_intent.json").write_text(
                "{}\n", encoding="ascii"
            )
            authoritative = root / "result.json"
            first: dict[str, object] = {
                "classification": "APPLE_VIEW_0008_NO_INCREMENTAL_EFFECT",
                "claim_boundary": {
                    "truth_key_bytes_read_after_public_diagnostic": False
                },
                "resources": {
                    "native_solver_calls": 1,
                    "persistent_artifact_bytes": 0,
                },
            }

            def fail_after_capsule_seal() -> None:
                raise OSError("injected post-seal publication failure")

            with self.assertRaises(OSError, msg="injected publication failure"):
                finalize_capsule(
                    capsule=capsule,
                    authoritative_result=authoritative,
                    result=first,
                    maximum_persistent_bytes=1_000_000,
                    _after_capsule_seal=fail_after_capsule_seal,
                )
            self.assertFalse(authoritative.exists())
            self.assertFalse((capsule / "artifacts.sha256").exists())
            self.assertEqual(capsule.stat().st_mode & 0o777, 0o755)

            (capsule / "native_failure.json").write_text(
                '{"error":"injected"}\n', encoding="ascii"
            )
            terminal: dict[str, object] = {
                "classification": "APPLE_VIEW_0008_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT",
                "claim_boundary": {
                    "truth_key_bytes_read_after_public_diagnostic": False
                },
                "resources": {
                    "native_solver_calls": 1,
                    "persistent_artifact_bytes": 0,
                },
            }
            finalize_capsule(
                capsule=capsule,
                authoritative_result=authoritative,
                result=terminal,
                maximum_persistent_bytes=1_000_000,
            )
            self.assertEqual(
                authoritative.read_bytes(), (capsule / "result.json").read_bytes()
            )
            self.assertEqual(capsule.stat().st_mode & 0o777, 0o555)
            self.assertEqual(
                cast(
                    Mapping[str, object],
                    json.loads(authoritative.read_text("ascii")),
                )["resources"],
                terminal["resources"],
            )
            with self.assertRaises(AppleView8MatchedError, msg="no overwrite"):
                finalize_capsule(
                    capsule=capsule,
                    authoritative_result=authoritative,
                    result=terminal,
                    maximum_persistent_bytes=1_000_000,
                )
            for path in sorted(
                capsule.rglob("*"), key=lambda item: len(item.parts), reverse=True
            ):
                os.chmod(path, 0o755 if path.is_dir() else 0o644)
            os.chmod(capsule, 0o755)

    def test_attempt_identity_is_frozen(self) -> None:
        self.assertEqual(ATTEMPT_ID, "APPLE-VIEW-0008-MATCHED")


if __name__ == "__main__":
    unittest.main()
