from __future__ import annotations

import hashlib
import io
import json
import fcntl
import os
import struct
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
from typing import Mapping
from unittest.mock import patch

from o1_crypto_lab.living_inverse import canonical_json_bytes
from o1_crypto_lab.o1c22_postresult_composer import (
    ACTIVE_WIDTHS,
    CONTROL_MARGIN_FIELDS,
    EFFICACY_GATES,
    INTEGRITY_GATES,
    PRIMARY_ARMS,
    UPSTREAM_METRICS_SCHEMA,
    UPSTREAM_RESULT_SCHEMA,
    compose_postresult_decision,
    empty_failure_memory,
    encode_o1o_fragment_document,
    encode_o1o_route,
)
from o1_crypto_lab.o1c22_postresult_composer_run import (
    O1C22PostResultComposerRunError,
    StructuralWorkLedger,
    _extract_exact_operator_marker,
    _interruption_recovery_metrics,
    _load_bound_o1c22_source,
    _load_verified_o1c22_source,
    _run_native_o1o_once,
    _tree_snapshot,
    _verify_o1o_core_sources,
    load_o1c22_postresult_composer_run_config,
    main,
    preflight_o1c22_postresult_composer,
    run_capsule_from_config,
)
from o1_crypto_lab.run_capsule import (
    CapsuleVerification,
    ClaimLevel,
    FinalizedRun,
    RunCapsuleManager,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c22_postresult_composer_v1.json"
UPSTREAM_EXECUTION_FILES = {
    "causal_vault_bridge_execution.json",
    "causal_vault_bridge_ledger.json",
    "causal_vault_state.bin",
    "raw_float_control.f64le",
    "normalized_float_control.f64le",
    "unit_sign_control.i8",
    "last_only_control.i8",
    "shuffled_control.i8",
    "shuffled_destinations.u16le",
}
SCORED_SHAPES = {
    "labels.bitpack": 128,
    "raw_predictions.f64le": 229_376,
    "calibrated_predictions.f64le": 229_376,
    "calibration_scales.f64le": 224,
    "nll_bits.f64le": 896,
    "compression_bits.f64le": 896,
    "upstream_o1c19_anchor.f32le": 4_096,
}


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _token(label: str) -> str:
    return _sha(canonical_json_bytes(["synthetic-o1c22", label]))


def _capsule_source_hashes(config: object) -> dict[str, str]:
    upstream = config.upstream_top
    source = upstream["source"]
    prerequisites = upstream["prerequisites"]
    hashes = {
        "config": config.upstream_config_sha256,
        "pyproject": config.upstream_static_source_sha256["pyproject"],
        "o1c18_capsule_manifest": source["o1c18_manifest_sha256"],
        "o1c18_artifact_index": source["o1c18_artifact_index_sha256"],
        "o1c18_artifact_corpus": source["o1c18_public_build_corpus_sha256"],
        "o1c19_source_config": prerequisites["o1c19"]["config_sha256"],
        "o1c21_source_config": prerequisites["o1c21_state"]["config_sha256"],
        **{
            label: digest
            for label, digest in config.upstream_static_source_sha256.items()
            if label != "pyproject"
        },
        "o1c19_capsule_manifest": _token("o1c19-capsule-manifest"),
        "o1c19_artifact_index": _token("o1c19-artifact-index"),
        "o1c19_result": _token("o1c19-result"),
    }
    for fold_index in range(4):
        for suffix in (
            "reader",
            "slow_state",
            "learning_freeze",
            "prediction_freeze",
        ):
            label = f"o1c19_fold_{fold_index:02d}_{suffix}"
            hashes[label] = _token(label)
    assert len(hashes) == 38
    return dict(sorted(hashes.items()))


def _result(source_hashes: Mapping[str, str]) -> dict[str, object]:
    curves = {
        "raw_float_delta_sum": (0.2, 0.5, 0.8, 1.4),
        "normalized_float_delta_sum": (0.2, 0.6, 1.0, 1.5),
        "quantized_int8_vault": (0.1, 0.4, 0.9, 1.4),
    }
    arms = {
        arm: {
            "widths": [
                {
                    "active_coordinates": width,
                    "mean_compression_bits": value,
                    "mean_nll_bits": 256.0 - value,
                    "mean_active_nll_bits": float(width),
                    "minimum_compression_bits": value - 0.1,
                    "maximum_compression_bits": value + 0.1,
                    "positive_folds": 4,
                }
                for width, value in zip(ACTIVE_WIDTHS, curves[arm])
            ]
        }
        for arm in PRIMARY_ARMS
    }
    gates = {name: True for name in set(INTEGRITY_GATES) | set(EFFICACY_GATES)}
    gates["integrity_gate_passed"] = True
    margins = {
        "raw_float_mean_final_compression_bits": 1.4,
        "normalized_float_mean_final_compression_bits": 1.5,
        "int8_mean_final_compression_bits": 1.4,
        "coordinate_shuffled_mean_final_compression_bits": 0.9,
        "last_horizon_only_mean_final_compression_bits": 1.0,
        "unit_sign_sum_mean_final_compression_bits": 1.1,
        CONTROL_MARGIN_FIELDS["coordinate_binding"]: 0.5,
        CONTROL_MARGIN_FIELDS["horizon_compounding"]: 0.4,
        CONTROL_MARGIN_FIELDS["confidence_magnitude"]: 0.3,
        "int8_preserves_normalized_float_fraction": 1.4 / 1.5,
        "int8_mean_compression_curve_bits": list(curves["quantized_int8_vault"]),
    }
    resources = {
        "existing_build_pools_loaded": 4,
        "o1c19_reader_replays": 32,
        "packet_slot_observations": 17_664,
        "physical_public_work_units": 1_130_496,
        "calibration_value_evaluations": 7_391_232,
        "physical_public_pools_generated": 0,
        "native_solver_branches": 0,
        "scientific_entropy_calls": 0,
        "sibling_reads": 0,
        "sibling_writes": 0,
        "mps_calls": 0,
        "gpu_calls": 0,
        "maximum_accumulator_live_state_bytes": 352,
        "upstream_reader_state_billed_separately": True,
        "source_artifact_bytes_read": 1,
    }
    unsigned: dict[str, object] = {
        "schema": UPSTREAM_RESULT_SCHEMA,
        "classification": "REAL_CAUSAL_VAULT_BUILD_LOO_PASS",
        "claim_boundary": "SYNTHETIC_EXACT_CONTRACT_FIXTURE",
        "active_coordinate_counts": list(ACTIVE_WIDTHS),
        "prediction_arms": [
            "raw_float_delta_sum",
            "normalized_float_delta_sum",
            "quantized_int8_vault",
            "last_horizon_only",
            "unit_sign_sum",
            "coordinate_shuffled_vault",
            "zero_prior",
        ],
        "calibration_scales": [1.0] * 7,
        "arms": arms,
        "source_anchor": source_hashes["o1c19_result"],
        "margins": margins,
        "gates": gates,
        "failed_gates": [],
        "calibration_orientation_flip_allowed": False,
        "calibration_scale_grid": [0.0, 0.5, 1.0, 1.5, 2.0],
        "integrity_diagnostics": {"synthetic_exact_fixture": True},
        "resources": resources,
        "source": {
            "o1c18_artifact_corpus_sha256": source_hashes["o1c18_artifact_corpus"],
            "o1c19_manifest_sha256": source_hashes["o1c19_capsule_manifest"],
            "o1c19_artifact_index_sha256": source_hashes["o1c19_artifact_index"],
            "o1c19_result_sha256": source_hashes["o1c19_result"],
            "o1c21_config_sha256": source_hashes["o1c21_source_config"],
        },
    }
    return {**unsigned, "result_sha256": _sha(canonical_json_bytes(unsigned))}


def _budget_checks(config: object, persistent_bytes: int) -> dict[str, bool]:
    budgets = config.upstream_top["budgets"]
    return {
        "cpu": 1.0 <= budgets["maximum_cpu_seconds"],
        "wall": 1.0 <= budgets["maximum_wall_seconds"],
        "resident_memory": 1 <= budgets["maximum_resident_memory_mib"] * 1024 * 1024,
        "persistent_artifacts": persistent_bytes
        <= budgets["maximum_persistent_artifact_bytes"],
        "source_artifact_bytes_read": 1
        <= budgets["maximum_source_artifact_bytes_read"],
        "existing_build_pools": budgets["expected_existing_build_pools"] == 4,
        "reader_replays": budgets["maximum_o1c19_reader_replays"] == 32,
        "packet_slots": budgets["maximum_packet_slot_observations"] == 17_664,
        "public_work": budgets["maximum_physical_public_work_units"] == 1_130_496,
        "calibration_value_evaluations": budgets[
            "maximum_calibration_value_evaluations"
        ]
        == 7_391_232,
        "physical_public_pools_generated": budgets[
            "maximum_physical_public_pools_generated"
        ]
        == 0,
        "native_solver_branches": budgets["maximum_native_solver_branches"] == 0,
        "scientific_entropy": budgets["maximum_scientific_entropy_calls"] == 0,
        "sibling_reads": budgets["maximum_sibling_reads"] == 0,
        "sibling_writes": budgets["maximum_sibling_writes"] == 0,
        "mps": budgets["maximum_mps_calls"] == 0,
        "gpu": budgets["maximum_gpu_calls"] == 0,
        "live_state": budgets["maximum_accumulator_live_state_bytes"] == 352,
    }


def _metrics(
    config: object,
    result: Mapping[str, object],
    persistent_bytes: int,
) -> dict[str, object]:
    checks = _budget_checks(config, persistent_bytes)
    assert len(checks) == 18 and all(checks.values())
    return {
        "schema": UPSTREAM_METRICS_SCHEMA,
        "classification": result["classification"],
        "scientific_success_gate_passed": True,
        "result_sha256": result["result_sha256"],
        "margins": result["margins"],
        "gates": result["gates"],
        "failed_gates": result["failed_gates"],
        "cpu_seconds": 1.0,
        "wall_seconds": 1.0,
        "peak_rss_bytes": 1,
        "persistent_artifact_bytes": persistent_bytes,
        "source_artifact_bytes_read": 1,
        "reader_replays": 32,
        "packet_slots": 17_664,
        "physical_public_work_units": 1_130_496,
        "calibration_value_evaluations": 7_391_232,
        "budget_checks": checks,
        "failed_budgets": [],
        "operationally_complete": True,
    }


def _ledger_state_and_execution(
    fold_index: int,
    quantizer_sha256: str,
) -> tuple[bytes, bytes, bytes]:
    state = bytes(80) + bytes(256) + struct.pack("<QQ", 255, 512)
    final_state_sha256 = _sha(state)
    previous = _token(f"fold-{fold_index}-initial-state")
    receipts: list[dict[str, object]] = []
    for coordinate in range(256):
        after = (
            final_state_sha256
            if coordinate == 255
            else _token(f"fold-{fold_index}-after-{coordinate}")
        )
        receipts.append(
            {
                "coordinate": coordinate,
                "quantized_deltas": [1, 0, -1],
                "normalized_deltas_float64_hex": [
                    float(1).hex(),
                    float(0.1).hex(),
                    float(-1).hex(),
                ],
                "accepted": True,
                "primary_state_sha256_before": previous,
                "primary_state_sha256_after": after,
            }
        )
        previous = after
    ledger = canonical_json_bytes(receipts)
    execution = canonical_json_bytes(
        {
            "schema": "o1-256-o1c22-causal-vault-execution-v1",
            "bridge_schema": "o1-256-o1c22-causal-vault-bridge-v1",
            "quantizer_sha256": quantizer_sha256,
            "groups_offered": 256,
            "groups_accepted": 256,
            "groups_duplicate": 0,
            "slots_offered": 768,
            "slots_accepted": 768,
            "physical_work_offered": 49_152,
            "physical_work_accepted": 49_152,
            "nonzero_vault_updates_accepted": 512,
            "zero_quantized_slots_accepted": 256,
            "zero_updates_are_skipped": True,
            "primary_live_state_bytes": 352,
            "control_live_state_bytes": 1_056,
            "static_control_plan_bytes": 512,
            "upstream_reader_billed_separately": True,
            "primary_state_sha256": _sha(state),
            "control_state_sha256": _token(f"fold-{fold_index}-control-state"),
            "static_control_plan_sha256": _token(f"fold-{fold_index}-control-plan"),
            "ledger_sha256": _sha(ledger),
            "duplicate_acceptance_rule": "REJECT_EXACT_GROUP_ID",
            "duplicate_primary_state_byte_invariant": True,
            "controls": [
                "raw_float",
                "normalized_float",
                "unit_sign",
                "last_only",
                "coordinate_shuffle",
            ],
            "zero_prior_representation": "IMPLICIT_ZERO",
            "current_target_supervised_updates": 0,
            "label_accesses": 0,
            "solver_calls": 0,
        }
    )
    return ledger, state, execution


def _add_payload(
    payloads: dict[str, tuple[bytes, str]],
    relative: str,
    payload: bytes,
    phase: str,
) -> None:
    assert relative not in payloads
    payloads[relative] = (payload, phase)


def _freeze_document(
    fields: Mapping[str, object],
    payloads: Mapping[str, tuple[bytes, str]],
    phase: str,
) -> bytes:
    artifacts = {
        relative: {"sha256": _sha(payload), "bytes": len(payload)}
        for relative, (payload, payload_phase) in sorted(payloads.items())
        if payload_phase == phase
    }
    unsigned = {**fields, "artifacts": artifacts}
    return canonical_json_bytes(
        {**unsigned, "freeze_sha256": _sha(canonical_json_bytes(unsigned))}
    )


def _build_artifact_payloads(
    source_hashes: Mapping[str, str],
) -> dict[str, tuple[bytes, str]]:
    payloads: dict[str, tuple[bytes, str]] = {}
    for fold_index in range(4):
        target = f"build-{fold_index:04d}"
        training_ordinals = [(fold_index + offset) % 4 for offset in range(1, 4)]
        training_targets = [f"build-{index:04d}" for index in training_ordinals]
        calibration_phase = f"CALIBRATION_PREDICTIONS_FROZEN_FOLD_{fold_index}"
        calibration_prefix = f"folds/{target}/calibration"
        quantizer = canonical_json_bytes(
            {"schema": "synthetic-quantizer-v1", "fold_index": fold_index}
        )
        _add_payload(
            payloads,
            f"{calibration_prefix}/quantizer.json",
            quantizer,
            calibration_phase,
        )
        _add_payload(
            payloads,
            f"{calibration_prefix}/raw_predictions.f64le",
            b"calibration-predictions",
            calibration_phase,
        )
        for training_target in training_targets:
            source_prefix = f"{calibration_prefix}/source-{training_target}"
            _add_payload(
                payloads,
                f"{source_prefix}/active_coordinates.json",
                canonical_json_bytes(list(ACTIVE_WIDTHS)),
                calibration_phase,
            )
            _add_payload(
                payloads,
                f"{source_prefix}/packet_deltas.json",
                canonical_json_bytes({"source": training_target}),
                calibration_phase,
            )
            for name in sorted(UPSTREAM_EXECUTION_FILES):
                _add_payload(
                    payloads,
                    f"{source_prefix}/execution/{name}",
                    f"calibration:{fold_index}:{training_target}:{name}".encode(),
                    calibration_phase,
                )
        calibration_freeze_relative = f"{calibration_prefix}/prediction_freeze.json"
        calibration_freeze = _freeze_document(
            {
                "schema": "o1-256-o1c22-calibration-prediction-freeze-v1",
                "phase": "THIS_FOLD_TRAINING_PUBLIC_DELTAS_STATES_AND_PREDICTIONS_FROZEN_BEFORE_THIS_FOLD_CALIBRATION_LABEL_USE",
                "fold_index": fold_index,
                "held_out_ordinal": fold_index,
                "held_out_target_id": target,
                "training_ordinals": training_ordinals,
                "training_target_ids": training_targets,
                "reader_state_sha256": source_hashes[
                    f"o1c19_fold_{fold_index:02d}_reader"
                ],
                "slow_state_sha256": source_hashes[
                    f"o1c19_fold_{fold_index:02d}_slow_state"
                ],
                "quantizer_sha256": _sha(quantizer),
                "labels_used_by_this_fold_before_calibration_freeze": [],
                "held_out_label_used_for_this_fold": False,
                "previously_opened_build_label_ordinals": [],
                "build_labels_may_have_been_opened_in_other_folds": True,
                "reader_updates": 0,
                "solver_calls": 0,
            },
            payloads,
            calibration_phase,
        )
        _add_payload(
            payloads,
            calibration_freeze_relative,
            calibration_freeze,
            calibration_phase,
        )

        heldout_phase = f"HELDOUT_PREDICTIONS_FROZEN_FOLD_{fold_index}"
        heldout_prefix = f"folds/{target}/heldout"
        base_payloads = {
            "active_coordinates.json": canonical_json_bytes(list(ACTIVE_WIDTHS)),
            "quantizer.json": quantizer,
            "calibration_scales.f64le": struct.pack("<7d", *([1.0] * 7)),
            "upstream_o1c19_learned_reader_exhaustive.f32le": bytes(32),
            "pre_oracle_controls.json": canonical_json_bytes(
                {"label_accesses": 0, "solver_calls": 0}
            ),
            "raw_predictions.f64le": bytes(32),
            "calibrated_predictions.f64le": bytes(32),
        }
        for name, payload in base_payloads.items():
            _add_payload(payloads, f"{heldout_prefix}/{name}", payload, heldout_phase)
        for width in ACTIVE_WIDTHS:
            width_prefix = f"{heldout_prefix}/k{width:03d}"
            _add_payload(
                payloads,
                f"{width_prefix}/packet_deltas.json",
                canonical_json_bytes({"active_coordinates": width}),
                heldout_phase,
            )
            if width == 256:
                ledger, state, execution = _ledger_state_and_execution(
                    fold_index, _sha(quantizer)
                )
                special = {
                    "causal_vault_bridge_ledger.json": ledger,
                    "causal_vault_state.bin": state,
                    "causal_vault_bridge_execution.json": execution,
                }
            else:
                special = {}
            for name in sorted(UPSTREAM_EXECUTION_FILES):
                _add_payload(
                    payloads,
                    f"{width_prefix}/execution/{name}",
                    special.get(name, f"heldout:{fold_index}:{width}:{name}".encode()),
                    heldout_phase,
                )
        swap_prefix = f"{heldout_prefix}/polarity_swap"
        _add_payload(
            payloads,
            f"{swap_prefix}/packet_deltas.json",
            canonical_json_bytes({"control": "polarity-swap"}),
            heldout_phase,
        )
        for name in sorted(UPSTREAM_EXECUTION_FILES):
            _add_payload(
                payloads,
                f"{swap_prefix}/execution/{name}",
                f"polarity:{fold_index}:{name}".encode(),
                heldout_phase,
            )
        heldout_freeze_relative = f"{heldout_prefix}/prediction_freeze.json"
        heldout_freeze = _freeze_document(
            {
                "schema": "o1-256-o1c22-heldout-prediction-freeze-v1",
                "phase": "ALL_HELDOUT_DELTAS_SCALES_STATES_CONTROLS_AND_PREDICTIONS_FROZEN_BEFORE_LABEL_ORACLE",
                "fold_index": fold_index,
                "held_out_ordinal": fold_index,
                "held_out_target_id": target,
                "held_out_action_pool_sha256": _token(f"fold-{fold_index}-action-pool"),
                "reader_state_sha256": source_hashes[
                    f"o1c19_fold_{fold_index:02d}_reader"
                ],
                "slow_state_sha256": source_hashes[
                    f"o1c19_fold_{fold_index:02d}_slow_state"
                ],
                "upstream_prediction_freeze_sha256": source_hashes[
                    f"o1c19_fold_{fold_index:02d}_prediction_freeze"
                ],
                "quantizer_sha256": _sha(quantizer),
                "calibration_scales": [1.0] * 7,
                "active_coordinate_plan_sha256": _token(
                    f"fold-{fold_index}-coordinate-plan"
                ),
                "active_coordinate_counts": list(ACTIVE_WIDTHS),
                "prediction_arms": [
                    "raw_float_delta_sum",
                    "normalized_float_delta_sum",
                    "quantized_int8_vault",
                    "last_horizon_only",
                    "unit_sign_sum",
                    "coordinate_shuffled_vault",
                    "zero_prior",
                ],
                "calibration_label_ordinals_used_for_this_fold": training_ordinals,
                "held_out_label_used_for_this_fold": False,
                "previously_opened_build_label_ordinals": training_ordinals,
                "held_out_label_may_have_been_opened_in_other_fold": True,
                "held_out_reader_updates": 0,
                "solver_calls": 0,
            },
            payloads,
            heldout_phase,
        )
        _add_payload(
            payloads,
            heldout_freeze_relative,
            heldout_freeze,
            heldout_phase,
        )

    result = _result(source_hashes)
    _add_payload(
        payloads,
        "o1c19_causal_vault_bridge.json",
        canonical_json_bytes(result),
        "POST_FREEZE_SCORED_RESULT",
    )
    for name, size in SCORED_SHAPES.items():
        _add_payload(payloads, name, bytes(size), "POST_FREEZE_SCORED_RESULT")
    assert len(payloads) == 384
    return payloads


def _head_commit() -> str:
    completed = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def _write_synthetic_exact_capsule(capsule: Path, config: object) -> FinalizedRun:
    capsule.mkdir()
    artifacts_root = capsule / "artifacts"
    artifacts_root.mkdir()
    source_hashes = _capsule_source_hashes(config)
    payloads = _build_artifact_payloads(source_hashes)
    entries: dict[str, object] = {}
    for relative, (payload, phase) in sorted(payloads.items()):
        destination = artifacts_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
        entries[relative] = {
            "sha256": _sha(payload),
            "bytes": len(payload),
            "phase": phase,
        }
    indexed_bytes = sum(
        int(entry["bytes"])
        for entry in entries.values()  # type: ignore[index]
    )
    artifact_index = {
        "schema": "o1-256-o1c19-causal-vault-artifact-index-v1",
        "attempt_id": "O1C-0022",
        "o1c19_manifest_sha256": source_hashes["o1c19_capsule_manifest"],
        "o1c19_artifact_index_sha256": source_hashes["o1c19_artifact_index"],
        "artifacts": entries,
        "indexed_artifact_count": len(entries),
        "indexed_artifact_bytes": indexed_bytes,
    }
    index_payload = canonical_json_bytes(artifact_index)
    (artifacts_root / "artifact_index.json").write_bytes(index_payload)

    capsule_config = {
        "schema": "o1c-run-config-v1",
        "publication_protocol": "manifested-prepared-state-v1",
        "attempt_id": "O1C-0022",
        "commit": _head_commit(),
        "hypothesis": config.upstream_top["hypothesis"],
        "prediction": config.upstream_top["prediction"],
        "controls": config.upstream_top["controls"],
        "budgets": config.upstream_top["budgets"],
        "source_hashes": source_hashes,
        "claim_level": "RETROSPECTIVE",
        "next_action": config.upstream_top["next_action"],
        "config": config.upstream_top,
    }
    (capsule / "config.json").write_bytes(canonical_json_bytes(capsule_config))
    result = json.loads(payloads["o1c19_causal_vault_bridge.json"][0])
    metrics = _metrics(config, result, indexed_bytes + len(index_payload))
    outer_metrics = {
        "schema": "o1c-run-metrics-v1",
        "attempt_id": "O1C-0022",
        "status": "completed",
        "claim_level": "RETROSPECTIVE",
        "started_at": "2026-07-18T00:00:00+02:00",
        "ended_at": "2026-07-18T00:00:01+02:00",
        "elapsed_seconds": 1.0,
        "next_action": "synthetic exact contract fixture",
        "values": metrics,
    }
    (capsule / "metrics.json").write_bytes(canonical_json_bytes(outer_metrics))
    manifest_sha256 = _token("synthetic-capsule-manifest")
    verification = CapsuleVerification(
        schema="o1c-capsule-verification-v1",
        path=capsule,
        manifest_sha256=manifest_sha256,
        checked=len(entries) + 3,
        missing=(),
        mismatched=(),
        unexpected=(),
    )
    return FinalizedRun(
        attempt_id="O1C-0022",
        path=capsule,
        manifest_sha256=manifest_sha256,
        verification=verification,
    )


class O1C22PostResultComposerRunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not (ROOT.parent / "O1-O/forge/core").is_dir():
            raise unittest.SkipTest("formal sibling O1-O source is unavailable")
        cls.config = load_o1c22_postresult_composer_run_config(CONFIG, root=ROOT)
        cls.temporary = tempfile.TemporaryDirectory()
        cls.finalized = _write_synthetic_exact_capsule(
            Path(cls.temporary.name) / "synthetic-o1c22", cls.config
        )
        cls.source = _load_bound_o1c22_source(cls.config, cls.finalized)
        cls.decision = compose_postresult_decision(
            cls.source.result,
            cls.source.metrics,
            capsule_manifest_sha256=cls.source.finalized.manifest_sha256,
            quantization_diagnostics=cls.source.diagnostics,
            failure_memory=empty_failure_memory(),
        )

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "temporary"):
            cls.temporary.cleanup()

    def test_pending_preflight_exits_two_without_reserving_o1c23(self) -> None:
        reservation = ROOT / "runs/.attempt_ids/O1C-0023.json"
        existed = reservation.exists()
        with (
            patch(
                "o1_crypto_lab.o1c22_postresult_composer_run."
                "RunCapsuleManager.finalized_attempt",
                return_value=None,
            ),
            patch(
                "o1_crypto_lab.o1c22_postresult_composer_run."
                "RunCapsuleManager.recoverable_attempt_ids",
                return_value=(),
            ),
        ):
            preflight = preflight_o1c22_postresult_composer(CONFIG, root=ROOT)
        self.assertEqual(preflight.report["status"], "prerequisite-pending")
        self.assertFalse(preflight.report["o1c23_reserved_by_this_preflight"])
        self.assertEqual(reservation.exists(), existed)
        with (
            patch(
                "o1_crypto_lab.o1c22_postresult_composer_run."
                "RunCapsuleManager.finalized_attempt",
                return_value=None,
            ),
            patch(
                "o1_crypto_lab.o1c22_postresult_composer_run."
                "RunCapsuleManager.recoverable_attempt_ids",
                return_value=(),
            ),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(main(["--config", str(CONFIG), "--preflight"]), 2)
        self.assertEqual(reservation.exists(), existed)

    def test_prepared_publication_recovers_without_source_config(self) -> None:
        for status, expected_return in (
            ("completed", 0),
            ("failed", 2),
            ("stopped", 2),
        ):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                lab = Path(tmp)
                (lab / "configs").mkdir()
                missing_config = lab / "configs/o1c22_postresult_composer_v1.json"
                manager = RunCapsuleManager(lab)
                run = manager.start(
                    attempt_id="O1C-0023",
                    slug=f"prepared-{status}",
                    commit="frozen-source",
                    hypothesis="prepared recovery",
                    prediction="publication only",
                    controls=("no replay",),
                    budgets={"fresh_targets": 0},
                    source_hashes={"probe": _sha(b"prepared-recovery")},
                    claim_level=ClaimLevel.RETROSPECTIVE,
                    next_action="preserve",
                    config={"schema": "prepared-recovery-probe-v1"},
                    command=("python3", "probe.py"),
                )
                with patch(
                    "o1_crypto_lab.run_capsule.os.rename",
                    side_effect=OSError("simulated publication interruption"),
                ):
                    with self.assertRaisesRegex(
                        OSError, "simulated publication interruption"
                    ):
                        run.finalize(metrics={"probe": status}, status=status)
                self.assertTrue(manager.recover("O1C-0023").publication_prepared)
                self.assertFalse(missing_config.exists())
                output = io.StringIO()
                with redirect_stdout(output):
                    return_code = run_capsule_from_config(
                        missing_config,
                        root=lab,
                    )
                self.assertEqual(return_code, expected_return)
                finalized = manager.finalized_attempt("O1C-0023")
                self.assertIsNotNone(finalized)
                assert finalized is not None
                metrics = json.loads((finalized.path / "metrics.json").read_bytes())
                self.assertEqual(metrics["status"], status)
                self.assertEqual(metrics["values"], {"probe": status})
                self.assertIn("publication-completed-no-replay", output.getvalue())

    def test_active_execution_lease_prevents_false_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lab = Path(tmp)
            manager = RunCapsuleManager(lab)
            missing_config = lab / "configs/o1c22_postresult_composer_v1.json"
            lease_path = manager.output_root / ".attempt_ids/O1C-0023.execution.lock"
            lease_fd = os.open(lease_path, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with (
                    patch(
                        "o1_crypto_lab.o1c22_postresult_composer_run."
                        "_run_capsule_from_config_under_lease"
                    ) as delegated,
                    patch("sys.stderr", new=io.StringIO()) as error,
                ):
                    return_code = run_capsule_from_config(missing_config, root=lab)
                self.assertEqual(return_code, 2)
                delegated.assert_not_called()
                self.assertIn("active-execution-lease-held", error.getvalue())
            finally:
                os.close(lease_fd)

    def test_recovery_checkpoint_bounds_and_write_proof_are_truthful(self) -> None:
        def recover(
            payload: Mapping[str, object], config: object
        ) -> Mapping[str, object]:
            with tempfile.TemporaryDirectory() as tmp:
                staging = Path(tmp)
                checkpoint = {
                    "schema": "o1c-run-checkpoint-v1",
                    "attempt_id": "O1C-0023",
                    "updated_at": "2026-07-18T00:00:00+02:00",
                    "sequence": 1,
                    "payload": dict(payload),
                }
                (staging / "checkpoint.json").write_bytes(
                    canonical_json_bytes(checkpoint)
                )
                interrupted = type("InterruptedProbe", (), {"staging_path": staging})()
                return _interruption_recovery_metrics(config, interrupted)

        reserved = recover(
            {
                "phase": "O1C0023_RESERVED_AFTER_VALID_O1C0022_PREFLIGHT",
                "native_o1o_invocations": 0,
                "fresh_targets_consumed": 0,
                "native_solver_branches": 0,
                "scientific_entropy_calls": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            },
            None,
        )
        self.assertTrue(reserved["sibling_write_free_proven"])
        self.assertEqual(reserved["sibling_writes"], 0)
        self.assertEqual(
            reserved["structural_work_counter_semantics"],
            "exact-at-reservation-checkpoint",
        )

        core = _verify_o1o_core_sources(self.config)
        tree, entries = _tree_snapshot(self.config.o1o_repository)
        for run_index in range(2):
            with self.subTest(run_index=run_index):
                work = StructuralWorkLedger(
                    native_o1o_invocations_started=run_index + 1,
                    native_o1o_invocations_returned=run_index,
                    native_o1o_invocations_validated=run_index,
                    generated_source_ast_parses=run_index,
                )
                payload = {
                    "phase": f"O1C0023_NATIVE_GUARD_RUN_{run_index}",
                    "o1o_core_source_sha256_before": core,
                    "sibling_snapshot_sha256_before": tree,
                    "sibling_snapshot_entries_before": entries,
                    "native_core_execution_source": "disposable-byte-exact-clone",
                    "original_o1o_repository_path_disclosed_to_child": False,
                    "native_child_launch_requires_inherited_execution_lease": True,
                    "structural_work": work.document(),
                }
                metrics = recover(payload, self.config)
                self.assertTrue(metrics["sibling_write_free_proven"])
                self.assertEqual(metrics["sibling_writes"], 0)
                self.assertEqual(
                    metrics["native_o1o_invocations_entered_upper_bound"],
                    run_index + 1,
                )
                self.assertEqual(
                    metrics["native_o1o_invocations_returned_lower_bound"],
                    run_index,
                )

                missing_ledger = dict(payload)
                del missing_ledger["structural_work"]
                unproven = recover(missing_ledger, self.config)
                self.assertFalse(unproven["sibling_write_free_proven"])
                self.assertIsNone(unproven["sibling_writes"])
                self.assertEqual(unproven["sibling_mutations_observed_lower_bound"], 0)

                changed = dict(payload)
                changed["sibling_snapshot_sha256_before"] = "0" * 64
                mismatch = recover(changed, self.config)
                self.assertFalse(mismatch["sibling_write_free_proven"])
                self.assertIsNone(mismatch["sibling_writes"])
                self.assertEqual(mismatch["sibling_mutations_observed_lower_bound"], 1)

                unavailable = recover(payload, None)
                self.assertFalse(unavailable["sibling_write_free_proven"])
                self.assertIsNone(unavailable["sibling_writes"])
                self.assertEqual(
                    unavailable["sibling_mutations_observed_lower_bound"], 0
                )

    def test_exact_384_artifact_source_loads_four_bound_k256_states(self) -> None:
        self.assertEqual([row.fold_index for row in self.source.folds], list(range(4)))
        self.assertTrue(all(len(row.state_payload) == 352 for row in self.source.folds))
        self.assertEqual(self.source.diagnostics["fold_count"], 4)
        self.assertEqual(self.source.diagnostics["accepted_slots"], 3_072)
        self.assertEqual(
            self.source.diagnostics["maximum_absolute_offered_sum_per_coordinate"],
            2,
        )
        self.assertFalse(
            self.source.diagnostics["vault_saturation_structurally_reachable"]
        )
        self.assertEqual(
            self.decision["operator"]["operator_id"],
            "prospective_full256_frozen_lineage_v1",
        )

    def test_caller_fabricated_finalized_run_is_not_authoritative(self) -> None:
        forged = replace(
            self.finalized,
            manifest_sha256="0" * 64,
            verification=replace(self.finalized.verification, manifest_sha256="0" * 64),
        )
        with (
            patch(
                "o1_crypto_lab.o1c22_postresult_composer_run."
                "RunCapsuleManager.finalized_attempt",
                return_value=self.finalized,
            ),
            patch(
                "o1_crypto_lab.o1c22_postresult_composer_run.RunCapsuleManager.verify",
                return_value=self.finalized.verification,
            ),
            self.assertRaisesRegex(
                O1C22PostResultComposerRunError,
                "not the authoritative manager-verified publication",
            ),
        ):
            _load_verified_o1c22_source(self.config, forged)

    def test_semantically_minimal_fake_capsule_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            capsule = Path(temporary) / "minimal"
            capsule.mkdir()
            (capsule / "config.json").write_bytes(b"{}\n")
            (capsule / "metrics.json").write_bytes(b"{}\n")
            verification = CapsuleVerification(
                schema="o1c-capsule-verification-v1",
                path=capsule,
                manifest_sha256=_token("minimal"),
                checked=2,
                missing=(),
                mismatched=(),
                unexpected=(),
            )
            finalized = FinalizedRun(
                "O1C-0022", capsule, verification.manifest_sha256, verification
            )
            with self.assertRaisesRegex(
                O1C22PostResultComposerRunError, "frozen capsule config differs"
            ):
                _load_bound_o1c22_source(self.config, finalized)

    def test_full_index_rejects_corruption_in_otherwise_unused_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            finalized = _write_synthetic_exact_capsule(
                Path(temporary) / "synthetic-o1c22", self.config
            )
            victim = (
                finalized.path / "artifacts/folds/build-0000/heldout/k012/execution/"
                "raw_float_control.f64le"
            )
            payload = victim.read_bytes()
            victim.write_bytes(b"X" + payload[1:])
            with self.assertRaisesRegex(
                O1C22PostResultComposerRunError, "artifact index entry differs"
            ):
                _load_bound_o1c22_source(self.config, finalized)

    def test_freeze_rejects_rehashed_post_freeze_payload_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            finalized = _write_synthetic_exact_capsule(
                Path(temporary) / "synthetic-o1c22", self.config
            )
            relative = "folds/build-0000/heldout/k012/execution/raw_float_control.f64le"
            victim = finalized.path / "artifacts" / relative
            payload = victim.read_bytes()
            victim.write_bytes(b"X" + payload[1:])
            index_path = finalized.path / "artifacts/artifact_index.json"
            index = json.loads(index_path.read_bytes())
            index["artifacts"][relative]["sha256"] = _sha(victim.read_bytes())
            index_path.write_bytes(canonical_json_bytes(index))
            with self.assertRaisesRegex(
                O1C22PostResultComposerRunError,
                "freeze commitment differs",
            ):
                _load_bound_o1c22_source(self.config, finalized)

    def test_exact_operator_marker_rejects_duplicates_and_payload_tamper(self) -> None:
        marker = canonical_json_bytes(
            {
                "schema": "o1-256-o1c22-next-operator-graph-v1",
                "decision_sha256": self.decision["decision_sha256"],
                "operator_id": self.decision["operator"]["operator_id"],
                "operator_fingerprint": self.decision["operator"][
                    "operator_fingerprint"
                ],
                "information_boundary": self.decision["information_boundary"],
            }
        )
        literal = repr(marker.decode("ascii"))
        valid = (
            f"NEXT_OPERATOR_JSON = {literal}\n"
            "def selected_o1c22_operator():\n"
            "    return NEXT_OPERATOR_JSON\n"
        ).encode()
        parsed = _extract_exact_operator_marker(valid, marker)
        self.assertEqual(parsed["decision_sha256"], self.decision["decision_sha256"])
        with self.assertRaisesRegex(
            O1C22PostResultComposerRunError, "marker structure differs"
        ):
            _extract_exact_operator_marker(valid + valid, marker)
        tampered_document = json.loads(marker)
        tampered_document["operator_id"] += "-tampered"
        tampered_literal = repr(canonical_json_bytes(tampered_document).decode("ascii"))
        tampered = (
            f"NEXT_OPERATOR_JSON = {tampered_literal}\n"
            "def selected_o1c22_operator():\n"
            "    return NEXT_OPERATOR_JSON\n"
        ).encode()
        with self.assertRaisesRegex(
            O1C22PostResultComposerRunError, "marker payload differs"
        ):
            _extract_exact_operator_marker(tampered, marker)

    def test_native_o1o_double_is_isolated_deterministic_and_write_free(self) -> None:
        core_before = _verify_o1o_core_sources(self.config)
        tree_before = _tree_snapshot(self.config.o1o_repository)
        causal = encode_o1o_route(self.decision)
        fragments = encode_o1o_fragment_document(self.decision)
        work = StructuralWorkLedger()
        work.native_o1o_invocations_started += 1
        first_receipt, first_source = _run_native_o1o_once(
            self.config,
            self.decision,
            causal,
            fragments,
            work,
            run_index=0,
        )
        work.native_o1o_invocations_started += 1
        second_receipt, second_source = _run_native_o1o_once(
            self.config,
            self.decision,
            causal,
            fragments,
            work,
            run_index=1,
        )
        core_after = _verify_o1o_core_sources(self.config)
        tree_after = _tree_snapshot(self.config.o1o_repository)
        work.sibling_write_free_proven = (
            core_before == core_after and tree_before == tree_after
        )
        work.validate_success(self.config.budgets)
        self.assertEqual(first_source, second_source)
        self.assertEqual(core_before, self.config.o1o_core_sha256)
        self.assertEqual(core_before, core_after)
        self.assertEqual(tree_before, tree_after)
        self.assertEqual(
            first_receipt["generated_sha256"], second_receipt["generated_sha256"]
        )
        self.assertEqual(first_receipt["python_flags"], ["-I", "-B", "-S"])
        self.assertEqual(
            first_receipt["hash_determinism"],
            "two-independent-byte-identical-native-runs",
        )
        self.assertTrue(first_receipt["isolation"]["isolated"])
        self.assertTrue(first_receipt["isolation"]["ignore_environment"])
        self.assertTrue(first_receipt["isolation"]["no_site"])
        self.assertEqual(first_receipt["fixture_mutations"], 0)
        self.assertEqual(
            first_receipt["o1o_core_execution_source"],
            "disposable-byte-exact-clone",
        )
        self.assertFalse(
            first_receipt["original_o1o_repository_path_disclosed_to_child"]
        )
        self.assertEqual(first_receipt["self_timeout_seconds"], 35)
        self.assertGreater(first_receipt["native_cpu_seconds"], 0.0)
        self.assertGreater(first_receipt["native_peak_rss_bytes"], 0)
        self.assertFalse(first_receipt["generated_code_compiled"])
        self.assertFalse(first_receipt["generated_code_executed"])
        self.assertEqual(first_receipt["assembly_intent_raw"], "")
        self.assertEqual(first_receipt["triplet_count"], 1)
        self.assertEqual(first_receipt["fragment_count"], 1)

    def test_structural_work_ledger_rejects_declared_zero_without_proof(self) -> None:
        work = StructuralWorkLedger(
            native_o1o_invocations_started=2,
            native_o1o_invocations_returned=2,
            native_o1o_invocations_validated=2,
            generated_source_ast_parses=2,
        )
        with self.assertRaisesRegex(
            O1C22PostResultComposerRunError, "structural work differs"
        ):
            work.validate_success(self.config.budgets)
        work.sibling_write_free_proven = True
        work.validate_success(self.config.budgets)
        document = work.document()
        self.assertEqual(document["native_solver_branches"], 0)
        self.assertEqual(document["scientific_entropy_calls"], 0)
        self.assertEqual(document["fresh_targets_consumed"], 0)
        self.assertEqual(document["generated_source_bytecode_compilations"], 0)
        self.assertEqual(document["generated_source_executions"], 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
