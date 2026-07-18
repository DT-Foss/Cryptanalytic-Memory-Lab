from __future__ import annotations

import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from o1_crypto_lab.living_inverse import canonical_json_bytes
from o1_crypto_lab.o1c22_postresult_composer import (
    ACTIVE_WIDTHS,
    CONTROL_MARGIN_FIELDS,
    DECISION_SCHEMA,
    INTEGRITY_GATES,
    O1O_FRAGMENT_FILENAME,
    O1O_KNOWLEDGE_FILENAME,
    O1C22PostResultComposerError,
    PRIMARY_ARMS,
    QUANTIZATION_DIAGNOSTICS_SCHEMA,
    UPSTREAM_METRICS_SCHEMA,
    UPSTREAM_RESULT_SCHEMA,
    compose_postresult_decision,
    decision_policy,
    decision_policy_sha256,
    decode_o1o_route,
    empty_failure_memory,
    encode_o1o_fragment_document,
    encode_o1o_route,
    next_operator_graph,
    o1o_fragment_document,
    record_operator_failure,
    summarize_quantization_artifacts,
    verify_decision,
)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _result(
    *,
    classification: str = "REAL_CAUSAL_VAULT_BUILD_LOO_PASS",
    raw: tuple[float, ...] = (0.2, 0.5, 0.8, 1.4),
    normalized: tuple[float, ...] = (0.2, 0.6, 1.0, 1.5),
    int8: tuple[float, ...] = (0.1, 0.4, 0.9, 1.4),
    shuffled_margin: float = 0.5,
    last_margin: float = 0.4,
    unit_margin: float = 0.3,
    gate_overrides: dict[str, bool] | None = None,
) -> dict[str, object]:
    curves = {
        "raw_float_delta_sum": raw,
        "normalized_float_delta_sum": normalized,
        "quantized_int8_vault": int8,
    }
    arms: dict[str, object] = {}
    for arm in PRIMARY_ARMS:
        arms[arm] = {
            "widths": [
                {
                    "active_coordinates": width,
                    "mean_compression_bits": value,
                    "mean_nll_bits": 256.0 - value,
                    "mean_active_nll_bits": float(width),
                    "minimum_compression_bits": value - 0.1,
                    "maximum_compression_bits": value + 0.1,
                    "positive_folds": 4 if value > 0.0 else 0,
                }
                for width, value in zip(ACTIVE_WIDTHS, curves[arm])
            ]
        }
    gates = {name: True for name in INTEGRITY_GATES}
    gates.update(
        {
            "all_four_final_folds_positive": int8[-1] > 0.0,
            "int8_mean_final_compression_bits_minimum": int8[-1] >= 1.0,
            "int8_minus_coordinate_shuffled_mean_compression_positive": (
                shuffled_margin > 0.0
            ),
            "int8_minus_last_horizon_only_mean_compression_positive": (
                last_margin > 0.0
            ),
            "int8_minus_unit_sign_sum_mean_compression_positive": unit_margin > 0.0,
            "int8_preserves_float_compression_fraction_minimum": (
                normalized[-1] > 0.0 and int8[-1] / normalized[-1] >= 0.9
            ),
            "strict_mean_compression_growth_across_k": all(
                right > left for left, right in zip(int8[:-1], int8[1:])
            ),
            "integrity_gate_passed": True,
        }
    )
    gates.update(gate_overrides or {})
    if any(gates.get(name) is False for name in INTEGRITY_GATES):
        gates["integrity_gate_passed"] = False
    preservation = int8[-1] / normalized[-1] if normalized[-1] > 0.0 else 0.0
    margins = {
        "raw_float_mean_final_compression_bits": raw[-1],
        "normalized_float_mean_final_compression_bits": normalized[-1],
        "int8_mean_final_compression_bits": int8[-1],
        "coordinate_shuffled_mean_final_compression_bits": int8[-1] - shuffled_margin,
        "last_horizon_only_mean_final_compression_bits": int8[-1] - last_margin,
        "unit_sign_sum_mean_final_compression_bits": int8[-1] - unit_margin,
        CONTROL_MARGIN_FIELDS["coordinate_binding"]: shuffled_margin,
        CONTROL_MARGIN_FIELDS["horizon_compounding"]: last_margin,
        CONTROL_MARGIN_FIELDS["confidence_magnitude"]: unit_margin,
        "int8_preserves_normalized_float_fraction": preservation,
        "int8_mean_compression_curve_bits": list(int8),
    }
    unsigned: dict[str, object] = {
        "schema": UPSTREAM_RESULT_SCHEMA,
        "classification": classification,
        "active_coordinate_counts": list(ACTIVE_WIDTHS),
        "arms": arms,
        "margins": margins,
        "gates": gates,
        "failed_gates": sorted(
            name
            for name, passed in gates.items()
            if name != "integrity_gate_passed" and not passed
        ),
    }
    return {**unsigned, "result_sha256": _sha(canonical_json_bytes(unsigned))}


def _metrics(result: dict[str, object], *failed_budgets: str) -> dict[str, object]:
    return {
        "schema": UPSTREAM_METRICS_SCHEMA,
        "result_sha256": result["result_sha256"],
        "operationally_complete": not failed_budgets,
        "failed_budgets": sorted(failed_budgets),
    }


def _quantization_artifacts(
    *,
    quantized: tuple[int, int, int] = (1, 0, -1),
    normalized: tuple[float, float, float] = (1.0, 0.1, -1.0),
) -> tuple[bytes, bytes]:
    evidence = [0] * 256
    accepted_updates = 0
    last_group_id = (1 << 64) - 1

    def state_bytes() -> bytes:
        return (
            bytes(80)
            + bytes(value & 0xFF for value in evidence)
            + struct.pack("<QQ", last_group_id, accepted_updates)
        )

    receipts = []
    for coordinate in range(256):
        before = state_bytes()
        for value in quantized:
            if value:
                evidence[coordinate] = max(-127, min(127, evidence[coordinate] + value))
                accepted_updates += 1
        last_group_id = coordinate
        after = state_bytes()
        receipts.append(
            {
                "coordinate": coordinate,
                "quantized_deltas": list(quantized),
                "normalized_deltas_float64_hex": [value.hex() for value in normalized],
                "accepted": True,
                "primary_state_sha256_before": _sha(before),
                "primary_state_sha256_after": _sha(after),
            }
        )
    return canonical_json_bytes(receipts), state_bytes()


def _quantization_diagnostics(
    *,
    quantized: tuple[int, int, int] = (1, 0, -1),
    normalized: tuple[float, float, float] = (1.0, 0.1, -1.0),
) -> dict[str, object]:
    ledger, state = _quantization_artifacts(
        quantized=quantized,
        normalized=normalized,
    )
    return summarize_quantization_artifacts(
        (ledger, ledger, ledger, ledger),
        (state, state, state, state),
    )


def _compose(
    result: dict[str, object],
    *,
    diagnostics: dict[str, object] | None = None,
    memory: dict[str, object] | None = None,
    failed_budgets: tuple[str, ...] = (),
) -> dict[str, object]:
    return compose_postresult_decision(
        result,
        _metrics(result, *failed_budgets),
        capsule_manifest_sha256="a" * 64,
        quantization_diagnostics=diagnostics or _quantization_diagnostics(),
        failure_memory=memory,
    )


class QuantizationArtifactTests(unittest.TestCase):
    def test_real_ledger_fields_separate_zero_clip_and_unreachable_saturation(
        self,
    ) -> None:
        diagnostics = _quantization_diagnostics(
            quantized=(0, 8, -8), normalized=(0.1, 7.6, -9.0)
        )
        self.assertEqual(diagnostics["schema"], QUANTIZATION_DIAGNOSTICS_SCHEMA)
        self.assertEqual(diagnostics["fold_count"], 4)
        self.assertEqual(diagnostics["accepted_slots"], 4 * 256 * 3)
        self.assertEqual(diagnostics["zero_quantized_slots"], 4 * 256)
        self.assertEqual(diagnostics["quantizer_limit_bin_slots"], 4 * 256 * 2)
        self.assertEqual(diagnostics["clip_hits"], 4 * 256)
        self.assertEqual(diagnostics["maximum_absolute_offered_sum_per_coordinate"], 16)
        self.assertFalse(diagnostics["vault_saturation_structurally_reachable"])
        self.assertEqual(diagnostics["vault_boundary_coordinates"], 0)

    def test_noncanonical_ledger_and_forbidden_vault_byte_fail_closed(self) -> None:
        canonical, state = _quantization_artifacts()
        with self.assertRaisesRegex(O1C22PostResultComposerError, "not canonical"):
            summarize_quantization_artifacts(
                (canonical + b"\n",),
                (state,),
            )
        forbidden = state[:80] + bytes((128,)) + state[81:]
        with self.assertRaisesRegex(O1C22PostResultComposerError, "forbidden -128"):
            summarize_quantization_artifacts((canonical,), (forbidden,))

    def test_rounding_limit_bin_true_clip_and_fold_pairing_are_exact(self) -> None:
        diagnostics = _quantization_diagnostics(
            quantized=(1, 8, 8),
            normalized=(0.5, 7.5, 8.5),
        )
        self.assertEqual(diagnostics["quantizer_limit_bin_slots"], 4 * 256 * 2)
        self.assertEqual(diagnostics["clip_hits"], 4 * 256)

        first_ledger, first_state = _quantization_artifacts()
        second_ledger, second_state = _quantization_artifacts(
            quantized=(1, 1, 1),
            normalized=(1.0, 1.0, 1.0),
        )
        with self.assertRaisesRegex(
            O1C22PostResultComposerError,
            "vault differs|final receipt",
        ):
            summarize_quantization_artifacts(
                (first_ledger, second_ledger, first_ledger, second_ledger),
                (first_state, first_state, first_state, second_state),
            )


class PostResultDecisionTests(unittest.TestCase):
    def test_policy_and_identical_input_are_byte_deterministic(self) -> None:
        result = _result()
        first = _compose(result)
        second = _compose(result)
        self.assertEqual(first, second)
        self.assertEqual(first["schema"], DECISION_SCHEMA)
        self.assertEqual(first["policy_sha256"], decision_policy_sha256())
        self.assertEqual(
            decision_policy_sha256(), _sha(canonical_json_bytes(decision_policy()))
        )
        self.assertEqual(
            first["operator"]["operator_id"],  # type: ignore[index]
            "prospective_full256_frozen_lineage_v1",
        )
        self.assertTrue(first["fresh_target_proposed"])
        self.assertFalse(first["fresh_target_authorized"])
        self.assertEqual(verify_decision(first), first)

    def test_operational_and_integrity_override_all_scientific_routes(self) -> None:
        result = _result()
        operational = _compose(result, failed_budgets=("wall",))
        self.assertEqual(
            operational["operator"]["operator_id"],  # type: ignore[index]
            "repair_operational_replay_v1",
        )
        integrity_result = _result(
            classification="INTEGRITY_OR_LIFECYCLE_FAILURE",
            gate_overrides={"all_predictions_finite": False},
        )
        integrity = _compose(integrity_result)
        self.assertEqual(
            integrity["operator"]["operator_id"],  # type: ignore[index]
            "repair_integrity_lifecycle_v1",
        )
        self.assertIn(
            "all_predictions_finite",
            integrity["reason_metrics"]["failed_integrity_gates"],  # type: ignore[index]
        )

    def test_every_real_integrity_gate_names_its_exact_repair_surface(self) -> None:
        diagnostics = _quantization_diagnostics()
        for gate in INTEGRITY_GATES:
            with self.subTest(gate=gate):
                result = _result(
                    classification="INTEGRITY_OR_LIFECYCLE_FAILURE",
                    gate_overrides={gate: False},
                )
                decision = _compose(result, diagnostics=diagnostics)
                self.assertEqual(
                    decision["reason_metrics"][  # type: ignore[index]
                        "failed_integrity_gates"
                    ],
                    [gate],
                )

    def test_true_continuous_width_collapse_routes_banked_coordinates(self) -> None:
        result = _result(
            classification="CROSS_COORDINATE_DILUTION",
            raw=(0.2, 0.1, 0.0, -0.2),
            normalized=(0.4, 0.8, 0.2, -0.3),
            int8=(0.2, 0.7, 0.1, -0.4),
        )
        decision = _compose(result)
        self.assertEqual(
            decision["operator"]["operator_id"],  # type: ignore[index]
            "banked_coordinate_chunks_v1",
        )
        self.assertEqual(decision["reason_metrics"]["best_positive_sub_k"], 52)  # type: ignore[index]

    def test_frozen_dilution_precedence_collision_routes_quantizer(self) -> None:
        result = _result(
            classification="CROSS_COORDINATE_DILUTION",
            raw=(0.2, 0.4, 0.8, 1.3),
            normalized=(0.3, 0.5, 0.9, 1.2),
            int8=(0.2, 0.4, 0.1, -0.2),
        )
        decision = _compose(result)
        self.assertEqual(
            decision["operator"]["operator_id"],  # type: ignore[index]
            "quantizer_precision_clip_ladder_v1",
        )
        self.assertTrue(
            decision["reason_metrics"][  # type: ignore[index]
                "vault_saturation_ruled_out_by_exact_replay"
            ]
        )

    def test_single_fold_only_sub_k_signal_routes_stability_before_banking(
        self,
    ) -> None:
        result = _result(
            classification="CROSS_COORDINATE_DILUTION",
            raw=(-0.3, -0.3, -0.3, -0.2),
            normalized=(-0.05, -0.3, -0.3, -0.2),
            int8=(-0.3, -0.3, -0.3, -0.2),
        )
        decision = _compose(result)
        self.assertEqual(
            decision["operator"]["operator_id"],  # type: ignore[index]
            "fold_growth_stability_v1",
        )
        self.assertTrue(
            decision["reason_metrics"][  # type: ignore[index]
                "only_single_fold_sub_k_signal_without_positive_mean"
            ]
        )

    def test_raw_only_sub_k_mean_and_single_fold_preserve_reader(self) -> None:
        mean_result = _result(
            classification="NO_REAL_PACKET_SIGNAL",
            raw=(0.2, 0.3, 0.1, -0.2),
            normalized=(-0.3, -0.3, -0.3, -0.2),
            int8=(-0.3, -0.3, -0.3, -0.2),
        )
        mean_decision = _compose(mean_result)
        self.assertEqual(
            mean_decision["operator"]["operator_id"],  # type: ignore[index]
            "banked_coordinate_chunks_v1",
        )
        self.assertFalse(
            mean_decision["operator"]["uses_a539_a541_transfer"]  # type: ignore[index]
        )

        fold_result = _result(
            classification="NO_REAL_PACKET_SIGNAL",
            raw=(-0.05, -0.3, -0.3, -0.2),
            normalized=(-0.3, -0.3, -0.3, -0.2),
            int8=(-0.3, -0.3, -0.3, -0.2),
        )
        self.assertEqual(
            _compose(fold_result)["operator"]["operator_id"],  # type: ignore[index]
            "fold_growth_stability_v1",
        )

    def test_surviving_int8_k256_overrides_normalized_width_collapse(self) -> None:
        result = _result(
            classification="NO_REAL_PACKET_SIGNAL",
            raw=(-0.3, -0.3, -0.3, -0.2),
            normalized=(0.2, 0.3, 0.1, -0.2),
            int8=(-0.2, -0.1, 0.0, 0.3),
        )
        decision = _compose(result)
        self.assertEqual(
            decision["operator"]["operator_id"],  # type: ignore[index]
            "quantized_denoising_replication_v1",
        )

    def test_all_float_null_preserves_int8_denoising_exception(self) -> None:
        denoising_result = _result(
            classification="NO_REAL_PACKET_SIGNAL",
            raw=(-0.2, -0.1, -0.2, -0.1),
            normalized=(-0.3, -0.2, -0.1, -0.2),
            int8=(-0.1, 0.0, 0.2, 0.3),
        )
        denoising = _compose(denoising_result)
        self.assertEqual(
            denoising["operator"]["operator_id"],  # type: ignore[index]
            "quantized_denoising_replication_v1",
        )
        self.assertFalse(
            denoising["operator"]["uses_a539_a541_transfer"]  # type: ignore[index]
        )

        null_result = _result(
            classification="NO_REAL_PACKET_SIGNAL",
            raw=(-0.2, -0.1, -0.2, -0.1),
            normalized=(-0.3, -0.2, -0.1, -0.2),
            int8=(-0.2, -0.1, -0.3, -0.4),
        )
        null = _compose(null_result)
        self.assertEqual(
            null["operator"]["operator_id"],  # type: ignore[index]
            "proof_ancestry_pair_residual_v1",
        )
        self.assertTrue(
            null["operator"]["uses_a539_a541_transfer"]  # type: ignore[index]
        )

    def test_scale_and_worst_control_margin_have_unique_routes(self) -> None:
        scale_result = _result(
            classification="SCALE_WEIGHTING_FAILURE",
            raw=(0.1, 0.3, 0.7, 1.0),
            normalized=(-0.1, -0.2, -0.1, -0.3),
            int8=(-0.2, -0.1, -0.2, -0.4),
        )
        self.assertEqual(
            _compose(scale_result)["operator"]["operator_id"],  # type: ignore[index]
            "horizon_nonnegative_simplex_v1",
        )

        quantizer_result = _result(
            classification="QUANTIZATION_OR_SATURATION_FAILURE",
            raw=(-0.4, -0.3, -0.2, 1.0),
            normalized=(-0.4, -0.3, -0.2, 1.0),
            int8=(-0.4, -0.3, -0.2, 0.2),
        )
        self.assertEqual(
            _compose(quantizer_result)["operator"]["operator_id"],  # type: ignore[index]
            "quantizer_precision_clip_ladder_v1",
        )
        control_result = _result(
            classification="CONTROL_SPECIFICITY_FAILURE",
            shuffled_margin=-0.2,
            last_margin=-0.8,
            unit_margin=-0.4,
        )
        control = _compose(control_result)
        self.assertEqual(
            control["operator"]["operator_id"],  # type: ignore[index]
            "horizon_surprise_compounding_v1",
        )
        axes = control["reason_metrics"]["ordered_failed_control_axes"]  # type: ignore[index]
        self.assertEqual(
            [row["axis"] for row in axes],
            ["horizon_compounding", "confidence_magnitude", "coordinate_binding"],
        )

    def test_failure_memory_closes_exact_context_but_not_entire_mechanism(self) -> None:
        result = _result(
            classification="NO_REAL_PACKET_SIGNAL",
            raw=(-0.2, -0.1, -0.2, -0.1),
            normalized=(-0.3, -0.2, -0.1, -0.2),
            int8=(-0.2, -0.1, -0.3, -0.4),
        )
        first = _compose(result)
        memory = record_operator_failure(
            empty_failure_memory(),
            first,
            outcome="NO_LIFT",
            evidence_sha256="b" * 64,
            capsule_manifest_sha256="c" * 64,
        )
        second = _compose(result, memory=memory)
        self.assertEqual(
            second["operator"]["operator_id"],  # type: ignore[index]
            "exact_contradiction_antecedent_reader_v1",
        )
        self.assertEqual(
            second["closed_candidates_skipped"],
            [first["operator"]["operator_fingerprint"]],  # type: ignore[index]
        )
        changed_result = _result(
            classification="NO_REAL_PACKET_SIGNAL",
            raw=(-0.4, -0.3, -0.2, -0.1),
            normalized=(-0.5, -0.4, -0.3, -0.2),
            int8=(-0.5, -0.4, -0.3, -0.2),
        )
        changed = _compose(changed_result, memory=memory)
        self.assertEqual(
            changed["operator"]["operator_id"],  # type: ignore[index]
            "proof_ancestry_pair_residual_v1",
        )

    def test_operational_failure_does_not_close_science_and_cross_never_uses_transfer(
        self,
    ) -> None:
        result = _result(
            classification="CROSS_COORDINATE_DILUTION",
            raw=(0.2, 0.1, 0.0, -0.2),
            normalized=(0.4, 0.8, 0.2, -0.3),
            int8=(0.2, 0.7, 0.1, -0.4),
        )
        first = _compose(result)
        operational_memory = record_operator_failure(
            empty_failure_memory(),
            first,
            outcome="OPERATIONAL_FAILURE",
            evidence_sha256="e" * 64,
            capsule_manifest_sha256="f" * 64,
        )
        replay = _compose(result, memory=operational_memory)
        self.assertEqual(
            replay["operator"]["operator_fingerprint"],  # type: ignore[index]
            first["operator"]["operator_fingerprint"],  # type: ignore[index]
        )

        scientific_memory = record_operator_failure(
            empty_failure_memory(),
            first,
            outcome="NO_LIFT",
            evidence_sha256="1" * 64,
            capsule_manifest_sha256="2" * 64,
        )
        fallback = _compose(result, memory=scientific_memory)
        self.assertEqual(
            fallback["operator"]["operator_id"],  # type: ignore[index]
            "fold_growth_stability_v1",
        )
        self.assertFalse(
            fallback["operator"]["uses_a539_a541_transfer"]  # type: ignore[index]
        )

    def test_result_decision_and_memory_tampering_fail_closed(self) -> None:
        result = _result()
        tampered_result = dict(result)
        tampered_result["classification"] = "NO_REAL_PACKET_SIGNAL"
        with self.assertRaisesRegex(O1C22PostResultComposerError, "result digest"):
            _compose(tampered_result)

        decision = _compose(result)
        decision["fresh_target_proposed"] = False
        with self.assertRaisesRegex(O1C22PostResultComposerError, "decision digest"):
            verify_decision(decision)

        memory = empty_failure_memory()
        memory["entries"] = [{}]
        with self.assertRaisesRegex(O1C22PostResultComposerError, "memory digest"):
            _compose(result, memory=memory)

    def test_rehashed_inconsistent_result_and_self_consistent_unknown_operator_fail(
        self,
    ) -> None:
        result = _result()
        inconsistent = dict(result)
        inconsistent["classification"] = "NO_REAL_PACKET_SIGNAL"
        inconsistent.pop("result_sha256")
        inconsistent["result_sha256"] = _sha(canonical_json_bytes(inconsistent))
        with self.assertRaisesRegex(O1C22PostResultComposerError, "frozen precedence"):
            _compose(inconsistent)

        gate_inconsistent = json.loads(json.dumps(result))
        gate_inconsistent["gates"]["strict_mean_compression_growth_across_k"] = False
        gate_inconsistent["failed_gates"] = ["strict_mean_compression_growth_across_k"]
        gate_inconsistent.pop("result_sha256")
        gate_inconsistent["result_sha256"] = _sha(
            canonical_json_bytes(gate_inconsistent)
        )
        with self.assertRaisesRegex(O1C22PostResultComposerError, "efficacy gate"):
            _compose(gate_inconsistent)

        forged = json.loads(json.dumps(_compose(result)))
        forged_operator = forged["operator"]
        forged_operator["operator_id"] = "arbitrary_unregistered_v1"
        forged_operator["fragment_key"] = "o1c22_op_arbitrary_unregistered_v1"
        instance = dict(forged_operator)
        instance.pop("operator_fingerprint")
        instance.pop("decision_token")
        forged_fingerprint = _sha(canonical_json_bytes(instance))
        forged_operator["operator_fingerprint"] = forged_fingerprint
        forged_operator["decision_token"] = f"o1c22d-{forged_fingerprint[:24]}"
        forged["o1o"]["decision_token"] = forged_operator["decision_token"]
        forged["o1o"]["expected_fragment_key"] = forged_operator["fragment_key"]
        forged.pop("decision_sha256")
        forged["decision_sha256"] = _sha(canonical_json_bytes(forged))
        with self.assertRaisesRegex(O1C22PostResultComposerError, "not registered"):
            verify_decision(forged)


class O1ORouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.decision = _compose(_result())

    def test_single_token_causal_route_and_data_only_fragment_are_bound(self) -> None:
        causal = encode_o1o_route(self.decision)
        graph = decode_o1o_route(causal, decision=self.decision)
        triplet = graph["triplets"][0]  # type: ignore[index]
        self.assertEqual(
            triplet["trigger"],
            self.decision["operator"]["decision_token"],  # type: ignore[index]
        )
        self.assertEqual(
            triplet["outcome"],
            self.decision["operator"]["fragment_key"],  # type: ignore[index]
        )
        fragments = o1o_fragment_document(self.decision)
        self.assertEqual(
            list(fragments),
            [self.decision["operator"]["fragment_key"]],  # type: ignore[index]
        )
        code = next(iter(fragments.values()))["code"]  # type: ignore[index]
        namespace: dict[str, object] = {}
        exec(compile(code, "o1c22_operator.py", "exec"), namespace)
        marker = json.loads(namespace["selected_o1c22_operator"]())  # type: ignore[operator]
        self.assertEqual(marker["decision_sha256"], self.decision["decision_sha256"])

        operator_graph = next_operator_graph(
            self.decision,
            causal_sha256=_sha(causal),
            fragment_sha256=_sha(encode_o1o_fragment_document(self.decision)),
            native_generated_sha256="d" * 64,
        )
        self.assertEqual(operator_graph["resources"]["sibling_writes"], 0)  # type: ignore[index]
        self.assertEqual(operator_graph["resources"]["fresh_target_consumed"], 0)  # type: ignore[index]

    def test_causal_semantic_tampering_is_rejected(self) -> None:
        causal = bytearray(encode_o1o_route(self.decision))
        causal[-1] ^= 1
        with self.assertRaises(O1C22PostResultComposerError):
            decode_o1o_route(bytes(causal), decision=self.decision)

    def test_optional_native_o1o_exact_route_and_static_assembly(self) -> None:
        configured = os.environ.get("O1O_FORGE_ROOT")
        if not configured:
            self.skipTest("set O1O_FORGE_ROOT to run native O1-O integration")
        forge_root = Path(configured).resolve()
        if (forge_root / "forge" / "core").is_dir():
            forge_root = forge_root / "forge"
        if not (forge_root / "core").is_dir():
            self.fail("O1O_FORGE_ROOT must name the repository or forge directory")
        child = r"""
import hashlib
import json
import sys
from pathlib import Path

forge = Path(sys.argv[1])
sys.path.insert(0, str(forge))
from core.code_assembler import CodeAssembler
from core.knowledge_engine import KnowledgeEngine

knowledge = KnowledgeEngine(Path(sys.argv[2]))
knowledge.zero_shot = True
selection_intent = {
    "raw": sys.argv[4], "entities": [], "tokens": [], "params": {},
    "mode": "BUILD", "confidence": 1.0, "requires_output": False,
}
paths = knowledge.infer(selection_intent, top_k=1)
if len(paths) != 1 or len(paths[0]) != 1:
    raise RuntimeError("native route is not singular")
triplet = paths[0][0]["triplet"]
if triplet.get("_source_graph") != "bridge_intents":
    raise RuntimeError("native route source differs")
assembler = CodeAssembler(Path(sys.argv[3]), knowledge)
assembly_intent = {
    "raw": "", "entities": [], "tokens": [], "params": {},
    "mode": "BUILD", "confidence": 1.0, "requires_output": False,
}
generated = assembler.assemble(paths[0], assembly_intent)
compile(generated, "native_o1c22_operator.py", "exec")
print(json.dumps({
    "outcome": triplet["outcome"],
    "source": triplet["_source_graph"],
    "used": assembler.last_used_fragments,
    "generated_sha256": hashlib.sha256(generated.encode()).hexdigest(),
}, sort_keys=True))
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            knowledge = root / "knowledge"
            fragments = root / "fragments"
            knowledge.mkdir()
            fragments.mkdir()
            (knowledge / O1O_KNOWLEDGE_FILENAME).write_bytes(
                encode_o1o_route(self.decision)
            )
            (fragments / O1O_FRAGMENT_FILENAME).write_bytes(
                encode_o1o_fragment_document(self.decision)
            )
            before = {
                path.relative_to(root).as_posix(): _sha(path.read_bytes())
                for path in root.rglob("*")
                if path.is_file()
            }
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    child,
                    str(forge_root),
                    str(knowledge),
                    str(fragments),
                    self.decision["operator"]["decision_token"],  # type: ignore[index]
                ],
                cwd=root,
                env={
                    **os.environ,
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONHASHSEED": "0",
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                check=False,
            )
            after = {
                path.relative_to(root).as_posix(): _sha(path.read_bytes())
                for path in root.rglob("*")
                if path.is_file()
            }
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(before, after)
        native = json.loads(completed.stdout.splitlines()[-1])
        expected = self.decision["operator"]["fragment_key"]  # type: ignore[index]
        self.assertEqual(native["source"], "bridge_intents")
        self.assertEqual(native["outcome"], expected)
        self.assertEqual(native["used"], [expected])
        self.assertEqual(len(native["generated_sha256"]), 64)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
