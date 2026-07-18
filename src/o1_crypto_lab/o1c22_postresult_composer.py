"""Deterministic O1C-0022 result-to-operator composition for O1C-0023.

O1C-0022 is source-frozen and intentionally remains unchanged.  Its result
classification has useful precedence, but some labels collapse distinct
mechanisms.  This module consumes the complete, hash-bound result surface and
emits one canonical *proposal* for the next experiment.  It never changes the
revealed O1C-0022 target or spends a fresh target.

The scientific decision stays in this strict lab-owned policy.  O1-O receives
only an opaque decision token in a disposable ``bridge_intents.causal`` graph,
selects one data-only fragment, and is checked against the reference route.
Failure memory is supplied as canonical records from already finalized run
capsules; there is no mutable global blacklist or autonomous code execution.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
import zlib
from dataclasses import dataclass
from typing import Final, Mapping, Sequence

from .living_inverse import canonical_json_bytes
from .o1o_public_fsm_bridge import (
    CAUSAL_MAGIC,
    CAUSAL_VERSION,
    _pack_messagepack,
    _safe_decompress,
    _unpack_messagepack,
)


ATTEMPT_ID: Final = "O1C-0023"
UPSTREAM_ATTEMPT_ID: Final = "O1C-0022"
UPSTREAM_RESULT_SCHEMA: Final = "o1-256-o1c19-causal-vault-bridge-result-v1"
UPSTREAM_METRICS_SCHEMA: Final = "o1-256-o1c19-causal-vault-bridge-cli-result-v1"
POLICY_SCHEMA: Final = "o1-256-o1c22-postresult-decision-policy-v1"
DECISION_SCHEMA: Final = "o1-256-o1c22-postresult-decision-v1"
FAILURE_MEMORY_SCHEMA: Final = "o1-256-o1c22-operator-failure-memory-v1"
QUANTIZATION_DIAGNOSTICS_SCHEMA: Final = "o1-256-o1c22-quantization-diagnostics-v1"
OPERATOR_GRAPH_SCHEMA: Final = "o1-256-o1c22-next-operator-graph-v1"
O1O_GRAPH_SCHEMA: Final = "o1-256-o1c22-next-operator-routes-v1"
O1O_FRAGMENT_SCHEMA: Final = "o1-256-o1c22-next-operator-fragments-v1"
O1O_KNOWLEDGE_FILENAME: Final = "bridge_intents.causal"
O1O_FRAGMENT_FILENAME: Final = "o1c22_next_operator_fragments.json"

ACTIVE_WIDTHS: Final = (12, 52, 128, 256)
PRIMARY_ARMS: Final = (
    "raw_float_delta_sum",
    "normalized_float_delta_sum",
    "quantized_int8_vault",
)
CONTROL_MARGIN_FIELDS: Final = {
    "coordinate_binding": (
        "int8_minus_coordinate_shuffled_mean_final_compression_bits"
    ),
    "horizon_compounding": ("int8_minus_last_horizon_only_mean_final_compression_bits"),
    "confidence_magnitude": ("int8_minus_unit_sign_sum_mean_final_compression_bits"),
}
SUPPORTED_CLASSIFICATIONS: Final = frozenset(
    {
        "INTEGRITY_OR_LIFECYCLE_FAILURE",
        "CROSS_COORDINATE_DILUTION",
        "NO_REAL_PACKET_SIGNAL",
        "SCALE_WEIGHTING_FAILURE",
        "QUANTIZATION_OR_SATURATION_FAILURE",
        "CONTROL_SPECIFICITY_FAILURE",
        "REAL_CAUSAL_VAULT_BUILD_LOO_PASS",
    }
)
INTEGRITY_GATES: Final = (
    "all_fold_calibration_predictions_frozen_before_that_folds_calibration_label_use",
    "all_fold_heldout_predictions_frozen_before_that_folds_heldout_label_use",
    "every_fold_excludes_its_heldout_label_from_calibration",
    "all_primary_live_states_exactly_352_bytes",
    "all_predictions_finite",
    "all_duplicate_groups_full_state_byte_invariant",
    "actual_polarity_swapped_pool_delta_and_logit_antisymmetry",
    "coordinate_permutation_commutes_with_accumulation",
    "calibration_scales_nonnegative_without_orientation_flip",
    "matched_public_packet_work_for_all_derived_arms",
    "zero_solver_entropy_sibling_mps_gpu_work",
    "reader_replays_exact",
    "packet_slot_observations_exact",
    "physical_public_work_units_exact",
    "calibration_value_evaluations_exact",
)
ROBUSTNESS_GATES: Final = (
    "all_four_final_folds_positive",
    "int8_mean_final_compression_bits_minimum",
    "strict_mean_compression_growth_across_k",
)
EFFICACY_GATES: Final = (
    "all_four_final_folds_positive",
    "int8_mean_final_compression_bits_minimum",
    "int8_minus_coordinate_shuffled_mean_compression_positive",
    "int8_minus_last_horizon_only_mean_compression_positive",
    "int8_minus_unit_sign_sum_mean_compression_positive",
    "int8_preserves_float_compression_fraction_minimum",
    "strict_mean_compression_growth_across_k",
)
_HEX = frozenset("0123456789abcdef")
_MAX_CAUSAL_BYTES: Final = 64 * 1024
_MAX_GRAPH_BYTES: Final = 32 * 1024


class O1C22PostResultComposerError(ValueError):
    """The result, policy, memory, diagnostic, or O1-O route differs."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX for character in value)
    ):
        raise O1C22PostResultComposerError(f"{field} must be lowercase SHA-256")
    return value


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise O1C22PostResultComposerError(f"{field} must be an object")
    return value


def _sequence(value: object, field: str) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise O1C22PostResultComposerError(f"{field} must be a sequence")
    return value


def _number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise O1C22PostResultComposerError(f"{field} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise O1C22PostResultComposerError(f"{field} must be finite")
    return result


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise O1C22PostResultComposerError(
            f"{field} must be an integer in [{minimum},{maximum}]"
        )
    return value


@dataclass(frozen=True)
class OperatorTemplate:
    """One frozen, data-only successor mechanism."""

    rule_id: str
    operator_id: str
    mechanism: str
    next_attempt_kind: str
    preserved_components: tuple[str, ...]
    replaced_components: tuple[str, ...]
    target_consumption: str
    uses_a539_a541_transfer: bool = False

    @property
    def fragment_key(self) -> str:
        return f"o1c22_op_{self.operator_id}"

    def describe(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "operator_id": self.operator_id,
            "mechanism": self.mechanism,
            "next_attempt_kind": self.next_attempt_kind,
            "preserved_components": list(self.preserved_components),
            "replaced_components": list(self.replaced_components),
            "target_consumption": self.target_consumption,
            "uses_a539_a541_transfer": self.uses_a539_a541_transfer,
            "fragment_key": self.fragment_key,
        }


_TEMPLATES: Final = {
    "operational_replay": OperatorTemplate(
        "R00_OPERATIONAL",
        "repair_operational_replay_v1",
        "Repair only failed resource/publication accounting and replay identical science.",
        "O1C22_EXACT_OPERATIONAL_REPLAY",
        ("reader", "packet_deltas", "quantizer", "vault", "efficacy_policy"),
        ("failed_operational_surface",),
        "NONE",
    ),
    "integrity_replay": OperatorTemplate(
        "R01_INTEGRITY",
        "repair_integrity_lifecycle_v1",
        "Repair the first frozen lifecycle or algebraic invariant and replay exact science.",
        "O1C22_INTEGRITY_RECOVERY_REPLAY",
        ("scientific_inputs", "reader", "quantizer", "vault", "work_budget"),
        ("failed_integrity_surface",),
        "NONE",
    ),
    "cross_coordinate": OperatorTemplate(
        "R02_WIDTH_COLLAPSE",
        "banked_coordinate_chunks_v1",
        "Reset upstream fast state between deterministic coordinate banks and merge into the same addressed vault.",
        "O1C22_CHUNK_RESET_K256",
        ("reader_weights", "quantizer", "packet_deltas", "352_byte_vault"),
        ("cross_coordinate_fast_state_schedule",),
        "CONSUMED_BUILD_ONLY",
    ),
    "scale_simplex": OperatorTemplate(
        "R03_SCALE",
        "horizon_nonnegative_simplex_v1",
        "Fit a frozen nonnegative h64/h65/h96 simplex on consumed BUILD folds.",
        "O1C22_HORIZON_SIMPLEX",
        ("reader", "raw_packet_deltas", "coordinate_binding", "vault"),
        ("horizon_scale_weighting",),
        "CONSUMED_BUILD_ONLY",
    ),
    "quantized_denoising": OperatorTemplate(
        "R04_QUANTIZED_DENOISING",
        "quantized_denoising_replication_v1",
        "Replicate the nonlinear int8-only signal before replacing the continuous reader.",
        "O1C22_QUANTIZED_DENOISING_REPLICATION",
        ("reader", "quantizer", "vault", "coordinate_binding"),
        ("replication_scope",),
        "CONSUMED_BUILD_ONLY",
    ),
    "quantizer_resolution": OperatorTemplate(
        "R05_QUANTIZER",
        "quantizer_precision_clip_ladder_v1",
        "Compare an int16 ceiling with a fixed symmetric precision/clip ladder at equal deltas and work.",
        "O1C22_QUANTIZER_LADDER",
        ("reader", "normalized_packet_deltas", "coordinate_binding"),
        ("quantizer_precision_and_clip",),
        "CONSUMED_BUILD_ONLY",
    ),
    "vault_multislot": OperatorTemplate(
        "R06_VAULT_SATURATION",
        "multislot_residual_vault_v1",
        "Split bounded residual magnitude across deterministic vault slots without changing the reader.",
        "O1C22_MULTISLOT_RESIDUAL_VAULT",
        ("reader", "normalized_packet_deltas", "quantizer_orientation"),
        ("single_slot_int8_vault",),
        "CONSUMED_BUILD_ONLY",
    ),
    "interaction_reader": OperatorTemplate(
        "R07_SENSOR_NULL",
        "proof_ancestry_pair_residual_v1",
        "Replace unary packet evidence with projected signed-variable pairs bound to proof ancestry and exact contradictions.",
        "O1C22_PROOF_ANCESTRY_PAIR_RESIDUAL",
        ("public_FAP", "coordinate_vault", "equal_work", "BUILD_LOO_lifecycle"),
        ("unary_packet_reader",),
        "CONSUMED_BUILD_ONLY",
        True,
    ),
    "contradiction_reader": OperatorTemplate(
        "R07B_SENSOR_NULL_FALLBACK",
        "exact_contradiction_antecedent_reader_v1",
        "Preserve proof identity but isolate antecedent-rooted exact contradiction events.",
        "O1C22_EXACT_CONTRADICTION_READER",
        ("public_FAP", "coordinate_vault", "equal_work", "BUILD_LOO_lifecycle"),
        ("unary_packet_reader",),
        "CONSUMED_BUILD_ONLY",
        True,
    ),
    "binding": OperatorTemplate(
        "R08_BINDING_CONTROL",
        "coordinate_phase_binding_repair_v1",
        "Replace coordinate routing with a hash-bound phase/address map while preserving evidence values.",
        "O1C22_BINDING_REPAIR",
        ("reader", "quantizer", "packet_order", "vault_width"),
        ("coordinate_binding",),
        "CONSUMED_BUILD_ONLY",
    ),
    "compounding": OperatorTemplate(
        "R09_COMPOUND_CONTROL",
        "horizon_surprise_compounding_v1",
        "Gate redundant horizons by public surprise so independent packets compound and duplicates do not.",
        "O1C22_COMPOUNDING_REPAIR",
        ("reader", "quantizer", "coordinate_binding", "vault_width"),
        ("horizon_compounding_gate",),
        "CONSUMED_BUILD_ONLY",
    ),
    "confidence": OperatorTemplate(
        "R10_CONFIDENCE_CONTROL",
        "magnitude_confidence_calibration_v1",
        "Repair magnitude calibration while keeping signs, addresses and packet order fixed.",
        "O1C22_CONFIDENCE_REPAIR",
        ("reader_sign", "coordinate_binding", "packet_order", "vault_width"),
        ("magnitude_confidence",),
        "CONSUMED_BUILD_ONLY",
    ),
    "robustness": OperatorTemplate(
        "R11_ROBUSTNESS",
        "fold_growth_stability_v1",
        "Use a fixed fold-by-width stability objective without opening a new target.",
        "O1C22_FOLD_GROWTH_STABILITY",
        ("reader", "quantizer", "coordinate_binding", "vault"),
        ("fold_robustness_selection",),
        "CONSUMED_BUILD_ONLY",
    ),
    "prospective": OperatorTemplate(
        "R12_PASS",
        "prospective_full256_frozen_lineage_v1",
        "Freeze an all-BUILD deployment lineage and attack exactly one newly brokered untouched full-round 256-bit target.",
        "O1C22_PROSPECTIVE_FULL256",
        ("passed_reader", "passed_quantizer", "passed_vault", "all_passed_controls"),
        ("retrospective_fold_wrapper",),
        "ONE_NEWLY_BROKERED_TARGET",
    ),
    "policy_extension": OperatorTemplate(
        "R99_EXHAUSTED",
        "novel_policy_extension_required_v1",
        "Refuse an identical closed successor and require a source-frozen novel mechanism.",
        "O1C22_POLICY_EXTENSION",
        ("source_result", "failure_memory", "closed_breadcrumbs"),
        ("decision_policy",),
        "NONE",
    ),
}


def decision_policy() -> dict[str, object]:
    """Return the complete pre-result routing policy as canonical data."""

    return {
        "schema": POLICY_SCHEMA,
        "upstream_attempt_id": UPSTREAM_ATTEMPT_ID,
        "active_widths": list(ACTIVE_WIDTHS),
        "classification_is_diagnostic_input_not_sole_authority": True,
        "ordered_rules": [
            "operational_completion",
            "integrity_and_lifecycle",
            "continuous_or_quantized_cross_width_collapse",
            "all_float_null_with_int8_denoising_exception",
            "raw_positive_normalized_nonpositive_scale_failure",
            "normalized_positive_int8_loss_quantizer_or_vault",
            "worst_failed_matched_control_fixed_lexicographic_tie",
            "cross_fold_effect_and_growth_robustness",
            "prospective_fresh_target_after_full_pass",
        ],
        "control_margin_fields": dict(sorted(CONTROL_MARGIN_FIELDS.items())),
        "integrity_gate_priority": list(INTEGRITY_GATES),
        "robustness_gate_priority": list(ROBUSTNESS_GATES),
        "templates": {
            key: template.describe() for key, template in sorted(_TEMPLATES.items())
        },
        "a539_a541_allowed_only_for_templates": [
            "contradiction_reader",
            "interaction_reader",
        ],
        "failure_memory_scope": (
            "exact source-result plus operator-instance fingerprint from verified finalized capsules"
        ),
        "o1o_role": "disposable-native-causal-selection-and-data-only-fragment-assembly",
        "o1o_is_not_scientific_decision_authority": True,
    }


def decision_policy_sha256() -> str:
    return _sha256_bytes(canonical_json_bytes(decision_policy()))


def empty_failure_memory() -> dict[str, object]:
    unsigned = {
        "schema": FAILURE_MEMORY_SCHEMA,
        "source_capsule_manifests": [],
        "entries": [],
    }
    return {
        **unsigned,
        "failure_memory_sha256": _sha256_bytes(canonical_json_bytes(unsigned)),
    }


def _closed_operator_fingerprints(memory: object) -> tuple[str, ...]:
    row = _mapping(memory, "failure_memory")
    expected = {
        "schema",
        "source_capsule_manifests",
        "entries",
        "failure_memory_sha256",
    }
    if set(row) != expected or row.get("schema") != FAILURE_MEMORY_SCHEMA:
        raise O1C22PostResultComposerError("failure memory schema or fields differ")
    unsigned = {key: row[key] for key in expected if key != "failure_memory_sha256"}
    expected_digest = _sha256_bytes(canonical_json_bytes(unsigned))
    if row.get("failure_memory_sha256") != expected_digest:
        raise O1C22PostResultComposerError("failure memory digest differs")
    raw_manifests = _sequence(row["source_capsule_manifests"], "source manifests")
    manifests = [
        _sha256(value, f"source_capsule_manifests[{index}]")
        for index, value in enumerate(raw_manifests)
    ]
    if manifests != sorted(set(manifests)):
        raise O1C22PostResultComposerError("source capsule manifests are not canonical")
    entries = _sequence(row["entries"], "failure entries")
    closed: list[str] = []
    previous_key: tuple[str, str, str, str, str] | None = None
    entry_manifests: set[str] = set()
    for index, value in enumerate(entries):
        entry = _mapping(value, f"failure entries[{index}]")
        if set(entry) != {
            "source_result_sha256",
            "operator_fingerprint",
            "outcome",
            "evidence_sha256",
            "capsule_manifest_sha256",
        }:
            raise O1C22PostResultComposerError("failure entry fields differ")
        source = _sha256(entry["source_result_sha256"], "source_result_sha256")
        fingerprint = _sha256(entry["operator_fingerprint"], "operator_fingerprint")
        evidence = _sha256(entry["evidence_sha256"], "evidence_sha256")
        capsule = _sha256(entry["capsule_manifest_sha256"], "capsule_manifest_sha256")
        outcome = entry["outcome"]
        if outcome not in {"NO_LIFT", "FAILED", "OPERATIONAL_FAILURE"}:
            raise O1C22PostResultComposerError("failure outcome differs")
        key = (source, fingerprint, str(outcome), evidence, capsule)
        if previous_key is not None and key <= previous_key:
            raise O1C22PostResultComposerError("failure entries are not canonical")
        previous_key = key
        entry_manifests.add(capsule)
        # A launch/publication/resource failure is a replay breadcrumb, not
        # scientific evidence against the selected mechanism.
        if outcome in {"NO_LIFT", "FAILED"}:
            closed.append(fingerprint)
    if manifests != sorted(entry_manifests):
        raise O1C22PostResultComposerError(
            "failure memory capsule manifest inventory differs"
        )
    return tuple(closed)


def record_operator_failure(
    memory: object,
    decision: object,
    *,
    outcome: str,
    evidence_sha256: str,
    capsule_manifest_sha256: str,
) -> dict[str, object]:
    """Return an updated canonical memory document for a future run capsule.

    The caller persists the returned bytes only inside its finalized immutable
    capsule.  This function performs no filesystem mutation.
    """

    _closed_operator_fingerprints(memory)
    row = _mapping(decision, "decision")
    verify_decision(row)
    if outcome not in {"NO_LIFT", "FAILED", "OPERATIONAL_FAILURE"}:
        raise O1C22PostResultComposerError("failure outcome differs")
    evidence = _sha256(evidence_sha256, "evidence_sha256")
    capsule = _sha256(capsule_manifest_sha256, "capsule_manifest_sha256")
    source = _mapping(row["source"], "decision.source")
    operator = _mapping(row["operator"], "decision.operator")
    entry = {
        "source_result_sha256": source["result_sha256"],
        "operator_fingerprint": operator["operator_fingerprint"],
        "outcome": outcome,
        "evidence_sha256": evidence,
        "capsule_manifest_sha256": capsule,
    }
    old = _mapping(memory, "failure_memory")
    entries = [
        dict(_mapping(value, "failure entry"))
        for value in _sequence(old["entries"], "entries")
    ]
    if entry in entries:
        raise O1C22PostResultComposerError("operator failure is already recorded")
    entries.append(entry)
    entries.sort(
        key=lambda value: (
            value["source_result_sha256"],
            value["operator_fingerprint"],
            value["outcome"],
            value["evidence_sha256"],
            value["capsule_manifest_sha256"],
        )
    )
    old_manifests = [
        _sha256(value, f"source_capsule_manifests[{index}]")
        for index, value in enumerate(
            _sequence(old["source_capsule_manifests"], "source manifests")
        )
    ]
    manifests = sorted(set(old_manifests) | {capsule})
    unsigned = {
        "schema": FAILURE_MEMORY_SCHEMA,
        "source_capsule_manifests": manifests,
        "entries": entries,
    }
    return {
        **unsigned,
        "failure_memory_sha256": _sha256_bytes(canonical_json_bytes(unsigned)),
    }


def summarize_quantization_artifacts(
    ledger_payloads: Sequence[bytes],
    primary_state_payloads: Sequence[bytes],
    *,
    fast_state_bytes: int = 80,
) -> dict[str, object]:
    """Derive zero/clip/saturation facts from frozen held-out K256 artifacts."""

    ledgers = tuple(ledger_payloads)
    states = tuple(primary_state_payloads)
    if not ledgers or len(ledgers) != len(states):
        raise O1C22PostResultComposerError("quantization artifact counts differ")
    _integer(fast_state_bytes, "fast_state_bytes", 0, 4096)
    accepted_slots = zero_slots = limit_bin_slots = clip_slots = 0
    accepted_update_counter_total = vault_saturation_events = 0
    maximum_normalized_abs = 0.0
    maximum_abs_offered_by_coordinate = 0
    boundary_coordinates = 0
    ledger_hashes: list[str] = []
    state_hashes: list[str] = []
    for fold_index, (ledger_payload, state_payload) in enumerate(zip(ledgers, states)):
        if not isinstance(ledger_payload, bytes) or not isinstance(
            state_payload, bytes
        ):
            raise O1C22PostResultComposerError("quantization artifacts must be bytes")
        try:
            ledger = json.loads(ledger_payload.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise O1C22PostResultComposerError("bridge ledger is invalid JSON") from exc
        if canonical_json_bytes(ledger) != ledger_payload:
            raise O1C22PostResultComposerError("bridge ledger is not canonical")
        rows = _sequence(ledger, f"ledger[{fold_index}]")
        if len(rows) != 256:
            raise O1C22PostResultComposerError(
                "held-out K256 bridge ledger must contain 256 groups"
            )
        offered_by_coordinate: dict[int, int] = {}
        replayed_evidence = [0] * 256
        replayed_accepted_updates = 0
        seen_coordinates: set[int] = set()
        previous_primary_after: str | None = None
        for row_index, raw in enumerate(rows):
            receipt = _mapping(raw, f"ledger[{fold_index}][{row_index}]")
            coordinate = _integer(
                receipt.get("coordinate"), "receipt.coordinate", 0, 255
            )
            accepted = receipt.get("accepted")
            if accepted is not True:
                raise O1C22PostResultComposerError(
                    "held-out K256 receipt must be accepted"
                )
            before = _sha256(
                receipt.get("primary_state_sha256_before"),
                "receipt.primary_state_sha256_before",
            )
            after = _sha256(
                receipt.get("primary_state_sha256_after"),
                "receipt.primary_state_sha256_after",
            )
            if previous_primary_after is not None and before != previous_primary_after:
                raise O1C22PostResultComposerError(
                    "primary vault receipt hash chain differs"
                )
            previous_primary_after = after
            quantized = _sequence(
                receipt.get("quantized_deltas"), "receipt.quantized_deltas"
            )
            normalized_hex = _sequence(
                receipt.get("normalized_deltas_float64_hex"),
                "receipt.normalized_deltas_float64_hex",
            )
            if len(quantized) != 3 or len(normalized_hex) != 3:
                raise O1C22PostResultComposerError("receipt delta widths differ")
            if coordinate in seen_coordinates:
                raise O1C22PostResultComposerError(
                    "held-out K256 coordinate is duplicated"
                )
            seen_coordinates.add(coordinate)
            coordinate_abs = 0
            for slot_index, (q_raw, hex_raw) in enumerate(
                zip(quantized, normalized_hex)
            ):
                q_value = _integer(
                    q_raw,
                    f"receipt.quantized_deltas[{slot_index}]",
                    -8,
                    8,
                )
                if not isinstance(hex_raw, str):
                    raise O1C22PostResultComposerError("normalized delta hex differs")
                try:
                    normalized = float.fromhex(hex_raw)
                except ValueError as exc:
                    raise O1C22PostResultComposerError(
                        "normalized delta hex differs"
                    ) from exc
                if not math.isfinite(normalized):
                    raise O1C22PostResultComposerError(
                        "normalized delta must be finite"
                    )
                magnitude = abs(normalized)
                expected_magnitude = (
                    8 if magnitude >= 7.5 else int(math.floor(magnitude + 0.5))
                )
                expected_q = (
                    -expected_magnitude if normalized < 0.0 else expected_magnitude
                )
                if q_value != expected_q:
                    raise O1C22PostResultComposerError(
                        "quantized delta differs from frozen rounding and clip"
                    )
                accepted_slots += 1
                zero_slots += int(q_value == 0)
                limit_bin_slots += int(abs(q_value) == 8)
                # q=8 is still the ordinary rounded bin for 7.5<=|x|<8.5;
                # clipping begins only when the unbounded rounded magnitude
                # would exceed the representable limit.
                clip_slots += int(abs(q_value) == 8 and abs(normalized) >= 8.5)
                coordinate_abs += abs(q_value)
                maximum_normalized_abs = max(maximum_normalized_abs, abs(normalized))
                if q_value:
                    unsaturated = replayed_evidence[coordinate] + q_value
                    vault_saturation_events += int(
                        unsaturated < -127 or unsaturated > 127
                    )
                    replayed_evidence[coordinate] = max(-127, min(127, unsaturated))
                    replayed_accepted_updates += 1
            offered_by_coordinate[coordinate] = (
                offered_by_coordinate.get(coordinate, 0) + coordinate_abs
            )
        maximum_abs_offered_by_coordinate = max(
            maximum_abs_offered_by_coordinate,
            max(offered_by_coordinate.values(), default=0),
        )
        if seen_coordinates != set(range(256)):
            raise O1C22PostResultComposerError(
                "held-out K256 coordinate inventory differs"
            )
        expected_state_bytes = fast_state_bytes + 256 + 16
        if len(state_payload) != expected_state_bytes:
            raise O1C22PostResultComposerError("primary vault state width differs")
        evidence = struct.unpack(
            "256b", state_payload[fast_state_bytes : fast_state_bytes + 256]
        )
        if -128 in evidence:
            raise O1C22PostResultComposerError("primary vault contains forbidden -128")
        if tuple(replayed_evidence) != evidence:
            raise O1C22PostResultComposerError(
                "primary vault differs from replayed quantized ledger"
            )
        _last_group_id, accepted_updates = struct.unpack("<QQ", state_payload[-16:])
        if accepted_updates != replayed_accepted_updates:
            raise O1C22PostResultComposerError(
                "primary vault accepted-update counter differs"
            )
        accepted_update_counter_total += accepted_updates
        if previous_primary_after != _sha256_bytes(state_payload):
            raise O1C22PostResultComposerError(
                "final receipt does not bind the primary vault state"
            )
        boundary_coordinates += sum(abs(value) == 127 for value in evidence)
        ledger_hashes.append(_sha256_bytes(ledger_payload))
        state_hashes.append(_sha256_bytes(state_payload))
    if accepted_slots <= 0:
        raise O1C22PostResultComposerError("quantization ledger is empty")
    # Exact per-coordinate offered magnitude <=127 proves int8 saturation cannot
    # have occurred, irrespective of the final evidence value.
    structurally_reachable = maximum_abs_offered_by_coordinate > 127
    unsigned = {
        "schema": QUANTIZATION_DIAGNOSTICS_SCHEMA,
        "fold_count": len(ledgers),
        "accepted_slots": accepted_slots,
        "zero_quantized_slots": zero_slots,
        "zero_quantized_fraction": zero_slots / accepted_slots,
        "quantizer_limit_bin_slots": limit_bin_slots,
        "clip_hits": clip_slots,
        "clip_fraction": clip_slots / accepted_slots,
        "maximum_absolute_normalized_delta": maximum_normalized_abs,
        "maximum_absolute_offered_sum_per_coordinate": (
            maximum_abs_offered_by_coordinate
        ),
        "vault_boundary_coordinates": boundary_coordinates,
        "vault_saturation_events": vault_saturation_events,
        "vault_saturation_structurally_reachable": structurally_reachable,
        "accepted_update_counter_total": accepted_update_counter_total,
        "ledger_sha256": ledger_hashes,
        "primary_state_sha256": state_hashes,
    }
    return {
        **unsigned,
        "diagnostics_sha256": _sha256_bytes(canonical_json_bytes(unsigned)),
    }


def _validate_quantization_diagnostics(value: object) -> Mapping[str, object]:
    row = _mapping(value, "quantization_diagnostics")
    expected = {
        "schema",
        "fold_count",
        "accepted_slots",
        "zero_quantized_slots",
        "zero_quantized_fraction",
        "quantizer_limit_bin_slots",
        "clip_hits",
        "clip_fraction",
        "maximum_absolute_normalized_delta",
        "maximum_absolute_offered_sum_per_coordinate",
        "vault_boundary_coordinates",
        "vault_saturation_events",
        "vault_saturation_structurally_reachable",
        "accepted_update_counter_total",
        "ledger_sha256",
        "primary_state_sha256",
        "diagnostics_sha256",
    }
    if set(row) != expected or row.get("schema") != QUANTIZATION_DIAGNOSTICS_SCHEMA:
        raise O1C22PostResultComposerError("quantization diagnostics fields differ")
    unsigned = {key: row[key] for key in expected if key != "diagnostics_sha256"}
    if row.get("diagnostics_sha256") != _sha256_bytes(canonical_json_bytes(unsigned)):
        raise O1C22PostResultComposerError("quantization diagnostics digest differs")
    fold_count = _integer(row["fold_count"], "fold_count", 4, 4)
    accepted = _integer(row["accepted_slots"], "accepted_slots", 1, 1 << 40)
    zero = _integer(row["zero_quantized_slots"], "zero slots", 0, accepted)
    clip = _integer(row["clip_hits"], "clip hits", 0, accepted)
    limit_bin = _integer(
        row["quantizer_limit_bin_slots"],
        "quantizer limit-bin slots",
        0,
        accepted,
    )
    if clip > limit_bin:
        raise O1C22PostResultComposerError("clip hits exceed limit-bin slots")
    if _number(row["zero_quantized_fraction"], "zero fraction") != zero / accepted:
        raise O1C22PostResultComposerError("zero quantized fraction differs")
    if _number(row["clip_fraction"], "clip fraction") != clip / accepted:
        raise O1C22PostResultComposerError("clip fraction differs")
    if (
        _number(
            row["maximum_absolute_normalized_delta"],
            "maximum_absolute_normalized_delta",
        )
        < 0.0
    ):
        raise O1C22PostResultComposerError(
            "maximum_absolute_normalized_delta must be non-negative"
        )
    maximum_offered = _integer(
        row["maximum_absolute_offered_sum_per_coordinate"],
        "maximum_absolute_offered_sum_per_coordinate",
        0,
        1 << 40,
    )
    boundary_coordinates = _integer(
        row["vault_boundary_coordinates"],
        "vault_boundary_coordinates",
        0,
        fold_count * 256,
    )
    saturation_events = _integer(
        row["vault_saturation_events"],
        "vault_saturation_events",
        0,
        accepted,
    )
    _integer(
        row["accepted_update_counter_total"],
        "accepted_update_counter_total",
        0,
        accepted,
    )
    if (
        accepted != 4 * 256 * 3
        or maximum_offered > 24
        or boundary_coordinates != 0
        or saturation_events != 0
        or row["vault_saturation_structurally_reachable"] is not False
    ):
        raise O1C22PostResultComposerError(
            "quantization diagnostics are not the frozen four-fold K256 inventory"
        )
    if not isinstance(row["vault_saturation_structurally_reachable"], bool):
        raise O1C22PostResultComposerError("vault saturation reachability differs")
    for field in ("ledger_sha256", "primary_state_sha256"):
        values = _sequence(row[field], field)
        if len(values) != fold_count:
            raise O1C22PostResultComposerError(f"{field} count differs")
        for index, digest in enumerate(values):
            _sha256(digest, f"{field}[{index}]")
    return row


def _arm_curve(result: Mapping[str, object], arm: str) -> tuple[float, ...]:
    arms = _mapping(result.get("arms"), "result.arms")
    arm_row = _mapping(arms.get(arm), f"result.arms.{arm}")
    widths = _sequence(arm_row.get("widths"), f"result.arms.{arm}.widths")
    if len(widths) != len(ACTIVE_WIDTHS):
        raise O1C22PostResultComposerError(f"{arm} width count differs")
    curve: list[float] = []
    for expected_width, raw in zip(ACTIVE_WIDTHS, widths):
        row = _mapping(raw, f"result.arms.{arm}.width")
        if row.get("active_coordinates") != expected_width:
            raise O1C22PostResultComposerError(f"{arm} active width differs")
        curve.append(
            _number(row.get("mean_compression_bits"), f"{arm}.mean_compression_bits")
        )
    return tuple(curve)


def _arm_maximum_curve(result: Mapping[str, object], arm: str) -> tuple[float, ...]:
    arms = _mapping(result.get("arms"), "result.arms")
    arm_row = _mapping(arms.get(arm), f"result.arms.{arm}")
    widths = _sequence(arm_row.get("widths"), f"result.arms.{arm}.widths")
    if len(widths) != len(ACTIVE_WIDTHS):
        raise O1C22PostResultComposerError(f"{arm} width count differs")
    maxima: list[float] = []
    for expected_width, raw in zip(ACTIVE_WIDTHS, widths):
        row = _mapping(raw, f"result.arms.{arm}.width")
        if row.get("active_coordinates") != expected_width:
            raise O1C22PostResultComposerError(f"{arm} active width differs")
        maxima.append(
            _number(
                row.get("maximum_compression_bits"),
                f"{arm}.maximum_compression_bits",
            )
        )
    return tuple(maxima)


def _arm_final_positive_folds(result: Mapping[str, object], arm: str) -> int:
    arms = _mapping(result.get("arms"), "result.arms")
    arm_row = _mapping(arms.get(arm), f"result.arms.{arm}")
    widths = _sequence(arm_row.get("widths"), f"result.arms.{arm}.widths")
    if len(widths) != len(ACTIVE_WIDTHS):
        raise O1C22PostResultComposerError(f"{arm} width count differs")
    final = _mapping(widths[-1], f"result.arms.{arm}.widths[-1]")
    return _integer(final.get("positive_folds"), f"{arm}.positive_folds", 0, 4)


def _validate_result(
    value: object,
) -> tuple[Mapping[str, object], dict[str, tuple[float, ...]]]:
    result = _mapping(value, "result")
    if result.get("schema") != UPSTREAM_RESULT_SCHEMA:
        raise O1C22PostResultComposerError("upstream result schema differs")
    classification = result.get("classification")
    if classification not in SUPPORTED_CLASSIFICATIONS:
        raise O1C22PostResultComposerError("upstream classification differs")
    supplied_digest = _sha256(result.get("result_sha256"), "result.result_sha256")
    unsigned = dict(result)
    unsigned.pop("result_sha256")
    if _sha256_bytes(canonical_json_bytes(unsigned)) != supplied_digest:
        raise O1C22PostResultComposerError("upstream result digest differs")
    if (
        tuple(_sequence(result.get("active_coordinate_counts"), "active widths"))
        != ACTIVE_WIDTHS
    ):
        raise O1C22PostResultComposerError("upstream active widths differ")
    curves = {arm: _arm_curve(result, arm) for arm in PRIMARY_ARMS}
    margins = _mapping(result.get("margins"), "result.margins")
    final_fields = {
        "raw_float_delta_sum": "raw_float_mean_final_compression_bits",
        "normalized_float_delta_sum": ("normalized_float_mean_final_compression_bits"),
        "quantized_int8_vault": "int8_mean_final_compression_bits",
    }
    for arm, field in final_fields.items():
        if _number(margins.get(field), f"margins.{field}") != curves[arm][-1]:
            raise O1C22PostResultComposerError(f"{arm} final margin differs")
    reported_curve = tuple(
        _number(value, "int8 curve")
        for value in _sequence(
            margins.get("int8_mean_compression_curve_bits"), "int8 curve"
        )
    )
    if reported_curve != curves["quantized_int8_vault"]:
        raise O1C22PostResultComposerError("int8 curve differs")
    gates = _mapping(result.get("gates"), "result.gates")
    expected_gates = (
        set(INTEGRITY_GATES) | set(EFFICACY_GATES) | {"integrity_gate_passed"}
    )
    if set(gates) != expected_gates or any(
        not isinstance(value, bool) for value in gates.values()
    ):
        raise O1C22PostResultComposerError("result gates must be boolean")
    raw_failed = _sequence(result.get("failed_gates"), "result.failed_gates")
    failed = [value for value in raw_failed if isinstance(value, str) and value]
    if (
        len(failed) != len(raw_failed)
        or failed != sorted(set(failed))
        or any(value not in gates for value in failed)
    ):
        raise O1C22PostResultComposerError("failed gates are not canonical")
    expected_failed = sorted(
        name
        for name in set(INTEGRITY_GATES) | set(EFFICACY_GATES)
        if gates[name] is False
    )
    if failed != expected_failed:
        raise O1C22PostResultComposerError("failed gates differ from gate values")
    integrity_passed = all(bool(gates[name]) for name in INTEGRITY_GATES)
    if gates["integrity_gate_passed"] is not integrity_passed:
        raise O1C22PostResultComposerError("integrity aggregate gate differs")

    raw_final = curves["raw_float_delta_sum"][-1]
    normalized_final = curves["normalized_float_delta_sum"][-1]
    int8_final = curves["quantized_int8_vault"][-1]
    preservation = _number(
        margins.get("int8_preserves_normalized_float_fraction"),
        "int8 preservation",
    )
    expected_efficacy = {
        "all_four_final_folds_positive": (
            _arm_final_positive_folds(result, "quantized_int8_vault") == 4
        ),
        "int8_mean_final_compression_bits_minimum": int8_final >= 1.0,
        "int8_minus_coordinate_shuffled_mean_compression_positive": (
            _number(
                margins.get(CONTROL_MARGIN_FIELDS["coordinate_binding"]),
                "coordinate-binding margin",
            )
            > 0.0
        ),
        "int8_minus_last_horizon_only_mean_compression_positive": (
            _number(
                margins.get(CONTROL_MARGIN_FIELDS["horizon_compounding"]),
                "horizon-compounding margin",
            )
            > 0.0
        ),
        "int8_minus_unit_sign_sum_mean_compression_positive": (
            _number(
                margins.get(CONTROL_MARGIN_FIELDS["confidence_magnitude"]),
                "confidence-magnitude margin",
            )
            > 0.0
        ),
        "int8_preserves_float_compression_fraction_minimum": preservation >= 0.9,
        "strict_mean_compression_growth_across_k": all(
            right > left
            for left, right in zip(
                curves["quantized_int8_vault"][:-1],
                curves["quantized_int8_vault"][1:],
            )
        ),
    }
    if any(gates[name] is not expected for name, expected in expected_efficacy.items()):
        raise O1C22PostResultComposerError(
            "efficacy gate differs from persisted arm metrics"
        )

    # Recompute the exact frozen O1C-0022 precedence.  Its smaller-signal test
    # uses any positive fold/cell, which is the per-width maximum persisted in
    # the arm summary rather than the mean curve used by the successor policy.
    normalized_maxima = _arm_maximum_curve(result, "normalized_float_delta_sum")
    int8_maxima = _arm_maximum_curve(result, "quantized_int8_vault")
    smaller_signal = max(normalized_maxima[:-1] + int8_maxima[:-1]) > 0.0
    if not integrity_passed:
        recomputed = "INTEGRITY_OR_LIFECYCLE_FAILURE"
    elif smaller_signal and int8_final <= 0.0:
        recomputed = "CROSS_COORDINATE_DILUTION"
    elif raw_final <= 0.0 and normalized_final <= 0.0:
        recomputed = "NO_REAL_PACKET_SIGNAL"
    elif raw_final > 0.0 and normalized_final <= 0.0:
        recomputed = "SCALE_WEIGHTING_FAILURE"
    elif normalized_final > 0.0 and (int8_final <= 0.0 or preservation < 0.9):
        recomputed = "QUANTIZATION_OR_SATURATION_FAILURE"
    elif not all(bool(gates[name]) for name in EFFICACY_GATES):
        recomputed = "CONTROL_SPECIFICITY_FAILURE"
    else:
        recomputed = "REAL_CAUSAL_VAULT_BUILD_LOO_PASS"
    if result.get("classification") != recomputed:
        raise O1C22PostResultComposerError(
            "upstream classification differs from frozen precedence"
        )
    return result, curves


def _validate_metrics(
    value: object,
    *,
    result_sha256: str,
) -> tuple[bool, tuple[str, ...]]:
    metrics = _mapping(value, "metrics")
    if metrics.get("schema") != UPSTREAM_METRICS_SCHEMA:
        raise O1C22PostResultComposerError("upstream metrics schema differs")
    if metrics.get("result_sha256") != result_sha256:
        raise O1C22PostResultComposerError("metrics result digest differs")
    complete = metrics.get("operationally_complete")
    if not isinstance(complete, bool):
        raise O1C22PostResultComposerError("operational completion differs")
    raw_failed = _sequence(metrics.get("failed_budgets"), "metrics.failed_budgets")
    failed = [value for value in raw_failed if isinstance(value, str) and value]
    if len(failed) != len(raw_failed) or failed != sorted(set(failed)):
        raise O1C22PostResultComposerError("failed budgets are not canonical")
    if complete == bool(failed):
        raise O1C22PostResultComposerError("operational completion contradicts budgets")
    return complete, tuple(failed)


def _operator_instance(
    template: OperatorTemplate,
    *,
    source_result_sha256: str,
    reason: Mapping[str, object],
) -> dict[str, object]:
    instance = {
        **template.describe(),
        "source_result_sha256": source_result_sha256,
        "policy_sha256": decision_policy_sha256(),
        "reason": dict(reason),
    }
    fingerprint = _sha256_bytes(canonical_json_bytes(instance))
    token = f"o1c22d-{fingerprint[:24]}"
    return {
        **instance,
        "operator_fingerprint": fingerprint,
        "decision_token": token,
    }


def _candidate_templates(
    result: Mapping[str, object],
    curves: Mapping[str, tuple[float, ...]],
    diagnostics: Mapping[str, object],
    operationally_complete: bool,
    failed_budgets: Sequence[str],
) -> tuple[list[OperatorTemplate], dict[str, object], list[str]]:
    classification = str(result["classification"])
    margins = _mapping(result["margins"], "result.margins")
    gates = _mapping(result["gates"], "result.gates")
    failed_gates = tuple(_sequence(result["failed_gates"], "failed_gates"))
    raw_curve = curves["raw_float_delta_sum"]
    normalized_curve = curves["normalized_float_delta_sum"]
    int8_curve = curves["quantized_int8_vault"]
    reason: dict[str, object] = {
        "reported_classification": classification,
        "failed_gates": list(failed_gates),
        "raw_curve_bits": list(raw_curve),
        "normalized_curve_bits": list(normalized_curve),
        "int8_curve_bits": list(int8_curve),
    }
    secondary: list[str] = []
    if not operationally_complete:
        reason["failed_budgets"] = list(failed_budgets)
        return [_TEMPLATES["operational_replay"]], reason, secondary

    failed_integrity = [name for name in INTEGRITY_GATES if gates.get(name) is False]
    if failed_integrity or classification == "INTEGRITY_OR_LIFECYCLE_FAILURE":
        reason["failed_integrity_gates"] = failed_integrity
        return [_TEMPLATES["integrity_replay"]], reason, secondary

    # Correct the frozen precedence collision: a positive continuous K256 arm
    # with int8 loss is a codec/vault issue, even if one positive sub-K cell made
    # the frozen headline label CROSS_COORDINATE_DILUTION.
    smaller_continuous = max(normalized_curve[:-1]) > 0.0
    smaller_quantized = max(int8_curve[:-1]) > 0.0
    continuous_width_collapse = (
        smaller_continuous and normalized_curve[-1] <= 0.0 and int8_curve[-1] <= 0.0
    )
    quantized_width_collapse = (
        normalized_curve[-1] <= 0.0 and smaller_quantized and int8_curve[-1] <= 0.0
    )
    if continuous_width_collapse or quantized_width_collapse:
        positive_widths = [
            width
            for width, continuous, quantized in zip(
                ACTIVE_WIDTHS[:-1], normalized_curve[:-1], int8_curve[:-1]
            )
            if max(continuous, quantized) > 0.0
        ]
        reason["best_positive_sub_k"] = max(
            positive_widths,
            key=lambda width: (
                max(
                    normalized_curve[ACTIVE_WIDTHS.index(width)],
                    int8_curve[ACTIVE_WIDTHS.index(width)],
                ),
                -width,
            ),
        )
        secondary.append("fold_growth_stability_if_banked_state_remains_null")
        return (
            [
                _TEMPLATES["cross_coordinate"],
                _TEMPLATES["robustness"],
            ],
            reason,
            secondary,
        )

    raw_final = raw_curve[-1]
    normalized_final = normalized_curve[-1]
    int8_final = int8_curve[-1]
    if raw_final <= 0.0 and normalized_final <= 0.0:
        raw_sub_k_mean_positive = max(raw_curve[:-1]) > 0.0
        raw_sub_k_any_positive = (
            max(_arm_maximum_curve(result, "raw_float_delta_sum")[:-1]) > 0.0
        )
        if int8_final <= 0.0 and raw_sub_k_mean_positive:
            reason["raw_only_positive_sub_k_mean"] = True
            secondary.extend(("horizon_scale_weighting", "fold_growth_stability"))
            return (
                [
                    _TEMPLATES["cross_coordinate"],
                    _TEMPLATES["scale_simplex"],
                    _TEMPLATES["robustness"],
                ],
                reason,
                secondary,
            )
        if int8_final <= 0.0 and raw_sub_k_any_positive:
            reason["raw_only_single_fold_sub_k_signal"] = True
            secondary.extend(("banked_coordinate_state", "horizon_scale_weighting"))
            return (
                [
                    _TEMPLATES["robustness"],
                    _TEMPLATES["cross_coordinate"],
                    _TEMPLATES["scale_simplex"],
                ],
                reason,
                secondary,
            )
        if classification == "CROSS_COORDINATE_DILUTION" and int8_final <= 0.0:
            reason["only_single_fold_sub_k_signal_without_positive_mean"] = True
            secondary.append("banked_coordinate_state_after_fold_stability")
            return (
                [
                    _TEMPLATES["robustness"],
                    _TEMPLATES["cross_coordinate"],
                ],
                reason,
                secondary,
            )
        if int8_final > 0.0:
            reason["nonlinear_int8_denoising_exception"] = True
            secondary.append("continuous_reader_orientation_remains_null")
            return (
                [
                    _TEMPLATES["quantized_denoising"],
                    _TEMPLATES["interaction_reader"],
                ],
                reason,
                secondary,
            )
        reason["all_real_primary_k256_arms_nonpositive"] = True
        return (
            [
                _TEMPLATES["interaction_reader"],
                _TEMPLATES["contradiction_reader"],
            ],
            reason,
            secondary,
        )

    if raw_final > 0.0 and normalized_final <= 0.0:
        reason["raw_minus_normalized_bits"] = raw_final - normalized_final
        return (
            [
                _TEMPLATES["scale_simplex"],
                _TEMPLATES["quantizer_resolution"],
            ],
            reason,
            secondary,
        )

    preservation = _number(
        margins.get("int8_preserves_normalized_float_fraction"),
        "int8 preservation",
    )
    if normalized_final > 0.0 and (int8_final <= 0.0 or preservation < 0.9):
        reason["int8_preservation_fraction"] = preservation
        saturation_events = _number(
            diagnostics["vault_saturation_events"], "vault saturation events"
        )
        if saturation_events > 0.0:
            return (
                [
                    _TEMPLATES["vault_multislot"],
                    _TEMPLATES["quantizer_resolution"],
                ],
                reason,
                secondary,
            )
        reason["vault_saturation_events"] = saturation_events
        reason["vault_saturation_ruled_out_by_exact_replay"] = True
        return (
            [
                _TEMPLATES["quantizer_resolution"],
                _TEMPLATES["vault_multislot"],
            ],
            reason,
            secondary,
        )

    failed_controls: list[tuple[float, str, str]] = []
    for mechanism, field in CONTROL_MARGIN_FIELDS.items():
        value = _number(margins.get(field), f"margins.{field}")
        reason[field] = value
        if value <= 0.0:
            failed_controls.append((value, mechanism, field))
    if failed_controls:
        failed_controls.sort(key=lambda item: (item[0], item[1]))
        key_for_mechanism = {
            "coordinate_binding": "binding",
            "horizon_compounding": "compounding",
            "confidence_magnitude": "confidence",
        }
        candidates = [
            _TEMPLATES[key_for_mechanism[mechanism]]
            for _, mechanism, _ in failed_controls
        ]
        if any(gates.get(name) is False for name in ROBUSTNESS_GATES):
            candidates.append(_TEMPLATES["robustness"])
        reason["ordered_failed_control_axes"] = [
            {"axis": mechanism, "margin_bits": value}
            for value, mechanism, _ in failed_controls
        ]
        secondary.extend(mechanism for _, mechanism, _ in failed_controls[1:])
        return candidates, reason, secondary

    failed_robustness = [name for name in ROBUSTNESS_GATES if gates.get(name) is False]
    if failed_robustness or classification != "REAL_CAUSAL_VAULT_BUILD_LOO_PASS":
        reason["failed_robustness_gates"] = failed_robustness
        return [_TEMPLATES["robustness"]], reason, secondary
    return [_TEMPLATES["prospective"]], reason, secondary


def compose_postresult_decision(
    result: object,
    metrics: object,
    *,
    capsule_manifest_sha256: str,
    quantization_diagnostics: object,
    failure_memory: object | None = None,
) -> dict[str, object]:
    """Compose one canonical, non-repeating successor from frozen artifacts."""

    source_manifest = _sha256(capsule_manifest_sha256, "capsule_manifest_sha256")
    checked_result, curves = _validate_result(result)
    result_sha = str(checked_result["result_sha256"])
    operationally_complete, failed_budgets = _validate_metrics(
        metrics, result_sha256=result_sha
    )
    diagnostics = _validate_quantization_diagnostics(quantization_diagnostics)
    memory = empty_failure_memory() if failure_memory is None else failure_memory
    closed = set(_closed_operator_fingerprints(memory))
    candidates, reason, secondary = _candidate_templates(
        checked_result,
        curves,
        diagnostics,
        operationally_complete,
        failed_budgets,
    )
    instances = [
        _operator_instance(template, source_result_sha256=result_sha, reason=reason)
        for template in candidates
    ]
    selected = next(
        (
            instance
            for instance in instances
            if instance["operator_fingerprint"] not in closed
        ),
        None,
    )
    if selected is None:
        extension = _operator_instance(
            _TEMPLATES["policy_extension"],
            source_result_sha256=result_sha,
            reason={
                **reason,
                "closed_candidate_operator_fingerprints": [
                    instance["operator_fingerprint"] for instance in instances
                ],
            },
        )
        if extension["operator_fingerprint"] in closed:
            raise O1C22PostResultComposerError(
                "all candidate and policy-extension operator instances are closed"
            )
        selected = extension
    selected_index = next(
        (
            index
            for index, instance in enumerate(instances)
            if instance["operator_fingerprint"] == selected["operator_fingerprint"]
        ),
        -1,
    )
    skipped = [
        instance["operator_fingerprint"]
        for instance in instances[
            : max(selected_index, len(instances) if selected_index < 0 else 0)
        ]
        if instance["operator_fingerprint"] in closed
    ]
    unsigned = {
        "schema": DECISION_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "information_boundary": "POST_REVEAL_PROPOSAL_FOR_NEXT_ATTEMPT_ONLY",
        "source": {
            "attempt_id": UPSTREAM_ATTEMPT_ID,
            "capsule_manifest_sha256": source_manifest,
            "result_sha256": result_sha,
            "reported_classification": checked_result["classification"],
            "operationally_complete": operationally_complete,
            "failed_budgets": list(failed_budgets),
        },
        "policy_sha256": decision_policy_sha256(),
        "quantization_diagnostics_sha256": diagnostics["diagnostics_sha256"],
        "failure_memory_sha256": _mapping(memory, "failure_memory")[
            "failure_memory_sha256"
        ],
        "reason_metrics": reason,
        "secondary_blockers": secondary,
        "closed_candidates_skipped": skipped,
        "operator": selected,
        "o1o": {
            "role": "NATIVE_CAUSAL_SELECTION_AND_DATA_ONLY_FRAGMENT_ASSEMBLY",
            "scientific_decision_authority": False,
            "decision_token": selected["decision_token"],
            "expected_fragment_key": selected["fragment_key"],
            "knowledge_filename": O1O_KNOWLEDGE_FILENAME,
            "fragment_filename": O1O_FRAGMENT_FILENAME,
            "sibling_writes": 0,
        },
        "fresh_target_proposed": selected["target_consumption"]
        == "ONE_NEWLY_BROKERED_TARGET",
        # The pure composer has no manifest-membership or target-broker
        # authority.  A later source-frozen prospective capsule must perform
        # both checks before it may consume a target.
        "fresh_target_authorized": False,
    }
    return {
        **unsigned,
        "decision_sha256": _sha256_bytes(canonical_json_bytes(unsigned)),
    }


def verify_decision(value: object) -> Mapping[str, object]:
    row = _mapping(value, "decision")
    expected_fields = {
        "schema",
        "attempt_id",
        "information_boundary",
        "source",
        "policy_sha256",
        "quantization_diagnostics_sha256",
        "failure_memory_sha256",
        "reason_metrics",
        "secondary_blockers",
        "closed_candidates_skipped",
        "operator",
        "o1o",
        "fresh_target_proposed",
        "fresh_target_authorized",
        "decision_sha256",
    }
    if (
        set(row) != expected_fields
        or row.get("schema") != DECISION_SCHEMA
        or row.get("attempt_id") != ATTEMPT_ID
        or row.get("information_boundary")
        != "POST_REVEAL_PROPOSAL_FOR_NEXT_ATTEMPT_ONLY"
    ):
        raise O1C22PostResultComposerError("decision schema differs")
    supplied = _sha256(row.get("decision_sha256"), "decision_sha256")
    unsigned = dict(row)
    unsigned.pop("decision_sha256", None)
    if supplied != _sha256_bytes(canonical_json_bytes(unsigned)):
        raise O1C22PostResultComposerError("decision digest differs")
    if row.get("policy_sha256") != decision_policy_sha256():
        raise O1C22PostResultComposerError("decision policy digest differs")
    _sha256(
        row.get("quantization_diagnostics_sha256"),
        "quantization_diagnostics_sha256",
    )
    _sha256(row.get("failure_memory_sha256"), "failure_memory_sha256")
    source = _mapping(row.get("source"), "decision.source")
    if (
        set(source)
        != {
            "attempt_id",
            "capsule_manifest_sha256",
            "result_sha256",
            "reported_classification",
            "operationally_complete",
            "failed_budgets",
        }
        or source.get("attempt_id") != UPSTREAM_ATTEMPT_ID
    ):
        raise O1C22PostResultComposerError("decision source fields differ")
    _sha256(source.get("capsule_manifest_sha256"), "source capsule manifest")
    source_result_sha256 = _sha256(source.get("result_sha256"), "source result SHA-256")
    if source.get("reported_classification") not in SUPPORTED_CLASSIFICATIONS:
        raise O1C22PostResultComposerError("source classification differs")
    operationally_complete = source.get("operationally_complete")
    raw_failed_budgets = _sequence(source.get("failed_budgets"), "failed budgets")
    failed_budgets = [
        item for item in raw_failed_budgets if isinstance(item, str) and item
    ]
    if (
        not isinstance(operationally_complete, bool)
        or len(failed_budgets) != len(raw_failed_budgets)
        or failed_budgets != sorted(set(failed_budgets))
        or operationally_complete == bool(failed_budgets)
    ):
        raise O1C22PostResultComposerError("decision operational source differs")
    reason = _mapping(row.get("reason_metrics"), "decision.reason_metrics")
    secondary = _sequence(row.get("secondary_blockers"), "secondary blockers")
    if any(not isinstance(item, str) or not item for item in secondary):
        raise O1C22PostResultComposerError("secondary blockers differ")
    closed = _sequence(
        row.get("closed_candidates_skipped"), "closed candidates skipped"
    )
    for index, digest in enumerate(closed):
        _sha256(digest, f"closed_candidates_skipped[{index}]")
    operator = _mapping(row.get("operator"), "decision.operator")
    operator_id = operator.get("operator_id")
    template = next(
        (
            candidate
            for candidate in _TEMPLATES.values()
            if candidate.operator_id == operator_id
        ),
        None,
    )
    if template is None:
        raise O1C22PostResultComposerError("operator template is not registered")
    static = template.describe()
    if any(operator.get(field) != expected for field, expected in static.items()):
        raise O1C22PostResultComposerError("operator template fields differ")
    if (
        operator.get("source_result_sha256") != source_result_sha256
        or operator.get("policy_sha256") != row.get("policy_sha256")
        or operator.get("reason") != reason
    ):
        raise O1C22PostResultComposerError("operator instance context differs")
    expected_operator_fields = set(static) | {
        "source_result_sha256",
        "policy_sha256",
        "reason",
        "operator_fingerprint",
        "decision_token",
    }
    if set(operator) != expected_operator_fields:
        raise O1C22PostResultComposerError("operator instance fields differ")
    fingerprint = _sha256(operator.get("operator_fingerprint"), "operator fingerprint")
    instance = dict(operator)
    instance.pop("operator_fingerprint", None)
    token = instance.pop("decision_token", None)
    if fingerprint != _sha256_bytes(canonical_json_bytes(instance)):
        raise O1C22PostResultComposerError("operator fingerprint differs")
    if token != f"o1c22d-{fingerprint[:24]}":
        raise O1C22PostResultComposerError("decision token differs")
    classification = source["reported_classification"]
    if template.uses_a539_a541_transfer and classification != "NO_REAL_PACKET_SIGNAL":
        raise O1C22PostResultComposerError(
            "A539/A541 transfer is outside the all-float-null branch"
        )
    prospective = template.target_consumption == "ONE_NEWLY_BROKERED_TARGET"
    if prospective and (
        classification != "REAL_CAUSAL_VAULT_BUILD_LOO_PASS"
        or operationally_complete is not True
        or failed_budgets
    ):
        raise O1C22PostResultComposerError("prospective operator source differs")
    if row.get("fresh_target_proposed") is not prospective:
        raise O1C22PostResultComposerError("fresh-target proposal flag differs")
    if row.get("fresh_target_authorized") is not False:
        raise O1C22PostResultComposerError(
            "post-result composer may not authorize a fresh target"
        )
    o1o = _mapping(row.get("o1o"), "decision.o1o")
    if set(o1o) != {
        "role",
        "scientific_decision_authority",
        "decision_token",
        "expected_fragment_key",
        "knowledge_filename",
        "fragment_filename",
        "sibling_writes",
    } or (
        o1o.get("role") != "NATIVE_CAUSAL_SELECTION_AND_DATA_ONLY_FRAGMENT_ASSEMBLY"
        or o1o.get("decision_token") != token
        or o1o.get("expected_fragment_key") != operator.get("fragment_key")
        or o1o.get("knowledge_filename") != O1O_KNOWLEDGE_FILENAME
        or o1o.get("fragment_filename") != O1O_FRAGMENT_FILENAME
        or o1o.get("sibling_writes") != 0
        or o1o.get("scientific_decision_authority") is not False
    ):
        raise O1C22PostResultComposerError("decision O1-O boundary differs")
    return row


def encode_o1o_route(decision: object) -> bytes:
    """Encode exactly one opaque decision-token route for native O1-O."""

    row = verify_decision(decision)
    operator = _mapping(row["operator"], "decision.operator")
    o1o = _mapping(row["o1o"], "decision.o1o")
    triplet = {
        "trigger": o1o["decision_token"],
        "mechanism": "pipeline",
        "outcome": o1o["expected_fragment_key"],
        "confidence": 1.0,
    }
    graph = {
        "triplets": [triplet],
        "metadata": {
            "schema": O1O_GRAPH_SCHEMA,
            "decision_sha256": row["decision_sha256"],
            "policy_sha256": row["policy_sha256"],
            "operator_fingerprint": operator["operator_fingerprint"],
            "selection_mode": "single-opaque-token-disposable-native-check",
        },
    }
    payload = (
        CAUSAL_MAGIC
        + struct.pack(">H", CAUSAL_VERSION)
        + zlib.compress(_pack_messagepack(graph), level=9)
    )
    if len(payload) > _MAX_CAUSAL_BYTES:
        raise O1C22PostResultComposerError("O1-O route exceeds size bound")
    decode_o1o_route(payload, decision=row)
    return payload


def decode_o1o_route(payload: bytes, *, decision: object) -> Mapping[str, object]:
    row = verify_decision(decision)
    if not isinstance(payload, bytes) or not payload.startswith(CAUSAL_MAGIC):
        raise O1C22PostResultComposerError("O1-O route header differs")
    if len(payload) < 8 or len(payload) > _MAX_CAUSAL_BYTES:
        raise O1C22PostResultComposerError("O1-O route size differs")
    if int.from_bytes(payload[6:8], "big") != CAUSAL_VERSION:
        raise O1C22PostResultComposerError("O1-O route version differs")
    try:
        raw_graph = _safe_decompress(payload[8:])
        if len(raw_graph) > _MAX_GRAPH_BYTES:
            raise O1C22PostResultComposerError("O1-O graph exceeds size bound")
        unpacked = _unpack_messagepack(raw_graph)
    except Exception as exc:
        raise O1C22PostResultComposerError("O1-O route payload is invalid") from exc
    graph = _mapping(unpacked, "O1-O graph")
    if set(graph) != {"triplets", "metadata"}:
        raise O1C22PostResultComposerError("O1-O graph fields differ")
    triplets = _sequence(graph["triplets"], "O1-O triplets")
    if len(triplets) != 1:
        raise O1C22PostResultComposerError("O1-O route must contain one triplet")
    triplet = _mapping(triplets[0], "O1-O triplet")
    o1o = _mapping(row["o1o"], "decision.o1o")
    if triplet != {
        "trigger": o1o["decision_token"],
        "mechanism": "pipeline",
        "outcome": o1o["expected_fragment_key"],
        "confidence": 1.0,
    }:
        raise O1C22PostResultComposerError("O1-O triplet differs")
    metadata = _mapping(graph["metadata"], "O1-O metadata")
    operator = _mapping(row["operator"], "decision.operator")
    if metadata != {
        "schema": O1O_GRAPH_SCHEMA,
        "decision_sha256": row["decision_sha256"],
        "policy_sha256": row["policy_sha256"],
        "operator_fingerprint": operator["operator_fingerprint"],
        "selection_mode": "single-opaque-token-disposable-native-check",
    }:
        raise O1C22PostResultComposerError("O1-O metadata differs")
    return graph


def o1o_fragment_document(decision: object) -> dict[str, object]:
    """Return one data-only fragment; generated code receives no I/O authority."""

    row = verify_decision(decision)
    operator = _mapping(row["operator"], "decision.operator")
    key = str(operator["fragment_key"])
    marker = {
        "schema": OPERATOR_GRAPH_SCHEMA,
        "decision_sha256": row["decision_sha256"],
        "operator_id": operator["operator_id"],
        "operator_fingerprint": operator["operator_fingerprint"],
        "information_boundary": row["information_boundary"],
    }
    marker_bytes = canonical_json_bytes(marker)
    code = (
        f"NEXT_OPERATOR_JSON = {marker_bytes.decode('ascii')!r}\n"
        "def selected_o1c22_operator():\n"
        "    return NEXT_OPERATOR_JSON\n"
    )
    return {
        key: {
            "code": code,
            "description": (
                "Pure O1C-0023 next-operator marker; no filesystem, network, "
                "subprocess, import, randomness, clock, or target access."
            ),
            "imports": [],
        }
    }


def encode_o1o_fragment_document(decision: object) -> bytes:
    return canonical_json_bytes(o1o_fragment_document(decision))


def next_operator_graph(
    decision: object,
    *,
    causal_sha256: str,
    fragment_sha256: str,
    native_generated_sha256: str,
) -> dict[str, object]:
    """Bind a checked native O1-O selection to the scientific proposal."""

    row = verify_decision(decision)
    operator = _mapping(row["operator"], "decision.operator")
    source = _mapping(row["source"], "decision.source")
    unsigned = {
        "schema": OPERATOR_GRAPH_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "information_boundary": row["information_boundary"],
        "source": dict(source),
        "decision_sha256": row["decision_sha256"],
        "policy_sha256": row["policy_sha256"],
        "selection": {
            "decision_token": operator["decision_token"],
            "fragment_key": operator["fragment_key"],
            "causal_sha256": _sha256(causal_sha256, "causal_sha256"),
            "fragment_sha256": _sha256(fragment_sha256, "fragment_sha256"),
            "native_generated_sha256": _sha256(
                native_generated_sha256, "native_generated_sha256"
            ),
            "native_o1o_role": ("disposable-selection-and-data-only-assembly-parity"),
        },
        "operator": dict(operator),
        "failure_memory_sha256": row["failure_memory_sha256"],
        "resources": {
            "new_solver_branches": 0,
            "fresh_target_consumed": 0,
            "sibling_writes": 0,
            "mps_calls": 0,
            "gpu_calls": 0,
        },
    }
    return {
        **unsigned,
        "operator_graph_sha256": _sha256_bytes(canonical_json_bytes(unsigned)),
    }


__all__ = [
    "ATTEMPT_ID",
    "DECISION_SCHEMA",
    "FAILURE_MEMORY_SCHEMA",
    "O1O_FRAGMENT_FILENAME",
    "O1O_KNOWLEDGE_FILENAME",
    "O1C22PostResultComposerError",
    "POLICY_SCHEMA",
    "QUANTIZATION_DIAGNOSTICS_SCHEMA",
    "compose_postresult_decision",
    "decision_policy",
    "decision_policy_sha256",
    "decode_o1o_route",
    "empty_failure_memory",
    "encode_o1o_fragment_document",
    "encode_o1o_route",
    "next_operator_graph",
    "o1o_fragment_document",
    "record_operator_failure",
    "summarize_quantization_artifacts",
    "verify_decision",
]
