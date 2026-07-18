from __future__ import annotations

import json
import hashlib
import unittest
from dataclasses import replace

import numpy as np

from o1_crypto_lab.o1c22_packet_codec import (
    FrozenMedianAbsQuantizer,
    PacketDeltaExtraction,
    PacketDeltaGroup,
    active_coordinate_sequence_sha256,
    complement_packet_polarity,
)
from o1_crypto_lab.o1c22_polyphase_bridge import (
    ENCODING_NORMALIZED_FLOAT32,
    ENCODING_QUANTIZED_INT8_FLOAT32,
    GROUP_BYTES,
    GROUP_SHAPE,
    FittedHorizonReadout,
    HotReadoutLineage,
    O1C22_HORIZONS,
    O1C22PolyphaseBridgeError,
    bind_o1o_hot_readout,
    build_dense_horizon_major_stream,
    consume_dense_horizon_major_stream,
    decode_packet_delta_extraction,
    fit_nonnegative_horizon_readout,
    freeze_hot_readout_lineage,
    permute_dense_coordinates,
    read_bound_hot_state,
    read_fitted_horizon_state,
)
from o1_crypto_lab.polyphase_sufficient_state_v2 import (
    BASIS_SHA256,
    STATE_BYTES,
    WAVELENGTHS,
    PolyphaseReadoutSpec,
    PolyphaseSufficientState,
    ReplayRequiredError,
    direct_polyphase_state,
    read_polyphase_reference,
    read_polyphase_state,
    reference_readout_roundoff_bound,
)


def _hash(character: str) -> str:
    return character * 64


def _delta(coordinate: int, horizon_index: int) -> float:
    numerator = ((coordinate * 11 + horizon_index * 7) % 29) - 14
    return float(numerator * (horizon_index + 1)) / 8.0


def _extraction(
    order: tuple[int, ...] = tuple(range(256)),
    *,
    delta_override: float | None = None,
) -> PacketDeltaExtraction:
    active_sha256 = active_coordinate_sequence_sha256(order)
    groups = tuple(
        PacketDeltaGroup(
            source_stream_sha256=_hash("1"),
            action_pool_sha256=_hash("2"),
            reader_state_sha256=_hash("3"),
            active_coordinates_sha256=active_sha256,
            pair_sha256=f"{coordinate:064x}",
            coordinate=coordinate,
            horizons=O1C22_HORIZONS,
            incremental_deltas=tuple(
                delta_override
                if delta_override is not None
                else _delta(coordinate, horizon_index)
                for horizon_index in range(len(O1C22_HORIZONS))
            ),
            incremental_work_units=(128, 2, 62),
            group_salt=17,
        )
        for coordinate in order
    )
    return PacketDeltaExtraction(
        source_stream_sha256=_hash("1"),
        action_pool_sha256=_hash("2"),
        active_coordinates=order,
        ordered_horizons=O1C22_HORIZONS,
        groups=groups,
        reader_state_sha256=_hash("3"),
        reader_state_bytes=96,
        slow_state_sha256=_hash("4"),
        slow_state_bytes=32,
        final_fast_state_sha256=_hash("5"),
        final_fast_state_bytes=512,
        physical_work_units=256 * 192,
        observed_slots=256 * 3,
    )


def _quantizer(*, scales: tuple[float, float, float] = (2.0, 4.0, 8.0)) -> FrozenMedianAbsQuantizer:
    return FrozenMedianAbsQuantizer(
        horizons=O1C22_HORIZONS,
        scales=scales,
        total_counts=(768, 768, 768),
        nonzero_counts=(700, 700, 700),
        public_replay_ledger_sha256=_hash("6"),
    )


def _complemented(extraction: PacketDeltaExtraction) -> PacketDeltaExtraction:
    groups = tuple(complement_packet_polarity(group) for group in extraction.groups)
    return PacketDeltaExtraction(
        source_stream_sha256=extraction.source_stream_sha256,
        action_pool_sha256=extraction.action_pool_sha256,
        active_coordinates=extraction.active_coordinates,
        ordered_horizons=extraction.ordered_horizons,
        groups=groups,
        reader_state_sha256=extraction.reader_state_sha256,
        reader_state_bytes=extraction.reader_state_bytes,
        slow_state_sha256=extraction.slow_state_sha256,
        slow_state_bytes=extraction.slow_state_bytes,
        final_fast_state_sha256=extraction.final_fast_state_sha256,
        final_fast_state_bytes=extraction.final_fast_state_bytes,
        physical_work_units=extraction.physical_work_units,
        observed_slots=extraction.observed_slots,
    )


def _sparse_coordinate_major_groups(
    extraction: PacketDeltaExtraction,
    quantizer: FrozenMedianAbsQuantizer,
) -> np.ndarray:
    result = np.zeros((256, 3, 256), dtype=np.float32)
    for time_index, packet in enumerate(extraction.groups):
        for horizon, delta in zip(packet.horizons, packet.incremental_deltas):
            result[time_index, WAVELENGTHS.index(horizon), packet.coordinate] = (
                np.float32(quantizer.normalized(horizon, delta))
            )
    return result


class PacketExtractionCodecTests(unittest.TestCase):
    def test_packet_extraction_roundtrip_is_exact_and_canonical(self) -> None:
        extraction = _extraction()
        payload = extraction.to_bytes()
        self.assertEqual(decode_packet_delta_extraction(payload).to_bytes(), payload)

        noncanonical = json.dumps(json.loads(payload), sort_keys=True).encode("ascii")
        self.assertNotEqual(noncanonical, payload)
        with self.assertRaisesRegex(
            O1C22PolyphaseBridgeError, "not canonical"
        ):
            decode_packet_delta_extraction(noncanonical)

    def test_packet_extraction_rejects_a_mutated_work_ledger(self) -> None:
        row = json.loads(_extraction().to_bytes())
        row["physical_work_units"] += 1
        payload = (
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
        with self.assertRaisesRegex(
            O1C22PolyphaseBridgeError, "physical work differs"
        ):
            decode_packet_delta_extraction(payload)


class HorizonMajorBridgeTests(unittest.TestCase):
    def test_normalized_and_quantized_transpose_are_exact(self) -> None:
        extraction = _extraction()
        quantizer = _quantizer()
        normalized = build_dense_horizon_major_stream(
            extraction,
            quantizer,
            encoding=ENCODING_NORMALIZED_FLOAT32,
        )
        quantized = build_dense_horizon_major_stream(
            extraction,
            quantizer,
            encoding=ENCODING_QUANTIZED_INT8_FLOAT32,
        )
        self.assertEqual(normalized.groups.shape, GROUP_SHAPE)
        self.assertEqual(len(normalized.evidence_bytes), GROUP_BYTES)
        self.assertFalse(normalized.groups.flags.writeable)
        for time_index, horizon in enumerate(O1C22_HORIZONS):
            wave_index = WAVELENGTHS.index(horizon)
            for coordinate in (0, 17, 255):
                expected = quantizer.normalized(
                    horizon, _delta(coordinate, time_index)
                )
                self.assertEqual(
                    normalized.groups[time_index, wave_index, coordinate],
                    np.float32(expected),
                )
                self.assertEqual(
                    quantized.groups[time_index, wave_index, coordinate],
                    np.float32(quantizer.quantize(horizon, _delta(coordinate, time_index))),
                )
            other_waves = [index for index in range(3) if index != wave_index]
            self.assertTrue(np.all(normalized.groups[time_index, other_waves] == 0.0))
        self.assertLessEqual(
            normalized.maximum_absolute_float64_to_float32_error,
            np.finfo(np.float32).eps,
        )
        self.assertEqual(quantized.maximum_absolute_float64_to_float32_error, 0.0)

        state = consume_dense_horizon_major_stream(normalized)
        self.assertEqual(state.clock, 3)
        self.assertTrue(np.all(state.coverage == 3))
        self.assertEqual(state.persistent_bytes, STATE_BYTES)

    def test_packet_ledger_order_is_canonicalized_but_sparse_order_is_not(self) -> None:
        quantizer = _quantizer()
        ascending = _extraction()
        descending = _extraction(tuple(reversed(range(256))))
        dense_a = build_dense_horizon_major_stream(
            ascending, quantizer, encoding=ENCODING_NORMALIZED_FLOAT32
        )
        dense_b = build_dense_horizon_major_stream(
            descending, quantizer, encoding=ENCODING_NORMALIZED_FLOAT32
        )
        self.assertEqual(dense_a.evidence_bytes, dense_b.evidence_bytes)
        self.assertNotEqual(dense_a.packet_ledger_sha256, dense_b.packet_ledger_sha256)
        self.assertEqual(
            consume_dense_horizon_major_stream(dense_a).to_bytes(),
            consume_dense_horizon_major_stream(dense_b).to_bytes(),
        )

        sparse_a = PolyphaseSufficientState.initial()
        sparse_b = PolyphaseSufficientState.initial()
        sparse_a.consume(_sparse_coordinate_major_groups(ascending, quantizer))
        sparse_b.consume(_sparse_coordinate_major_groups(descending, quantizer))
        self.assertNotEqual(sparse_a.to_bytes(), sparse_b.to_bytes())
        self.assertEqual(sparse_a.clock, 256)
        self.assertEqual(sparse_b.clock, 256)

    def test_repeated_consumption_is_allocation_alignment_invariant(self) -> None:
        stream = build_dense_horizon_major_stream(
            _extraction(), _quantizer(), encoding=ENCODING_NORMALIZED_FLOAT32
        )
        hashes = {
            consume_dense_horizon_major_stream(stream).sha256() for _ in range(64)
        }
        self.assertEqual(len(hashes), 1)

    def test_complement_is_exactly_odd_and_reference_bound_holds(self) -> None:
        extraction = _extraction()
        quantizer = _quantizer()
        primary_stream = build_dense_horizon_major_stream(
            extraction, quantizer, encoding=ENCODING_NORMALIZED_FLOAT32
        )
        swapped_stream = build_dense_horizon_major_stream(
            _complemented(extraction),
            quantizer,
            encoding=ENCODING_NORMALIZED_FLOAT32,
        )
        self.assertTrue(np.array_equal(swapped_stream.groups, -primary_stream.groups))
        primary = consume_dense_horizon_major_stream(primary_stream)
        swapped = consume_dense_horizon_major_stream(swapped_stream)
        self.assertTrue(np.array_equal(swapped.slots, -primary.slots))
        self.assertTrue(np.array_equal(swapped.coverage, primary.coverage))

        spec = PolyphaseReadoutSpec(
            name="balanced",
            basis_sha256=BASIS_SHA256,
            slot_weights=np.full((3, 4), np.float32(1.0 / 12.0), dtype=np.float32),
            temperature=1.0,
        )
        logits = read_polyphase_state(primary, spec)
        swapped_logits = read_polyphase_state(swapped, spec)
        self.assertTrue(np.array_equal(swapped_logits, -logits))
        reference_state = direct_polyphase_state(primary_stream.groups)
        reference = read_polyphase_reference(reference_state, spec)
        bound = reference_readout_roundoff_bound(reference_state, spec)
        self.assertTrue(np.all(np.abs(logits.astype(np.float64) - reference) <= bound))

    def test_float32_overflow_is_rejected_transactionally(self) -> None:
        extraction = _extraction(delta_override=1.0)
        quantizer = _quantizer(scales=(1e-300, 1e-300, 1e-300))
        with self.assertRaisesRegex(
            O1C22PolyphaseBridgeError, "not representable as float32"
        ):
            build_dense_horizon_major_stream(
                extraction,
                quantizer,
                encoding=ENCODING_NORMALIZED_FLOAT32,
            )

    def test_coordinate_permutation_is_full_width_and_matched(self) -> None:
        stream = build_dense_horizon_major_stream(
            _extraction(), _quantizer(), encoding=ENCODING_NORMALIZED_FLOAT32
        )
        mapping = tuple((coordinate + 17) % 256 for coordinate in range(256))
        permuted = permute_dense_coordinates(stream, mapping)
        self.assertEqual(permuted.shape, GROUP_SHAPE)
        self.assertFalse(permuted.flags.writeable)
        for source in (0, 17, 255):
            self.assertTrue(
                np.array_equal(permuted[:, :, mapping[source]], stream.groups[:, :, source])
            )
        with self.assertRaisesRegex(
            O1C22PolyphaseBridgeError, "permutation"
        ):
            permute_dense_coordinates(stream, tuple(range(255)) + (254,))


class O1OReadoutBindingTests(unittest.TestCase):
    @staticmethod
    def _operator(
        operator_id: str,
        replaced: str,
        **extra: object,
    ) -> dict[str, object]:
        return {
            "operator_id": operator_id,
            "operator_fingerprint": _hash("a"),
            "source_result_sha256": _hash("b"),
            "verified_decision_sha256": _hash("c"),
            "policy_sha256": _hash("d"),
            "replaced_components": [replaced],
            **extra,
        }

    @staticmethod
    def _state_and_lineage() -> tuple[
        PolyphaseSufficientState,
        HotReadoutLineage,
        FittedHorizonReadout,
    ]:
        quantizer = _quantizer()
        stream = build_dense_horizon_major_stream(
            _extraction(), quantizer, encoding=ENCODING_NORMALIZED_FLOAT32
        )
        state = consume_dense_horizon_major_stream(stream)
        labels = np.stack(
            [
                np.asarray(
                    [(coordinate + seed) & 1 for coordinate in range(256)],
                    dtype=np.uint8,
                )
                for seed in (0, 1)
            ]
        )
        fit_states = []
        for row in labels:
            evidence = np.zeros(GROUP_SHAPE, dtype=np.float32)
            evidence[2, WAVELENGTHS.index(96)] = (
                2.0 * row.astype(np.float32) - 1.0
            )
            fit_state = PolyphaseSufficientState.initial()
            fit_state.consume(evidence)
            fit_states.append(fit_state)
        fit = fit_nonnegative_horizon_readout(
            tuple(fit_states), labels, alpha=1.0
        )
        lineage = freeze_hot_readout_lineage(stream, quantizer, state, fit)
        return state, lineage, fit

    def test_hot_operator_binds_without_replay_or_state_mutation(self) -> None:
        state, lineage, fit = self._state_and_lineage()
        simplex = fit.slot_weights
        binding = bind_o1o_hot_readout(
            self._operator(
                "horizon_nonnegative_simplex_v1",
                "horizon_scale_weighting",
                weight_contract="nonnegative_horizon_simplex_equal_poles",
            ),
            slot_weights=simplex,
            temperature=fit.temperature,
            lineage=lineage,
        )
        self.assertEqual(binding.describe()["stream_replay_required"], False)
        self.assertEqual(binding.describe()["o1o_is_scientific_weight_authority"], False)
        before = state.to_bytes()
        first = read_bound_hot_state(state, binding)
        second = read_bound_hot_state(state, binding)
        self.assertTrue(np.array_equal(first, second))
        self.assertEqual(state.to_bytes(), before)

        confidence_weights = fit.slot_weights
        weights_sha256 = hashlib.sha256(
            confidence_weights.astype("<f4", copy=False).tobytes(order="C")
        ).hexdigest()
        confidence = bind_o1o_hot_readout(
            self._operator(
                "magnitude_confidence_calibration_v1",
                "magnitude_confidence",
                calibration_scope="global_temperature_only",
                frozen_slot_weights_sha256=weights_sha256,
            ),
            slot_weights=confidence_weights,
            temperature=2.0,
            lineage=lineage,
        )
        self.assertNotEqual(binding.binding_sha256, confidence.binding_sha256)
        with self.assertRaisesRegex(ValueError, "InitVar '_factory_token'"):
            replace(lineage, state_sha256=_hash("e"))
        with self.assertRaisesRegex(ValueError, "InitVar '_factory_token'"):
            replace(binding, binding_sha256=_hash("f"))

    def test_cold_or_misdeclared_operator_cannot_reinterpret_state(self) -> None:
        state, lineage, fit = self._state_and_lineage()
        with self.assertRaises(ReplayRequiredError):
            bind_o1o_hot_readout(
                self._operator(
                    "coordinate_phase_binding_repair_v1", "coordinate_binding"
                ),
                slot_weights=np.ones((3, 4), dtype=np.float32),
                temperature=1.0,
                lineage=lineage,
            )
        with self.assertRaisesRegex(
            O1C22PolyphaseBridgeError, "replacement surface"
        ):
            bind_o1o_hot_readout(
                self._operator(
                    "horizon_nonnegative_simplex_v1", "coordinate_binding"
                ),
                slot_weights=np.ones((3, 4), dtype=np.float32),
                temperature=1.0,
                lineage=lineage,
            )

        valid = bind_o1o_hot_readout(
            self._operator(
                "horizon_nonnegative_simplex_v1",
                "horizon_scale_weighting",
                weight_contract="nonnegative_horizon_simplex_equal_poles",
            ),
            slot_weights=fit.slot_weights,
            temperature=fit.temperature,
            lineage=lineage,
        )
        with self.assertRaises(ReplayRequiredError):
            read_bound_hot_state(PolyphaseSufficientState.initial(), valid)

    def test_hot_templates_reject_arbitrary_weights(self) -> None:
        _state, lineage, fit = self._state_and_lineage()
        with self.assertRaisesRegex(O1C22PolyphaseBridgeError, "simplex weights"):
            bind_o1o_hot_readout(
                self._operator(
                    "horizon_nonnegative_simplex_v1",
                    "horizon_scale_weighting",
                    weight_contract="nonnegative_horizon_simplex_equal_poles",
                ),
                slot_weights=np.asarray(
                    [[0.5, 0.25, 0.125, 0.125], [0.0] * 4, [0.0] * 4],
                    dtype=np.float32,
                ),
                temperature=1.0,
                lineage=lineage,
            )

        different_simplex = np.roll(fit.slot_weights, 1, axis=0).copy()
        self.assertFalse(np.array_equal(different_simplex, fit.slot_weights))
        with self.assertRaisesRegex(ReplayRequiredError, "frozen scientific fit"):
            bind_o1o_hot_readout(
                self._operator(
                    "horizon_nonnegative_simplex_v1",
                    "horizon_scale_weighting",
                    weight_contract="nonnegative_horizon_simplex_equal_poles",
                ),
                slot_weights=different_simplex,
                temperature=fit.temperature,
                lineage=lineage,
            )
        with self.assertRaisesRegex(ReplayRequiredError, "frozen scientific fit"):
            bind_o1o_hot_readout(
                self._operator(
                    "horizon_nonnegative_simplex_v1",
                    "horizon_scale_weighting",
                    weight_contract="nonnegative_horizon_simplex_equal_poles",
                ),
                slot_weights=fit.slot_weights,
                temperature=fit.temperature * 2.0,
                lineage=lineage,
            )
        frozen = fit.slot_weights
        with self.assertRaises(ReplayRequiredError):
            bind_o1o_hot_readout(
                self._operator(
                    "magnitude_confidence_calibration_v1",
                    "magnitude_confidence",
                    calibration_scope="global_temperature_only",
                    frozen_slot_weights_sha256=hashlib.sha256(
                        frozen.astype("<f4", copy=False).tobytes(order="C")
                    ).hexdigest(),
                ),
                slot_weights=np.ones((3, 4), dtype=np.float32),
                temperature=1.0,
                lineage=lineage,
            )

    def test_lineage_factory_rejects_wrong_quantizer_or_state(self) -> None:
        quantizer = _quantizer()
        stream = build_dense_horizon_major_stream(
            _extraction(), quantizer, encoding=ENCODING_NORMALIZED_FLOAT32
        )
        _state, _lineage, fit = self._state_and_lineage()
        with self.assertRaisesRegex(ReplayRequiredError, "different frozen quantizer"):
            freeze_hot_readout_lineage(
                stream,
                _quantizer(scales=(3.0, 4.0, 8.0)),
                consume_dense_horizon_major_stream(stream),
                fit,
            )
        with self.assertRaisesRegex(ReplayRequiredError, "does not derive"):
            freeze_hot_readout_lineage(
                stream,
                quantizer,
                PolyphaseSufficientState.initial(),
                fit,
            )


class NonnegativeHorizonFitTests(unittest.TestCase):
    @staticmethod
    def _state_for_labels(labels: np.ndarray) -> PolyphaseSufficientState:
        groups = np.zeros(GROUP_SHAPE, dtype=np.float32)
        groups[2, WAVELENGTHS.index(96), :] = (
            2.0 * labels.astype(np.float32) - 1.0
        )
        state = PolyphaseSufficientState.initial()
        state.consume(groups)
        return state

    def test_nonnegative_fit_recovers_a_shared_horizon_and_generalizes(self) -> None:
        labels = np.stack(
            [
                np.asarray([(coordinate + seed) & 1 for coordinate in range(256)], dtype=np.uint8)
                for seed in (0, 1, 2)
            ]
        )
        states = tuple(self._state_for_labels(row) for row in labels[:2])
        fit = fit_nonnegative_horizon_readout(states, labels[:2], alpha=1.0)
        self.assertFalse(fit.abstained)
        self.assertTrue(np.all(fit.horizon_weights >= 0.0))
        self.assertAlmostEqual(float(fit.horizon_weights.sum()), 1.0, places=6)
        prediction = read_fitted_horizon_state(
            self._state_for_labels(labels[2]), fit
        )
        self.assertTrue(
            np.array_equal((prediction > 0.0).astype(np.uint8), labels[2])
        )

    def test_zero_design_abstains_to_an_exact_zero_prior(self) -> None:
        states = (PolyphaseSufficientState.initial(), PolyphaseSufficientState.initial())
        labels = np.stack(
            [
                np.asarray([coordinate & 1 for coordinate in range(256)], dtype=np.uint8),
                np.asarray([(coordinate + 1) & 1 for coordinate in range(256)], dtype=np.uint8),
            ]
        )
        fit = fit_nonnegative_horizon_readout(states, labels, alpha=1.0)
        self.assertTrue(fit.abstained)
        self.assertEqual(fit.active_mask, 0)
        self.assertTrue(
            np.array_equal(
                read_fitted_horizon_state(states[0], fit),
                np.zeros(256, dtype=np.float32),
            )
        )

    def test_fitted_object_is_factory_only_and_rejects_replace(self) -> None:
        labels = np.stack([_label_row for _label_row in (
            np.asarray([coordinate & 1 for coordinate in range(256)], dtype=np.uint8),
            np.asarray([(coordinate + 1) & 1 for coordinate in range(256)], dtype=np.uint8),
        )])
        fit = fit_nonnegative_horizon_readout(
            tuple(self._state_for_labels(row) for row in labels),
            labels,
            alpha=1.0,
        )
        corrupted = fit.slot_weights.copy()
        corrupted[0, 0] += np.float32(0.125)
        with self.assertRaisesRegex(ValueError, "InitVar '_factory_token'"):
            replace(fit, slot_weights=corrupted)
        with self.assertRaisesRegex(ValueError, "InitVar '_factory_token'"):
            replace(fit, active_mask=fit.active_mask ^ 1)
        with self.assertRaisesRegex(ValueError, "InitVar '_factory_token'"):
            replace(fit, fit_receipt_sha256=_hash("f"))


if __name__ == "__main__":
    unittest.main()
