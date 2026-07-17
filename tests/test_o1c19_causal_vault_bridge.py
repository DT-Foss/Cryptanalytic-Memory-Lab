from __future__ import annotations

import hashlib
import inspect
import unittest
from types import SimpleNamespace

import numpy as np

from o1_crypto_lab.causal_evidence_stream import CausalEvidenceConfig
from o1_crypto_lab.full256_action_pool import BRANCH_FEATURES, Full256ActionPool
from o1_crypto_lab.o1_streaming_core import (
    StreamingSelectiveHolographicCore,
    torch,
)
from o1_crypto_lab.online_causal_controller import (
    KEY_BITS,
    CausalAction,
    OnlineCausalControllerConfig,
)
from o1_crypto_lab.o1c19_causal_vault_bridge import (
    ACTIVE_COORDINATE_WIDTHS,
    FORMAL_VAULT_BYTES,
    CausalVaultBridge,
    CausalVaultBridgeState,
    FrozenMedianAbsQuantizer,
    NestedActiveCoordinatePlan,
    O1C19CausalVaultBridgeError,
    PacketDeltaGroup,
    active_coordinate_sequence_sha256,
    complement_packet_polarity,
    deterministic_coordinate_permutation,
    execute_packet_delta_groups,
    extract_frozen_o1c19_packet_groups,
    permute_packet_coordinate,
)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


_SOURCE = _sha256(b"fixture-source")
_PAIR = _sha256(b"fixture-pair")
_ACTION_POOL = _sha256(b"fixture-action-pool")
_READER = _sha256(b"fixture-reader")
_ACTIVE = _sha256(b"fixture-active-coordinates")
_ORIENTATION = (
    (1, 1, -1, -1, 1, -1, 1, -1),
    (1, 1, -1, -1, -1, 1, -1, 1),
    (-1, -1, 1, 1, 1, -1, -1, 1),
    (-1, -1, 1, 1, -1, 1, 1, -1),
)


def _causal_config() -> CausalEvidenceConfig:
    return CausalEvidenceConfig(
        n_bits=256,
        regime_count=4,
        family_count=8,
        quality_reliabilities=(0.625, 0.75),
        coefficient_magnitudes=(1, 2),
        orientation_matrix=_ORIENTATION,
        event_dimension=21,
        address_dimension=4,
        model_dimension=8,
        heads=1,
        head_dimension=4,
        holographic_slots=2,
        feedforward_dimension=12,
        phase_scale=float(np.pi),
        core_seed=220_021,
        build_seeds=(220_101,),
        calibration_seeds=(220_201,),
        development_seeds=(220_301,),
        evaluation_seeds=(220_401,),
        independent_group_prefixes=(1, 2),
        repeat_factors=(1, 2),
        independent_comparison_groups=1,
        independent_comparison_repeat_factor=2,
        training_steps=1,
        training_batch_size=2,
        learning_rate=0.01,
        temperature_grid_max=2.0,
        temperature_grid_steps=3,
        shuffled_label_seed=220_501,
        cpu_threads=1,
    )


def _group(
    coordinate: int,
    deltas: tuple[float, ...],
    *,
    horizons: tuple[int, ...] = (1, 4, 7),
    salt: int = 0,
    source: str = _SOURCE,
) -> PacketDeltaGroup:
    previous = 0
    work = []
    for horizon in horizons:
        work.append(2 * (horizon - previous))
        previous = horizon
    return PacketDeltaGroup(
        source_stream_sha256=source,
        action_pool_sha256=_ACTION_POOL,
        reader_state_sha256=_READER,
        active_coordinates_sha256=_ACTIVE,
        pair_sha256=_PAIR,
        coordinate=coordinate,
        horizons=horizons,
        incremental_deltas=deltas,
        incremental_work_units=tuple(work),
        group_salt=salt,
    )


def _manual_quantizer(
    horizons: tuple[int, ...],
    scales: tuple[float, ...],
) -> FrozenMedianAbsQuantizer:
    return FrozenMedianAbsQuantizer(
        horizons=horizons,
        scales=scales,
        total_counts=tuple(3 for _ in horizons),
        nonzero_counts=tuple(3 for _ in horizons),
        public_replay_ledger_sha256=_sha256(b"fixture-public-replay-ledger"),
    )


class NestedCoordinateAndPacketTests(unittest.TestCase):
    def test_public_sha_order_is_frozen_nested_and_roundtrips(self) -> None:
        plan = NestedActiveCoordinatePlan(_SOURCE, 0x123456789ABCDEF0)
        self.assertEqual(
            plan.coordinate_order[:16],
            (
                172,
                247,
                73,
                198,
                116,
                245,
                67,
                224,
                210,
                169,
                142,
                234,
                112,
                150,
                250,
                81,
            ),
        )
        self.assertEqual(len(set(plan.coordinate_order)), KEY_BITS)
        prefixes = {
            width: plan.active_coordinates(width) for width in ACTIVE_COORDINATE_WIDTHS
        }
        self.assertEqual(tuple(prefixes), (12, 52, 128, 256))
        self.assertEqual(prefixes[12], prefixes[52][:12])
        self.assertEqual(prefixes[52], prefixes[128][:52])
        self.assertEqual(prefixes[128], prefixes[256][:128])
        self.assertEqual(
            NestedActiveCoordinatePlan.from_bytes(plan.to_bytes()),
            plan,
        )
        self.assertNotEqual(
            NestedActiveCoordinatePlan(_SOURCE, plan.salt + 1).coordinate_order,
            plan.coordinate_order,
        )
        with self.assertRaisesRegex(O1C19CausalVaultBridgeError, "12/52/128/256"):
            plan.active_coordinates(13)

    def test_packet_bytes_bind_exact_delta_work_coordinate_and_salt(self) -> None:
        group = _group(17, (0.0, -2.5, 7.25), salt=19)
        restored = PacketDeltaGroup.from_bytes(group.to_bytes())
        self.assertEqual(restored, group)
        self.assertEqual(restored.incremental_work_units, (2, 6, 6))
        self.assertEqual(restored.physical_work_units, 14)
        self.assertNotEqual(group.group_id, complement_packet_polarity(group).group_id)
        self.assertNotEqual(
            group.group_id, _group(17, group.incremental_deltas, salt=20).group_id
        )

        with self.assertRaisesRegex(O1C19CausalVaultBridgeError, "incremental work"):
            PacketDeltaGroup(
                source_stream_sha256=_SOURCE,
                action_pool_sha256=_ACTION_POOL,
                reader_state_sha256=_READER,
                active_coordinates_sha256=_ACTIVE,
                pair_sha256=_PAIR,
                coordinate=17,
                horizons=(1, 4, 7),
                incremental_deltas=(0.0, 1.0, 2.0),
                incremental_work_units=(2, 8, 4),
            )
        with self.assertRaisesRegex(O1C19CausalVaultBridgeError, "finite"):
            _group(17, (0.0, float("nan"), 1.0))


class FrozenMedianAbsQuantizerTests(unittest.TestCase):
    def test_nonzero_median_fallback_rounding_clip_and_roundtrip(self) -> None:
        groups = (
            _group(1, (0.0, -2.0, 0.0), salt=1),
            _group(2, (1.0, 4.0, 0.0), salt=2),
            _group(3, (3.0, 0.0, 0.0), salt=3),
        )
        quantizer = FrozenMedianAbsQuantizer.fit_public_replays(groups)
        self.assertEqual(quantizer.scales, (2.0, 3.0, 1.0))
        self.assertEqual(quantizer.total_counts, (3, 3, 3))
        self.assertEqual(quantizer.nonzero_counts, (2, 2, 0))
        self.assertEqual(quantizer.quantize(1, 3.0), 2)
        self.assertEqual(quantizer.quantize(1, -3.0), -2)
        self.assertEqual(quantizer.quantize(1, 1.0), 1)
        self.assertEqual(quantizer.quantize(1, 0.98), 0)
        self.assertEqual(quantizer.quantize(1, 1_000_000.0), 8)
        self.assertEqual(quantizer.quantize(1, -1_000_000.0), -8)
        self.assertEqual(
            FrozenMedianAbsQuantizer.from_bytes(quantizer.to_bytes()),
            quantizer,
        )
        self.assertEqual(len(quantizer.sha256), 64)

    def test_quantizer_rejects_horizon_mixing_and_empty_implicit_fit(self) -> None:
        with self.assertRaisesRegex(O1C19CausalVaultBridgeError, "explicit horizons"):
            FrozenMedianAbsQuantizer.fit_public_replays(())
        with self.assertRaisesRegex(O1C19CausalVaultBridgeError, "horizons differ"):
            FrozenMedianAbsQuantizer.fit_public_replays(
                (
                    _group(1, (1.0, 2.0, 3.0)),
                    _group(2, (1.0, 2.0), horizons=(1, 4)),
                )
            )


@unittest.skipUnless(torch is not None, "optional torch state dependency is absent")
class CausalVaultAtomicExecutionTests(unittest.TestCase):
    def _state_and_bridge(
        self,
        quantizer: FrozenMedianAbsQuantizer,
    ) -> tuple[CausalEvidenceConfig, CausalVaultBridgeState, CausalVaultBridge]:
        config = _causal_config()
        core = StreamingSelectiveHolographicCore(config.core_config)
        shuffle = deterministic_coordinate_permutation(
            _SOURCE,
            7,
            shuffled_destination=True,
        )
        state = CausalVaultBridgeState.initial(config, core, shuffle)
        return (
            config,
            state,
            CausalVaultBridge(
                config,
                quantizer,
                _SOURCE,
                action_pool_sha256=_ACTION_POOL,
                reader_state_sha256=_READER,
                active_coordinates_sha256=_ACTIVE,
            ),
        )

    def test_exact_352_byte_vault_controls_and_duplicate_atomicity(self) -> None:
        horizons = (2, 5, 9)
        quantizer = _manual_quantizer(horizons, (2.0, 2.0, 2.0))
        config, state, bridge = self._state_and_bridge(quantizer)
        group = _group(
            11,
            (1.0, -3.0, 20.0),
            horizons=horizons,
            salt=99,
        )
        execution = execute_packet_delta_groups(bridge, state, (group, group))
        first, duplicate = execution.receipts
        destination = state.shuffled_destinations[11]

        self.assertTrue(first.accepted)
        self.assertFalse(duplicate.accepted)
        self.assertEqual(first.quantized_deltas, (1, -2, 8))
        self.assertEqual(first.offered_work_units, 18)
        self.assertEqual(duplicate.offered_work_units, 18)
        self.assertEqual(duplicate.accepted_work_units, 0)
        self.assertEqual(
            first.primary_state_sha256_after,
            duplicate.primary_state_sha256_before,
        )
        self.assertEqual(
            duplicate.primary_state_sha256_before,
            duplicate.primary_state_sha256_after,
        )
        self.assertEqual(len(state.primary_bytes(config)), FORMAL_VAULT_BYTES)
        self.assertEqual(state.vault.evidence[11], 7)
        self.assertEqual(state.vault.accepted_updates, 3)
        self.assertEqual(state.raw_float_accumulator[11], 18.0)
        self.assertEqual(state.normalized_float_accumulator[11], 9.0)
        self.assertEqual(state.unit_sign_sum[11], 1)
        self.assertEqual(state.last_only[11], 8)
        self.assertEqual(state.shuffled[destination], 7)

        report = execution.describe(config)
        self.assertEqual(report["groups_offered"], 2)
        self.assertEqual(report["groups_accepted"], 1)
        self.assertEqual(report["groups_duplicate"], 1)
        self.assertEqual(report["slots_offered"], 6)
        self.assertEqual(report["slots_accepted"], 3)
        self.assertEqual(report["physical_work_offered"], 36)
        self.assertEqual(report["physical_work_accepted"], 18)
        self.assertEqual(report["nonzero_vault_updates_accepted"], 3)
        self.assertTrue(report["duplicate_primary_state_byte_invariant"])
        self.assertTrue(report["upstream_reader_billed_separately"])
        self.assertIn("zero_prior_implicit_exact_zeros", report["controls"])
        self.assertEqual(state.control_live_state_bytes, 4864)
        artifacts = execution.artifacts(config)
        self.assertEqual(len(artifacts["causal_vault_state.bin"]), 352)
        self.assertEqual(len(artifacts["raw_float_control.f64le"]), 2048)
        self.assertEqual(len(artifacts["normalized_float_control.f64le"]), 2048)
        self.assertEqual(len(artifacts["unit_sign_control.i8"]), 256)
        arms = state.arm_values(config)
        self.assertEqual(
            tuple(arms),
            (
                "raw_float_delta_sum",
                "normalized_float_delta_sum",
                "quantized_int8_vault",
                "last_horizon_only",
                "unit_sign_sum",
                "coordinate_shuffled_vault",
                "zero_prior",
            ),
        )
        self.assertTrue(np.all(arms["zero_prior"] == 0.0))

    def test_zero_q_slots_keep_work_but_do_not_advance_vault_updates(self) -> None:
        horizons = (1, 2, 3)
        quantizer = _manual_quantizer(horizons, (10.0, 10.0, 10.0))
        config, state, bridge = self._state_and_bridge(quantizer)
        group = _group(8, (1.0, 0.0, -2.0), horizons=horizons, salt=1)
        receipt = bridge.apply_group(state, group)
        self.assertEqual(receipt.quantized_deltas, (0, 0, 0))
        self.assertTrue(receipt.accepted)
        self.assertEqual(receipt.accepted_work_units, 6)
        self.assertEqual(state.vault.accepted_updates, 0)
        self.assertEqual(state.vault.evidence[8], 0)
        self.assertEqual(state.raw_float_accumulator[8], -1.0)
        self.assertAlmostEqual(state.normalized_float_accumulator[8], -0.1)
        self.assertEqual(state.unit_sign_sum[8], 0)
        self.assertEqual(state.last_only[8], 0)
        report = execute_packet_delta_groups(bridge, state, ()).describe(config)
        self.assertTrue(report["zero_updates_are_skipped"])

    def test_counter_overflow_preflight_is_transactional(self) -> None:
        horizons = (1, 2, 3)
        quantizer = _manual_quantizer(horizons, (1.0, 1.0, 1.0))
        config, state, bridge = self._state_and_bridge(quantizer)
        state.vault.accepted_updates = (1 << 64) - 2
        group = _group(8, (1.0, 1.0, 1.0), horizons=horizons, salt=7)
        primary_before = state.primary_bytes(config)
        controls_before = state.control_bytes()
        with self.assertRaisesRegex(O1C19CausalVaultBridgeError, "overflow"):
            bridge.apply_group(state, group)
        self.assertEqual(state.primary_bytes(config), primary_before)
        self.assertEqual(state.control_bytes(), controls_before)

    def test_polarity_and_coordinate_transforms_are_exact(self) -> None:
        horizons = (2, 5, 9)
        quantizer = _manual_quantizer(horizons, (2.0, 2.0, 2.0))
        config, base_state, bridge = self._state_and_bridge(quantizer)
        _config, complement_state, _bridge = self._state_and_bridge(quantizer)
        _config, permuted_state, _bridge = self._state_and_bridge(quantizer)
        group = _group(11, (1.0, -3.0, 20.0), horizons=horizons, salt=31)
        complement = complement_packet_polarity(group)
        mapping = tuple((coordinate + 17) % KEY_BITS for coordinate in range(KEY_BITS))
        permuted = permute_packet_coordinate(group, mapping)
        permuted_bridge = CausalVaultBridge(
            config,
            quantizer,
            _SOURCE,
            action_pool_sha256=_ACTION_POOL,
            reader_state_sha256=_READER,
            active_coordinates_sha256=permuted.active_coordinates_sha256,
        )

        base = bridge.apply_group(base_state, group)
        inverse = bridge.apply_group(complement_state, complement)
        moved = permuted_bridge.apply_group(permuted_state, permuted)
        self.assertEqual(
            inverse.quantized_deltas, tuple(-q for q in base.quantized_deltas)
        )
        self.assertEqual(inverse.offered_work_units, base.offered_work_units)
        self.assertEqual(moved.quantized_deltas, base.quantized_deltas)
        self.assertEqual(moved.offered_work_units, base.offered_work_units)
        self.assertEqual(permuted.coordinate, mapping[group.coordinate])
        self.assertEqual(
            complement_state.vault.evidence[group.coordinate],
            -int(base_state.vault.evidence[group.coordinate]),
        )
        self.assertEqual(
            permuted_state.vault.evidence[permuted.coordinate],
            base_state.vault.evidence[group.coordinate],
        )
        self.assertEqual(
            complement_state.raw_float_accumulator[group.coordinate],
            -base_state.raw_float_accumulator[group.coordinate],
        )
        self.assertEqual(len(base_state.primary_bytes(config)), 352)


def _base_controller_config() -> OnlineCausalControllerConfig:
    return OnlineCausalControllerConfig(
        horizons=(3, 1, 2),
        nuisance_rank=1,
        nuisance_learning_rate=1.0 / 16.0,
        nuisance_warmup=1,
        model_dimension=4,
        heads=1,
        head_dimension=2,
        holographic_slots=1,
        feedforward_dimension=4,
        reader_learning_rate=1e-3,
        recall_loss_weight=1.0,
        gradient_chunk_actions=2,
        cpu_threads=1,
        seed=220_119,
    )


def _pool(config: OnlineCausalControllerConfig) -> Full256ActionPool:
    features = np.zeros(
        (len(config.horizons), KEY_BITS, 2, BRANCH_FEATURES),
        dtype=np.float32,
    )
    resources = np.zeros((KEY_BITS, 2, 3), dtype=np.uint64)
    pairs = tuple(
        _sha256(f"pair-{coordinate}".encode()) for coordinate in range(KEY_BITS)
    )
    return Full256ActionPool(
        horizons=config.horizons,
        branch_features=features,
        final_resources=resources,
        pair_sha256=pairs,
        source_stream_sha256=_SOURCE,
    )


class _FixtureFastState:
    def __init__(
        self,
        config: OnlineCausalControllerConfig,
        coordinates: tuple[int, ...],
    ) -> None:
        horizons = tuple(sorted(config.horizons))
        self.packet_evidence = np.zeros(
            (len(config.horizons), KEY_BITS),
            dtype=np.float32,
        )
        coverage = np.zeros_like(self.packet_evidence, dtype=np.uint16)
        for coordinate in coordinates:
            for horizon in horizons:
                index = config.horizons.index(horizon)
                self.packet_evidence[index, coordinate] = np.float32(
                    coordinate + horizon / 8.0
                )
                coverage[index, coordinate] = np.uint16(1)
        self.base = SimpleNamespace(
            action_count=len(coordinates) * len(horizons),
            coverage=coverage,
        )
        self.decision_count = len(coordinates)
        self.physical_work_units = 2 * horizons[-1] * len(coordinates)

    def to_bytes(self, _config: object) -> bytes:
        return b"fixture-fast-state-v1\x00" + self.packet_evidence.astype(
            "<f4", copy=False
        ).tobytes(order="C")


class _FrozenFixtureController:
    def __init__(self, config: OnlineCausalControllerConfig) -> None:
        self.config = config
        self.controller_config = SimpleNamespace(
            ordered_horizons=tuple(sorted(config.horizons))
        )
        self.label_accesses = 0

    def reader_state_bytes(self) -> bytes:
        return b"frozen-fixture-reader-v1"

    def slow_state_bytes(self) -> bytes:
        return b"frozen-fixture-reader-and-critic-v1"

    def labels_after_prediction_freeze(self) -> np.ndarray:
        self.label_accesses += 1
        raise AssertionError("label surface must never be called")

    def run_action_order(
        self,
        _pool_value: Full256ActionPool,
        action_order: tuple[int, ...],
    ) -> _FixtureFastState:
        decoded = tuple(
            CausalAction.from_flat_index(value, self.config) for value in action_order
        )
        self.last_decoded = decoded
        return _FixtureFastState(
            self.config,
            tuple(action.bit_index for action in decoded),
        )


class FrozenReaderExtractionTests(unittest.TestCase):
    def test_extracts_ordered_exact_incremental_deltas_without_labels(self) -> None:
        config = _base_controller_config()
        pool = _pool(config)
        controller = _FrozenFixtureController(config)
        coordinates = (9, 2, 77)
        extraction = extract_frozen_o1c19_packet_groups(
            controller,
            pool,
            coordinates,
            group_salt=44,
        )
        self.assertEqual(controller.label_accesses, 0)
        self.assertEqual(
            controller.last_decoded,
            tuple(CausalAction(coordinate, 3) for coordinate in coordinates),
        )
        self.assertEqual(extraction.active_coordinates, coordinates)
        self.assertEqual(extraction.ordered_horizons, (1, 2, 3))
        self.assertEqual(extraction.observed_slots, 9)
        self.assertEqual(extraction.physical_work_units, 18)
        self.assertEqual(extraction.groups[0].incremental_work_units, (2, 2, 2))
        self.assertEqual(
            extraction.groups[0].active_coordinates_sha256,
            active_coordinate_sequence_sha256(coordinates),
        )
        self.assertEqual(
            extraction.groups[0].reader_state_sha256,
            extraction.reader_state_sha256,
        )
        self.assertEqual(
            extraction.groups[0].action_pool_sha256,
            extraction.action_pool_sha256,
        )
        self.assertEqual(
            extraction.groups[0].incremental_deltas,
            tuple(float(np.float32(9 + horizon / 8.0)) for horizon in (1, 2, 3)),
        )
        report = extraction.describe()
        self.assertEqual(report["label_accesses"], 0)
        self.assertEqual(report["solver_calls"], 0)
        self.assertEqual(report["current_target_supervised_updates"], 0)
        self.assertTrue(report["upstream_reader_billed_separately_from_live_vault"])
        self.assertEqual(len(extraction.public_packet_ledger_sha256), 64)
        self.assertEqual(len(extraction.sha256), 64)

    def test_core_execution_signatures_have_no_truth_or_label_surface(self) -> None:
        for callable_value in (
            CausalVaultBridge.apply_group,
            execute_packet_delta_groups,
            extract_frozen_o1c19_packet_groups,
        ):
            names = set(inspect.signature(callable_value).parameters)
            self.assertFalse(names & {"key", "labels", "truth", "outcome", "reveal"})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
