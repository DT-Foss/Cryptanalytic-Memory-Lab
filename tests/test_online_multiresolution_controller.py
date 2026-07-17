from __future__ import annotations

import hashlib
import unittest
from dataclasses import replace

import numpy as np

from o1_crypto_lab.full256_action_pool import BRANCH_FEATURES, Full256ActionPool
from o1_crypto_lab.online_causal_controller import (
    KEY_BITS,
    CausalAction,
    OnlineCausalControllerConfig,
    torch,
)
from o1_crypto_lab.online_multiresolution_controller import (
    ZERO_SHA256,
    MultiResolutionCausalController,
    MultiResolutionControllerConfig,
    MultiResolutionControllerError,
    MultiResolutionFastState,
    PacketActionDecision,
    PacketExhaustedDecision,
    PacketStopDecision,
)
from o1_crypto_lab.stationarity_critic import StationarityPrediction


SOURCE_SHA256 = hashlib.sha256(b"o1c19-test-source").hexdigest()
OTHER_SOURCE_SHA256 = hashlib.sha256(b"o1c19-other-source").hexdigest()
PAIR_SHA256 = tuple(
    hashlib.sha256(f"o1c19-pair-{bit}".encode("ascii")).hexdigest()
    for bit in range(KEY_BITS)
)


def _base_config(**overrides: object) -> OnlineCausalControllerConfig:
    values: dict[str, object] = {
        # Deliberately not depth-sorted: packet expansion must use numerical depth,
        # while the persisted base slot ledger must retain configured flat indexes.
        "horizons": (1, 3, 2),
        "nuisance_rank": 1,
        "nuisance_learning_rate": 1.0 / 16.0,
        "nuisance_warmup": 1,
        "model_dimension": 4,
        "heads": 1,
        "head_dimension": 2,
        "holographic_slots": 1,
        "feedforward_dimension": 4,
        "reader_learning_rate": 1e-3,
        "recall_loss_weight": 1.0,
        "gradient_chunk_actions": 2,
        "cpu_threads": 1,
        "seed": 190019,
    }
    values.update(overrides)
    return OnlineCausalControllerConfig(**values)


def _config(**overrides: object) -> MultiResolutionControllerConfig:
    base_overrides = overrides.pop("base_overrides", {})
    values: dict[str, object] = {
        "base": _base_config(**base_overrides),
        "stationarity_penalty": 1.0,
        "critic_exploration_scale": 0.0,
        "soft_coverage_weight": 0.0,
        "soft_age_weight": 0.0,
        "starvation_steps": 8,
        "minimum_decisions_before_stop": 256,
        "stop_margin": 0.0,
        "require_all_coordinates_before_stop": True,
    }
    values.update(overrides)
    return MultiResolutionControllerConfig(**values)


def _synthetic_pool(
    config: MultiResolutionControllerConfig,
    *,
    source_stream_sha256: str = SOURCE_SHA256,
) -> Full256ActionPool:
    features = np.zeros(
        (config.horizon_count, KEY_BITS, 2, BRANCH_FEATURES),
        dtype=np.float32,
    )
    bits = np.arange(KEY_BITS, dtype=np.float32)
    parity = np.where(np.arange(KEY_BITS) % 2 == 0, 1.0, -1.0).astype(np.float32)
    for horizon_index, _horizon in enumerate(config.base.horizons):
        common = np.zeros((KEY_BITS, BRANCH_FEATURES), dtype=np.float32)
        signed = np.zeros_like(common)
        common[:, 0] = np.float32(horizon_index + 1) / 8.0
        common[:, 1] = (bits + np.float32(0.5)) / np.float32(KEY_BITS)
        common[:, 4] = np.sin(
            (bits + np.float32(1.0)) * np.float32(horizon_index + 1) / 19.0
        )
        signed[:, 2] = parity * np.float32(0.5 + 0.1 * horizon_index)
        signed[:, 3] = np.cos(
            (bits + np.float32(1.0)) / np.float32(7.0 + horizon_index)
        )
        signed[:, 5] = parity * (bits + np.float32(1.0)) / np.float32(4 * KEY_BITS)
        features[horizon_index, :, 0] = common - np.float32(0.5) * signed
        features[horizon_index, :, 1] = common + np.float32(0.5) * signed
    resources = np.zeros((KEY_BITS, 2, 3), dtype=np.uint64)
    resources[:, :, 0] = np.arange(KEY_BITS, dtype=np.uint64)[:, None] + 1
    return Full256ActionPool(
        horizons=config.base.horizons,
        branch_features=features,
        final_resources=resources,
        pair_sha256=PAIR_SHA256,
        source_stream_sha256=source_stream_sha256,
    )


def _manual_decision(
    controller: MultiResolutionCausalController,
    state: MultiResolutionFastState,
    action: CausalAction,
) -> PacketActionDecision:
    return PacketActionDecision(
        action=action,
        score=0.0,
        predicted_reward=0.0,
        stationarity_std=0.0,
        epistemic_bonus=0.0,
        coverage_bonus=0.0,
        age_bonus=0.0,
        physical_work_units=controller.action_physical_work_units(state, action),
        starvation_forced=False,
        state_before_sha256=state.sha256(controller.controller_config),
        context=np.zeros(
            controller.controller_config.critic_context_dimension,
            dtype=np.float32,
        ),
    )


@unittest.skipUnless(torch is not None, "optional torch training dependency is absent")
class OnlineMultiResolutionControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = _config()
        self.pool = _synthetic_pool(self.config)
        self.controller = MultiResolutionCausalController(self.config)

    def test_packet_stores_each_q_after_minus_q_before_exactly_once(self) -> None:
        state = self.controller.initial_fast_state(SOURCE_SHA256)
        bit = 17
        q0 = float(self.controller.query_o1_field(state)[bit])

        first = CausalAction(bit, 1)
        first_receipt = self.controller.observe_action(
            state,
            self.pool,
            _manual_decision(self.controller, state, first),
        )
        q1 = float(self.controller.query_o1_field(state)[bit])
        first_slot = self.config.base.horizons.index(1)
        self.assertEqual(
            float(state.packet_evidence[first_slot, bit]),
            np.float32(q1 - q0),
        )
        self.assertEqual(
            first_receipt.packet_delta_sum,
            float(state.packet_evidence[first_slot, bit]),
        )

        second = CausalAction(bit, 2)
        second_receipt = self.controller.observe_action(
            state,
            self.pool,
            _manual_decision(self.controller, state, second),
        )
        q2 = float(self.controller.query_o1_field(state)[bit])
        second_slot = self.config.base.horizons.index(2)
        self.assertEqual(
            float(state.packet_evidence[second_slot, bit]),
            np.float32(q2 - q1),
        )
        self.assertEqual(
            second_receipt.packet_delta_sum,
            float(state.packet_evidence[second_slot, bit]),
        )

        packet_sum = float(state.packet_evidence[:, bit].sum(dtype=np.float32))
        self.assertEqual(packet_sum, np.float32(q2 - q0))
        # The gate starts with exact unit weights, so the deployed logit is the
        # telescoped increment, not q1 + q2 (the O1C18 double integration).
        self.assertEqual(float(state.base.posterior_logits[bit]), packet_sum)
        self.assertNotEqual(float(state.base.posterior_logits[bit]), q1 + q2)

    def test_deep_request_auto_observes_prefixes_and_bills_incremental_work(
        self,
    ) -> None:
        state = self.controller.initial_fast_state(SOURCE_SHA256)
        bit = 41
        deep = CausalAction(bit, 3)

        receipt = self.controller.observe_action(
            state,
            self.pool,
            _manual_decision(self.controller, state, deep),
        )

        self.assertEqual(
            receipt.observed_slots,
            (CausalAction(bit, 1), CausalAction(bit, 2), CausalAction(bit, 3)),
        )
        self.assertEqual(receipt.physical_work_units, 6)
        self.assertEqual(state.physical_work_units, 6)
        self.assertEqual(state.decision_count, 1)
        self.assertEqual(state.base.action_count, 3)
        self.assertEqual(
            state.decision_order[:1].tolist(),
            [deep.flat_index(self.config.base)],
        )
        self.assertEqual(
            state.base.action_order[:3].tolist(),
            [
                CausalAction(bit, horizon).flat_index(self.config.base)
                for horizon in (1, 2, 3)
            ],
        )
        self.assertEqual(int(state.base.coverage[:, bit].sum()), 3)

        incremental = self.controller.initial_fast_state(SOURCE_SHA256)
        shallow = CausalAction(bit, 1)
        shallow_receipt = self.controller.observe_action(
            incremental,
            self.pool,
            _manual_decision(self.controller, incremental, shallow),
        )
        deep_receipt = self.controller.observe_action(
            incremental,
            self.pool,
            _manual_decision(self.controller, incremental, deep),
        )
        self.assertEqual(shallow_receipt.physical_work_units, 2)
        self.assertEqual(deep_receipt.physical_work_units, 4)
        self.assertEqual(
            deep_receipt.observed_slots,
            (CausalAction(bit, 2), CausalAction(bit, 3)),
        )
        self.assertEqual(incremental.physical_work_units, 6)

    def test_observation_errors_are_atomic_and_source_and_snapshot_bound(self) -> None:
        state = self.controller.initial_fast_state(SOURCE_SHA256)
        action = CausalAction(7, 1)
        decision = _manual_decision(self.controller, state, action)
        fast_before = state.to_bytes(self.config)
        slow_before = self.controller.slow_state_bytes()
        other_pool = _synthetic_pool(
            self.config,
            source_stream_sha256=OTHER_SOURCE_SHA256,
        )

        with self.assertRaisesRegex(MultiResolutionControllerError, "source differs"):
            self.controller.observe_action(state, other_pool, decision)
        self.assertEqual(state.to_bytes(self.config), fast_before)
        self.assertEqual(self.controller.slow_state_bytes(), slow_before)

        wrong_work = replace(
            decision, physical_work_units=decision.physical_work_units + 1
        )
        with self.assertRaisesRegex(MultiResolutionControllerError, "work"):
            self.controller.observe_action(state, self.pool, wrong_work)
        self.assertEqual(state.to_bytes(self.config), fast_before)

        with self.assertRaisesRegex(MultiResolutionControllerError, "work"):
            self.controller.observe_action(
                state,
                self.pool,
                decision,
                maximum_work_units=decision.physical_work_units - 1,
            )
        self.assertEqual(state.to_bytes(self.config), fast_before)

        self.controller.observe_action(state, self.pool, decision)
        fast_after = state.to_bytes(self.config)
        with self.assertRaisesRegex(MultiResolutionControllerError, "stale"):
            self.controller.observe_action(state, self.pool, decision)
        self.assertEqual(state.to_bytes(self.config), fast_after)
        self.assertEqual(self.controller.slow_state_bytes(), slow_before)

    def test_picker_queries_every_affordable_state_address(self) -> None:
        state = self.controller.initial_fast_state(SOURCE_SHA256)
        fast_before = state.to_bytes(self.config)
        slow_before = self.controller.slow_state_bytes()
        queried: list[tuple[CausalAction, ...]] = []
        original = self.controller._action_query_logits

        def recording_query(
            live_state: MultiResolutionFastState,
            actions: tuple[CausalAction, ...] | list[CausalAction],
        ) -> tuple[np.ndarray, np.ndarray]:
            queried.append(tuple(actions))
            return original(live_state, actions)

        self.controller._action_query_logits = recording_query  # type: ignore[method-assign]
        decision = self.controller.choose_action(state)

        self.assertIsInstance(decision, PacketActionDecision)
        self.assertEqual(len(queried), 1)
        self.assertEqual(len(queried[0]), KEY_BITS)
        self.assertEqual(
            {action.bit_index for action in queried[0]}, set(range(KEY_BITS))
        )
        self.assertEqual({action.horizon for action in queried[0]}, {1})
        self.assertEqual(state.decision_count, 0)
        self.assertEqual(state.to_bytes(self.config), fast_before)
        self.assertEqual(self.controller.slow_state_bytes(), slow_before)

    def test_starvation_is_finite_fallback_not_permanent_minimum_coverage(
        self,
    ) -> None:
        config = _config(starvation_steps=1)
        controller = MultiResolutionCausalController(config)
        pool = _synthetic_pool(config)
        state = controller.initial_fast_state(SOURCE_SHA256)
        controller.observe_action(
            state,
            pool,
            _manual_decision(controller, state, CausalAction(3, 1)),
        )

        decision = controller.choose_action(state)

        self.assertIsInstance(decision, PacketActionDecision)
        assert isinstance(decision, PacketActionDecision)
        self.assertTrue(decision.starvation_forced)
        self.assertNotEqual(decision.action.bit_index, 3)
        self.assertEqual(decision.action.horizon, 1)

    def test_learned_utility_can_deepen_before_global_breadth(self) -> None:
        config = _config(starvation_steps=1000)
        controller = MultiResolutionCausalController(config)
        pool = _synthetic_pool(config)
        state = controller.initial_fast_state(SOURCE_SHA256)
        controller.observe_action(
            state,
            pool,
            _manual_decision(controller, state, CausalAction(3, 1)),
        )

        def prefer_covered_h2(
            context: np.ndarray,
            _stationarity_penalty: float,
            _exploration_scale: float,
        ) -> StationarityPrediction:
            covered_coordinate = float(context[4]) < 0.75
            h2_index = 6 + config.base.horizons.index(2)
            preferred = covered_coordinate and float(context[h2_index]) == 1.0
            mean = 100.0 if preferred else 0.0
            return StationarityPrediction(mean, 0.0, 0.0, mean)

        queried: list[tuple[CausalAction, ...]] = []
        original_query = controller._action_query_logits

        def record_query(
            live_state: MultiResolutionFastState,
            actions: tuple[CausalAction, ...] | list[CausalAction],
        ) -> tuple[np.ndarray, np.ndarray]:
            queried.append(tuple(actions))
            return original_query(live_state, actions)

        controller._action_query_logits = record_query  # type: ignore[method-assign]
        controller.critic.predict = prefer_covered_h2  # type: ignore[method-assign]
        decision = controller.choose_action(state)

        self.assertIsInstance(decision, PacketActionDecision)
        assert isinstance(decision, PacketActionDecision)
        self.assertFalse(decision.starvation_forced)
        self.assertEqual(decision.action, CausalAction(3, 2))
        self.assertEqual(len(queried[0]), KEY_BITS + 1)
        self.assertIn(CausalAction(3, 2), queried[0])
        self.assertIn(CausalAction(3, 3), queried[0])

    def test_policy_apply_reproves_winner_and_horizon_filters_fail_loudly(
        self,
    ) -> None:
        state = self.controller.initial_fast_state(SOURCE_SHA256)
        with self.assertRaisesRegex(MultiResolutionControllerError, "scout depth"):
            self.controller.choose_action(state, allowed_horizons=(3,))
        with self.assertRaisesRegex(MultiResolutionControllerError, "unknown"):
            self.controller.choose_action(state, allowed_horizons=(True,))

        decision = self.controller.choose_action(state, allowed_horizons=(1,))
        self.assertIsInstance(decision, PacketActionDecision)
        assert isinstance(decision, PacketActionDecision)
        self.assertEqual(decision.allowed_horizons, (1,))
        before = state.sha256(self.config)
        forged = replace(decision, score=decision.score + 1.0)
        with self.assertRaisesRegex(MultiResolutionControllerError, "proof differs"):
            self.controller.apply_policy_action(state, self.pool, forged)
        self.assertEqual(state.sha256(self.config), before)

        receipt = self.controller.apply_policy_action(state, self.pool, decision)
        self.assertEqual(receipt.requested_action, decision.action)
        manual_state = self.controller.initial_fast_state(SOURCE_SHA256)
        with self.assertRaisesRegex(MultiResolutionControllerError, "manual decisions"):
            self.controller.apply_policy_action(
                manual_state,
                self.pool,
                _manual_decision(
                    self.controller,
                    manual_state,
                    CausalAction(3, 1),
                ),
            )

    def test_stop_and_budget_exhaustion_are_distinct_decisions(self) -> None:
        config = _config(
            minimum_decisions_before_stop=0,
            require_all_coordinates_before_stop=False,
            stop_margin=1.0,
        )
        controller = MultiResolutionCausalController(config)
        zero_design = np.zeros(
            (1, config.critic_context_dimension),
            dtype=np.float64,
        )
        zero_design[0, 0] = 1.0
        zero_reward = np.zeros(1, dtype=np.float64)
        controller.critic.update_episode(zero_design, zero_reward)
        controller.critic.update_episode(zero_design, zero_reward)
        controller.critic_reader_sha256 = controller.reader_state_sha256
        state = controller.initial_fast_state(SOURCE_SHA256)

        exhausted = controller.choose_action(state, maximum_work_units=0)
        self.assertIsInstance(exhausted, PacketExhaustedDecision)
        assert isinstance(exhausted, PacketExhaustedDecision)
        self.assertEqual(exhausted.remaining_work_units, 0)
        self.assertFalse(state.stopped)

        stop = controller.choose_action(state)
        self.assertIsInstance(stop, PacketStopDecision)
        assert isinstance(stop, PacketStopDecision)
        self.assertGreaterEqual(stop.score, stop.best_candidate_score)
        controller.apply_stop(state, stop)
        self.assertTrue(state.stopped)
        self.assertEqual(state.stop_decision_count, 0)
        with self.assertRaisesRegex(MultiResolutionControllerError, "already stopped"):
            controller.choose_action(state)

        starvation_config = _config(
            starvation_steps=1,
            minimum_decisions_before_stop=0,
            require_all_coordinates_before_stop=False,
            stop_margin=1.0,
        )
        starvation_controller = MultiResolutionCausalController(starvation_config)
        starvation_state = starvation_controller.initial_fast_state(SOURCE_SHA256)
        forced = starvation_controller.choose_action(starvation_state)
        self.assertIsInstance(forced, PacketActionDecision)
        assert isinstance(forced, PacketActionDecision)
        self.assertTrue(forced.starvation_forced)

    def test_work_budgeted_policy_uses_incremental_ledger_without_slow_updates(
        self,
    ) -> None:
        slow_before = self.controller.slow_state_bytes()

        state = self.controller.run_work_budgeted_policy(self.pool, work_budget=5)

        self.assertEqual(state.physical_work_units, 4)
        self.assertEqual(self.controller.requested_work_units(state), 4)
        self.assertEqual(state.decision_count, 2)
        self.assertLessEqual(state.physical_work_units, 5)
        self.assertEqual(self.controller.slow_state_bytes(), slow_before)

    def test_global_polarity_swap_is_exactly_odd_through_gate_and_packet(
        self,
    ) -> None:
        direct = self.controller.initial_fast_state(SOURCE_SHA256)
        swapped = self.controller.initial_fast_state(SOURCE_SHA256)
        swapped_pool = self.pool.polarity_swapped()
        for action in (CausalAction(13, 3), CausalAction(201, 2)):
            self.controller.observe_action(
                direct,
                self.pool,
                _manual_decision(self.controller, direct, action),
            )
            self.controller.observe_action(
                swapped,
                swapped_pool,
                _manual_decision(self.controller, swapped, action),
            )

        np.testing.assert_array_equal(direct.packet_evidence, -swapped.packet_evidence)
        np.testing.assert_array_equal(
            direct.base.posterior_logits,
            -swapped.base.posterior_logits,
        )
        np.testing.assert_array_equal(
            direct.base.posterior_precision,
            swapped.base.posterior_precision,
        )
        self.assertEqual(
            direct.base.positive_o1.to_bytes(self.config.base.o1_config),
            swapped.base.negative_o1.to_bytes(self.config.base.o1_config),
        )
        self.assertEqual(
            direct.base.negative_o1.to_bytes(self.config.base.o1_config),
            swapped.base.positive_o1.to_bytes(self.config.base.o1_config),
        )

    def test_precision_tracks_effective_gate_weight(self) -> None:
        with torch.no_grad():
            self.controller.gate.raw_scales.zero_()
        state = self.controller.initial_fast_state(SOURCE_SHA256)
        action = CausalAction(37, 1)

        self.controller.observe_action(
            state,
            self.pool,
            _manual_decision(self.controller, state, action),
        )

        self.assertNotEqual(
            float(state.packet_evidence[self.config.base.horizons.index(1), 37]),
            0.0,
        )
        self.assertEqual(float(state.base.posterior_logits[37]), 0.0)
        self.assertEqual(float(state.base.posterior_precision[37]), 0.0)

    def test_fast_and_slow_serialization_are_exact_and_atomic(self) -> None:
        state = self.controller.initial_fast_state(SOURCE_SHA256)
        initial_bytes = state.to_bytes(self.config)
        self.controller.observe_action(
            state,
            self.pool,
            _manual_decision(self.controller, state, CausalAction(29, 3)),
        )
        payload = state.to_bytes(self.config)
        restored = MultiResolutionFastState.from_bytes(payload, self.config)

        self.assertEqual(len(payload), len(initial_bytes))
        self.assertEqual(restored.to_bytes(self.config), payload)
        self.assertEqual(restored.sha256(self.config), state.sha256(self.config))

        bad_work = restored.clone()
        bad_work.physical_work_units += 1
        with self.assertRaisesRegex(MultiResolutionControllerError, "work ledger"):
            bad_work.to_bytes(self.config)

        bad_packet = restored.clone()
        uncovered = tuple(np.argwhere(bad_packet.base.coverage == 0)[0])
        bad_packet.packet_evidence[uncovered] = np.float32(0.25)
        with self.assertRaisesRegex(MultiResolutionControllerError, "uncovered"):
            bad_packet.to_bytes(self.config)

        forged_stop = self.controller.initial_fast_state(SOURCE_SHA256)
        forged_stop.stopped = True
        with self.assertRaisesRegex(
            MultiResolutionControllerError,
            "minimum decision clock",
        ):
            forged_stop.to_bytes(self.config)

        permissive_config = _config(
            minimum_decisions_before_stop=0,
            require_all_coordinates_before_stop=False,
        )
        permissive_controller = MultiResolutionCausalController(permissive_config)
        forged_stationarity = permissive_controller.initial_fast_state(SOURCE_SHA256)
        forged_stationarity.stopped = True
        forged_stationarity.validate(permissive_config)
        with self.assertRaisesRegex(
            MultiResolutionControllerError,
            "stationary STOP eligibility",
        ):
            permissive_controller.query_posteriors(forged_stationarity)

        reader_payload = self.controller.reader_state_bytes()
        slow_payload = self.controller.slow_state_bytes()
        clone = MultiResolutionCausalController(self.config)
        clone.load_slow_state_bytes(slow_payload)
        self.assertEqual(clone.reader_state_bytes(), reader_payload)
        self.assertEqual(clone.slow_state_bytes(), slow_payload)

        slow_before = clone.slow_state_bytes()
        corrupted = bytearray(slow_payload)
        corrupted[-1] ^= 1
        with self.assertRaises(Exception):
            clone.load_slow_state_bytes(bytes(corrupted))
        self.assertEqual(clone.slow_state_bytes(), slow_before)

    def test_reward_replay_telescopes_and_never_mutates_slow_state(self) -> None:
        order = [
            CausalAction(5, 3).flat_index(self.config.base),
            CausalAction(91, 2).flat_index(self.config.base),
            CausalAction(207, 1).flat_index(self.config.base),
        ]
        labels = (np.arange(KEY_BITS) % 2).astype(np.float32)
        slow_before = self.controller.slow_state_bytes()

        replay = self.controller.replay_packet_rewards(self.pool, order, labels)

        self.assertEqual(self.controller.slow_state_bytes(), slow_before)
        self.assertEqual(replay.action_order.tolist(), order)
        self.assertEqual(
            replay.contexts.shape,
            (len(order), self.config.critic_context_dimension),
        )
        self.assertEqual(replay.physical_work_units.tolist(), [6, 4, 2])
        self.assertAlmostEqual(
            float(replay.delta_nll_bits.sum()),
            replay.initial_nll_bits - replay.final_nll_bits,
            places=10,
        )
        self.assertFalse(replay.action_order.flags.writeable)
        self.assertFalse(replay.contexts.flags.writeable)
        self.assertFalse(replay.physical_work_units.flags.writeable)
        self.assertFalse(replay.packet_delta_sums.flags.writeable)
        self.assertFalse(replay.delta_nll_bits.flags.writeable)

        with self.assertRaisesRegex(MultiResolutionControllerError, "unique"):
            self.controller.replay_packet_rewards(
                self.pool,
                [order[0], order[0]],
                labels,
            )
        self.assertEqual(self.controller.slow_state_bytes(), slow_before)

    def test_critic_is_frozen_reader_bound_and_reader_learning_invalidates_it(
        self,
    ) -> None:
        order = [
            CausalAction(11, 3).flat_index(self.config.base),
            CausalAction(103, 2).flat_index(self.config.base),
        ]
        labels = (np.arange(KEY_BITS) % 2).astype(np.float32)
        reader_before_fit = self.controller.reader_state_bytes()

        critic_report = self.controller.fit_critic_episode(self.pool, order, labels)

        self.assertEqual(self.controller.reader_state_bytes(), reader_before_fit)
        self.assertEqual(self.controller.critic.episode_count, 1)
        self.assertEqual(
            self.controller.critic_reader_sha256,
            self.controller.reader_state_sha256,
        )
        self.assertEqual(critic_report.decisions, len(order))
        self.assertEqual(critic_report.critic_episode_count, 1)
        self.assertEqual(
            critic_report.reader_state_sha256,
            self.controller.reader_state_sha256,
        )
        fitted_payload = self.controller.slow_state_bytes()
        restored = MultiResolutionCausalController(self.config)
        restored.load_slow_state_bytes(fitted_payload)
        self.assertEqual(restored.slow_state_bytes(), fitted_payload)
        self.assertEqual(restored.critic.episode_count, 1)
        self.assertEqual(
            restored.critic_reader_sha256,
            restored.reader_state_sha256,
        )

        state = self.controller.run_action_order(self.pool, order)
        reader_before_learn = self.controller.reader_state_sha256
        training_report = self.controller.learn_reader_after_reveal(
            self.pool,
            state,
            labels,
        )

        self.assertTrue(state.base.reveal_consumed)
        self.assertTrue(training_report.critic_invalidated)
        self.assertEqual(training_report.decisions, len(order))
        self.assertEqual(training_report.observed_slots, 5)
        self.assertEqual(training_report.training_passes, 1)
        self.assertEqual(training_report.streamed_training_slots, 5)
        self.assertGreaterEqual(len(training_report.training_loss_bits), 1)
        self.assertNotEqual(self.controller.reader_state_sha256, reader_before_learn)
        self.assertEqual(self.controller.reader_episodes, 1)
        self.assertEqual(self.controller.critic.episode_count, 0)
        self.assertEqual(self.controller.critic_reader_sha256, ZERO_SHA256)
        with self.assertRaisesRegex(MultiResolutionControllerError, "already consumed"):
            self.controller.learn_reader_after_reveal(self.pool, state, labels)

    def test_final_reader_can_atomically_refit_all_build_critic_episodes(
        self,
    ) -> None:
        labels = (np.arange(KEY_BITS) % 2).astype(np.float32)
        first_order = [CausalAction(7, 2).flat_index(self.config.base)]
        second_order = [CausalAction(73, 3).flat_index(self.config.base)]
        reader_before = self.controller.reader_state_bytes()

        report = self.controller.refit_critic_corpus(
            (
                (self.pool, first_order, labels),
                (
                    _synthetic_pool(
                        self.config,
                        source_stream_sha256=OTHER_SOURCE_SHA256,
                    ),
                    second_order,
                    1.0 - labels,
                ),
            )
        )

        self.assertEqual(self.controller.reader_state_bytes(), reader_before)
        self.assertEqual(self.controller.critic.episode_count, 2)
        self.assertEqual(len(report.episode_reports), 2)
        self.assertEqual(report.total_decisions, 2)
        self.assertEqual(report.final_critic_sha256, self.controller.critic.sha256())
        self.assertEqual(
            report.reader_state_sha256, self.controller.reader_state_sha256
        )
        critic_before_error = self.controller.critic.to_bytes()
        binding_before_error = self.controller.critic_reader_sha256
        with self.assertRaisesRegex(MultiResolutionControllerError, "unique"):
            self.controller.refit_critic_corpus(
                (
                    (self.pool, first_order, labels),
                    (self.pool, second_order, 1.0 - labels),
                )
            )
        self.assertEqual(self.controller.critic.to_bytes(), critic_before_error)
        self.assertEqual(self.controller.critic_reader_sha256, binding_before_error)
        with self.assertRaisesRegex(MultiResolutionControllerError, "entry"):
            self.controller.refit_critic_corpus(
                (
                    (self.pool, first_order, labels),
                    (self.pool, second_order),  # type: ignore[arg-type]
                )
            )
        self.assertEqual(self.controller.critic.to_bytes(), critic_before_error)
        self.assertEqual(self.controller.critic_reader_sha256, binding_before_error)

    def test_invalid_reveal_is_atomic_and_small_training_updates_gate_or_stream(
        self,
    ) -> None:
        order = [
            CausalAction(3, 2).flat_index(self.config.base),
            CausalAction(17, 1).flat_index(self.config.base),
        ]
        state = self.controller.run_action_order(self.pool, order)
        slow_before = self.controller.slow_state_bytes()
        fast_before = state.to_bytes(self.config)

        with self.assertRaisesRegex(MultiResolutionControllerError, "binary shape"):
            self.controller.learn_reader_after_reveal(
                self.pool,
                state,
                np.zeros(KEY_BITS - 1, dtype=np.float32),
            )
        self.assertEqual(self.controller.slow_state_bytes(), slow_before)
        self.assertEqual(state.to_bytes(self.config), fast_before)

        labels = (np.arange(KEY_BITS) % 2).astype(np.float32)
        report = self.controller.learn_reader_after_reveal(self.pool, state, labels)
        self.assertEqual(report.decisions, 2)
        self.assertEqual(report.observed_slots, 3)
        self.assertEqual(report.training_passes, 1)
        self.assertEqual(report.streamed_training_slots, 3)
        self.assertTrue(all(np.isfinite(report.training_loss_bits)))
        self.assertNotEqual(
            report.reader_state_sha256_before, report.reader_state_sha256_after
        )

    def test_multiple_training_passes_replay_whole_frozen_stream(self) -> None:
        config = _config(reader_training_passes=2)
        controller = MultiResolutionCausalController(config)
        pool = _synthetic_pool(config)
        order = [CausalAction(23, 2).flat_index(config.base)]
        state = controller.run_action_order(pool, order)
        labels = (np.arange(KEY_BITS) % 2).astype(np.float32)

        report = controller.learn_reader_after_reveal(pool, state, labels)

        self.assertEqual(report.training_passes, 2)
        self.assertEqual(report.observed_slots, 2)
        self.assertEqual(report.streamed_training_slots, 4)
        self.assertEqual(len(report.training_loss_bits), 2)

    def test_training_forwards_entire_episode_with_one_frozen_snapshot(self) -> None:
        order = [
            CausalAction(5, 3).flat_index(self.config.base),
            CausalAction(19, 2).flat_index(self.config.base),
        ]
        labels = (np.arange(KEY_BITS) % 2).astype(np.float32)
        reader_before = self.controller.reader_state_sha256
        forward_reader_hashes: list[str] = []
        original_stream = self.controller._stream_packet_delta_torch

        def recording_stream(*args: object, **kwargs: object) -> object:
            forward_reader_hashes.append(self.controller.reader_state_sha256)
            return original_stream(*args, **kwargs)

        self.controller._stream_packet_delta_torch = recording_stream  # type: ignore[method-assign]
        losses, observed_slots = self.controller._train_packet_reader_episode(
            self.pool,
            order,
            labels,
            train_stream=True,
            train_gate=True,
        )

        self.assertEqual(observed_slots, 5)
        self.assertGreaterEqual(len(losses), 2)
        self.assertEqual(forward_reader_hashes, [reader_before] * observed_slots)
        self.assertNotEqual(self.controller.reader_state_sha256, reader_before)

    def test_stream_only_and_gate_only_training_touch_only_enabled_parameters(
        self,
    ) -> None:
        order = [CausalAction(11, 2).flat_index(self.config.base)]
        labels = (np.arange(KEY_BITS) % 2).astype(np.float32)

        gate_only = MultiResolutionCausalController(self.config)
        gate_pool = _synthetic_pool(self.config)
        gate_reader_before = [
            value.detach().clone() for value in gate_only.reader.parameters()
        ]
        gate_before = [value.detach().clone() for value in gate_only.gate.parameters()]
        gate_only._train_packet_reader_episode(
            gate_pool,
            order,
            labels,
            train_stream=False,
            train_gate=True,
        )
        self.assertTrue(
            all(
                torch.equal(before, after)
                for before, after in zip(
                    gate_reader_before,
                    gate_only.reader.parameters(),
                    strict=True,
                )
            )
        )
        self.assertTrue(
            any(
                not torch.equal(before, after)
                for before, after in zip(
                    gate_before,
                    gate_only.gate.parameters(),
                    strict=True,
                )
            )
        )

        stream_only = MultiResolutionCausalController(self.config)
        stream_pool = _synthetic_pool(self.config)
        stream_before = [
            value.detach().clone() for value in stream_only.reader.parameters()
        ]
        stream_gate_before = [
            value.detach().clone() for value in stream_only.gate.parameters()
        ]
        stream_only._train_packet_reader_episode(
            stream_pool,
            order,
            labels,
            train_stream=True,
            train_gate=False,
        )
        self.assertTrue(
            any(
                not torch.equal(before, after)
                for before, after in zip(
                    stream_before,
                    stream_only.reader.parameters(),
                    strict=True,
                )
            )
        )
        self.assertTrue(
            all(
                torch.equal(before, after)
                for before, after in zip(
                    stream_gate_before,
                    stream_only.gate.parameters(),
                    strict=True,
                )
            )
        )

    def test_mismatched_nonempty_critic_binding_is_rejected_by_picker(self) -> None:
        order = [CausalAction(31, 1).flat_index(self.config.base)]
        labels = (np.arange(KEY_BITS) % 2).astype(np.float32)
        self.controller.fit_critic_episode(self.pool, order, labels)
        self.controller.critic_reader_sha256 = OTHER_SOURCE_SHA256

        with self.assertRaisesRegex(MultiResolutionControllerError, "critic.*bound"):
            self.controller.initial_fast_state(SOURCE_SHA256)
