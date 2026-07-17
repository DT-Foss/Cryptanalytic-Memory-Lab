from __future__ import annotations

import hashlib
import unittest

import numpy as np

from o1_crypto_lab.full256_action_pool import (
    BRANCH_FEATURES,
    Full256ActionPool,
)
from o1_crypto_lab.online_causal_controller import (
    KEY_BITS,
    BoundedLinUCBCritic,
    CausalAction,
    OnlineCausalController,
    OnlineCausalControllerConfig,
    OnlineCausalControllerError,
    OnlineCausalFastState,
    OnlineNuisanceState,
    PairedCausalObservation,
    mobius_contrast,
    torch,
)


SOURCE_SHA256 = hashlib.sha256(b"online-controller-test-source").hexdigest()
OTHER_SOURCE_SHA256 = hashlib.sha256(b"online-controller-other-source").hexdigest()
PAIR_SHA256 = tuple(
    hashlib.sha256(f"online-controller-pair-{bit}".encode("ascii")).hexdigest()
    for bit in range(KEY_BITS)
)


def _config(**overrides: object) -> OnlineCausalControllerConfig:
    values: dict[str, object] = {
        "horizons": (3, 5),
        "nuisance_rank": 2,
        "nuisance_learning_rate": 1.0 / 16.0,
        "nuisance_warmup": 2,
        "model_dimension": 8,
        "heads": 1,
        "head_dimension": 4,
        "holographic_slots": 2,
        "feedforward_dimension": 8,
        "reader_learning_rate": 1e-3,
        "gradient_chunk_actions": 2,
        "cpu_threads": 1,
        "seed": 170017,
    }
    values.update(overrides)
    return OnlineCausalControllerConfig(**values)


def _synthetic_pool(
    config: OnlineCausalControllerConfig,
    *,
    source_stream_sha256: str = SOURCE_SHA256,
) -> Full256ActionPool:
    features = np.zeros(
        (config.horizon_count, KEY_BITS, 2, BRANCH_FEATURES),
        dtype=np.float32,
    )
    bits = np.arange(KEY_BITS, dtype=np.float32)
    parity = np.where(np.arange(KEY_BITS) % 2 == 0, 1.0, -1.0).astype(np.float32)
    for horizon_index, _horizon in enumerate(config.horizons):
        common = np.zeros((KEY_BITS, BRANCH_FEATURES), dtype=np.float32)
        signed = np.zeros_like(common)
        common[:, 0] = np.float32(horizon_index + 1) / 8.0
        common[:, 1] = (bits + 0.5) / KEY_BITS
        common[:, 4] = np.sin((bits + 1.0) * (horizon_index + 1.0) / 19.0)
        signed[:, 2] = parity * np.float32(0.5 + 0.1 * horizon_index)
        signed[:, 3] = np.cos((bits + 1.0) / (7.0 + horizon_index))
        signed[:, 5] = parity * (bits + 1.0) / (4.0 * KEY_BITS)
        features[horizon_index, :, 0] = common - 0.5 * signed
        features[horizon_index, :, 1] = common + 0.5 * signed
    resources = np.zeros((KEY_BITS, 2, 3), dtype=np.uint64)
    resources[:, :, 0] = np.arange(KEY_BITS, dtype=np.uint64)[:, None] + 1
    return Full256ActionPool(
        horizons=config.horizons,
        branch_features=features,
        final_resources=resources,
        pair_sha256=PAIR_SHA256,
        source_stream_sha256=source_stream_sha256,
    )


@unittest.skipUnless(torch is not None, "optional torch training dependency is absent")
class OnlineCausalControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = _config()
        self.pool = _synthetic_pool(self.config)

    def test_observation_swap_negates_signed_and_preserves_common(self) -> None:
        action = CausalAction(bit_index=17, horizon=self.config.horizons[0])
        observation = PairedCausalObservation.from_pool(self.pool, action)
        swapped = observation.polarity_swapped()

        np.testing.assert_array_equal(
            observation.signed,
            observation.one_features - observation.zero_features,
        )
        np.testing.assert_array_equal(
            observation.common,
            0.5 * (observation.one_features + observation.zero_features),
        )
        np.testing.assert_array_equal(swapped.signed, -observation.signed)
        np.testing.assert_array_equal(swapped.common, observation.common)
        self.assertFalse(observation.zero_features.flags.writeable)
        self.assertFalse(observation.one_features.flags.writeable)

    def test_nuisance_global_swap_preserves_odd_even_invariants(self) -> None:
        direct = OnlineNuisanceState.initial(self.config)
        swapped = OnlineNuisanceState.initial(self.config)
        generator = np.random.Generator(np.random.PCG64(71))

        for step in range(6):
            signed = generator.standard_normal(BRANCH_FEATURES).astype(np.float32)
            common = generator.standard_normal(BRANCH_FEATURES).astype(np.float32)
            horizon_index = step % self.config.horizon_count
            odd_primary, odd_residual, even = direct.transform(
                signed,
                common,
                horizon_index,
                self.config,
                update=True,
            )
            (
                swapped_primary,
                swapped_residual,
                swapped_even,
            ) = swapped.transform(
                -signed,
                common,
                horizon_index,
                self.config,
                update=True,
            )
            np.testing.assert_allclose(
                swapped_primary, -odd_primary, rtol=0.0, atol=1e-7
            )
            np.testing.assert_allclose(
                swapped_residual, -odd_residual, rtol=0.0, atol=1e-7
            )
            np.testing.assert_allclose(swapped_even, even, rtol=0.0, atol=0.0)

        np.testing.assert_array_equal(swapped.counts, direct.counts)
        np.testing.assert_allclose(
            swapped.signed_mean, -direct.signed_mean, rtol=0.0, atol=1e-14
        )
        np.testing.assert_allclose(
            swapped.signed_m2, direct.signed_m2, rtol=0.0, atol=1e-14
        )
        np.testing.assert_allclose(
            swapped.common_mean, direct.common_mean, rtol=0.0, atol=0.0
        )
        np.testing.assert_allclose(
            swapped.common_m2, direct.common_m2, rtol=0.0, atol=0.0
        )
        np.testing.assert_allclose(swapped.basis, direct.basis, rtol=0.0, atol=1e-14)

    def test_mirrored_controller_is_antisymmetric_and_common_only_is_zero(
        self,
    ) -> None:
        controller = OnlineCausalController(self.config)
        direct = controller.initial_fast_state(SOURCE_SHA256)
        swapped = controller.initial_fast_state(SOURCE_SHA256)
        swapped_pool = self.pool.polarity_swapped()
        actions = (
            CausalAction(3, self.config.horizons[0]),
            CausalAction(91, self.config.horizons[1]),
            CausalAction(207, self.config.horizons[0]),
        )

        for action in actions:
            controller.observe(
                direct, PairedCausalObservation.from_pool(self.pool, action)
            )
            controller.observe(
                swapped,
                PairedCausalObservation.from_pool(swapped_pool, action),
            )
            self.assertEqual(
                direct.positive_o1.to_bytes(self.config.o1_config),
                swapped.negative_o1.to_bytes(self.config.o1_config),
            )
            self.assertEqual(
                direct.negative_o1.to_bytes(self.config.o1_config),
                swapped.positive_o1.to_bytes(self.config.o1_config),
            )
            np.testing.assert_array_equal(
                direct.posterior_logits, -swapped.posterior_logits
            )

        direct_query = controller.query_posteriors(direct)
        swapped_query = controller.query_posteriors(swapped)
        np.testing.assert_array_equal(direct_query, -swapped_query)

        common_state = controller.initial_fast_state(SOURCE_SHA256)
        common = np.linspace(-0.5, 0.5, BRANCH_FEATURES, dtype=np.float32)
        common_observation = PairedCausalObservation(
            action=CausalAction(11, self.config.horizons[0]),
            zero_features=common,
            one_features=common,
            work_units=2 * self.config.horizons[0],
            pair_sha256=PAIR_SHA256[11],
            source_stream_sha256=SOURCE_SHA256,
        )
        controller.observe(common_state, common_observation)
        self.assertEqual(
            common_state.positive_o1.to_bytes(self.config.o1_config),
            common_state.negative_o1.to_bytes(self.config.o1_config),
        )
        np.testing.assert_array_equal(
            common_state.posterior_logits,
            np.zeros(KEY_BITS, dtype=np.float32),
        )

    def test_picker_is_pool_blind_and_ties_are_hash_deterministic(self) -> None:
        controller = OnlineCausalController(self.config)
        left = controller.initial_fast_state(SOURCE_SHA256)
        right = controller.initial_fast_state(SOURCE_SHA256)
        first_left = controller.choose_action(left)
        first_right = controller.choose_action(right)
        self.assertIsNotNone(first_left)
        self.assertIsNotNone(first_right)
        assert first_left is not None and first_right is not None
        self.assertEqual(first_left.action, first_right.action)
        other_source_state = controller.initial_fast_state(OTHER_SOURCE_SHA256)
        other_source_choice = controller.choose_action(other_source_state)
        self.assertIsNotNone(other_source_choice)
        assert other_source_choice is not None
        self.assertEqual(first_left.action, other_source_choice.action)

        changed_features = np.full_like(self.pool.branch_features, 123.0)
        horizon_index = self.config.horizons.index(first_left.action.horizon)
        bit = first_left.action.bit_index
        changed_features[horizon_index, bit] = self.pool.branch_features[
            horizon_index, bit
        ]
        changed_pool = Full256ActionPool(
            horizons=self.pool.horizons,
            branch_features=changed_features,
            final_resources=self.pool.final_resources,
            pair_sha256=self.pool.pair_sha256,
            source_stream_sha256=self.pool.source_stream_sha256,
        )
        controller.observe(
            left,
            PairedCausalObservation.from_pool(self.pool, first_left.action),
        )
        controller.observe(
            right,
            PairedCausalObservation.from_pool(changed_pool, first_right.action),
        )
        next_left = controller.choose_action(left)
        next_right = controller.choose_action(right)
        self.assertIsNotNone(next_left)
        self.assertIsNotNone(next_right)
        assert next_left is not None and next_right is not None
        self.assertEqual(next_left.action, next_right.action)

        tie_config = _config(critic_exploration=0.0, coverage_weight=0.0)
        tie_controller = OnlineCausalController(tie_config)
        tie_state = tie_controller.initial_fast_state(SOURCE_SHA256)
        candidates = (
            CausalAction(bit, horizon)
            for horizon in tie_config.horizons
            for bit in range(KEY_BITS)
        )
        expected = min(
            candidates,
            key=lambda action: action.pool_blind_tiebreak_sha256(tie_config),
        )
        first_tie = tie_controller.choose_action(tie_state)
        second_tie = tie_controller.choose_action(tie_state)
        self.assertIsNotNone(first_tie)
        self.assertIsNotNone(second_tie)
        assert first_tie is not None and second_tie is not None
        self.assertEqual(first_tie.action, expected)
        self.assertEqual(second_tie.action, expected)
        self.assertEqual(first_tie.score, 0.0)

    def test_picker_shortlist_is_bounded_and_horizons_are_one_hot(self) -> None:
        shortlist_size = 7
        config = _config(critic_shortlist_size=shortlist_size)
        controller = OnlineCausalController(config)
        state = controller.initial_fast_state(SOURCE_SHA256)
        queried: list[tuple[CausalAction, ...]] = []
        original_query = controller._action_query_logits

        def recording_query(
            live_state: OnlineCausalFastState,
            actions: tuple[CausalAction, ...] | list[CausalAction],
        ) -> tuple[np.ndarray, np.ndarray]:
            queried.append(tuple(actions))
            return original_query(live_state, actions)

        controller._action_query_logits = recording_query  # type: ignore[method-assign]
        choice = controller.choose_action(state)
        self.assertIsNotNone(choice)
        assert choice is not None
        self.assertEqual(len(queried), 1)
        self.assertEqual(len(queried[0]), shortlist_size)
        expected_shortlist = tuple(
            sorted(
                (
                    CausalAction(bit, horizon)
                    for horizon in config.horizons
                    for bit in range(KEY_BITS)
                ),
                key=lambda action: action.pool_blind_tiebreak_sha256(config),
            )[:shortlist_size]
        )
        self.assertEqual(queried[0], expected_shortlist)
        self.assertEqual(
            choice.context.shape,
            (config.critic_context_dimension,),
        )

        horizon_encoding = choice.context[6 : 6 + config.horizon_count]
        expected_encoding = np.zeros(config.horizon_count, dtype=np.float32)
        expected_encoding[config.horizons.index(choice.action.horizon)] = 1.0
        np.testing.assert_array_equal(horizon_encoding, expected_encoding)
        self.assertEqual(config.describe()["critic_horizon_encoding"], "one-hot")
        self.assertEqual(
            config.describe()["critic_reward_target"], "raw-delta-nll-bits"
        )

    def test_picker_preserves_negative_learned_utility(self) -> None:
        config = _config(
            critic_exploration=0.0,
            coverage_weight=0.0,
            critic_shortlist_size=16,
        )
        controller = OnlineCausalController(config)
        controller.critic.b[0] = -2.0
        controller.critic.validate(config)
        state = controller.initial_fast_state(SOURCE_SHA256)

        choice = controller.choose_action(state)

        self.assertIsNotNone(choice)
        assert choice is not None
        self.assertLess(choice.predicted_reward, 0.0)
        self.assertLess(choice.score, 0.0)

    def test_critic_round_trip_tracks_horizon_dimension_and_rejects_v1(self) -> None:
        payloads: dict[int, bytes] = {}
        for horizons in ((3,), (3, 5), (3, 5, 7)):
            with self.subTest(horizons=horizons):
                config = _config(horizons=horizons)
                critic = BoundedLinUCBCritic.initial(config)
                context = np.ones(
                    config.critic_context_dimension,
                    dtype=np.float32,
                )
                critic.update(context, 0.25, config)
                payload = critic.to_bytes()
                restored = BoundedLinUCBCritic.from_bytes(payload)
                restored.validate(config)
                self.assertEqual(restored.to_bytes(), payload)
                self.assertEqual(restored.dimension, 7 + len(horizons))
                payloads[len(horizons)] = payload

        wrong_dimension = BoundedLinUCBCritic.from_bytes(payloads[2])
        with self.assertRaisesRegex(
            OnlineCausalControllerError,
            "dimension differs",
        ):
            wrong_dimension.validate(_config(horizons=(3, 5, 7)))

        v1_payload = payloads[1].replace(
            b"o1-256-bounded-linucb-v2",
            b"o1-256-bounded-linucb-v1",
            1,
        )
        with self.assertRaisesRegex(OnlineCausalControllerError, "schema differs"):
            BoundedLinUCBCritic.from_bytes(v1_payload)

    def test_actions_do_not_repeat_and_coverage_cannot_starve_coordinates(self) -> None:
        controller = OnlineCausalController(self.config)
        state = controller.initial_fast_state(SOURCE_SHA256)
        used: set[int] = set()
        selected_bits: set[int] = set()
        first_observation = None

        for step in range(8):
            choice = controller.choose_action(state)
            self.assertIsNotNone(choice)
            assert choice is not None
            flat_index = choice.action.flat_index(self.config)
            self.assertNotIn(flat_index, used)
            used.add(flat_index)
            selected_bits.add(choice.action.bit_index)
            observation = PairedCausalObservation.from_pool(self.pool, choice.action)
            if first_observation is None:
                first_observation = observation
            controller.observe(state, observation)
            self.assertEqual(state.action_count, step + 1)
            self.assertEqual(int(state.coverage.sum()), step + 1)

        self.assertEqual(len(selected_bits), 8)
        self.assertEqual(
            [int(value) for value in state.action_order[: state.action_count]],
            list(dict.fromkeys(state.action_order[: state.action_count])),
        )
        assert first_observation is not None
        with self.assertRaisesRegex(OnlineCausalControllerError, "observed twice"):
            controller.observe(state, first_observation)

    def test_predeclared_action_order_is_atomic_and_exact(self) -> None:
        controller = OnlineCausalController(self.config)
        order = [
            CausalAction(bit, self.config.horizons[index % 2]).flat_index(
                self.config
            )
            for index, bit in enumerate((3, 17, 91, 207))
        ]
        slow_before = controller.slow_state_bytes()

        state = controller.run_action_order(self.pool, order)

        self.assertEqual(
            [int(value) for value in state.action_order[: state.action_count]],
            order,
        )
        self.assertEqual(controller.slow_state_bytes(), slow_before)
        with self.assertRaisesRegex(OnlineCausalControllerError, "unique"):
            controller.run_action_order(self.pool, [order[0], order[0]])
        self.assertEqual(controller.slow_state_bytes(), slow_before)

    def test_work_budget_filters_actions_and_is_recomputed_from_ledger(self) -> None:
        controller = OnlineCausalController(self.config)
        state = controller.initial_fast_state(SOURCE_SHA256)
        slow_before = controller.slow_state_bytes()

        self.assertIsNone(controller.choose_action(state, maximum_work_units=0))
        self.assertIsNone(controller.choose_action(state, maximum_work_units=1))
        with self.assertRaisesRegex(
            OnlineCausalControllerError, "maximum_work_units"
        ):
            controller.choose_action(state, maximum_work_units=-1)

        minimum_horizon = min(self.config.horizons)
        exact_minimum = 2 * minimum_horizon
        choice = controller.choose_action(
            state,
            maximum_work_units=exact_minimum,
        )
        self.assertIsNotNone(choice)
        assert choice is not None
        self.assertEqual(choice.action.horizon, minimum_horizon)
        self.assertEqual(controller.slow_state_bytes(), slow_before)
        self.assertEqual(state.action_count, 0)

        budget = exact_minimum * 5
        completed = controller.run_work_budgeted_policy(
            self.pool,
            work_budget=budget,
        )
        used = controller.requested_work_units(completed)
        self.assertLessEqual(used, budget)
        self.assertGreater(used, budget - exact_minimum)
        expected = sum(
            2
            * CausalAction.from_flat_index(int(value), self.config).horizon
            for value in completed.action_order[: completed.action_count]
        )
        self.assertEqual(used, expected)
        self.assertEqual(controller.slow_state_bytes(), slow_before)

        with self.assertRaisesRegex(OnlineCausalControllerError, "work_budget"):
            controller.run_work_budgeted_policy(self.pool, work_budget=-1)

    def test_unknown_observation_and_queries_never_change_slow_or_o1_state(
        self,
    ) -> None:
        controller = OnlineCausalController(self.config)
        state = controller.initial_fast_state(SOURCE_SHA256)
        slow_before = controller.slow_state_sha256
        critic_before = controller.critic.to_bytes()
        action = CausalAction(37, self.config.horizons[1])
        controller.observe(state, PairedCausalObservation.from_pool(self.pool, action))

        self.assertEqual(controller.slow_state_sha256, slow_before)
        self.assertEqual(controller.critic.to_bytes(), critic_before)
        self.assertEqual(state.slow_state_sha256, slow_before)
        positive_before = state.positive_o1.to_bytes(self.config.o1_config)
        negative_before = state.negative_o1.to_bytes(self.config.o1_config)
        fast_before = state.to_bytes(self.config)
        queried = controller.query_posteriors(state)
        self.assertEqual(
            state.positive_o1.to_bytes(self.config.o1_config), positive_before
        )
        self.assertEqual(
            state.negative_o1.to_bytes(self.config.o1_config), negative_before
        )
        self.assertEqual(state.to_bytes(self.config), fast_before)
        np.testing.assert_array_equal(queried, state.posterior_logits)

    def test_fast_state_round_trip_is_exact_fixed_width_and_probabilities_clip(
        self,
    ) -> None:
        controller = OnlineCausalController(self.config)
        state = controller.initial_fast_state(SOURCE_SHA256)
        initial_bytes = state.to_bytes(self.config)
        for _step in range(3):
            choice = controller.choose_action(state)
            self.assertIsNotNone(choice)
            assert choice is not None
            controller.observe(
                state, PairedCausalObservation.from_pool(self.pool, choice.action)
            )
        payload = state.to_bytes(self.config)
        restored = OnlineCausalFastState.from_bytes(payload, self.config)

        self.assertEqual(len(payload), len(initial_bytes))
        self.assertEqual(restored.to_bytes(self.config), payload)
        self.assertEqual(restored.sha256(self.config), state.sha256(self.config))
        tampered_coverage = OnlineCausalFastState.from_bytes(payload, self.config)
        used_position = tuple(np.argwhere(tampered_coverage.coverage == 1)[0])
        unused_position = tuple(np.argwhere(tampered_coverage.coverage == 0)[0])
        tampered_coverage.coverage[unused_position] = np.uint16(1)
        tampered_coverage.coverage[used_position] = np.uint16(0)
        with self.assertRaisesRegex(
            OnlineCausalControllerError, "coverage and selection clocks"
        ):
            tampered_coverage.to_bytes(self.config)
        tampered_clock = OnlineCausalFastState.from_bytes(payload, self.config)
        used_flat = int(tampered_clock.action_order[0])
        used_action = CausalAction.from_flat_index(used_flat, self.config)
        used_horizon = self.config.horizons.index(used_action.horizon)
        tampered_clock.last_selected[used_horizon, used_action.bit_index] += np.uint32(
            1
        )
        with self.assertRaisesRegex(
            OnlineCausalControllerError, "coverage and selection clocks"
        ):
            tampered_clock.to_bytes(self.config)
        tampered_nuisance = OnlineCausalFastState.from_bytes(payload, self.config)
        tampered_nuisance.nuisance.counts[0] += np.uint64(1)
        with self.assertRaisesRegex(OnlineCausalControllerError, "nuisance counts"):
            tampered_nuisance.to_bytes(self.config)
        tampered_uncovered = OnlineCausalFastState.from_bytes(payload, self.config)
        uncovered_bit = int(
            np.flatnonzero(tampered_uncovered.coverage.sum(axis=0) == 0)[0]
        )
        tampered_uncovered.posterior_logits[uncovered_bit] = np.float32(0.25)
        with self.assertRaisesRegex(
            OnlineCausalControllerError, "uncovered posterior registers"
        ):
            tampered_uncovered.to_bytes(self.config)
        covered_bits = np.flatnonzero(restored.coverage.sum(axis=0) > 0)
        positive_bit, negative_bit = (int(value) for value in covered_bits[:2])
        restored.posterior_logits[positive_bit] = np.float32(1e30)
        restored.posterior_logits[negative_bit] = np.float32(-1e30)
        probabilities = restored.probabilities(self.config)
        epsilon = self.config.posterior_epsilon
        self.assertTrue(np.all(probabilities >= epsilon))
        self.assertTrue(np.all(probabilities <= 1.0 - epsilon))
        self.assertTrue(np.all((probabilities > 0.0) & (probabilities < 1.0)))
        self.assertEqual(probabilities[positive_bit], 1.0 - epsilon)
        self.assertEqual(probabilities[negative_bit], epsilon)

    def test_reveal_changes_slow_state_and_trains_reader_in_two_chunks(self) -> None:
        controller = OnlineCausalController(self.config)
        slow_before = controller.slow_state_sha256
        critic_before = controller.critic.to_bytes()
        reader_before = {
            name: tensor.detach().clone()
            for name, tensor in controller.reader.state_dict().items()
        }
        state = controller.run_policy(self.pool, action_budget=4)
        fast_bytes_before_reveal = state.to_bytes(self.config)

        self.assertEqual(controller.slow_state_sha256, slow_before)
        self.assertEqual(controller.critic.to_bytes(), critic_before)
        self.assertEqual(controller.critic.updates, 0)
        labels = (np.arange(KEY_BITS) % 2).astype(np.float32)
        report = controller.reveal_and_learn(self.pool, state, labels)

        self.assertEqual(report.actions, 4)
        self.assertEqual(report.critic_updates, 4)
        self.assertAlmostEqual(
            report.critic_reward_sum,
            report.reward_sum_bits,
            places=10,
        )
        self.assertNotEqual(report.reward_sum_bits, 0.0)
        self.assertEqual(len(report.training_loss_bits), 2)
        self.assertTrue(
            all(math_value > 0.0 for math_value in report.training_loss_bits)
        )
        self.assertEqual(report.slow_state_sha256_before, slow_before)
        self.assertEqual(report.slow_state_sha256_after, controller.slow_state_sha256)
        self.assertNotEqual(controller.slow_state_sha256, slow_before)
        self.assertEqual(controller.critic.updates, 4)
        self.assertEqual(controller.episodes, 1)
        self.assertTrue(state.reveal_consumed)
        fast_bytes_after_reveal = state.to_bytes(self.config)
        self.assertEqual(len(fast_bytes_after_reveal), len(fast_bytes_before_reveal))
        self.assertEqual(
            OnlineCausalFastState.from_bytes(
                fast_bytes_after_reveal, self.config
            ).to_bytes(self.config),
            fast_bytes_after_reveal,
        )
        self.assertTrue(
            any(
                not torch.equal(reader_before[name], tensor)
                for name, tensor in controller.reader.state_dict().items()
            )
        )
        with self.assertRaisesRegex(OnlineCausalControllerError, "already consumed"):
            controller.reveal_and_learn(self.pool, state, labels)

    def test_shifted_critic_control_keeps_reader_byte_identical(self) -> None:
        primary = OnlineCausalController(self.config)
        shifted = OnlineCausalController(self.config)
        order = [
            CausalAction(bit, self.config.horizons[index % 2]).flat_index(
                self.config
            )
            for index, bit in enumerate((3, 17, 91, 207))
        ]
        primary_state = primary.run_action_order(self.pool, order)
        shifted_state = shifted.run_action_order(self.pool, order)
        labels = (np.arange(KEY_BITS) % 2).astype(np.float32)
        slow_before_replay = primary.slow_state_bytes()
        replay = primary.replay_action_rewards(self.pool, order, labels)

        self.assertEqual(primary.slow_state_bytes(), slow_before_replay)
        self.assertEqual(replay.action_order.tolist(), order)
        self.assertEqual(
            replay.contexts.shape,
            (len(order), self.config.critic_context_dimension),
        )
        self.assertAlmostEqual(
            float(replay.delta_nll_bits.sum()),
            replay.initial_nll_bits - replay.final_nll_bits,
            places=10,
        )
        self.assertFalse(replay.contexts.flags.writeable)
        with self.assertRaisesRegex(OnlineCausalControllerError, "unique"):
            primary.replay_action_rewards(
                self.pool,
                [order[0], order[0]],
                labels,
            )

        primary_report = primary.reveal_and_learn(
            self.pool,
            primary_state,
            labels,
        )
        shifted_report = shifted.reveal_and_learn(
            self.pool,
            shifted_state,
            labels,
            critic_reward_labels=np.roll(labels, 1),
        )

        self.assertTrue(primary_report.critic_labels_match_reader_labels)
        self.assertFalse(shifted_report.critic_labels_match_reader_labels)
        self.assertEqual(primary.reader_state_bytes(), shifted.reader_state_bytes())
        self.assertEqual(primary.reader_state_sha256, shifted.reader_state_sha256)
        self.assertNotEqual(primary.critic.to_bytes(), shifted.critic.to_bytes())

    def test_invalid_labels_and_sources_are_rejected_without_slow_update(self) -> None:
        controller = OnlineCausalController(self.config)
        state = controller.initial_fast_state(SOURCE_SHA256)
        action = CausalAction(9, self.config.horizons[0])
        valid = PairedCausalObservation.from_pool(self.pool, action)
        wrong_source = PairedCausalObservation(
            action=valid.action,
            zero_features=valid.zero_features,
            one_features=valid.one_features,
            work_units=valid.work_units,
            pair_sha256=valid.pair_sha256,
            source_stream_sha256=OTHER_SOURCE_SHA256,
        )
        slow_before = controller.slow_state_sha256

        with self.assertRaisesRegex(OnlineCausalControllerError, "source differs"):
            controller.observe(state, wrong_source)
        controller.observe(state, valid)
        with self.assertRaisesRegex(OnlineCausalControllerError, "binary shape"):
            controller.reveal_and_learn(
                self.pool, state, np.zeros(KEY_BITS - 1, dtype=np.float32)
            )
        bad_labels = np.zeros(KEY_BITS, dtype=np.float32)
        bad_labels[0] = 2.0
        with self.assertRaisesRegex(OnlineCausalControllerError, "binary shape"):
            controller.reveal_and_learn(self.pool, state, bad_labels)
        with self.assertRaisesRegex(
            OnlineCausalControllerError, "critic_reward_labels"
        ):
            controller.reveal_and_learn(
                self.pool,
                state,
                np.zeros(KEY_BITS, dtype=np.float32),
                critic_reward_labels=bad_labels,
            )
        other_pool = _synthetic_pool(
            self.config, source_stream_sha256=OTHER_SOURCE_SHA256
        )
        with self.assertRaisesRegex(
            OnlineCausalControllerError, "state and pool source differ"
        ):
            controller.reveal_and_learn(
                other_pool, state, np.zeros(KEY_BITS, dtype=np.float32)
            )

        self.assertEqual(controller.slow_state_sha256, slow_before)
        self.assertEqual(controller.critic.updates, 0)
        self.assertFalse(state.reveal_consumed)

    def test_mobius_algebra_slow_round_trip_and_snapshot_guard(self) -> None:
        self.assertEqual(mobius_contrast((3.0, 8.0)), 5.0)
        self.assertEqual(mobius_contrast((1.0, 2.0, 4.0, 10.0)), 5.0)
        self.assertEqual(
            mobius_contrast((1.0, 3.0, 4.0, 8.0, 7.0, 12.0, 15.0, 25.0)),
            3.0,
        )
        vectors = np.arange(8 * 3, dtype=np.float64).reshape(8, 3)
        np.testing.assert_array_equal(
            mobius_contrast(vectors),
            -vectors[0]
            + vectors[1]
            + vectors[2]
            - vectors[3]
            + vectors[4]
            - vectors[5]
            - vectors[6]
            + vectors[7],
        )

        controller = OnlineCausalController(self.config)
        slow = controller.slow_state_bytes()
        restored = OnlineCausalController(self.config)
        restored.load_slow_state_bytes(slow)
        self.assertEqual(restored.slow_state_bytes(), slow)

        state = controller.initial_fast_state(SOURCE_SHA256)
        controller.critic.update(
            np.ones(self.config.critic_context_dimension, dtype=np.float32),
            0.25,
            self.config,
        )
        self.assertNotEqual(state.slow_state_sha256, controller.slow_state_sha256)
        with self.assertRaisesRegex(OnlineCausalControllerError, "slow state changed"):
            controller.choose_action(state)

        damaged = slow[:-1]
        before = restored.slow_state_bytes()
        with self.assertRaises(OnlineCausalControllerError):
            restored.load_slow_state_bytes(damaged)
        self.assertEqual(restored.slow_state_bytes(), before)

    def test_nonfinite_slow_parameters_cannot_serialize_or_load(self) -> None:
        controller = OnlineCausalController(self.config)
        payload = bytearray(controller.slow_state_bytes())
        parameter = next(controller.reader.parameters())
        finite = parameter.detach().view(-1)[0].item()
        finite_bytes = np.asarray((finite,), dtype="<f4").tobytes()
        offset = bytes(payload).find(finite_bytes)
        self.assertGreaterEqual(offset, 0)
        payload[offset : offset + 4] = np.asarray((np.nan,), dtype="<f4").tobytes()
        fresh = OnlineCausalController(self.config)
        with self.assertRaisesRegex(OnlineCausalControllerError, "not finite"):
            fresh.load_slow_state_bytes(bytes(payload))

        with torch.no_grad():
            parameter.view(-1)[0] = float("nan")
        with self.assertRaisesRegex(OnlineCausalControllerError, "not finite"):
            controller.slow_state_bytes()


if __name__ == "__main__":
    unittest.main()
