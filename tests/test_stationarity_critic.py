from __future__ import annotations

import struct
import unittest

import numpy as np

from o1_crypto_lab.stationarity_critic import (
    STATIONARITY_CRITIC_MAGIC,
    STATIONARITY_CRITIC_SCHEMA,
    EpisodeEqualRidgeCritic,
    StationarityCriticError,
)


class EpisodeEqualRidgeCriticTests(unittest.TestCase):
    def test_stationary_context_beats_equal_mean_sign_flipping_context(self) -> None:
        critic = EpisodeEqualRidgeCritic.initial(dimension=2, ridge=1.0)
        design = np.eye(2, dtype=np.float64)
        for sign in (1.0, -1.0, 1.0, -1.0):
            critic.update_episode(
                design,
                np.asarray([0.0, 3.0 * sign], dtype=np.float64),
            )

        stationary = critic.predict(
            np.asarray([1.0, 0.0], dtype=np.float64),
            stationarity_penalty=1.0,
            exploration_scale=0.25,
        )
        flipping = critic.predict(
            np.asarray([0.0, 1.0], dtype=np.float64),
            stationarity_penalty=1.0,
            exploration_scale=0.25,
        )

        self.assertEqual(stationary.mean, flipping.mean)
        self.assertEqual(stationary.across_episode_std, 0.0)
        self.assertGreater(flipping.across_episode_std, 0.0)
        self.assertGreater(stationary.conservative_lcb, flipping.conservative_lcb)
        self.assertGreater(stationary.epistemic_bonus, 0.0)
        self.assertGreater(flipping.epistemic_bonus, 0.0)

    def test_episode_equality_is_exact_despite_row_imbalance(self) -> None:
        balanced = EpisodeEqualRidgeCritic.initial(dimension=1, ridge=1.0)
        imbalanced = EpisodeEqualRidgeCritic.initial(dimension=1, ridge=1.0)
        first_design = np.ones((1, 1), dtype=np.float64)
        first_rewards = np.asarray([2.0], dtype=np.float64)
        balanced.update_episode(first_design, first_rewards)
        imbalanced.update_episode(first_design, first_rewards)

        balanced.update_episode(
            np.ones((1, 1), dtype=np.float64),
            np.asarray([6.0], dtype=np.float64),
        )
        imbalanced.update_episode(
            np.ones((257, 1), dtype=np.float64),
            np.full(257, 6.0, dtype=np.float64),
        )

        self.assertEqual(balanced.episode_count, 2)
        np.testing.assert_array_equal(
            balanced.mean_weights,
            np.asarray([2.0], dtype=np.float64),
        )
        self.assertEqual(balanced.to_bytes(), imbalanced.to_bytes())

    def test_full_weight_covariance_preserves_cancelling_context(self) -> None:
        critic = EpisodeEqualRidgeCritic.initial(dimension=2, ridge=1.0)
        design = np.eye(2, dtype=np.float64)
        critic.update_episode(
            design,
            np.asarray([3.0, 3.0], dtype=np.float64),
        )
        critic.update_episode(
            design,
            np.asarray([-3.0, -3.0], dtype=np.float64),
        )

        prediction = critic.predict(
            np.asarray([1.0, -1.0], dtype=np.float64),
            stationarity_penalty=1.0,
            exploration_scale=0.0,
        )

        self.assertEqual(prediction.mean, 0.0)
        self.assertEqual(prediction.across_episode_std, 0.0)
        self.assertEqual(prediction.conservative_lcb, 0.0)

    def test_byte_exact_round_trip_clone_and_sha256(self) -> None:
        critic = EpisodeEqualRidgeCritic.initial(dimension=3, ridge=0.75)
        design = np.asarray(
            [
                [1.0, 0.0, -1.0],
                [0.5, 2.0, 0.25],
                [-0.5, 0.25, 1.5],
            ],
            dtype=np.float64,
        )
        critic.update_episode(
            design,
            np.asarray([0.5, -1.0, 2.0], dtype=np.float64),
        )
        critic.update_episode(
            design[::-1].copy(),
            np.asarray([-0.25, 1.5, 0.75], dtype=np.float64),
        )

        payload = critic.to_bytes()
        restored = EpisodeEqualRidgeCritic.from_bytes(payload)
        cloned = critic.clone()

        self.assertEqual(restored.to_bytes(), payload)
        self.assertEqual(cloned.to_bytes(), payload)
        self.assertEqual(restored.sha256(), critic.sha256())
        self.assertIsNot(restored.mean_weights, critic.mean_weights)
        self.assertIsNot(cloned.pooled_design_inverse, critic.pooled_design_inverse)

    def test_malformed_payload_and_invalid_update_are_rejected_atomically(
        self,
    ) -> None:
        critic = EpisodeEqualRidgeCritic.initial(dimension=2, ridge=1.0)
        critic.update_episode(
            np.eye(2, dtype=np.float64),
            np.asarray([1.0, -1.0], dtype=np.float64),
        )
        before = critic.to_bytes()

        malformed = (
            before.replace(
                STATIONARITY_CRITIC_SCHEMA.encode("ascii"),
                STATIONARITY_CRITIC_SCHEMA[:-1].encode("ascii") + b"0",
                1,
            ),
            before[:-1],
            before + b"\x00",
            before[:-8] + struct.pack("<d", float("nan")),
            b"BAD" + before[len(STATIONARITY_CRITIC_MAGIC) :],
        )
        for payload in malformed:
            with self.subTest(length=len(payload)):
                with self.assertRaises(StationarityCriticError):
                    EpisodeEqualRidgeCritic.from_bytes(payload)

        with self.assertRaises(StationarityCriticError):
            critic.update_episode(
                np.eye(2, dtype=np.float32),
                np.asarray([1.0, 2.0], dtype=np.float64),
            )
        self.assertEqual(critic.to_bytes(), before)
        with self.assertRaises(StationarityCriticError):
            critic.update_episode(
                np.eye(2, dtype=np.float64),
                np.asarray([1.0, float("inf")], dtype=np.float64),
            )
        self.assertEqual(critic.to_bytes(), before)

    def test_identical_streams_are_byte_and_prediction_deterministic(self) -> None:
        left = EpisodeEqualRidgeCritic.initial(dimension=4, ridge=0.5)
        right = EpisodeEqualRidgeCritic.initial(dimension=4, ridge=0.5)
        generator = np.random.Generator(np.random.PCG64(190019))
        episodes = [
            (
                np.ascontiguousarray(generator.standard_normal((rows, 4))),
                np.ascontiguousarray(generator.standard_normal(rows)),
            )
            for rows in (3, 11, 5, 29)
        ]
        for design, rewards in episodes:
            np.testing.assert_array_equal(
                left.update_episode(design, rewards),
                right.update_episode(design, rewards),
            )

        context = np.asarray([0.5, -1.0, 0.25, 2.0], dtype=np.float64)
        self.assertEqual(left.to_bytes(), right.to_bytes())
        self.assertEqual(left.sha256(), right.sha256())
        self.assertEqual(
            left.predict(context, 1.5, 0.2),
            right.predict(context, 1.5, 0.2),
        )


if __name__ == "__main__":
    unittest.main()
