from __future__ import annotations

import unittest

import numpy as np

from o1_crypto_lab.living_inverse import (
    bits_to_key,
    build_known_target,
    key_bits,
    uncertainty_beam_metrics,
)
from o1_crypto_lab.posterior_frontier import (
    PosteriorFrontierError,
    evaluate_factorized_frontier,
    exhaustive_small_width_proof,
    iter_factorized_topk,
    verify_frontier_against_public_target,
)


class FactorizedTopKTests(unittest.TestCase):
    def test_small_width_best_first_order_matches_exhaustive_space(self) -> None:
        cases = (
            np.asarray([0.525, 0.55, 0.56], dtype=np.float64),
            np.asarray([0.5] * 8, dtype=np.float64),
            np.asarray(
                [0.11, 0.23, 0.37, 0.49, 0.61, 0.73, 0.89],
                dtype=np.float64,
            ),
        )
        for probabilities in cases:
            with self.subTest(width=probabilities.size):
                limit = min(1 << int(probabilities.size), 128)
                first = exhaustive_small_width_proof(
                    probabilities,
                    limit=limit,
                )
                second = exhaustive_small_width_proof(
                    probabilities,
                    limit=limit,
                )
                self.assertTrue(first["orders_match"])
                self.assertEqual(first, second)

    def test_global_top_k_is_not_the_legacy_least_uncertain_cube(self) -> None:
        probabilities = np.full(256, 0.99, dtype=np.float64)
        probabilities[:3] = (0.525, 0.55, 0.56)
        candidates = list(iter_factorized_topk(probabilities, limit=4))
        self.assertEqual(
            [candidate.flipped_coordinates for candidate in candidates],
            [(), (0,), (1,), (2,)],
        )

        truth = (probabilities >= 0.5).astype(np.uint8)
        truth[2] ^= 1
        true_key = bits_to_key(truth)
        legacy = uncertainty_beam_metrics(
            true_key,
            probabilities,
            uncertain_bits=2,
            beam_size=4,
        )
        self.assertEqual(legacy["uncertain_coordinates"], [0, 1])
        self.assertFalse(legacy["exact_key_in_beam"])

        evaluation = evaluate_factorized_frontier(true_key, candidates)
        self.assertTrue(evaluation["exact_key_hit"])
        self.assertEqual(evaluation["true_rank_one_based"], 4)
        self.assertEqual(evaluation["best_hamming_distance"], 0)

    def test_actual_truncated_frontier_hamming_exposes_legacy_bug(self) -> None:
        probabilities = np.full(256, 0.01, dtype=np.float64)
        probabilities[0] = 0.49
        probabilities[1] = 0.48
        truth = np.zeros(256, dtype=np.uint8)
        truth[0] = 1
        true_key = bits_to_key(truth)

        legacy = uncertainty_beam_metrics(
            true_key,
            probabilities,
            uncertain_bits=2,
            beam_size=1,
        )
        self.assertEqual(legacy["fixed_bit_errors"], 0)
        self.assertEqual(legacy["best_hamming_distance"], 0)
        self.assertEqual(legacy["true_local_rank"], 2)
        self.assertFalse(legacy["exact_key_in_beam"])

        evaluation = evaluate_factorized_frontier(
            true_key,
            iter_factorized_topk(probabilities, limit=1),
        )
        self.assertFalse(evaluation["exact_key_hit"])
        self.assertEqual(evaluation["best_hamming_distance"], 1)
        self.assertEqual(evaluation["best_hamming_rank_one_based"], 1)

    def test_uniform_ties_have_deterministic_topology_order_and_nested_prefixes(
        self,
    ) -> None:
        probabilities = np.full(256, 0.5, dtype=np.float64)
        first = list(iter_factorized_topk(probabilities, limit=32))
        replay = list(iter_factorized_topk(probabilities, limit=32))
        prefix = list(iter_factorized_topk(probabilities, limit=8))
        self.assertEqual(first, replay)
        self.assertEqual(first[:8], prefix)
        self.assertEqual(
            [candidate.topology_code for candidate in first], list(range(32))
        )
        self.assertTrue(
            all(candidate.log2_probability == -256.0 for candidate in first)
        )

    def test_generator_is_truth_free_and_evaluator_changes_only_with_reveal(
        self,
    ) -> None:
        probabilities = np.linspace(0.2, 0.8, 256, dtype=np.float64)
        candidates = tuple(iter_factorized_topk(probabilities, limit=64))
        mode_key = candidates[0].key
        other_bits = key_bits(mode_key).copy()
        other_bits[127] ^= 1
        other_key = bits_to_key(other_bits)

        mode_evaluation = evaluate_factorized_frontier(mode_key, iter(candidates))
        other_evaluation = evaluate_factorized_frontier(other_key, iter(candidates))
        self.assertEqual(mode_evaluation["true_rank_one_based"], 1)
        self.assertNotEqual(
            mode_evaluation["true_key_sha256"],
            other_evaluation["true_key_sha256"],
        )
        self.assertEqual(
            mode_evaluation["candidate_stream_sha256"],
            other_evaluation["candidate_stream_sha256"],
        )

    def test_invalid_requests_and_empty_stream_fail_closed(self) -> None:
        with self.assertRaises(PosteriorFrontierError):
            iter_factorized_topk([0.5] * 255, limit=1)
        with self.assertRaises(PosteriorFrontierError):
            iter_factorized_topk([0.0] * 256, limit=1)
        with self.assertRaises(PosteriorFrontierError):
            iter_factorized_topk([0.5] * 256, limit=0)
        with self.assertRaises(PosteriorFrontierError):
            exhaustive_small_width_proof([0.5] * 21, limit=1)
        with self.assertRaisesRegex(PosteriorFrontierError, "empty"):
            evaluate_factorized_frontier(bytes(32), ())


class PublicVerificationTests(unittest.TestCase):
    def test_oracle_mode_is_verified_from_public_chacha_view(self) -> None:
        key = bytes((17 * index + 9) & 0xFF for index in range(32))
        target = build_known_target(
            key,
            counter=7,
            nonce=bytes(range(12)),
            block_count=2,
        )
        truth = key_bits(key)
        probabilities = np.where(truth == 1, 0.99, 0.01)

        verification = verify_frontier_against_public_target(
            target.public,
            iter_factorized_topk(probabilities, limit=8),
        )
        self.assertTrue(verification["exact_match_found"])
        self.assertEqual(verification["first_match_rank_one_based"], 1)
        self.assertEqual(verification["first_match_key_hex"], key.hex())
        self.assertEqual(verification["candidates_verified"], 1)
        self.assertTrue(verification["stopped_on_first_match"])

    def test_public_verification_limit_is_explicit(self) -> None:
        key = bytes((31 * index + 3) & 0xFF for index in range(32))
        target = build_known_target(
            key,
            counter=1,
            nonce=bytes(reversed(range(12))),
        )
        probabilities = np.full(256, 0.5, dtype=np.float64)
        verification = verify_frontier_against_public_target(
            target.public,
            iter_factorized_topk(probabilities, limit=8),
            maximum_candidates=2,
        )
        self.assertEqual(verification["candidates_verified"], 2)
        self.assertTrue(verification["verification_limit_reached"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
