from __future__ import annotations

import unittest

import numpy as np

from o1_crypto_lab.chacha_trace import chacha20_block
from o1_crypto_lab.living_inverse import PublicTargetView, key_bits
from o1_crypto_lab.residual_recovery_handoff import (
    A325_W46,
    A526_W52,
    ResidualRecoveryHandoff,
    completion_from_logits,
    post_reveal_complement_gate,
)


class ResidualRecoveryHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = bytes(range(32))
        self.public = PublicTargetView(
            counter_schedule=(1,),
            nonce=bytes.fromhex("000000090000004a00000000"),
            output_blocks=(
                chacha20_block(
                    self.key,
                    1,
                    bytes.fromhex("000000090000004a00000000"),
                ),
            ),
        )

    def test_w52_codec_reconstructs_exact_key_and_verifies(self) -> None:
        bits = key_bits(self.key)
        assignment = sum(int(bits[index]) << index for index in range(52))
        handoff = ResidualRecoveryHandoff(
            A526_W52,
            self.public,
            tuple(int(value) for value in bits[52:]),
        )
        self.assertEqual(handoff.candidate_key(assignment), self.key)
        self.assertTrue(handoff.verify(assignment))
        self.assertEqual(handoff.describe()["fixed_bit_count"], 204)

    def test_a325_codec_reconstructs_exact_key(self) -> None:
        bits = key_bits(self.key)
        assignment = sum(int(bits[index]) << index for index in range(46))
        handoff = ResidualRecoveryHandoff(
            A325_W46,
            self.public,
            tuple(int(value) for value in bits[46:]),
        )
        self.assertEqual(handoff.candidate_key(assignment), self.key)
        self.assertTrue(handoff.verify(assignment))

    def test_gate_rejects_one_wrong_fixed_bit(self) -> None:
        fixed = key_bits(self.key)[52:].copy()
        fixed[17] ^= 1
        gate = post_reveal_complement_gate(
            fixed,
            truth_key=self.key,
            layout=A526_W52,
        )
        self.assertFalse(gate.eligible)
        self.assertEqual(gate.correct_bits, 203)
        self.assertEqual(gate.first_wrong_coordinate, 69)

    def test_zero_logit_uses_frozen_positive_tie_semantics(self) -> None:
        completion = completion_from_logits(np.zeros(256), A325_W46)
        self.assertEqual(completion, (1,) * 210)


if __name__ == "__main__":
    unittest.main()
