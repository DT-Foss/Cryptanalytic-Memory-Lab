from __future__ import annotations

import unittest

from o1_crypto_lab.chacha_trace import (
    ChaChaTraceError,
    add32_with_carry_mask,
    chacha20_block,
    chacha20_block_trace,
    chacha20_blocks,
)


class ChaChaTraceTests(unittest.TestCase):
    def test_rfc8439_block_vector_and_trace_shape(self) -> None:
        key = bytes(range(32))
        nonce = bytes.fromhex("000000090000004a00000000")
        expected = bytes.fromhex(
            "10f1e7e4d13b5915500fdd1fa32071c4"
            "c7d1f4c733c068030422aa9ac3d46c4e"
            "d2826446079faa0914c2d705d98b02a2"
            "b5129cd1de164eb9cbd083e8a2503c4e"
        )
        trace = chacha20_block_trace(key, 1, nonce)
        self.assertEqual(trace.output, expected)
        self.assertEqual(chacha20_block(key, 1, nonce), expected)
        self.assertEqual(len(trace.round_states), 21)
        self.assertEqual(len(trace.round_carry_masks), 20)
        self.assertTrue(all(len(row) == 16 for row in trace.round_carry_masks))
        self.assertEqual(len(trace.feedforward_carry_masks), 16)
        self.assertEqual(trace.logical_bytes, 2752)
        self.assertEqual(len(trace.digest()), 64)

    def test_carry_mask_has_bitwise_semantics(self) -> None:
        self.assertEqual(add32_with_carry_mask(1, 1), (2, 1))
        self.assertEqual(add32_with_carry_mask(0xFFFFFFFF, 1), (0, 0xFFFFFFFF))
        self.assertEqual(add32_with_carry_mask(0x12345678, 0), (0x12345678, 0))

    def test_multiple_blocks_and_bad_inputs(self) -> None:
        key = bytes(32)
        nonce = bytes(12)
        blocks = chacha20_blocks(key, 7, nonce, 3)
        self.assertEqual(len(blocks), 3)
        self.assertEqual(blocks[1], chacha20_block(key, 8, nonce))
        with self.assertRaises(ChaChaTraceError):
            chacha20_block(bytes(31), 0, nonce)
        with self.assertRaises(ChaChaTraceError):
            chacha20_block(key, True, nonce)
        with self.assertRaises(ChaChaTraceError):
            chacha20_blocks(key, (1 << 32) - 1, nonce, 2)


if __name__ == "__main__":
    unittest.main()
