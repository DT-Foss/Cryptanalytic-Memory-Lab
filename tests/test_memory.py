import unittest

from o1_crypto_lab.memory import (
    CountSketchBitMemory,
    DirectBitVault,
    FullContextAttentionCeiling,
    HolographicBitMemory,
    StreamingEvidenceAccumulator,
)


class DirectBitVaultTests(unittest.TestCase):
    def test_exact_recall_and_closed_haystack_gate(self):
        vault = DirectBitVault(8)
        bits = [1, 0, 1, 1, 0, 0, 1, 0]
        for address in reversed(range(8)):
            vault.write(address, bits[address])
        before = vault.state_digest()
        for token in range(10_000):
            vault.observe_haystack(token)
        self.assertEqual([vault.read(index) for index in range(8)], bits)
        self.assertEqual(vault.state_digest(), before)
        self.assertEqual(vault.state_scalars, 8)

    def test_rejects_invalid_access(self):
        vault = DirectBitVault(2)
        with self.assertRaises(KeyError):
            vault.read(0)
        with self.assertRaises(IndexError):
            vault.write(2, 1)
        with self.assertRaises(ValueError):
            vault.write(0, 3)
        with self.assertRaises(ValueError):
            vault.write(0, 1.0)

    def test_full_context_ceiling_is_exact_and_grows_with_haystack(self):
        ceiling = FullContextAttentionCeiling()
        ceiling.write(4, 1)
        before = ceiling.state_scalars
        ceiling.observe_haystack(99)
        self.assertEqual(ceiling.read(4), 1)
        self.assertGreater(ceiling.state_scalars, before)
        with self.assertRaises(IndexError):
            ceiling.write(1 << 64, 1)


class HolographicMemoryTests(unittest.TestCase):
    def test_single_binding_is_exact_and_deterministic(self):
        left = HolographicBitMemory(16, seed=7)
        right = HolographicBitMemory(16, seed=7)
        for memory in (left, right):
            memory.write("bit/137", 0)
        self.assertEqual(left.read("bit/137"), 0)
        self.assertLess(left.score("bit/137"), 0.0)
        self.assertEqual(left.state_digest(), right.state_digest())
        self.assertEqual(left.state_scalars, 32)

    def test_address_types_have_distinct_phase_codes(self):
        integer = HolographicBitMemory(8, seed=3)
        text = HolographicBitMemory(8, seed=3)
        raw = HolographicBitMemory(8, seed=3)
        integer.write(97, 1)
        text.write("a", 1)
        raw.write(b"a", 1)
        self.assertEqual(
            len({integer.state_digest(), text.state_digest(), raw.state_digest()}), 3
        )

    def test_countsketch_is_fixed_width(self):
        memory = CountSketchBitMemory(7, seed=11)
        for address in range(100):
            memory.write(address, address & 1)
        before = memory.state_digest()
        memory.observe_haystack(123)
        self.assertEqual(memory.state_scalars, 7)
        self.assertEqual(memory.state_digest(), before)


class StreamingAccumulatorTests(unittest.TestCase):
    def test_dense_and_sparse_updates(self):
        accumulator = StreamingEvidenceAccumulator(3, decay=0.5, clip=2.0)
        accumulator.update([1.0, -1.0, 0.25])
        self.assertEqual(accumulator.predict(), [1, 0, 1])
        accumulator.update_sparse([(1, 2.0)])
        self.assertAlmostEqual(accumulator.score(0), 0.5)
        self.assertAlmostEqual(accumulator.score(1), 1.5)
        self.assertAlmostEqual(accumulator.score(2), 0.125)
        accumulator.update([100.0, -100.0, 0.0])
        self.assertEqual(accumulator.score(0), 2.0)
        self.assertEqual(accumulator.score(1), -2.0)

    def test_rejects_bad_evidence(self):
        accumulator = StreamingEvidenceAccumulator(2)
        before = accumulator.state_digest()
        with self.assertRaises(ValueError):
            accumulator.update([1.0])
        with self.assertRaises(ValueError):
            accumulator.update([1.0, float("nan")])
        self.assertEqual(accumulator.state_digest(), before)
        accumulator.update([1.0, -1.0])
        before_sparse = accumulator.state_digest()
        with self.assertRaises(IndexError):
            accumulator.update_sparse([(0, 1.0), (2, 1.0)])
        self.assertEqual(accumulator.state_digest(), before_sparse)
        with self.assertRaises(IndexError):
            accumulator.score(-1)
        with self.assertRaises(ValueError):
            StreamingEvidenceAccumulator(1, clip=float("nan"))


if __name__ == "__main__":
    unittest.main()
