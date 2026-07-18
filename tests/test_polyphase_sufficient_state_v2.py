from __future__ import annotations

import math
import unittest
from collections.abc import Iterator

import numpy as np

from o1_crypto_lab.polyphase_sufficient_state import (
    PolyphaseSufficientState as LegacyPolyphaseState,
)
from o1_crypto_lab.polyphase_sufficient_state_v2 import (
    BASIS_PREFIX_BYTES,
    BASIS_SCHEMA,
    BASIS_SHA256,
    CORE_STATE_BYTES,
    KEY_BITS,
    STATE_BYTES,
    STATE_SCHEMA,
    PolyphaseReadoutSpec,
    PolyphaseSufficientState,
    PolyphaseSufficientStateError,
    ReplayRequiredError,
    basis_descriptor,
    basis_sha256_from_descriptor,
    read_polyphase_state,
)


def _fixture(groups: int = 9) -> np.ndarray:
    result = np.empty((groups, 3, KEY_BITS), dtype=np.float32)
    coordinates = np.arange(KEY_BITS, dtype=np.int64)
    for time_index in range(groups):
        for horizon in range(3):
            numerator = 2 * (
                (17 * coordinates + 29 * time_index + 7 * horizon) & 31
            ) - 31
            result[time_index, horizon] = np.asarray(
                numerator / 64.0, dtype=np.float32
            )
    return result


def _spec(*, basis_sha256: str = BASIS_SHA256, temperature: float = 1.0) -> PolyphaseReadoutSpec:
    return PolyphaseReadoutSpec(
        name="balanced-v2",
        basis_sha256=basis_sha256,
        slot_weights=np.full((3, 4), 1.0 / 12.0, dtype=np.float32),
        temperature=temperature,
    )


class PolyphaseSufficientStateV2Tests(unittest.TestCase):
    def test_descriptor_commits_rounding_error_policy_and_self_describing_abi(self) -> None:
        descriptor = basis_descriptor()
        self.assertEqual(descriptor["schema"], BASIS_SCHEMA)
        self.assertEqual(descriptor["abi_revision"], 2)
        self.assertEqual(basis_sha256_from_descriptor(descriptor), BASIS_SHA256)
        self.assertEqual(len(descriptor["kernel"]["production_rounding_schedule"]), 9)
        self.assertEqual(
            descriptor["kernel"]["floating_error_policy"]["ambient_numpy_seterr"],
            "overridden-locally",
        )
        self.assertEqual(descriptor["state"]["basis_prefix_bytes"], BASIS_PREFIX_BYTES)
        self.assertEqual(CORE_STATE_BYTES, 25_096)
        self.assertEqual(STATE_BYTES, 25_128)

    def test_roundtrip_prefix_schema_and_immutable_properties(self) -> None:
        state = PolyphaseSufficientState.initial()
        state.consume(_fixture())
        payload = state.to_bytes()
        self.assertEqual(payload[:BASIS_PREFIX_BYTES], bytes.fromhex(BASIS_SHA256))
        self.assertEqual(len(payload), STATE_BYTES)
        self.assertEqual(PolyphaseSufficientState.from_bytes(payload).to_bytes(), payload)
        self.assertEqual(state.describe()["schema"], STATE_SCHEMA)
        self.assertFalse(state.slots.flags.writeable)
        self.assertFalse(state.coverage.flags.writeable)
        self.assertFalse(_spec().slot_weights.flags.writeable)

    def test_legacy_or_foreign_state_prefix_requires_cold_replay(self) -> None:
        legacy = LegacyPolyphaseState.initial().to_bytes()
        self.assertEqual(len(legacy), CORE_STATE_BYTES)
        with self.assertRaises(ReplayRequiredError):
            PolyphaseSufficientState.from_bytes(legacy)

        current = bytearray(PolyphaseSufficientState.initial().to_bytes())
        current[0] ^= 1
        with self.assertRaises(ReplayRequiredError):
            PolyphaseSufficientState.from_bytes(bytes(current))

    def test_chunk_and_allocation_invariance(self) -> None:
        source = _fixture(17)
        whole = PolyphaseSufficientState.initial()
        split = PolyphaseSufficientState.initial()
        whole.consume(source)
        split.consume((source[:3], source[3:11], source[11:]))
        self.assertEqual(whole.to_bytes(), split.to_bytes())
        hashes = set()
        for _ in range(128):
            state = PolyphaseSufficientState.initial()
            state.consume(source)
            hashes.add(state.sha256())
        self.assertEqual(hashes, {whole.sha256()})

    def test_ambient_underflow_policy_cannot_change_state(self) -> None:
        smallest = np.nextafter(
            np.float32(0.0), np.float32(1.0), dtype=np.float32
        )
        source = np.full((3, 3, KEY_BITS), smallest, dtype=np.float32)
        previous = np.seterr(under="ignore")
        try:
            ignored = PolyphaseSufficientState.initial()
            ignored.consume(source)
            np.seterr(under="raise")
            raised = PolyphaseSufficientState.initial()
            raised.consume(source)
        finally:
            np.seterr(**previous)
        self.assertEqual(ignored.to_bytes(), raised.to_bytes())

    def test_finite_overflow_aborts_transactionally(self) -> None:
        state = PolyphaseSufficientState.initial()
        before = state.to_bytes()
        maximum = float(np.finfo(np.float32).max)

        def resonant_groups() -> Iterator[np.ndarray]:
            for time_index in range(4096):
                group = np.zeros((3, KEY_BITS), dtype=np.float32)
                group[0].fill(
                    np.float32(
                        0.5
                        * maximum
                        * math.cos(2.0 * math.pi * time_index / 64.0)
                    )
                )
                yield group

        with self.assertRaisesRegex(
            PolyphaseSufficientStateError, "overflowed the explicit complex64"
        ):
            state.consume(resonant_groups())
        self.assertEqual(state.to_bytes(), before)

    def test_temperature_is_frozen_float32_and_subnormal_underflow_rejected(self) -> None:
        spec = _spec(temperature=0.1)
        self.assertEqual(spec.temperature, float(np.float32(0.1)))
        with self.assertRaisesRegex(
            PolyphaseSufficientStateError, "positive finite float32"
        ):
            _spec(temperature=1e-300)

    def test_foreign_readout_basis_requires_replay_without_mutation(self) -> None:
        state = PolyphaseSufficientState.initial()
        state.consume(_fixture())
        before = state.to_bytes()
        foreign = _spec(basis_sha256="0" * 64)
        with self.assertRaises(ReplayRequiredError):
            read_polyphase_state(state, foreign)
        self.assertEqual(state.to_bytes(), before)


if __name__ == "__main__":
    unittest.main()
