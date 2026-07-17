from __future__ import annotations

import hashlib
import unittest

from o1_crypto_lab.o1_streaming_core import (
    O1FastState,
    O1StreamingCoreConfig,
    O1StreamingCoreError,
    StreamingO1KeyReader,
    StreamingSelectiveHolographicCore,
    stateful_linear_scan,
    torch,
)


@unittest.skipUnless(torch is not None, "optional torch training dependency is absent")
class O1StreamingCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = O1StreamingCoreConfig(
            event_dimension=5,
            address_dimension=3,
            model_dimension=8,
            heads=2,
            head_dimension=4,
            holographic_slots=2,
            feedforward_dimension=12,
            seed=170017,
        )

    def _stream(
        self, *, batch: int = 2, length: int = 7, seed: int = 11
    ) -> tuple[object, object, object]:
        generator = torch.Generator(device="cpu").manual_seed(seed)
        events = torch.randn(
            batch,
            length,
            self.config.event_dimension,
            generator=generator,
            dtype=torch.float32,
        )
        addresses = torch.randn(
            batch,
            length,
            self.config.address_dimension,
            generator=generator,
            dtype=torch.float32,
        )
        update_mask = torch.ones(batch, length, dtype=torch.bool)
        return events, addresses, update_mask

    def test_stateful_recurrence_is_exact_and_carries_across_chunks(self) -> None:
        drive = torch.tensor(
            [[[0.1, -0.2], [0.2, 0.3], [-0.4, 0.5]]],
            dtype=torch.float32,
        )
        gamma = torch.tensor(
            [[[0.5, 0.25], [1.0, 0.0], [0.0, 1.0]]],
            dtype=torch.float32,
        )
        initial = torch.tensor([[1.0, -1.0]], dtype=torch.float32)
        expected = torch.tensor(
            [[[0.6, -0.45], [0.8, 0.3], [-0.4, 0.8]]],
            dtype=torch.float32,
        )

        sequence, final = stateful_linear_scan(drive, gamma, initial)
        first, carried = stateful_linear_scan(drive[:, :2], gamma[:, :2], initial)
        second, chunk_final = stateful_linear_scan(drive[:, 2:], gamma[:, 2:], carried)

        torch.testing.assert_close(sequence, expected, rtol=0.0, atol=1e-7)
        torch.testing.assert_close(final, expected[:, -1], rtol=0.0, atol=1e-7)
        torch.testing.assert_close(
            torch.cat((first, second), dim=1), sequence, rtol=0.0, atol=0.0
        )
        torch.testing.assert_close(chunk_final, final, rtol=0.0, atol=0.0)

    def test_full_model_forward_equals_arbitrary_chunking(self) -> None:
        model = StreamingSelectiveHolographicCore(self.config).eval()
        events, addresses, update_mask = self._stream(length=7)

        full_output, full_state = model(events, addresses, update_mask)
        first_output, carried = model(
            events[:, :3], addresses[:, :3], update_mask[:, :3]
        )
        second_output, chunk_state = model(
            events[:, 3:], addresses[:, 3:], update_mask[:, 3:], carried
        )

        torch.testing.assert_close(
            torch.cat((first_output, second_output), dim=1),
            full_output,
            rtol=1e-6,
            atol=1e-6,
        )
        for name in (
            "gssm_z",
            "holographic_real",
            "holographic_imaginary",
        ):
            torch.testing.assert_close(
                getattr(chunk_state, name),
                getattr(full_state, name),
                rtol=1e-6,
                atol=1e-6,
            )

    def test_scan_rejects_bad_gamma_and_malformed_initial_state(self) -> None:
        drive = torch.zeros(1, 2, 3, dtype=torch.float32)
        gamma = torch.ones_like(drive)

        for bad_gamma in (
            gamma.clone().index_fill(1, torch.tensor([0]), 1.1),
            gamma.clone().index_fill(1, torch.tensor([1]), -0.1),
            gamma.clone().index_fill(1, torch.tensor([0]), float("nan")),
        ):
            with self.subTest(value=float(bad_gamma.flatten()[0])):
                with self.assertRaisesRegex(
                    O1StreamingCoreError, "finite|gamma must be in"
                ):
                    stateful_linear_scan(drive, bad_gamma, None)

        malformed_initials = (
            torch.zeros(1, 2, dtype=torch.float32),
            torch.zeros(1, 3, dtype=torch.float64),
            torch.full((1, 3), float("inf"), dtype=torch.float32),
        )
        for initial in malformed_initials:
            with self.subTest(shape=tuple(initial.shape), dtype=str(initial.dtype)):
                with self.assertRaisesRegex(O1StreamingCoreError, "initial state"):
                    stateful_linear_scan(drive, gamma, initial)

    def test_fast_state_validation_rejects_malformed_members(self) -> None:
        model = StreamingSelectiveHolographicCore(self.config)
        valid = model.initial_state(2)
        bad_shape = O1FastState(
            valid.gssm_z[:, :, :-1],
            valid.holographic_real,
            valid.holographic_imaginary,
        )
        bad_dtype = O1FastState(
            valid.gssm_z.to(torch.float64),
            valid.holographic_real,
            valid.holographic_imaginary,
        )
        bad_finite = valid.clone()
        bad_finite.holographic_imaginary[0, 0, 0, 0] = float("nan")

        for state, message in (
            (bad_shape, "shape differs"),
            (bad_dtype, "float32"),
            (bad_finite, "not finite"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(O1StreamingCoreError, message):
                    state.validate(self.config)

    def test_fast_state_serialization_hash_and_byte_count_round_trip(self) -> None:
        model = StreamingSelectiveHolographicCore(self.config).eval()
        events, addresses, update_mask = self._stream(batch=3, length=4)
        _output, state = model(events, addresses, update_mask)

        payload = state.to_bytes(self.config)
        expected_hash = hashlib.sha256(payload).hexdigest()
        restored = O1FastState.from_bytes(payload, config=self.config, batch_size=3)

        self.assertEqual(len(payload), self.config.fast_state_bytes(3))
        self.assertEqual(state.sha256(self.config), expected_hash)
        self.assertEqual(restored.to_bytes(self.config), payload)
        self.assertEqual(restored.sha256(self.config), expected_hash)
        for name in (
            "gssm_z",
            "holographic_real",
            "holographic_imaginary",
        ):
            torch.testing.assert_close(
                getattr(restored, name), getattr(state, name), rtol=0.0, atol=0.0
            )
        with self.assertRaisesRegex(O1StreamingCoreError, "length differs"):
            O1FastState.from_bytes(payload[:-1], config=self.config, batch_size=3)

    def test_model_initialization_is_seed_deterministic(self) -> None:
        torch.manual_seed(1)
        first = StreamingO1KeyReader(self.config)
        torch.manual_seed(999999)
        second = StreamingO1KeyReader(self.config)

        first_state = first.state_dict()
        second_state = second.state_dict()
        self.assertEqual(tuple(first_state), tuple(second_state))
        for name in first_state:
            with self.subTest(parameter=name):
                torch.testing.assert_close(
                    first_state[name], second_state[name], rtol=0.0, atol=0.0
                )

        changed_config = O1StreamingCoreConfig(
            event_dimension=5,
            address_dimension=3,
            model_dimension=8,
            heads=2,
            head_dimension=4,
            holographic_slots=2,
            feedforward_dimension=12,
            seed=self.config.seed + 1,
        )
        changed = StreamingO1KeyReader(changed_config)
        self.assertFalse(
            torch.equal(
                first.core.event_projection.weight,
                changed.core.event_projection.weight,
            )
        )

    def test_query_mask_holds_every_carried_state_component_exactly(self) -> None:
        model = StreamingSelectiveHolographicCore(self.config).eval()
        generator = torch.Generator(device="cpu").manual_seed(29)
        carried = O1FastState(
            gssm_z=-torch.rand(
                2,
                self.config.heads,
                self.config.head_dimension,
                generator=generator,
            ),
            holographic_real=torch.randn(
                2,
                self.config.heads,
                self.config.holographic_slots,
                self.config.head_dimension,
                generator=generator,
            ),
            holographic_imaginary=torch.randn(
                2,
                self.config.heads,
                self.config.holographic_slots,
                self.config.head_dimension,
                generator=generator,
            ),
        )
        carried.holographic_real[0, 0, 0, 0] = -0.0
        carried.validate(self.config)
        before = carried.to_bytes(self.config)
        events, addresses, _update_mask = self._stream(batch=2, length=5, seed=31)
        query_mask = torch.zeros(2, 5, dtype=torch.bool)

        _output, held, internals = model(
            events,
            addresses,
            query_mask,
            carried,
            return_internals=True,
        )

        self.assertEqual(held.to_bytes(self.config), before)
        torch.testing.assert_close(
            internals["gssm_z_sequence"],
            carried.gssm_z[:, None].expand(-1, 5, -1, -1),
            rtol=0.0,
            atol=0.0,
        )
        self.assertFalse(bool(internals["update_mask"].any()))

    def test_signed_holographic_carrier_preserves_evidence_orientation(self) -> None:
        model = StreamingSelectiveHolographicCore(self.config).eval()
        with torch.no_grad():
            model.value_gate.weight.zero_()
            model.forget_gate.weight.zero_()
            model.input_gate.weight.zero_()
        events, _addresses, update_mask = self._stream(batch=1, length=4, seed=37)
        addresses = torch.zeros(
            1, 4, self.config.address_dimension, dtype=torch.float32
        )

        _positive_output, positive_state, positive = model(
            events,
            addresses,
            update_mask,
            return_internals=True,
        )
        _negative_output, negative_state, negative = model(
            -events,
            addresses,
            update_mask,
            return_internals=True,
        )

        torch.testing.assert_close(
            positive["drive"], negative["drive"], rtol=0.0, atol=0.0
        )
        torch.testing.assert_close(
            positive["signed_holographic_drive"],
            -negative["signed_holographic_drive"],
            rtol=0.0,
            atol=0.0,
        )
        torch.testing.assert_close(
            positive_state.gssm_z, negative_state.gssm_z, rtol=0.0, atol=0.0
        )
        torch.testing.assert_close(
            positive_state.holographic_real,
            -negative_state.holographic_real,
            rtol=0.0,
            atol=0.0,
        )
        torch.testing.assert_close(
            positive_state.holographic_imaginary,
            -negative_state.holographic_imaginary,
            rtol=0.0,
            atol=0.0,
        )

    def test_detached_carry_supports_two_streaming_gradient_steps(self) -> None:
        model = StreamingO1KeyReader(self.config)
        optimizer = torch.optim.SGD(model.parameters(), lr=1e-3)
        events, addresses, update_mask = self._stream(length=6, seed=41)

        first_logits, first_state = model(
            events[:, :3], addresses[:, :3], update_mask[:, :3]
        )
        first_loss = first_logits.square().mean()
        optimizer.zero_grad(set_to_none=True)
        first_loss.backward()
        first_gradient = sum(
            float(parameter.grad.abs().sum())
            for parameter in model.parameters()
            if parameter.grad is not None
        )
        self.assertGreater(first_gradient, 0.0)
        self.assertTrue(first_state.gssm_z.requires_grad)
        optimizer.step()

        carried = first_state.detached()
        for tensor in (
            carried.gssm_z,
            carried.holographic_real,
            carried.holographic_imaginary,
        ):
            self.assertFalse(tensor.requires_grad)
            self.assertIsNone(tensor.grad_fn)

        optimizer.zero_grad(set_to_none=True)
        second_logits, second_state = model(
            events[:, 3:], addresses[:, 3:], update_mask[:, 3:], carried
        )
        second_logits.square().mean().backward()
        second_gradient = sum(
            float(parameter.grad.abs().sum())
            for parameter in model.parameters()
            if parameter.grad is not None
        )
        self.assertGreater(second_gradient, 0.0)
        self.assertTrue(second_state.gssm_z.requires_grad)
        self.assertIsNone(carried.gssm_z.grad)


if __name__ == "__main__":
    unittest.main()
