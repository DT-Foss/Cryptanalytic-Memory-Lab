from __future__ import annotations

import hashlib
import inspect
import json
import struct
import unittest
from dataclasses import asdict, replace
from types import SimpleNamespace
from unittest import mock

import numpy as np

import o1_crypto_lab.causal_evidence_stream as causal
from o1_crypto_lab.causal_evidence_stream import (
    ALL_ARMS,
    CausalEvidenceConfig,
    CausalEvidenceError,
    CausalEvidenceState,
    EvidenceTruthAccessError,
    FrozenCausalEvidenceReader,
    OutcomePublicFSMState,
    SealedEvidenceTruthLedger,
    build_public_evidence_episode,
    execute_public_evidence_episode,
    recompute_causal_evidence_scores,
    run_causal_evidence_stream,
)
from o1_crypto_lab.o1_streaming_core import O1FastState, torch
from o1_crypto_lab.selective_mqar import canonical_module_bytes

_ORIENTATION = (
    (1, 1, -1, -1, 1, -1, 1, -1),
    (1, 1, -1, -1, -1, 1, -1, 1),
    (-1, -1, 1, 1, 1, -1, -1, 1),
    (-1, -1, 1, 1, -1, 1, 1, -1),
)


def _config(*, n_bits: int = 8) -> CausalEvidenceConfig:
    """A tiny deterministic protocol using no formal O1C-0021 seeds."""

    return CausalEvidenceConfig(
        n_bits=n_bits,
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
        core_seed=921001,
        build_seeds=(921101,),
        calibration_seeds=(921201,),
        development_seeds=(921301,),
        evaluation_seeds=(921401,),
        independent_group_prefixes=(1, 2),
        repeat_factors=(1, 2),
        independent_comparison_groups=1,
        independent_comparison_repeat_factor=2,
        training_steps=1,
        training_batch_size=4,
        learning_rate=0.01,
        temperature_grid_max=2.0,
        temperature_grid_steps=5,
        shuffled_label_seed=921501,
        cpu_threads=1,
    )


if torch is not None:

    class _FakeCore(torch.nn.Module):
        def __init__(self, config: CausalEvidenceConfig) -> None:
            super().__init__()
            self.config = config.core_config

        def initial_state(
            self, batch_size: int, *, device: object = "cpu"
        ) -> O1FastState:
            config = self.config
            return O1FastState(
                gssm_z=torch.zeros(
                    batch_size,
                    config.heads,
                    config.head_dimension,
                    dtype=torch.float32,
                    device=device,
                ),
                holographic_real=torch.zeros(
                    batch_size,
                    config.heads,
                    config.holographic_slots,
                    config.head_dimension,
                    dtype=torch.float32,
                    device=device,
                ),
                holographic_imaginary=torch.zeros(
                    batch_size,
                    config.heads,
                    config.holographic_slots,
                    config.head_dimension,
                    dtype=torch.float32,
                    device=device,
                ),
            )

    class _FakeReader(torch.nn.Module):
        """A deterministic reader isolating protocol semantics from SGD."""

        def __init__(
            self, config: CausalEvidenceConfig, *, coefficient_sign: int = 1
        ) -> None:
            super().__init__()
            self.config = config
            self.core = _FakeCore(config)
            self.coefficient_sign = coefficient_sign

        def initial_state(self) -> O1FastState:
            return self.core.initial_state(1, device="cpu")

        def route_scores(self, events: np.ndarray) -> np.ndarray:
            rows = np.asarray(events, dtype=np.float32)
            relevant_kind = (rows[:, causal._MARKER] == 1.0) | (
                rows[:, causal._EVIDENCE] == 1.0
            )
            novel = rows[:, causal._NOVELTY] == 1.0
            return np.where(relevant_kind & novel, 10.0, -10.0).astype(np.float32)

        def step_marker(
            self,
            event: np.ndarray,
            _address: np.ndarray,
            state: O1FastState,
            *,
            update: bool,
        ) -> O1FastState:
            result = state.clone()
            if update:
                regime = int(
                    np.argmax(
                        np.asarray(event)[
                            causal._REGIME : causal._REGIME + self.config.regime_count
                        ]
                    )
                )
                result.gssm_z.fill_(float(regime + 1))
            return result

        def coefficients(
            self,
            events: np.ndarray,
            _addresses: np.ndarray,
            state: O1FastState,
        ) -> np.ndarray:
            recurrent = bool(torch.count_nonzero(state.gssm_z))
            magnitude = 2 if recurrent else 1
            return np.full(
                np.asarray(events).shape[0],
                self.coefficient_sign * magnitude,
                dtype=np.float32,
            )


def _fake_frozen_reader(config: CausalEvidenceConfig) -> FrozenCausalEvidenceReader:
    if torch is None:  # pragma: no cover - guarded by skip decorators.
        raise RuntimeError("Torch is unavailable")
    primary = _FakeReader(config)
    shuffled = _FakeReader(config, coefficient_sign=-1)
    primary_bytes = canonical_module_bytes(primary)
    shuffled_bytes = canonical_module_bytes(shuffled)
    public_fsm = (
        np.asarray(config.orientation_matrix, dtype=np.int8)[:, :, None]
        * np.asarray(config.coefficient_magnitudes, dtype=np.int8)[None, None, :]
    ).astype(np.int8)
    return FrozenCausalEvidenceReader(
        primary=primary,
        shuffled=shuffled,
        route_threshold=0.0,
        temperatures={arm: 1.0 for arm in ALL_ARMS},
        primary_slow_state_bytes=primary_bytes,
        shuffled_slow_state_bytes=shuffled_bytes,
        primary_slow_state_sha256=hashlib.sha256(primary_bytes).hexdigest(),
        shuffled_slow_state_sha256=hashlib.sha256(shuffled_bytes).hexdigest(),
        initial_state_sha256=primary.initial_state().sha256(config.core_config),
        public_fsm_coefficients=public_fsm,
        public_fsm_coefficients_sha256=hashlib.sha256(
            public_fsm.tobytes(order="C")
        ).hexdigest(),
        training_metrics={"fixture": "deterministic"},
        calibration_metrics={
            "fixture": "deterministic",
            "work": {
                "physical_public_tokens": 0,
                "reader_token_evaluations": 0,
                "public_fsm_table_lookups": 0,
                "temperature_grid_value_evaluations": 0,
            },
        },
    )


class CausalEvidenceConfigAndGroupTests(unittest.TestCase):
    def test_delayed_public_regime_is_previous_symbol_and_rejects_bad_values(
        self,
    ) -> None:
        for previous in range(4):
            for current in range(4):
                with self.subTest(previous=previous, current=current):
                    self.assertEqual(
                        causal._compose_public_regime(
                            np.int64(previous), np.int64(current)
                        ),
                        previous,
                    )

        invalid = (-1, 4, True, False, np.bool_(True), 1.0, "1", None)
        for value in invalid:
            with self.subTest(position="previous", value=repr(value)):
                with self.assertRaisesRegex(CausalEvidenceError, r"\[0,3\]"):
                    causal._compose_public_regime(value, 0)
            with self.subTest(position="current", value=repr(value)):
                with self.assertRaisesRegex(CausalEvidenceError, r"\[0,3\]"):
                    causal._compose_public_regime(0, value)

    def test_config_roundtrip_and_exact_formal_state_budget(self) -> None:
        tiny = _config()
        restored = CausalEvidenceConfig.from_mapping(asdict(tiny))
        self.assertEqual(restored, tiny)
        self.assertEqual(tiny.core_config.fast_state_bytes(), 80)
        self.assertEqual(tiny.live_state_bytes, 104)

        formal_width = _config(n_bits=256)
        self.assertEqual(formal_width.core_config.fast_state_bytes(), 80)
        self.assertEqual(formal_width.live_state_bytes, 352)
        self.assertEqual(
            formal_width.describe()["stream_length_dependent_model_state"], False
        )
        self.assertEqual(formal_width.describe()["external_index_bytes"], 0)

        with self.assertRaisesRegex(CausalEvidenceError, "split|disjoint"):
            replace(tiny, evaluation_seeds=tiny.build_seeds)
        with self.assertRaisesRegex(CausalEvidenceError, "eight families"):
            replace(tiny, family_count=4)
        with self.assertRaisesRegex(CausalEvidenceError, "replacement"):
            replace(tiny, independent_comparison_groups=2)


class CausalEvidencePublicFSMBuildTests(unittest.TestCase):
    def test_outcome_only_fit_is_hashed_immutable_and_fully_billed(self) -> None:
        config = _config()
        (
            events,
            _addresses,
            votes,
            truths,
            _strata,
            _route_events,
            _route_targets,
        ) = causal._training_corpus(config, config.build_seeds)
        coefficients, metrics = causal._fit_outcome_public_fsm(
            config, events, votes, truths
        )
        self.assertEqual(
            coefficients.shape,
            (
                config.regime_count,
                config.family_count,
                len(config.quality_reliabilities),
            ),
        )
        self.assertEqual(coefficients.nbytes, 64)
        self.assertEqual(
            metrics["sha256"],
            hashlib.sha256(coefficients.tobytes(order="C")).hexdigest(),
        )
        self.assertEqual(
            metrics["outcome_lookups"], events.shape[0] * causal._BUILD_STREAM_GROUPS
        )
        self.assertFalse(coefficients.flags.writeable)
        with self.assertRaises(ValueError):
            coefficients[0, 0, 0] = 0

    def test_group_is_immutable_and_rejects_semantic_corruption(self) -> None:
        config = _config()
        episode, _ledger = build_public_evidence_episode(config, 921901)
        group = episode.group(0)
        for name in (
            "coordinates",
            "families",
            "qualities",
            "evidence_votes",
            "nuisance_votes",
            "evidence_events",
            "nuisance_events",
            "evidence_addresses",
            "nuisance_addresses",
            "marker_event",
            "marker_address",
        ):
            self.assertFalse(getattr(group, name).flags.writeable, name)
        with self.assertRaises(ValueError):
            group.coordinates[0] = 1

        corruptions: list[tuple[str, dict[str, object]]] = []
        coordinates = group.coordinates.copy()
        coordinates[-1] = coordinates[0]
        corruptions.append(("duplicate coordinates", {"coordinates": coordinates}))
        coordinates = group.coordinates.copy()
        coordinates[0] = config.n_bits
        corruptions.append(("coordinate range", {"coordinates": coordinates}))
        families = group.families.copy()
        families[0] = config.family_count
        corruptions.append(("family range", {"families": families}))
        qualities = group.qualities.copy()
        qualities[0] = len(config.quality_reliabilities)
        corruptions.append(("quality range", {"qualities": qualities}))
        votes = group.evidence_votes.copy()
        votes[0] = 0
        corruptions.append(("vote alphabet", {"evidence_votes": votes}))
        events = group.evidence_events.copy()
        events[0, causal._EVIDENCE] = 0.0
        corruptions.append(("event semantics", {"evidence_events": events}))
        events = group.evidence_events.copy()
        family = int(group.families[0])
        events[0, causal._FAMILY + family] = 0.0
        events[0, causal._FAMILY + ((family + 1) % config.family_count)] = 1.0
        corruptions.append(("event family binding", {"evidence_events": events}))
        events = group.evidence_events.copy()
        quality = int(group.qualities[0])
        events[0, causal._QUALITY + quality] = 0.0
        events[
            0,
            causal._QUALITY + ((quality + 1) % len(config.quality_reliabilities)),
        ] = 1.0
        corruptions.append(("event quality binding", {"evidence_events": events}))
        nuisance_events = group.nuisance_events.copy()
        nuisance_events[0, causal._NUISANCE] = 0.0
        corruptions.append(
            ("nuisance event semantics", {"nuisance_events": nuisance_events})
        )
        marker_event = group.marker_event.copy()
        marker_event[causal._MARKER] = 0.0
        corruptions.append(("marker event semantics", {"marker_event": marker_event}))
        addresses = group.evidence_addresses.copy()
        addresses[0, 0] = np.nan
        corruptions.append(("finite address", {"evidence_addresses": addresses}))
        corruptions.extend(
            (
                ("group index", {"group_index": -1}),
                ("boolean group index", {"group_index": True}),
                ("group id", {"group_id": -1}),
                ("boolean group id", {"group_id": True}),
                ("group id overflow", {"group_id": 1 << 64}),
                ("group sentinel", {"group_id": (1 << 64) - 1}),
            )
        )
        for label, values in corruptions:
            with self.subTest(label=label):
                with self.assertRaises(CausalEvidenceError):
                    replace(group, **values)

    def test_truth_path_complement_changes_only_evidence_vote(self) -> None:
        config = _config()
        material = hashlib.sha256(b"o1c21-complement-test").digest()
        base, base_ledger = build_public_evidence_episode(
            config, 921902, secret_material=material
        )
        complement, complement_ledger = build_public_evidence_episode(
            config, 921902, complement=True, secret_material=material
        )
        for group_index in range(config.maximum_groups):
            left = base.group(group_index)
            right = complement.group(group_index)
            self.assertEqual(left.group_id, right.group_id)
            for field in (
                "coordinates",
                "families",
                "qualities",
                "nuisance_votes",
                "evidence_events",
                "nuisance_events",
                "evidence_addresses",
                "nuisance_addresses",
                "marker_event",
                "marker_address",
            ):
                np.testing.assert_array_equal(
                    getattr(left, field), getattr(right, field)
                )
            np.testing.assert_array_equal(left.evidence_votes, -right.evidence_votes)
        self.assertEqual(base_ledger.reveal_count, 0)
        self.assertEqual(complement_ledger.reveal_count, 0)
        base_truth = base_ledger.reveal().bits
        complement_truth = complement_ledger.reveal().bits
        np.testing.assert_array_equal(base_truth, np.uint8(1) - complement_truth)

    def test_opaque_id_and_coordinate_transforms_preserve_allowed_semantics(
        self,
    ) -> None:
        config = _config()
        material = hashlib.sha256(b"o1c21-transform-test").digest()
        base, base_ledger = build_public_evidence_episode(
            config, 921903, secret_material=material
        )
        id_variant, id_ledger = build_public_evidence_episode(
            config,
            921903,
            id_permutation_salt=0x123456,
            secret_material=material,
        )
        coordinate_variant, coordinate_ledger = build_public_evidence_episode(
            config,
            921903,
            coordinate_permutation_salt=0x654321,
            secret_material=material,
        )
        mapping = coordinate_variant.logical_to_public
        self.assertEqual(set(mapping.tolist()), set(range(config.n_bits)))
        self.assertFalse(np.array_equal(mapping, np.arange(config.n_bits)))
        for group_index in range(config.maximum_groups):
            original = base.group(group_index)
            renamed = id_variant.group(group_index)
            permuted = coordinate_variant.group(group_index)
            self.assertNotEqual(original.group_id, renamed.group_id)
            for field in (
                "coordinates",
                "families",
                "qualities",
                "evidence_votes",
                "nuisance_votes",
                "evidence_events",
                "nuisance_events",
                "evidence_addresses",
                "nuisance_addresses",
                "marker_event",
                "marker_address",
            ):
                np.testing.assert_array_equal(
                    getattr(original, field), getattr(renamed, field)
                )
            np.testing.assert_array_equal(
                permuted.coordinates, mapping[original.coordinates]
            )
            for field in (
                "families",
                "qualities",
                "evidence_votes",
                "nuisance_votes",
                "evidence_events",
                "nuisance_events",
                "evidence_addresses",
                "nuisance_addresses",
                "marker_event",
                "marker_address",
            ):
                np.testing.assert_array_equal(
                    getattr(original, field), getattr(permuted, field)
                )
        base_truth = base_ledger.reveal().bits
        np.testing.assert_array_equal(base_truth, id_ledger.reveal().bits)
        coordinate_truth = coordinate_ledger.reveal().bits
        np.testing.assert_array_equal(coordinate_truth[mapping], base_truth)


class CausalEvidenceTrainingCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = _config()
        cls.corpus = causal._training_corpus(cls.config, cls.config.build_seeds)

    def test_continuous_corpus_shapes_and_alternating_marker_evidence(self) -> None:
        config = self.config
        (
            events,
            addresses,
            votes,
            truth,
            strata,
            route_events,
            route_targets,
        ) = self.corpus
        base_sequences = (
            len(config.build_seeds)
            * config.family_count
            * len(config.quality_reliabilities)
            * causal._BUILD_OUTCOME_REPETITIONS
        )
        groups = causal._BUILD_STREAM_GROUPS
        self.assertEqual(events.shape, (2 * base_sequences, 2 * groups, 21))
        self.assertEqual(
            addresses.shape,
            (2 * base_sequences, 2 * groups, config.address_dimension),
        )
        self.assertEqual(votes.shape, (2 * base_sequences, groups))
        self.assertEqual(truth.shape, votes.shape)
        self.assertEqual(strata.shape, (2 * base_sequences,))
        self.assertEqual(route_events.shape, (5 * base_sequences, 21))
        self.assertEqual(route_targets.shape, (5 * base_sequences,))

        marker_rows = events[:, 0::2]
        evidence_rows = events[:, 1::2]
        self.assertTrue(bool((marker_rows[..., causal._MARKER] == 1.0).all()))
        self.assertTrue(bool((evidence_rows[..., causal._EVIDENCE] == 1.0).all()))
        self.assertTrue(bool((marker_rows[..., :3].sum(axis=-1) == 1.0).all()))
        self.assertTrue(bool((evidence_rows[..., :3].sum(axis=-1) == 1.0).all()))
        self.assertTrue(
            bool(
                (
                    marker_rows[
                        ..., causal._REGIME : causal._REGIME + config.regime_count
                    ].sum(axis=-1)
                    == 1.0
                ).all()
            )
        )
        self.assertFalse(
            bool(
                evidence_rows[
                    ..., causal._REGIME : causal._REGIME + config.regime_count
                ].any()
            )
        )
        self.assertTrue(bool(np.isin(votes, (-1.0, 1.0)).all()))
        self.assertTrue(bool(np.isin(truth, (0.0, 1.0)).all()))

    def test_adjacent_antithetic_pairs_share_public_input_exactly(self) -> None:
        events, addresses, votes, truth, strata, _route_events, _route_targets = (
            self.corpus
        )
        for left in range(0, events.shape[0], 2):
            right = left + 1
            with self.subTest(pair=left // 2):
                self.assertEqual(events[left].tobytes(), events[right].tobytes())
                self.assertEqual(addresses[left].tobytes(), addresses[right].tobytes())
                np.testing.assert_array_equal(votes[right], -votes[left])
                np.testing.assert_array_equal(truth[right], 1.0 - truth[left])
                self.assertEqual(int(strata[left]), int(strata[right]))

    def test_public_stream_randomness_is_shared_across_family_quality_strata(
        self,
    ) -> None:
        config = self.config
        events, addresses, _votes, _truth, _strata, _route_events, _route_targets = (
            self.corpus
        )
        qualities = len(config.quality_reliabilities)
        repetitions = causal._BUILD_OUTCOME_REPETITIONS

        def sequence_index(family: int, quality: int, repetition: int) -> int:
            return 2 * ((family * qualities + quality) * repetitions + repetition)

        for repetition in range(repetitions):
            reference_index = sequence_index(0, 0, repetition)
            reference_markers = events[reference_index, 0::2]
            reference_marker_addresses = addresses[reference_index, 0::2]
            reference_evidence = events[reference_index, 1::2]
            for family in range(config.family_count):
                for quality in range(qualities):
                    index = sequence_index(family, quality, repetition)
                    with self.subTest(
                        repetition=repetition,
                        family=family,
                        quality=quality,
                    ):
                        self.assertEqual(
                            events[index, 0::2].tobytes(),
                            reference_markers.tobytes(),
                        )
                        self.assertEqual(
                            addresses[index, 0::2].tobytes(),
                            reference_marker_addresses.tobytes(),
                        )
                        # Family/quality one-hots and their operator address are
                        # intentional semantics.  Every other evidence byte,
                        # including all nuisance-noise bytes, must be shared.
                        candidate_evidence = events[index, 1::2]
                        self.assertEqual(
                            candidate_evidence[:, : causal._FAMILY].tobytes(),
                            reference_evidence[:, : causal._FAMILY].tobytes(),
                        )
                        self.assertEqual(
                            candidate_evidence[:, causal._REGIME :].tobytes(),
                            reference_evidence[:, causal._REGIME :].tobytes(),
                        )


class SealedEvidenceLedgerTests(unittest.TestCase):
    def test_ledger_is_opaque_single_reveal_and_execution_has_no_truth_argument(
        self,
    ) -> None:
        ledger = SealedEvidenceTruthLedger(
            np.asarray([0, 1, 1, 0, 1, 0, 0, 1], dtype=np.uint8)
        )
        with self.assertRaises(EvidenceTruthAccessError):
            _ = ledger[0]
        with self.assertRaises(EvidenceTruthAccessError):
            iter(ledger)
        with self.assertRaises(EvidenceTruthAccessError):
            np.asarray(ledger)
        self.assertEqual(ledger.reveal_count, 0)
        revealed = ledger.reveal()
        self.assertEqual(ledger.reveal_count, 1)
        revealed.bits[0] = 1
        with self.assertRaisesRegex(EvidenceTruthAccessError, "exactly once"):
            ledger.reveal()
        signature = inspect.signature(execute_public_evidence_episode)
        self.assertNotIn("truth", signature.parameters)
        self.assertNotIn("ledger", signature.parameters)


@unittest.skipUnless(torch is not None, "optional Torch dependency is absent")
class CausalEvidenceStateAndExecutionTests(unittest.TestCase):
    def test_exact_273_byte_public_fsm_roundtrip_and_saturation(self) -> None:
        config = _config(n_bits=256)
        state = OutcomePublicFSMState.initial(config)
        for _ in range(200):
            state.add(0, 1)
            state.add(255, -1)
        state.previous_symbol = 3
        state.last_group_id = 123456789
        self.assertEqual(int(state.evidence[0]), 127)
        self.assertEqual(int(state.evidence[255]), -127)
        self.assertEqual(state.accepted_updates, 400)
        payload = state.to_bytes(config)
        self.assertEqual(len(payload), 273)
        restored = OutcomePublicFSMState.from_bytes(payload, config=config)
        self.assertEqual(restored.to_bytes(config), payload)
        self.assertEqual(restored.sha256(config), hashlib.sha256(payload).hexdigest())

        asymmetric = bytearray(payload)
        asymmetric[0] = 0x80
        with self.assertRaisesRegex(CausalEvidenceError, "-128"):
            OutcomePublicFSMState.from_bytes(bytes(asymmetric), config=config)
        with self.assertRaisesRegex(CausalEvidenceError, "length"):
            OutcomePublicFSMState.from_bytes(payload[:-1], config=config)
        with self.assertRaises(CausalEvidenceError):
            state.add(0, True)

    def test_exact_352_byte_roundtrip_and_symmetric_int8_saturation(self) -> None:
        config = _config(n_bits=256)
        reader = _fake_frozen_reader(config)
        state = CausalEvidenceState.initial(config, reader.primary.core)
        for _ in range(200):
            state.add(0, 1)
            state.add(255, -1)
        state.last_group_id = 123456789
        self.assertEqual(int(state.evidence[0]), 127)
        self.assertEqual(int(state.evidence[255]), -127)
        self.assertEqual(state.accepted_updates, 400)
        payload = state.to_bytes(config)
        self.assertEqual(len(payload), 352)
        restored = CausalEvidenceState.from_bytes(payload, config=config)
        self.assertEqual(restored.to_bytes(config), payload)
        self.assertEqual(restored.sha256(config), hashlib.sha256(payload).hexdigest())

        asymmetric = bytearray(payload)
        asymmetric[config.core_config.fast_state_bytes()] = 0x80
        with self.assertRaisesRegex(CausalEvidenceError, "-128"):
            CausalEvidenceState.from_bytes(bytes(asymmetric), config=config)
        with self.assertRaisesRegex(CausalEvidenceError, "length"):
            CausalEvidenceState.from_bytes(payload[:-1], config=config)
        with self.assertRaises(CausalEvidenceError):
            state.add(0, True)

    def test_route_recurrence_differs_from_static_and_duplicates_are_invariant(
        self,
    ) -> None:
        config = _config()
        reader = _fake_frozen_reader(config)
        episode, ledger = build_public_evidence_episode(config, 921904)
        complement_episode, complement_ledger = build_public_evidence_episode(
            config, 921904, complement=True
        )
        base = execute_public_evidence_episode(config, reader, episode, repeat_factor=1)
        duplicate = execute_public_evidence_episode(
            config, reader, episode, repeat_factor=2
        )
        complement = execute_public_evidence_episode(
            config, reader, complement_episode, repeat_factor=1
        )
        self.assertEqual(ledger.reveal_count, 0)
        self.assertEqual(complement_ledger.reveal_count, 0)
        np.testing.assert_array_equal(
            base.raw_scores[causal.PRIMARY_ARM],
            2 * base.raw_scores["same_encoder_static_sum"],
        )
        self.assertFalse(
            np.array_equal(
                base.raw_scores[causal.PRIMARY_ARM],
                base.raw_scores["same_encoder_static_sum"],
            )
        )
        np.testing.assert_array_equal(
            base.raw_scores[causal.PRIMARY_ARM],
            duplicate.raw_scores[causal.PRIMARY_ARM],
        )
        self.assertIn("same_encoder_current_marker_sum", causal.CONTROL_ARMS)
        self.assertIn("same_encoder_current_marker_sum", base.raw_scores)
        np.testing.assert_array_equal(
            base.raw_scores["same_encoder_current_marker_sum"],
            duplicate.raw_scores["same_encoder_current_marker_sum"],
        )
        self.assertEqual(
            base.work["current_marker_control_updates"], config.maximum_groups
        )
        self.assertEqual(
            duplicate.work["current_marker_control_updates"],
            base.work["current_marker_control_updates"],
        )
        self.assertEqual(base.prefix_state_sha256, duplicate.prefix_state_sha256)
        self.assertEqual(base.final_state_bytes, duplicate.final_state_bytes)
        self.assertEqual(
            base.public_fsm_prefix_state_sha256,
            duplicate.public_fsm_prefix_state_sha256,
        )
        self.assertEqual(
            base.public_fsm_final_state_bytes,
            duplicate.public_fsm_final_state_bytes,
        )
        self.assertEqual(len(base.public_fsm_final_state_bytes), config.n_bits + 17)
        self.assertEqual(
            base.work["accepted_update_opportunities"],
            config.maximum_groups * config.n_bits,
        )
        self.assertEqual(
            duplicate.work["accepted_update_opportunities"],
            base.work["accepted_update_opportunities"],
        )
        self.assertEqual(
            duplicate.work["physical_public_tokens"],
            2 * base.work["physical_public_tokens"],
        )
        self.assertEqual(
            duplicate.work["public_fsm_table_lookups"],
            base.work["public_fsm_table_lookups"],
        )
        self.assertEqual(
            base.receipt["metadata_sha256"], complement.receipt["metadata_sha256"]
        )
        self.assertEqual(
            base.receipt["route_mask_sha256"],
            complement.receipt["route_mask_sha256"],
        )
        self.assertEqual(
            base.receipt["evidence_vote_sha256"],
            complement.receipt["negated_evidence_vote_sha256"],
        )
        np.testing.assert_array_equal(
            base.raw_scores[causal.PRIMARY_ARM],
            -complement.raw_scores[causal.PRIMARY_ARM],
        )
        np.testing.assert_array_equal(
            base.raw_scores[causal.PUBLIC_FSM_ARM],
            -complement.raw_scores[causal.PUBLIC_FSM_ARM],
        )

    def test_public_fsm_owns_route_duplicate_and_delayed_marker_state(self) -> None:
        config = _config()
        blocked_reader = replace(_fake_frozen_reader(config), route_threshold=100.0)
        episode, _ledger = build_public_evidence_episode(config, 921905)
        execution = execute_public_evidence_episode(
            config, blocked_reader, episode, repeat_factor=2
        )
        self.assertEqual(execution.work["accepted_update_opportunities"], 0)
        self.assertEqual(
            execution.work["public_fsm_table_lookups"],
            config.maximum_groups * config.n_bits,
        )
        manual = np.zeros(config.n_bits, dtype=np.int16)
        previous_symbol = 0
        table = blocked_reader.public_fsm_coefficients
        for group_index in range(config.maximum_groups):
            group = episode.group(group_index)
            for offset, coordinate in enumerate(group.coordinates):
                manual[int(coordinate)] += int(
                    table[
                        previous_symbol,
                        int(group.families[offset]),
                        int(group.qualities[offset]),
                    ]
                ) * int(group.evidence_votes[offset])
            marker = group.marker_event[
                causal._REGIME : causal._REGIME + config.regime_count
            ]
            previous_symbol = int(np.argmax(marker))
        np.testing.assert_array_equal(
            execution.raw_scores[causal.PUBLIC_FSM_ARM][-1],
            manual.astype(np.float64),
        )
        self.assertTrue(
            np.all(execution.raw_scores[causal.PRIMARY_ARM][-1] == 0.0)
        )


def _serialized_scoring_fixture(
    config: CausalEvidenceConfig,
    *,
    public_fsm_exact: bool = True,
) -> tuple[bytes, bytes, bytes, bytes]:
    seed = config.evaluation_seeds[0]
    truth = np.arange(config.n_bits, dtype=np.uint8) & np.uint8(1)
    complement = np.uint8(1) - truth
    signs = 2.0 * truth.astype(np.float32) - 1.0
    complement_signs = -signs
    variants = (
        ("base", f"base/{seed}", signs),
        ("duplicate_r2", f"base/{seed}", signs),
        ("complement", f"complement/{seed}", complement_signs),
        ("id_permutation", f"id_permutation/{seed}", signs),
        ("coordinate_permutation", f"coordinate_permutation/{seed}", signs),
    )
    records: dict[str, tuple[np.ndarray, str, np.ndarray]] = {}
    for variant, truth_key, orientation in variants:
        for arm in ALL_ARMS:
            values = np.stack((orientation, 2.0 * orientation)).astype(np.float32)
            if arm not in (
                causal.PRIMARY_ARM,
                causal.PUBLIC_FSM_ARM,
                causal.ORACLE_ARM,
            ):
                values = np.zeros_like(values)
            if arm == causal.PUBLIC_FSM_ARM and not public_fsm_exact:
                values = np.zeros_like(values)
            records[f"{variant}/{seed}/{arm}"] = (
                values,
                truth_key,
                np.arange(config.n_bits, dtype=np.int64),
            )
    prediction_blob, prediction_index = causal._serialize_prediction_records(
        config, records
    )
    truth_blob, truth_index = causal._serialize_truth_records(
        {
            f"base/{seed}": truth,
            f"complement/{seed}": complement,
            f"id_permutation/{seed}": truth,
            f"coordinate_permutation/{seed}": truth,
        }
    )
    return prediction_blob, prediction_index, truth_blob, truth_index


class CausalEvidenceSerializationTests(unittest.TestCase):
    def test_public_fsm_failure_has_explicit_precedence_classification(self) -> None:
        config = _config()
        prediction_blob, prediction_index, truth_blob, truth_index = (
            _serialized_scoring_fixture(config, public_fsm_exact=False)
        )
        report = recompute_causal_evidence_scores(
            config,
            prediction_blob=prediction_blob,
            prediction_index=prediction_index,
            truth_blob=truth_blob,
            truth_index=truth_index,
        )
        self.assertEqual(report["classification"], "PUBLIC_FSM_REFERENCE_INSUFFICIENT")
        self.assertFalse(report["gates"]["outcome_public_fsm_reference_exact_every_seed"])

    def test_serialized_predictions_recompute_and_detect_every_tamper(self) -> None:
        config = _config()
        prediction_blob, prediction_index, truth_blob, truth_index = (
            _serialized_scoring_fixture(config)
        )
        report = recompute_causal_evidence_scores(
            config,
            prediction_blob=prediction_blob,
            prediction_index=prediction_index,
            truth_blob=truth_blob,
            truth_index=truth_index,
        )
        self.assertEqual(len(report["metrics_sha256"]), 64)
        self.assertEqual(
            report["prediction_blob_sha256"],
            hashlib.sha256(prediction_blob).hexdigest(),
        )
        self.assertEqual(report["truth_record_count"], 4)
        for gate in (
            "outcome_public_fsm_complement_antisymmetry",
            "outcome_public_fsm_opaque_id_equivariance",
            "outcome_public_fsm_coordinate_equivariance",
            "outcome_public_fsm_duplicate_expansion_invariant",
        ):
            self.assertTrue(report["gates"][gate], gate)

        corrupted_prediction = bytearray(prediction_blob)
        corrupted_prediction[0] ^= 1
        with self.assertRaisesRegex(CausalEvidenceError, "commitment"):
            recompute_causal_evidence_scores(
                config,
                prediction_blob=bytes(corrupted_prediction),
                prediction_index=prediction_index,
                truth_blob=truth_blob,
                truth_index=truth_index,
            )

        corrupted_truth = bytearray(truth_blob)
        corrupted_truth[-1] ^= 1
        with self.assertRaisesRegex(CausalEvidenceError, "commitment"):
            recompute_causal_evidence_scores(
                config,
                prediction_blob=prediction_blob,
                prediction_index=prediction_index,
                truth_blob=bytes(corrupted_truth),
                truth_index=truth_index,
            )

        index_document = json.loads(prediction_index)
        index_document["records"][0]["offset_values"] = 1
        corrupted_index = causal._canonical_json(index_document)
        with self.assertRaisesRegex(CausalEvidenceError, "bounds"):
            recompute_causal_evidence_scores(
                config,
                prediction_blob=prediction_blob,
                prediction_index=corrupted_index,
                truth_blob=truth_blob,
                truth_index=truth_index,
            )


@unittest.skipUnless(torch is not None, "optional Torch dependency is absent")
class CausalEvidenceLifecycleTests(unittest.TestCase):
    def _run_with_fake_learning(self, **kwargs: object):
        config = _config()
        reader = _fake_frozen_reader(config)
        training = SimpleNamespace(
            metrics={
                "token_exposures": 0,
                "outcome_public_fsm": {"outcome_lookups": 0},
            }
        )

        def provider(seeds):
            return (
                {
                    seed: hashlib.sha256(
                        struct.pack("<q", seed) + b"test-only-evaluation-material"
                    ).digest()
                    for seed in seeds
                },
                1,
            )

        with (
            mock.patch.object(
                causal,
                "train_causal_evidence_reader",
                side_effect=(training, training),
            ),
            mock.patch.object(
                causal,
                "calibrate_causal_evidence_readers",
                return_value=reader,
            ),
        ):
            return run_causal_evidence_stream(
                config,
                evaluation_material_provider=provider,
                **kwargs,
            )

    def test_callbacks_freeze_predictions_then_persist_raw_truth_before_score(
        self,
    ) -> None:
        phases: list[str] = []
        freeze_sha: dict[str, str] = {}

        def learning_callback(artifacts, document) -> None:
            phases.append(str(document["phase"]))
            self.assertEqual(document["evaluation_ledgers_generated"], 0)
            self.assertEqual(document["evaluation_tokens_seen"], 0)
            self.assertIn("learning/primary_slow_state.bin", artifacts)
            self.assertFalse(any(name.startswith("prediction/") for name in artifacts))

        def prediction_callback(artifacts, document) -> None:
            phases.append(str(document["phase"]))
            self.assertEqual(document["truth_ledger_reveal_count"], 0)
            self.assertEqual(document["scorer_calls"], 0)
            self.assertIn("prediction/evaluation_predictions.f32le", artifacts)
            self.assertFalse(any(name.startswith("truth/") for name in artifacts))
            rendered = json.dumps(document, sort_keys=True)
            self.assertNotIn("correct_bits", rendered)
            self.assertNotIn("evaluation_truth", rendered)
            freeze_sha["prediction"] = str(document["freeze_sha256"])

        def truth_callback(artifacts, document) -> None:
            phases.append(str(document["phase"]))
            self.assertEqual(
                document["parent_prediction_freeze_sha256"],
                freeze_sha["prediction"],
            )
            self.assertEqual(document["scorer_calls"], 0)
            self.assertIn("truth/evaluation_truth.bitpack", artifacts)
            self.assertIn("truth/evaluation_truth_index.json", artifacts)
            parsed, _index = causal._parse_truth_records(
                artifacts["truth/evaluation_truth.bitpack"],
                artifacts["truth/evaluation_truth_index.json"],
            )
            self.assertEqual(len(parsed), 4)

        result = self._run_with_fake_learning(
            on_learning_frozen=learning_callback,
            on_predictions_frozen=prediction_callback,
            on_truth_revealed_before_scoring=truth_callback,
        )
        self.assertEqual(
            phases,
            [
                "ALL_SLOW_STATES_FROZEN_BEFORE_EVALUATION_LEDGER_GENERATION",
                "ALL_EVALUATION_PREDICTIONS_FROZEN_BEFORE_TRUTH_REVEAL",
                "RAW_EVALUATION_TRUTH_PERSISTED_AFTER_PREDICTION_FREEZE_BEFORE_SCORING",
            ],
        )
        self.assertEqual(result.report["work"]["scientific_entropy_calls"], 1)
        self.assertEqual(len(result.report["artifacts"]["truth_index_sha256"]), 64)

    def test_prediction_sink_failure_prevents_all_truth_reveals(self) -> None:
        reveal_calls = 0
        original = SealedEvidenceTruthLedger.reveal

        def counted(ledger):
            nonlocal reveal_calls
            reveal_calls += 1
            return original(ledger)

        def fail_prediction_sink(_artifacts, _document) -> None:
            raise RuntimeError("intentional prediction persistence failure")

        with mock.patch.object(SealedEvidenceTruthLedger, "reveal", counted):
            with self.assertRaisesRegex(RuntimeError, "intentional prediction"):
                self._run_with_fake_learning(on_predictions_frozen=fail_prediction_sink)
        self.assertEqual(reveal_calls, 0)


if __name__ == "__main__":
    unittest.main()
