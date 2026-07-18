from __future__ import annotations

import hashlib
import inspect
import json
import math
import unittest
from fractions import Fraction
from collections.abc import Mapping

import numpy as np

from o1_crypto_lab.living_inverse import (
    KEY_BITS,
    PublicTargetView,
    bits_to_key,
    build_known_target,
    canonical_json_bytes,
    key_bits,
)
from o1_crypto_lab.posterior_frontier import (
    PosteriorFrontierError,
    iter_factorized_topk,
)
from o1_crypto_lab.posterior_logit_frontier import (
    FactorizedLogitFrontierCandidate,
    LOGIT_DIAGNOSTICS_SCHEMA,
    LOGIT_FRONTIER_FREEZE_PHASE,
    LOGIT_FRONTIER_FREEZE_SCHEMA,
    O1C22_ARMS,
    O1C22_SOURCE_ARTIFACT_BYTES,
    O1C22_SOURCE_SHAPE,
    O1C22_WIDTHS,
    PosteriorLogitFrontierError,
    SELECTED_LOGIT_BYTES,
    factorized_logit_diagnostics,
    iter_factorized_logit_topk,
    make_logit_frontier_freeze,
    select_o1c22_logits,
    verify_logit_frontier_against_public_target,
)


def _o1c22_payload(
    selected: np.ndarray | None = None,
) -> tuple[bytes, np.ndarray]:
    tensor = np.linspace(
        -7.0,
        7.0,
        math.prod(O1C22_SOURCE_SHAPE),
        dtype=np.float64,
    ).reshape(O1C22_SOURCE_SHAPE)
    if selected is not None:
        tensor[-1, 2] = np.asarray(selected, dtype=np.float64)
    payload = tensor.astype("<f8", copy=False).tobytes(order="C")
    return payload, tensor


def _selected_bytes(logits: np.ndarray) -> bytes:
    return np.asarray(logits, dtype="<f8").tobytes(order="C")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _token(label: str) -> str:
    return _sha256(label.encode("ascii"))


def _canonical_freeze_payload(fields: Mapping[str, object]) -> bytes:
    unsigned = dict(fields)
    return canonical_json_bytes(
        {
            **unsigned,
            "freeze_sha256": _sha256(canonical_json_bytes(unsigned)),
        }
    )


def _freeze_kwargs(
    payload: bytes,
    public_target: PublicTargetView,
    *,
    upstream_overrides: Mapping[str, object] | None = None,
    source_freeze_overrides: Mapping[str, object] | None = None,
) -> dict[str, object]:
    source_path = "folds/build-0000/heldout/calibrated_predictions.f64le"
    source_freeze_path = "folds/build-0000/heldout/prediction_freeze.json"
    action_pool_sha256 = _token("o1c19-fold-0-action-pool")
    upstream_fields: dict[str, object] = {
        "schema": ("o1-256-fullround-multiresolution-build-loo-prediction-freeze-v1"),
        "phase": "ALL_HELD_OUT_TRAJECTORIES_FROZEN_BEFORE_LABEL_ACCESS",
        "fold_index": 0,
        "held_out_ordinal": 0,
        "target_id": "build-0000",
        "public_view_sha256": public_target.digest(),
        "action_pool_sha256": action_pool_sha256,
        "held_out_labels_materialized": 0,
        "held_out_reader_updates": 0,
        "held_out_critic_updates": 0,
    }
    if upstream_overrides is not None:
        upstream_fields.update(upstream_overrides)
    upstream_payload = _canonical_freeze_payload(upstream_fields)
    upstream_document = json.loads(upstream_payload)

    source_artifact_sha256 = _sha256(payload)
    source_freeze_fields: dict[str, object] = {
        "schema": "o1-256-o1c22-heldout-prediction-freeze-v1",
        "phase": "ALL_HELDOUT_DELTAS_SCALES_STATES_CONTROLS_AND_PREDICTIONS_FROZEN_BEFORE_LABEL_ORACLE",
        "fold_index": 0,
        "held_out_ordinal": 0,
        "held_out_target_id": "build-0000",
        "held_out_action_pool_sha256": action_pool_sha256,
        "upstream_prediction_freeze_sha256": upstream_document["freeze_sha256"],
        "active_coordinate_counts": list(O1C22_WIDTHS),
        "prediction_arms": list(O1C22_ARMS),
        "held_out_label_used_for_this_fold": False,
        "held_out_reader_updates": 0,
        "solver_calls": 0,
        "scientific_entropy_calls": 0,
        "artifacts": {
            source_path: {
                "sha256": source_artifact_sha256,
                "bytes": len(payload),
            }
        },
    }
    if source_freeze_overrides is not None:
        source_freeze_fields.update(source_freeze_overrides)
    source_freeze_payload = _canonical_freeze_payload(source_freeze_fields)
    source_freeze_document = json.loads(source_freeze_payload)
    source_freeze_payload_sha256 = _sha256(source_freeze_payload)

    artifact_entries = {
        source_path: {
            "sha256": source_artifact_sha256,
            "bytes": len(payload),
            "phase": "HELDOUT_PREDICTIONS_FROZEN_FOLD_0",
        },
        source_freeze_path: {
            "sha256": source_freeze_payload_sha256,
            "bytes": len(source_freeze_payload),
            "phase": "HELDOUT_PREDICTIONS_FROZEN_FOLD_0",
        },
    }
    artifact_index_payload = canonical_json_bytes(
        {
            "schema": "o1-256-o1c19-causal-vault-artifact-index-v1",
            "attempt_id": "O1C-0022",
            "artifacts": artifact_entries,
            "indexed_artifact_count": len(artifact_entries),
            "indexed_artifact_bytes": sum(
                int(entry["bytes"]) for entry in artifact_entries.values()
            ),
        }
    )
    artifact_index_sha256 = _sha256(artifact_index_payload)
    manifest_entries = {
        "artifacts/artifact_index.json": artifact_index_sha256,
        f"artifacts/{source_path}": source_artifact_sha256,
        f"artifacts/{source_freeze_path}": source_freeze_payload_sha256,
    }
    manifest_payload = "".join(
        f"{digest}  {relative}\n"
        for relative, digest in sorted(manifest_entries.items())
    ).encode("ascii")

    return {
        "source_payload": payload,
        "source_capsule_manifest_payload": manifest_payload,
        "source_artifact_index_payload": artifact_index_payload,
        "source_prediction_freeze_payload": source_freeze_payload,
        "upstream_prediction_freeze_payload": upstream_payload,
        "source_artifact_sha256": source_artifact_sha256,
        "source_prediction_freeze_sha256": source_freeze_document["freeze_sha256"],
        "source_artifact_path": source_path,
        "source_artifact_bytes": len(payload),
        "source_capsule_manifest_sha256": _sha256(manifest_payload),
        "source_artifact_index_sha256": artifact_index_sha256,
        "public_target": public_target,
        "candidate_limit": 65_536,
    }


def _nested_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {
            nested for child in value.values() for nested in _nested_keys(child)
        }
    if isinstance(value, list):
        return {nested for child in value for nested in _nested_keys(child)}
    return set()


class O1C22SliceTests(unittest.TestCase):
    def test_exact_f64le_k256_quantized_int8_slice_is_immutable(self) -> None:
        self.assertEqual(O1C22_WIDTHS, (12, 52, 128, 256))
        self.assertEqual(
            O1C22_ARMS,
            (
                "raw_float_delta_sum",
                "normalized_float_delta_sum",
                "quantized_int8_vault",
                "last_horizon_only",
                "unit_sign_sum",
                "coordinate_shuffled_vault",
                "zero_prior",
            ),
        )
        self.assertEqual(O1C22_SOURCE_SHAPE, (4, 7, 256))
        self.assertEqual(O1C22_SOURCE_ARTIFACT_BYTES, 4 * 7 * 256 * 8)
        self.assertEqual(SELECTED_LOGIT_BYTES, 256 * 8)

        payload, tensor = _o1c22_payload()
        selected = select_o1c22_logits(
            payload,
            width=256,
            arm="quantized_int8_vault",
        )
        np.testing.assert_array_equal(selected, tensor[3, 2])
        self.assertEqual(selected.shape, (KEY_BITS,))
        self.assertEqual(selected.dtype, np.dtype(np.float64))
        self.assertEqual(selected.nbytes, SELECTED_LOGIT_BYTES)
        self.assertFalse(selected.flags.writeable)

    def test_selector_rejects_wrong_abi_and_nonfinite_tensor(self) -> None:
        payload, tensor = _o1c22_payload()
        invalid_calls = (
            (payload[:-8], 256, "quantized_int8_vault"),
            (payload + bytes(8), 256, "quantized_int8_vault"),
            (bytearray(payload), 256, "quantized_int8_vault"),
            (payload, 255, "quantized_int8_vault"),
            (payload, True, "quantized_int8_vault"),
            (payload, 256, "int8"),
        )
        for raw, width, arm in invalid_calls:
            with (
                self.subTest(width=width, arm=arm, payload_type=type(raw).__name__),
                self.assertRaises(PosteriorLogitFrontierError),
            ):
                select_o1c22_logits(raw, width=width, arm=arm)  # type: ignore[arg-type]

        tensor[0, 0, 0] = np.nan
        nonfinite = tensor.astype("<f8", copy=False).tobytes(order="C")
        with self.assertRaisesRegex(PosteriorLogitFrontierError, "non-finite"):
            select_o1c22_logits(nonfinite)


class FactorizedLogitDecoderTests(unittest.TestCase):
    def test_non_saturating_logits_match_o1c24_probability_frontier(self) -> None:
        rng = np.random.default_rng(0xC0025)
        logits = rng.uniform(-4.0, 4.0, KEY_BITS).astype(np.float64)
        probabilities = 0.5 + 0.5 * np.tanh(0.5 * logits)
        self.assertTrue(np.all((probabilities > 0.0) & (probabilities < 1.0)))

        logit_candidates = list(iter_factorized_logit_topk(logits, limit=128))
        probability_candidates = list(iter_factorized_topk(probabilities, limit=128))
        self.assertEqual(len(logit_candidates), len(probability_candidates))
        for logit_row, probability_row in zip(
            logit_candidates,
            probability_candidates,
            strict=True,
        ):
            self.assertEqual(logit_row.rank, probability_row.rank)
            self.assertEqual(logit_row.key, probability_row.key)
            self.assertEqual(
                logit_row.flipped_coordinates,
                probability_row.flipped_coordinates,
            )
            self.assertEqual(logit_row.topology_code, probability_row.topology_code)
            self.assertAlmostEqual(
                logit_row.flip_penalty_bits,
                probability_row.flip_penalty_bits,
                places=12,
            )
            self.assertAlmostEqual(
                logit_row.log2_probability,
                probability_row.log2_probability,
                places=12,
            )

        diagnostics = factorized_logit_diagnostics(logits)
        self.assertEqual(diagnostics["schema"], LOGIT_DIAGNOSTICS_SCHEMA)
        self.assertEqual(diagnostics["posterior_logits_bytes"], 2_048)
        self.assertEqual(
            diagnostics["posterior_logits_sha256"],
            hashlib.sha256(_selected_bytes(logits)).hexdigest(),
        )
        self.assertAlmostEqual(
            float(diagnostics["map_log2_probability"]),
            probability_candidates[0].log2_probability,
            places=12,
        )
        self.assertEqual(diagnostics["truth_reads"], 0)
        self.assertEqual(diagnostics["label_reads"], 0)
        self.assertFalse(diagnostics["truth_used"])

    def test_adjacent_binary64_penalties_keep_exact_global_order(self) -> None:
        logits = np.full(KEY_BITS, 100.0, dtype=np.float64)
        logits[0] = np.nextafter(np.float64(0.7), np.float64(math.inf))
        logits[1] = np.float64(0.7)

        candidates = list(iter_factorized_logit_topk(logits, limit=3))
        self.assertTrue(
            all(
                isinstance(candidate, FactorizedLogitFrontierCandidate)
                for candidate in candidates
            )
        )
        self.assertEqual(
            [candidate.flipped_coordinates for candidate in candidates],
            [(), (1,), (0,)],
        )
        self.assertEqual(
            [candidate.topology_code for candidate in candidates],
            [0, 1, 2],
        )
        exact_units = [candidate.exact_penalty_units for candidate in candidates]
        self.assertEqual(exact_units[0], 0)
        self.assertLess(exact_units[1], exact_units[2])
        self.assertTrue(
            all(
                left <= right
                for left, right in zip(
                    exact_units[:-1],
                    exact_units[1:],
                    strict=True,
                )
            )
        )
        self.assertEqual(
            len({candidate.penalty_unit_exponent for candidate in candidates}),
            1,
        )

    def test_exact_heap_matches_exhaustive_rational_subset_order(self) -> None:
        width = 8
        logits = np.full(KEY_BITS, 1_000.0, dtype=np.float64)
        logits[:width] = np.asarray(
            (0.0, -0.125, 0.25, -0.375, 0.5, -0.625, 0.75, -0.875),
            dtype=np.float64,
        )
        candidates = list(iter_factorized_logit_topk(logits, limit=1 << width))
        penalties = tuple(Fraction.from_float(abs(float(value))) for value in logits)
        expected_masks = sorted(
            range(1 << width),
            key=lambda mask: (
                sum(
                    penalties[coordinate]
                    for coordinate in range(width)
                    if mask & (1 << coordinate)
                ),
                mask,
            ),
        )
        self.assertEqual(
            [candidate.topology_code for candidate in candidates],
            expected_masks,
        )
        exponent = candidates[0].penalty_unit_exponent
        self.assertEqual(
            [candidate.exact_penalty_units for candidate in candidates],
            [
                int(
                    sum(
                        penalties[coordinate]
                        for coordinate in range(width)
                        if mask & (1 << coordinate)
                    )
                    * (1 << exponent)
                )
                for mask in expected_masks
            ],
        )

    def test_extreme_logits_decode_without_probability_endpoints(self) -> None:
        logits = np.where(np.arange(KEY_BITS) % 2 == 0, 1_000.0, -1_000.0)
        saturated = 0.5 + 0.5 * np.tanh(0.5 * logits)
        self.assertEqual(int(np.count_nonzero(saturated == 0.0)), KEY_BITS // 2)
        self.assertEqual(int(np.count_nonzero(saturated == 1.0)), KEY_BITS // 2)
        with self.assertRaises(PosteriorFrontierError):
            iter_factorized_topk(saturated, limit=1)

        candidates = list(iter_factorized_logit_topk(logits, limit=16))
        replay = list(iter_factorized_logit_topk(logits, limit=16))
        self.assertEqual(candidates, replay)
        self.assertEqual(
            [candidate.topology_code for candidate in candidates],
            [0, *(1 << coordinate for coordinate in range(15))],
        )
        self.assertTrue(
            all(
                math.isfinite(candidate.log2_probability)
                and math.isfinite(candidate.flip_penalty_bits)
                for candidate in candidates
            )
        )
        diagnostics = factorized_logit_diagnostics(logits)
        self.assertEqual(diagnostics["maximum_absolute_logit"], 1_000.0)
        self.assertTrue(math.isfinite(float(diagnostics["factorized_entropy_bits"])))
        self.assertTrue(
            math.isfinite(float(diagnostics["effective_domain_compression_bits"]))
        )

    def test_zero_penalty_ties_are_exact_deterministic_nested_prefixes(self) -> None:
        logits = np.zeros(KEY_BITS, dtype=np.float64)
        first = list(iter_factorized_logit_topk(logits, limit=32))
        replay = list(iter_factorized_logit_topk(logits, limit=32))
        prefix = list(iter_factorized_logit_topk(logits, limit=8))
        self.assertEqual(first, replay)
        self.assertEqual(first[:8], prefix)
        self.assertEqual(
            [candidate.topology_code for candidate in first],
            list(range(32)),
        )
        self.assertTrue(all(candidate.flip_penalty_bits == 0.0 for candidate in first))
        self.assertTrue(
            all(candidate.log2_probability == -256.0 for candidate in first)
        )

    def test_truth_free_candidates_hit_full_round_public_chacha_at_rank_four(
        self,
    ) -> None:
        key = bytes((37 * index + 11) & 0xFF for index in range(32))
        truth = key_bits(key)
        mode = truth.copy()
        mode[2] ^= 1
        magnitudes = np.full(KEY_BITS, 8.0, dtype=np.float64)
        magnitudes[:3] = (0.10, 0.20, 0.29)
        logits = np.where(mode == 1, magnitudes, -magnitudes)

        parameters = inspect.signature(iter_factorized_logit_topk).parameters
        self.assertEqual(tuple(parameters), ("logits", "limit"))
        self.assertNotIn("key", parameters)
        self.assertNotIn("truth", parameters)
        candidates = tuple(iter_factorized_logit_topk(logits, limit=8))
        self.assertEqual(
            [candidate.flipped_coordinates for candidate in candidates[:4]],
            [(), (0,), (1,), (2,)],
        )

        target = build_known_target(
            key,
            counter=0x10203040,
            nonce=bytes((13 * index + 5) & 0xFF for index in range(12)),
            block_count=2,
        )
        verification = verify_logit_frontier_against_public_target(
            target.public,
            iter(candidates),
        )
        self.assertTrue(verification["exact_match_found"])
        self.assertEqual(verification["first_match_rank_one_based"], 4)
        self.assertEqual(verification["candidates_verified"], 4)
        self.assertEqual(verification["first_match_key_hex"], key.hex())

    def test_invalid_logits_and_limits_fail_closed(self) -> None:
        invalid_logits = (
            np.zeros(255, dtype=np.float64),
            np.zeros((128, 2), dtype=np.float64),
            np.full(KEY_BITS, np.nan, dtype=np.float64),
            np.full(KEY_BITS, np.inf, dtype=np.float64),
            np.full(KEY_BITS, np.finfo(np.float64).max, dtype=np.float64),
            ["not-a-logit"] * KEY_BITS,
        )
        for logits in invalid_logits:
            with self.subTest(shape=np.shape(logits)), np.errstate(over="ignore"):
                with self.assertRaises(PosteriorLogitFrontierError):
                    list(iter_factorized_logit_topk(logits, limit=1))
                with self.assertRaises(PosteriorLogitFrontierError):
                    factorized_logit_diagnostics(logits)

        for limit in (0, -1, True, 1.5, (1 << KEY_BITS) + 1):
            with (
                self.subTest(limit=limit),
                self.assertRaises(PosteriorLogitFrontierError),
            ):
                iter_factorized_logit_topk(np.zeros(KEY_BITS), limit=limit)  # type: ignore[arg-type]


class LogitFrontierFreezeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.logits = np.linspace(-3.0, 3.0, KEY_BITS, dtype=np.float64)
        self.payload, _ = _o1c22_payload(self.logits)
        self.key = bits_to_key((self.logits >= 0.0).astype(np.uint8))
        self.target = build_known_target(
            self.key,
            counter=19,
            nonce=bytes(range(12)),
        )

    def _freeze(
        self,
        logits: np.ndarray | None = None,
        payload: bytes | None = None,
        **overrides: object,
    ) -> dict[str, object]:
        selected = self.logits if logits is None else logits
        source = self.payload if payload is None else payload
        kwargs = _freeze_kwargs(source, self.target.public)
        kwargs.update(overrides)
        return make_logit_frontier_freeze(selected, **kwargs)  # type: ignore[arg-type]

    def test_freeze_is_canonical_hash_bound_and_contains_no_key_material(
        self,
    ) -> None:
        lifecycle = _freeze_kwargs(self.payload, self.target.public)
        freeze = self._freeze()
        replay = self._freeze()
        self.assertEqual(freeze, replay)
        self.assertEqual(freeze["schema"], LOGIT_FRONTIER_FREEZE_SCHEMA)
        self.assertEqual(freeze["phase"], LOGIT_FRONTIER_FREEZE_PHASE)
        self.assertEqual(freeze["source_shape"], [4, 7, 256])
        self.assertEqual(freeze["source_artifact_bytes"], 57_344)
        self.assertEqual(freeze["selected_width_index"], 3)
        self.assertEqual(freeze["selected_arm_index"], 2)
        self.assertEqual(freeze["selected_logits_bytes"], 2_048)
        self.assertEqual(
            freeze["source_artifact_sha256"],
            hashlib.sha256(self.payload).hexdigest(),
        )
        self.assertEqual(
            freeze["selected_logits_sha256"],
            hashlib.sha256(_selected_bytes(self.logits)).hexdigest(),
        )
        self.assertEqual(
            freeze["source_capsule_manifest_sha256"],
            lifecycle["source_capsule_manifest_sha256"],
        )
        self.assertEqual(
            freeze["source_artifact_index_sha256"],
            lifecycle["source_artifact_index_sha256"],
        )
        self.assertEqual(
            freeze["source_prediction_freeze_sha256"],
            lifecycle["source_prediction_freeze_sha256"],
        )
        upstream = json.loads(lifecycle["upstream_prediction_freeze_payload"])
        self.assertEqual(
            freeze["upstream_prediction_freeze_sha256"],
            upstream["freeze_sha256"],
        )
        self.assertEqual(freeze["source_fold_index"], 0)
        self.assertEqual(freeze["source_target_id"], "build-0000")
        self.assertEqual(
            freeze["source_action_pool_sha256"],
            upstream["action_pool_sha256"],
        )
        self.assertEqual(
            freeze["upstream_public_view_sha256"],
            self.target.public.digest(),
        )
        self.assertEqual(freeze["public_target_sha256"], self.target.public.digest())
        self.assertEqual(freeze["truth_reads"], 0)
        self.assertEqual(freeze["label_reads"], 0)
        self.assertFalse(freeze["truth_used_for_generation"])

        unsigned = dict(freeze)
        supplied_hash = unsigned.pop("freeze_sha256")
        self.assertEqual(
            supplied_hash,
            hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest(),
        )
        encoded = canonical_json_bytes(freeze)
        self.assertEqual(json.loads(encoded), freeze)

        forbidden = {
            "key_hex",
            "map_key_hex",
            "map_key_sha256",
            "true_key",
            "true_key_hex",
            "true_key_sha256",
            "target_key",
            "target_trace",
            "target_traces",
            "nonce_hex",
            "output_blocks_hex",
            "label_bits",
            "labels",
            "reveal",
            "evaluation",
        }
        self.assertTrue(forbidden.isdisjoint(_nested_keys(freeze)))

    def test_freeze_changes_with_bound_source_and_selected_logits(self) -> None:
        original = self._freeze()
        changed_logits = self.logits.copy()
        changed_logits[73] += 0.125
        changed_payload, _ = _o1c22_payload(changed_logits)
        changed = self._freeze(changed_logits, changed_payload)
        self.assertNotEqual(
            original["source_artifact_sha256"],
            changed["source_artifact_sha256"],
        )
        self.assertNotEqual(
            original["selected_logits_sha256"],
            changed["selected_logits_sha256"],
        )
        self.assertNotEqual(original["freeze_sha256"], changed["freeze_sha256"])

    def test_freeze_rejects_foreign_selected_vector(self) -> None:
        foreign = self.logits.copy()
        foreign[17] = np.nextafter(foreign[17], math.inf)
        with self.assertRaisesRegex(PosteriorLogitFrontierError, "selected logits"):
            self._freeze(foreign)

    def test_freeze_rejects_foreign_target_and_lifecycle_mismatches(self) -> None:
        foreign = build_known_target(
            bytes(reversed(self.key)),
            counter=19,
            nonce=bytes(range(12)),
        )
        foreign_target_kwargs = _freeze_kwargs(self.payload, self.target.public)
        foreign_target_kwargs["public_target"] = foreign.public
        with self.assertRaisesRegex(PosteriorLogitFrontierError, "supplied public"):
            make_logit_frontier_freeze(
                self.logits,
                **foreign_target_kwargs,  # type: ignore[arg-type]
            )

        mismatches = (
            {"source_freeze_overrides": {"held_out_target_id": "build-0001"}},
            {
                "source_freeze_overrides": {
                    "held_out_action_pool_sha256": _token("wrong-action-pool")
                }
            },
            {"upstream_overrides": {"fold_index": 1}},
        )
        for fixture_overrides in mismatches:
            kwargs = _freeze_kwargs(
                self.payload,
                self.target.public,
                **fixture_overrides,  # type: ignore[arg-type]
            )
            with (
                self.subTest(fixture_overrides=fixture_overrides),
                self.assertRaises(PosteriorLogitFrontierError),
            ):
                make_logit_frontier_freeze(
                    self.logits,
                    **kwargs,  # type: ignore[arg-type]
                )

    def test_freeze_invalid_inputs_fail_closed(self) -> None:
        cases = (
            {"source_payload": self.payload[:-8]},
            {"source_capsule_manifest_payload": b"{}"},
            {"source_artifact_index_payload": b"{}"},
            {"source_prediction_freeze_payload": b"{}"},
            {"upstream_prediction_freeze_payload": b"{}"},
            {"source_artifact_sha256": "0" * 64},
            {"source_artifact_sha256": "A" * 64},
            {"source_artifact_bytes": 57_336},
            {"source_capsule_manifest_sha256": "0" * 64},
            {"source_artifact_index_sha256": "0" * 64},
            {"source_prediction_freeze_sha256": "0" * 64},
            {"source_prediction_freeze_sha256": "x" * 64},
            {"source_artifact_path": "../predictions.f64le"},
            {"source_artifact_path": "folds/build-0000/heldout/labels.bitpack"},
            {"source_capsule_manifest_sha256": "A" * 64},
            {"source_artifact_index_sha256": None},
            {"public_target": object()},
            {"candidate_limit": 0},
            {"candidate_limit": True},
            {"candidate_limit": 65_535},
            {"candidate_limit": 65_537},
            {"selected_width": 255},
            {"selected_width": 128},
            {"selected_arm": "int8"},
            {"selected_arm": "raw_float_delta_sum"},
            {"source_shape": (4, 7, 255)},
        )
        for overrides in cases:
            with (
                self.subTest(overrides=overrides),
                self.assertRaises(PosteriorLogitFrontierError),
            ):
                self._freeze(**overrides)

        nonfinite_payload, tensor = _o1c22_payload(self.logits)
        del nonfinite_payload
        tensor[0, 0, 0] = np.inf
        payload = tensor.astype("<f8", copy=False).tobytes(order="C")
        with self.assertRaises(PosteriorLogitFrontierError):
            self._freeze(
                payload=payload,
                source_artifact_sha256=hashlib.sha256(payload).hexdigest(),
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
