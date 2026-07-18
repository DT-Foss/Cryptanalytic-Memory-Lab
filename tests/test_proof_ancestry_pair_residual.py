from __future__ import annotations

import hashlib
import json
import math
import struct
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np

from o1_crypto_lab.full256_action_pool import BRANCH_FEATURES, Full256ActionPool
from o1_crypto_lab.proof_ancestry_pair_residual import (
    ACCOUNTED_NUMERIC_PAYLOAD_BYTES,
    ADDITIVE_ARM,
    ALPHA_GRID,
    COMMON_MODE_ARM,
    CONTEXT_COLUMNS,
    EXPECTED_HORIZONS,
    FEATURE_WIDTH,
    FrozenInnerOOF,
    LIVE_STATE_BYTES,
    OFF_DIAGONAL_ONLY_ABLATION,
    PAIR_SHUFFLE_ARM,
    POSTERIOR_BYTES,
    PROCESS_LOCAL_SCRATCH_CEILING_BYTES,
    PRIMARY_ARM,
    PROXY_OPERATOR_ID,
    ProjectedResidualState,
    ProofAncestryPairResidualError,
    SELF_ONLY_ABLATION,
    WEIGHT_BYTES,
    finish_outer_fold,
    fit_inner_oof,
    fit_offset_ridge,
    fit_outer_fold,
    pair_shuffle_sources,
    project_coordinate,
    projection_policy,
    projection_policy_sha256,
    select_nonnegative_alpha,
    touch_projection_table,
    verify_o1c23_selection,
)


def _token(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _pool(
    features: np.ndarray, horizons: tuple[int, ...] = EXPECTED_HORIZONS
) -> Full256ActionPool:
    return Full256ActionPool(
        horizons=horizons,
        branch_features=np.asarray(features, dtype=np.float32),
        final_resources=np.zeros((256, 2, 3), dtype=np.uint64),
        pair_sha256=tuple(_token(f"pair-{index}") for index in range(256)),
        source_stream_sha256=_token("stream"),
    )


def _random_pool() -> Full256ActionPool:
    rng = np.random.default_rng(260026)
    features = rng.normal(
        0.0,
        0.25,
        size=(3, 256, 2, BRANCH_FEATURES),
    ).astype(np.float32)
    return _pool(features)


def _odd_even(zero: np.float32, one: np.float32) -> tuple[float, float]:
    z = float(zero)
    o = float(one)
    pz = z / (1.0 + abs(z))
    po = o / (1.0 + abs(o))
    return 0.5 * (po - pz), 0.5 * (po + pz)


def _digest(domain: bytes, horizon: int, coordinate: int, source: int) -> bytes:
    return hashlib.sha256(
        domain + struct.pack(">HHH", horizon, coordinate, source)
    ).digest()


def _reference_primary(pool: Full256ActionPool, coordinate: int) -> np.ndarray:
    rows: list[np.ndarray] = []
    for horizon in range(3):
        odd_touch = np.zeros(16, dtype=np.float64)
        even_touch = np.zeros(16, dtype=np.float64)
        for source in range(256):
            digest = _digest(
                b"o1c26/touch-sketch/v2\0",
                horizon,
                coordinate,
                source,
            )
            bucket = 0 if source == coordinate else 1 + digest[0] % 15
            sign = 1.0 if digest[1] % 2 == 0 else -1.0
            odd, even = _odd_even(
                pool.branch_features[horizon, coordinate, 0, 74 + source],
                pool.branch_features[horizon, coordinate, 1, 74 + source],
            )
            odd_touch[bucket] += sign * odd
            even_touch[bucket] += sign * even
        odd_touch /= 16.0
        even_touch /= 16.0

        odd_context = np.zeros(8, dtype=np.float64)
        even_context = np.zeros(8, dtype=np.float64)
        for source in CONTEXT_COLUMNS:
            digest = _digest(
                b"o1c26/context-sketch/v2\0",
                horizon,
                coordinate,
                source,
            )
            bucket = digest[0] % 8
            sign = 1.0 if digest[1] % 2 == 0 else -1.0
            odd, even = _odd_even(
                pool.branch_features[horizon, coordinate, 0, source],
                pool.branch_features[horizon, coordinate, 1, source],
            )
            odd_context[bucket] += sign * odd / math.sqrt(67.0)
            even_context[bucket] += sign * even / math.sqrt(67.0)
        rows.extend(
            (
                np.outer(odd_touch, even_context).reshape(-1),
                np.outer(even_touch, odd_context).reshape(-1),
            )
        )
    result = np.concatenate(rows)
    result[result == 0.0] = 0.0
    return result


class ProjectionPolicyTests(unittest.TestCase):
    def test_policy_freezes_v2_abi_and_exact_state_ceiling(self) -> None:
        policy = projection_policy()
        self.assertEqual(
            policy["schema"],
            "o1-256-proof-ancestry-pair-projection-policy-v2",
        )
        self.assertEqual(PROXY_OPERATOR_ID, "fap_ancestry_touch_bilinear_proxy_v2")
        self.assertEqual(policy["horizons_in_raw_fap_order"], [64, 96, 65])
        self.assertEqual(policy["input_shape"], [3, 256, 2, 330])
        self.assertEqual(policy["feature_width"], 768)
        self.assertEqual(FEATURE_WIDTH, 768)
        self.assertEqual(WEIGHT_BYTES, 6_144)
        self.assertEqual(POSTERIOR_BYTES, 2_048)
        self.assertEqual(LIVE_STATE_BYTES, 8_192)
        self.assertEqual(ACCOUNTED_NUMERIC_PAYLOAD_BYTES, 12_672)
        self.assertEqual(PROCESS_LOCAL_SCRATCH_CEILING_BYTES, 16_384)
        self.assertLess(
            ACCOUNTED_NUMERIC_PAYLOAD_BYTES,
            PROCESS_LOCAL_SCRATCH_CEILING_BYTES,
        )
        self.assertEqual(projection_policy_sha256(), projection_policy_sha256())

    def test_source_config_is_bound_to_policy_and_build_faps(self) -> None:
        config = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "configs"
                / "proof_ancestry_pair_residual_v2.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            config["projection_policy_sha256"],
            projection_policy_sha256(),
        )
        self.assertEqual(
            config["raw_fap_abi"]["context_columns"], list(CONTEXT_COLUMNS)
        )
        self.assertEqual(
            [entry["sha256"] for entry in config["build_faps"]],
            [
                "0473112acf83efec096418c90e14aa394fc86ff286b4923dd6caa3c7cba79520",
                "47c184183f1211bd0a718cccf4ab202446574d9e21d5a969920280b8c0eb6df5",
                "fcee9c6c05e40c47023417acf7df34bbcf694398b650810b96d6640871ad7b06",
                "04a4b19797877fd7f6fc6dec9cd7af5b7608a5eab765090600be4567562bde0b",
            ],
        )

    def test_exact_touch_hash_and_derangement(self) -> None:
        horizon = 2
        coordinate = 137
        source = 19
        digest = _digest(
            b"o1c26/touch-sketch/v2\0",
            horizon,
            coordinate,
            source,
        )
        self.assertEqual(
            touch_projection_table(horizon, coordinate)[source],
            (1 + digest[0] % 15, 1 if digest[1] % 2 == 0 else -1),
        )
        self_digest = _digest(
            b"o1c26/touch-sketch/v2\0",
            horizon,
            coordinate,
            coordinate,
        )
        self.assertEqual(
            touch_projection_table(horizon, coordinate)[coordinate],
            (0, 1 if self_digest[1] % 2 == 0 else -1),
        )
        shuffled = pair_shuffle_sources(horizon, coordinate)
        self.assertEqual(sorted(shuffled), list(range(256)))
        self.assertTrue(all(source != dest for dest, source in enumerate(shuffled)))


class ProjectionMechanismTests(unittest.TestCase):
    pool: Full256ActionPool

    @classmethod
    def setUpClass(cls) -> None:
        cls.pool = _random_pool()

    def test_primary_matches_independent_reference_and_repeats_bytes(self) -> None:
        first = project_coordinate(self.pool, 137)
        second = project_coordinate(self.pool, 137)
        reference = _reference_primary(self.pool, 137)
        np.testing.assert_allclose(first, reference, rtol=0.0, atol=1e-18)
        self.assertEqual(first.tobytes(), second.tobytes())
        self.assertFalse(first.flags.writeable)

    def test_actual_branch_swap_odd_arms_negate_and_even_arm_is_invariant(self) -> None:
        swapped = self.pool.polarity_swapped()
        for arm in (PRIMARY_ARM, PAIR_SHUFFLE_ARM, ADDITIVE_ARM):
            original = project_coordinate(self.pool, 41, arm=arm)
            swapped_row = project_coordinate(swapped, 41, arm=arm)
            np.testing.assert_allclose(swapped_row, -original, rtol=0.0, atol=1e-15)
        original_even = project_coordinate(self.pool, 41, arm=COMMON_MODE_ARM)
        swapped_even = project_coordinate(swapped, 41, arm=COMMON_MODE_ARM)
        np.testing.assert_array_equal(swapped_even, original_even)

    def test_self_lane_is_bilinear_and_ablatable(self) -> None:
        features = np.zeros((3, 256, 2, BRANCH_FEATURES), dtype=np.float32)
        coordinate = 23
        for horizon in range(3):
            features[horizon, coordinate, 0, 74 + coordinate] = -0.5
            features[horizon, coordinate, 1, 74 + coordinate] = 0.5
            features[horizon, coordinate, :, 6] = 1.0
        pool = _pool(features)
        primary = project_coordinate(pool, coordinate)
        off_diagonal = project_coordinate(
            pool,
            coordinate,
            ablation=OFF_DIAGONAL_ONLY_ABLATION,
        )
        self_only = project_coordinate(
            pool,
            coordinate,
            ablation=SELF_ONLY_ABLATION,
        )
        self.assertGreater(float(np.linalg.norm(primary)), 0.0)
        np.testing.assert_array_equal(off_diagonal, np.zeros(FEATURE_WIDTH))
        np.testing.assert_array_equal(self_only, primary)

        features[:, coordinate, :, 6] = 0.0
        no_context = project_coordinate(_pool(features), coordinate)
        np.testing.assert_array_equal(no_context, np.zeros(FEATURE_WIDTH))

    def test_additive_control_cannot_use_even_context_multiplicatively(self) -> None:
        features = np.zeros((3, 256, 2, BRANCH_FEATURES), dtype=np.float32)
        coordinate = 7
        features[:, coordinate, 0, 74 + coordinate] = -0.25
        features[:, coordinate, 1, 74 + coordinate] = 0.25
        first = features.copy()
        second = features.copy()
        first[:, coordinate, :, 6] = 0.5
        second[:, coordinate, :, 6] = 2.0
        first_pool = _pool(first)
        second_pool = _pool(second)
        np.testing.assert_array_equal(
            project_coordinate(first_pool, coordinate, arm=ADDITIVE_ARM),
            project_coordinate(second_pool, coordinate, arm=ADDITIVE_ARM),
        )
        self.assertFalse(
            np.array_equal(
                project_coordinate(first_pool, coordinate),
                project_coordinate(second_pool, coordinate),
            )
        )

    def test_exact_raw_fap_horizon_order_is_required(self) -> None:
        features = np.zeros((3, 256, 2, BRANCH_FEATURES), dtype=np.float32)
        wrong = _pool(features, horizons=(64, 65, 96))
        with self.assertRaisesRegex(
            ProofAncestryPairResidualError, "exact raw FAP ABI"
        ):
            project_coordinate(wrong, 0)


class RidgeAndStateTests(unittest.TestCase):
    def test_scale_invariant_ridge_matches_direct_standardized_reference(self) -> None:
        matrix = np.zeros((3, FEATURE_WIDTH), dtype=np.float64)
        matrix[0, 0] = 1.0
        matrix[1, 1] = 2.0
        matrix[2, 2] = -3.0
        labels = np.array([1.0, -1.0, 1.0], dtype=np.float64)
        offsets = np.array([0.2, -0.4, 0.6], dtype=np.float64)
        fit = fit_offset_ridge(matrix, labels, offsets)

        s2 = float(np.sum(matrix * matrix)) / FEATURE_WIDTH
        scale = math.sqrt(s2)
        standardized = matrix / scale
        residual = labels - np.tanh(offsets / 2.0)
        gram = standardized @ standardized.T
        gram = 0.5 * (gram + gram.T) + np.eye(3)
        with np.errstate(divide="ignore", over="ignore", invalid="ignore"):
            expected = standardized.T @ np.linalg.solve(gram, residual) / scale
        np.testing.assert_allclose(fit.weights, expected, rtol=1e-13, atol=1e-13)
        self.assertEqual(fit.regularization, s2)

    def test_zero_fit_alpha_tie_and_outer_accounting_are_exact(self) -> None:
        zero_matrix = np.zeros((256, FEATURE_WIDTH), dtype=np.float64)
        labels = np.ones(256, dtype=np.float64)
        offsets = np.zeros(256, dtype=np.float64)
        zero_fit = fit_offset_ridge(zero_matrix, labels, offsets)
        self.assertEqual(zero_fit.regularization, 0.0)
        self.assertEqual(zero_fit.weights.tobytes(), bytes(WEIGHT_BYTES))
        alpha, evaluations = select_nonnegative_alpha(
            np.zeros(256, dtype=np.float64),
            labels,
            offsets,
        )
        self.assertEqual(alpha, 0.0)
        self.assertEqual(evaluations, len(ALPHA_GRID) * 256)

        outer = fit_outer_fold(
            [zero_matrix] * 3,
            [labels] * 3,
            [offsets] * 3,
            zero_matrix,
            offsets,
        )
        self.assertEqual(outer.ridge_fits, 4)
        self.assertEqual(outer.alpha_bit_evaluations, 401 * 3 * 256)
        self.assertEqual(outer.alpha, 0.0)
        self.assertEqual(len(outer.effective_weight_bytes), WEIGHT_BYTES)
        self.assertEqual(outer.effective_weight_bytes, bytes(WEIGHT_BYTES))

    def test_alpha_endpoint_and_bounded_streaming_state(self) -> None:
        labels = np.array([1.0, -1.0, 1.0, -1.0], dtype=np.float64)
        raw = labels.copy()
        offsets = np.zeros(4, dtype=np.float64)
        alpha, evaluations = select_nonnegative_alpha(raw, labels, offsets)
        self.assertEqual(alpha, 2.0)
        self.assertEqual(evaluations, 401 * 4)

        pool = _random_pool()
        weights = np.linspace(-0.5, 0.5, FEATURE_WIDTH, dtype=np.float64)
        state = ProjectedResidualState(weights)
        self.assertEqual(state.live_state_bytes, LIVE_STATE_BYTES)
        logit = state.infer_coordinate(pool, 11, offset=0.25)
        with np.errstate(divide="ignore", over="ignore", invalid="ignore"):
            expected = 0.25 + float(project_coordinate(pool, 11) @ weights)
        self.assertEqual(logit, expected)
        self.assertEqual(state.posterior()[11], expected)
        self.assertFalse(state.effective_weights.flags.writeable)

    def test_inner_freeze_then_finish_is_exactly_wrapper_equivalent(self) -> None:
        matrices: list[np.ndarray] = []
        labels: list[np.ndarray] = []
        offsets: list[np.ndarray] = []
        for target in range(3):
            matrix = np.zeros((256, FEATURE_WIDTH), dtype=np.float64)
            matrix[:, target] = np.linspace(-1.0, 1.0, 256)
            matrices.append(matrix)
            labels.append(
                np.where(np.arange(256) % 2 == target % 2, 1.0, -1.0).astype(np.float64)
            )
            offsets.append(np.full(256, target * 0.1, dtype=np.float64))
        held = np.zeros((256, FEATURE_WIDTH), dtype=np.float64)
        held[:, :3] = 0.25
        held_offsets = np.linspace(-0.2, 0.2, 256, dtype=np.float64)
        inner = fit_inner_oof(matrices, labels, offsets)
        self.assertIsInstance(inner, FrozenInnerOOF)
        self.assertEqual(len(inner.raw_prediction_bytes), 3 * 256 * 8)
        reloaded = FrozenInnerOOF(
            np.frombuffer(inner.raw_prediction_bytes, dtype="<f8")
            .reshape(3, 256)
            .copy(),
            inner.regularizations,
            inner.ridge_fits,
        )
        split = finish_outer_fold(
            matrices,
            labels,
            offsets,
            held,
            held_offsets,
            reloaded,
        )
        wrapped = fit_outer_fold(
            matrices,
            labels,
            offsets,
            held,
            held_offsets,
        )
        self.assertEqual(split.effective_weight_bytes, wrapped.effective_weight_bytes)
        self.assertEqual(split.alpha, wrapped.alpha)
        self.assertEqual(
            split.held_out_logits.tobytes(), wrapped.held_out_logits.tobytes()
        )

    def test_nonfinite_scale_or_alpha_candidate_is_operational_failure(self) -> None:
        matrix = np.zeros((1, FEATURE_WIDTH), dtype=np.float64)
        matrix[0, 0] = np.finfo(np.float64).max
        with self.assertRaisesRegex(
            ProofAncestryPairResidualError, "feature scale is non-finite"
        ):
            fit_offset_ridge(
                matrix,
                np.ones(1, dtype=np.float64),
                np.zeros(1, dtype=np.float64),
            )
        with self.assertRaisesRegex(
            ProofAncestryPairResidualError, "candidate logits are non-finite"
        ):
            select_nonnegative_alpha(
                np.full(1, np.finfo(np.float64).max, dtype=np.float64),
                np.ones(1, dtype=np.float64),
                np.zeros(1, dtype=np.float64),
            )


class SelectionGateTests(unittest.TestCase):
    @patch("o1_crypto_lab.proof_ancestry_pair_residual.next_operator_graph")
    @patch("o1_crypto_lab.proof_ancestry_pair_residual.verify_decision")
    def test_checked_graph_yields_non_authorizing_receipt(
        self,
        verify_mock: unittest.mock.Mock,
        graph_mock: unittest.mock.Mock,
    ) -> None:
        decision = {
            "decision_sha256": "a" * 64,
            "operator": {
                "operator_id": "proof_ancestry_pair_residual_v1",
                "operator_fingerprint": "b" * 64,
            },
            "source": {
                "capsule_manifest_sha256": "c" * 64,
                "result_sha256": "d" * 64,
            },
        }
        graph = {
            "schema": "o1-256-o1c22-next-operator-graph-v1",
            "selection": {
                "causal_sha256": "e" * 64,
                "fragment_sha256": "f" * 64,
                "native_generated_sha256": "0" * 64,
            },
            "operator_graph_sha256": "1" * 64,
        }
        verify_mock.return_value = decision
        graph_mock.return_value = graph
        receipt = verify_o1c23_selection(decision, graph)
        self.assertEqual(receipt.operator_graph_sha256, "1" * 64)
        self.assertFalse(receipt.describe()["attempt_reservation_authorized"])

    @patch("o1_crypto_lab.proof_ancestry_pair_residual.verify_decision")
    def test_wrong_selected_operator_is_rejected(
        self,
        verify_mock: unittest.mock.Mock,
    ) -> None:
        verify_mock.return_value = {"operator": {"operator_id": "another_operator"}}
        with self.assertRaisesRegex(ProofAncestryPairResidualError, "must select"):
            verify_o1c23_selection({}, {})


if __name__ == "__main__":
    unittest.main()
