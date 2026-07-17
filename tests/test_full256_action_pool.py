from __future__ import annotations

import hashlib
import json
import math
import unittest

import numpy as np

from o1_crypto_lab.cadical_sensor import (
    KEY_BITS,
    MOTIF_DIMENSIONS,
    ProofPrefixSummary,
    SolverSnapshot,
)
from o1_crypto_lab.full256_action_pool import (
    ACTION_POOL_MAGIC,
    ACTION_POOL_SCHEMA,
    BRANCH_FEATURES,
    Full256ActionPool,
    Full256ActionPoolError,
    branch_feature_vector,
    deserialize_action_pool,
    serialize_action_pool,
)


HORIZONS = (64, 96, 65)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _summary() -> ProofPrefixSummary:
    motif = np.linspace(-2.0, 2.0, MOTIF_DIMENSIONS, dtype=np.float32)
    key_touch = np.linspace(0.0, 1.0, KEY_BITS, dtype=np.float32)
    return ProofPrefixSummary(
        horizon=65,
        snapshot=SolverSnapshot(
            conflicts=65,
            decisions=7,
            propagations=101,
            ticks=1_003,
        ),
        exact_conflict_event_present=True,
        frontier_event_gap=2,
        derived_clause_count=11,
        redundant_clause_count=5,
        derived_literal_count=37,
        antecedent_link_count=41,
        maximum_ancestry_depth=4,
        motif=motif,
        key_touch=key_touch,
        summary_sha256=_sha("summary"),
    )


def _pool() -> Full256ActionPool:
    shape = (len(HORIZONS), KEY_BITS, 2, BRANCH_FEATURES)
    linear = np.arange(math.prod(shape), dtype=np.uint32).reshape(shape)
    features = ((linear % 2_003).astype(np.float32) - 1_001.0) / 257.0
    resources = np.arange(KEY_BITS * 2 * 3, dtype=np.uint64).reshape(KEY_BITS, 2, 3)
    resources += np.uint64(1)
    return Full256ActionPool(
        horizons=HORIZONS,
        branch_features=features,
        final_resources=resources,
        pair_sha256=tuple(_sha(f"pair-{index}") for index in range(KEY_BITS)),
        source_stream_sha256=_sha("source-stream"),
    )


class BranchFeatureMappingTests(unittest.TestCase):
    def test_exact_330_wide_mapping_preserves_motif_and_all_key_touches(self):
        summary = _summary()
        vector = branch_feature_vector(summary)

        self.assertEqual(vector.shape, (330,))
        self.assertEqual(vector.dtype, np.float32)
        self.assertFalse(vector.flags.writeable)
        expected_counts = (7, 101, 1_003, 11, 5, 37, 41, 4, 2)
        np.testing.assert_array_equal(
            vector[:9],
            np.log1p(np.asarray(expected_counts, dtype=np.float64)).astype(np.float32),
        )
        self.assertEqual(vector[9], np.float32(1.0))
        np.testing.assert_array_equal(vector[10:74], summary.motif)
        np.testing.assert_array_equal(vector[74:330], summary.key_touch)

    def test_mapping_rejects_wrong_vector_shape_and_non_finite_input(self):
        summary = _summary()
        wrong_shape = ProofPrefixSummary(
            **{
                **summary.__dict__,
                "motif": np.zeros(MOTIF_DIMENSIONS - 1, dtype=np.float32),
            }
        )
        with self.assertRaisesRegex(Full256ActionPoolError, "motif"):
            branch_feature_vector(wrong_shape)

        non_finite = summary.key_touch.copy()
        non_finite[19] = np.inf
        bad_touch = ProofPrefixSummary(**{**summary.__dict__, "key_touch": non_finite})
        with self.assertRaisesRegex(Full256ActionPoolError, "key_touch"):
            branch_feature_vector(bad_touch)


class Full256ActionPoolTests(unittest.TestCase):
    def test_pool_owns_immutable_exact_shape_arrays(self):
        shape = (len(HORIZONS), KEY_BITS, 2, BRANCH_FEATURES)
        features = np.zeros(shape, dtype=np.float32)
        resources = np.zeros((KEY_BITS, 2, 3), dtype=np.uint64)
        pool = Full256ActionPool(
            horizons=HORIZONS,
            branch_features=features,
            final_resources=resources,
            pair_sha256=tuple(_sha(f"pair-{index}") for index in range(KEY_BITS)),
            source_stream_sha256=_sha("stream"),
        )
        features[0, 0, 0, 0] = 9.0
        resources[0, 0, 0] = 9

        self.assertEqual(pool.branch_features[0, 0, 0, 0], 0.0)
        self.assertEqual(pool.final_resources[0, 0, 0], 0)
        self.assertFalse(pool.branch_features.flags.writeable)
        self.assertFalse(pool.final_resources.flags.writeable)
        with self.assertRaises(ValueError):
            pool.branch_features.setflags(write=True)
        with self.assertRaises(ValueError):
            pool.final_resources.setflags(write=True)
        self.assertEqual(pool.branch_features.shape, (3, 256, 2, 330))
        self.assertEqual(pool.raw_feature_bytes, 3 * 256 * 2 * 330 * 4)
        self.assertEqual(pool.resource_bytes, 256 * 2 * 3 * 8)

    def test_signed_common_and_polarity_swap_are_exact(self):
        pool = _pool()
        expected_signed = (
            pool.branch_features[:, :, 1, :] - pool.branch_features[:, :, 0, :]
        )
        expected_common = np.float32(0.5) * (
            pool.branch_features[:, :, 1, :] + pool.branch_features[:, :, 0, :]
        )

        np.testing.assert_array_equal(pool.signed_field(), expected_signed)
        np.testing.assert_array_equal(pool.common_field(), expected_common)
        self.assertFalse(pool.signed_field().flags.writeable)
        self.assertFalse(pool.common_field().flags.writeable)
        swapped = pool.polarity_swapped()
        np.testing.assert_array_equal(swapped.signed_field(), -pool.signed_field())
        np.testing.assert_array_equal(swapped.common_field(), pool.common_field())
        np.testing.assert_array_equal(
            swapped.final_resources, pool.final_resources[:, ::-1, :]
        )
        self.assertEqual(swapped.pair_sha256, pool.pair_sha256)
        self.assertTrue(pool.swap_control()["passed"])

    def test_conflict_accounting_separates_prefix_actions_from_generation(self):
        pool = _pool()

        self.assertEqual(pool.requested_conflicts_for(64), 64 * 512)
        self.assertEqual(pool.requested_conflicts_for(96, (1, 7, 173)), 96 * 6)
        self.assertEqual(
            pool.all_prefix_requested_conflicts,
            (64 + 96 + 65) * 512,
        )
        self.assertEqual(
            pool.maximum_horizon_sweep_requested_conflicts,
            96 * 512,
        )
        with self.assertRaisesRegex(Full256ActionPoolError, "absent"):
            pool.requested_conflicts_for(72)
        with self.assertRaisesRegex(Full256ActionPoolError, "unique"):
            pool.requested_conflicts_for(64, (3, 3))

    def test_canonical_binary_roundtrip_hash_and_inventory_are_exact(self):
        pool = _pool()
        payload = serialize_action_pool(pool)
        restored = deserialize_action_pool(payload)

        self.assertTrue(payload.startswith(ACTION_POOL_MAGIC))
        self.assertEqual(serialize_action_pool(restored), payload)
        self.assertEqual(restored.action_pool_sha256, pool.action_pool_sha256)
        self.assertEqual(restored.horizons, pool.horizons)
        self.assertEqual(restored.pair_sha256, pool.pair_sha256)
        np.testing.assert_array_equal(restored.branch_features, pool.branch_features)
        np.testing.assert_array_equal(restored.final_resources, pool.final_resources)
        inventory = pool.byte_inventory()
        self.assertEqual(inventory["serialized_bytes"], len(payload))
        self.assertEqual(
            inventory["payload_bytes"],
            pool.raw_feature_bytes + pool.resource_bytes,
        )
        self.assertEqual(
            [row["name"] for row in inventory["arrays"]],
            ["branch_features", "final_resources"],
        )

        damaged = bytearray(payload)
        damaged[-1] ^= 1
        with self.assertRaisesRegex(Full256ActionPoolError, "payload"):
            deserialize_action_pool(bytes(damaged))

    def test_schema_and_binary_header_contain_no_outcome_field(self):
        pool = _pool()
        description = pool.describe()
        self.assertEqual(description["schema"], ACTION_POOL_SCHEMA)
        encoded_description = json.dumps(description, sort_keys=True).lower()
        self.assertNotIn("label", encoded_description)
        self.assertNotIn("key_material", encoded_description)

        payload = serialize_action_pool(pool)
        cursor = len(ACTION_POOL_MAGIC)
        header_length = int.from_bytes(payload[cursor : cursor + 8], "big")
        cursor += 8
        header = payload[cursor : cursor + header_length].decode("ascii").lower()
        self.assertNotIn("label", header)
        self.assertNotIn("key_material", header)

    def test_validation_rejects_dtype_shape_hash_and_horizon_errors(self):
        pool = _pool()
        with self.assertRaisesRegex(Full256ActionPoolError, "float32"):
            Full256ActionPool(
                horizons=pool.horizons,
                branch_features=pool.branch_features.astype(np.float64),
                final_resources=pool.final_resources,
                pair_sha256=pool.pair_sha256,
                source_stream_sha256=pool.source_stream_sha256,
            )
        with self.assertRaisesRegex(Full256ActionPoolError, "uint64"):
            Full256ActionPool(
                horizons=pool.horizons,
                branch_features=pool.branch_features,
                final_resources=pool.final_resources.astype(np.int64),
                pair_sha256=pool.pair_sha256,
                source_stream_sha256=pool.source_stream_sha256,
            )
        with self.assertRaisesRegex(Full256ActionPoolError, "unique"):
            Full256ActionPool(
                horizons=(64, 64, 96),
                branch_features=pool.branch_features,
                final_resources=pool.final_resources,
                pair_sha256=pool.pair_sha256,
                source_stream_sha256=pool.source_stream_sha256,
            )
        with self.assertRaisesRegex(Full256ActionPoolError, "256 hashes"):
            Full256ActionPool(
                horizons=pool.horizons,
                branch_features=pool.branch_features,
                final_resources=pool.final_resources,
                pair_sha256=pool.pair_sha256[:-1],
                source_stream_sha256=pool.source_stream_sha256,
            )
        bad_hashes = list(pool.pair_sha256)
        bad_hashes[4] = "not-a-hash"
        with self.assertRaisesRegex(Full256ActionPoolError, r"pair_sha256\[4\]"):
            Full256ActionPool(
                horizons=pool.horizons,
                branch_features=pool.branch_features,
                final_resources=pool.final_resources,
                pair_sha256=tuple(bad_hashes),
                source_stream_sha256=pool.source_stream_sha256,
            )


if __name__ == "__main__":
    unittest.main()
