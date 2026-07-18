from __future__ import annotations

import json
import unittest

import numpy as np

from o1_crypto_lab.a296_shallow_byte_cube import (
    A296ByteCubeError,
    candidate_order,
    key_byte_reader_mapping,
    parse_a296_native_cube,
    revealed_byte_rank,
)
from o1_crypto_lab.full256_cnf import KEY_FIRST_VARIABLE


class A296ShallowByteCubeTests(unittest.TestCase):
    def test_mapping_places_selected_byte_in_legacy_assumption_positions(self) -> None:
        mapping = key_byte_reader_mapping(7)
        selected = tuple(KEY_FIRST_VARIABLE + bit for bit in range(56, 64))
        self.assertEqual(mapping[12:], selected)
        self.assertEqual(len(mapping), len(set(mapping)))
        self.assertTrue(set(mapping[:12]).isdisjoint(mapping[12:]))

    def test_candidate_order_and_reveal_rank_are_descending_and_stable(self) -> None:
        scores = np.zeros(256, dtype=np.float64)
        scores[17] = 2.0
        scores[3] = 1.0
        order = candidate_order(scores)
        self.assertEqual(order[:2], [17, 3])
        self.assertEqual(revealed_byte_rank(scores, 17), 1)
        self.assertEqual(revealed_byte_rank(scores, 3), 2)
        self.assertEqual(order[2:6], [0, 1, 2, 4])

    def test_parser_rejects_incomplete_transcript(self) -> None:
        summary = {
            "cells": 256,
            "stages_emitted": 1024,
            "unknown_cells": 256,
            "sat_cells": 0,
            "unsat_cells": 0,
            "conflict_horizons": [1, 2, 4, 8],
            "learned_clause_maximum_size": 64,
            "bounded_variable_addition_enabled": False,
        }
        with self.assertRaisesRegex(A296ByteCubeError, "complete-cube"):
            parse_a296_native_cube("FRESH_CI_SUMMARY " + json.dumps(summary))


if __name__ == "__main__":
    unittest.main()
