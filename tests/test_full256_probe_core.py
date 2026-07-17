from __future__ import annotations

import dataclasses
import hashlib
import os
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np

from o1_crypto_lab.cadical_sensor import (
    KEY_BITS,
    MOTIF_DIMENSIONS,
    ProbeRecord,
    ProbeStreamHeader,
    ProofEvent,
    ProofPrefixSummary,
    SolverSnapshot,
)
from o1_crypto_lab.causal_bitfield import ARX_NEIGHBORS, CausalBitfieldPlan
from o1_crypto_lab.full256_probe_core import (
    READER_FEATURES,
    Full256ProbeCoreConfig,
    Full256ProbeCoreError,
    _reader_feature_panel,
    midrank_quantiles,
    run_full256_probe_core,
)
from o1_crypto_lab.living_inverse import canonical_sha256


ROOT = Path(__file__).resolve().parents[1]
CANONICAL_CAPSULE = (
    ROOT / "runs/20260717_054138_O1C-0011_full256-public-cnf-foundation-v1"
)
CANONICAL_CNF = CANONICAL_CAPSULE / "artifacts/cnf/public_attacker_instance.cnf"
CANONICAL_MAP = CANONICAL_CAPSULE / "artifacts/cnf/full256_chacha20.map.json"
CANONICAL_CNF_SHA256 = (
    "dde6a2791726e148c99064ec71f746fb8803e5d0f6b1996dd8b238c9c9b0a2a0"
)
CANONICAL_MAP_SHA256 = (
    "7f7438a6277086787ff2cf9b6d7468367b4edd82a65b9cfc4f9249f7ecda3318"
)
CANONICAL_STATE_SHA256 = (
    "aea9d4c0bd88d2c8480fb51b98d5524bc8c6fc319dd612c9dc345aa03035b664"
)


def _record(bit: int, assumed_value: int) -> ProbeRecord:
    literal = bit + 1 if assumed_value else -(bit + 1)
    return ProbeRecord(
        bit_index=bit,
        assumed_value=assumed_value,
        assumption_literal=literal,
        requested_conflict_horizon=96,
        status=0,
        reported_status=0,
        original_clause_count=7,
        last_original_id=7,
        reserved_original_ids=7,
        stats={
            "conflicts": 96 + bit % 3,
            "decisions": 100 + bit,
            "propagations": 1_000 + bit,
            "ticks": 10_000 + bit,
        },
        proof_counters={},
        conclusion={},
        assumption_clauses=(),
        resources={
            "solver_cpu_microseconds": 100 + bit + assumed_value,
            "solver_wall_microseconds": 200 + bit + assumed_value,
            "solver_peak_rss_bytes": 1_000_000 + bit,
        },
        final_overshoot_conflicts=bit % 3,
        events=(),
        deterministic_sha256=canonical_sha256(
            {"bit": bit, "assumed_value": assumed_value}
        ),
    )


def _header(first_bit: int, last_bit: int) -> ProbeStreamHeader:
    baseline = ProofEvent(
        clause_id=8,
        redundant=True,
        witness=0,
        conclusion_phase=False,
        snapshot=SolverSnapshot(1, 2, 3, 4),
        clause=(1, -2),
        antecedents=(1, 2),
    )
    return ProbeStreamHeader(
        cadical_version="3.0.0",
        cnf_path="synthetic.cnf",
        variables=42,
        original_clause_count=7,
        first_bit=first_bit,
        last_bit=last_bit,
        conflict_horizon=96,
        seed=0,
        branch_isolation="single-threaded-posix-fork-cow",
        baseline_snapshot=SolverSnapshot(1, 2, 3, 4),
        baseline_events=(baseline,),
    )


def _stream(first_bit: int, last_bit: int):
    yield _header(first_bit, last_bit)
    for bit in range(first_bit, last_bit + 1):
        yield _record(bit, 0)
        yield _record(bit, 1)


def _summary(record: ProbeRecord, _provenance, horizons, **_kwargs):
    result: dict[int, ProofPrefixSummary] = {}
    direction = -1.0 if record.assumed_value == 0 else 1.0
    for horizon_index, horizon in enumerate(horizons):
        motif = np.zeros(MOTIF_DIMENSIONS, dtype=np.float32)
        for family in range(4):
            motif[16 * family + (record.bit_index % 16)] = np.float32(
                direction * (horizon_index + 1) * (family + 1) / 1_000.0
            )
        key_touch = np.zeros(KEY_BITS, dtype=np.float32)
        for edge, neighbor in enumerate(ARX_NEIGHBORS[record.bit_index]):
            key_touch[int(neighbor)] = np.float32(
                direction * (horizon_index + 1) * (edge + 1) / 2_000.0
            )
        snapshot = SolverSnapshot(
            conflicts=horizon,
            decisions=(
                20_000
                + 17 * record.bit_index
                + 3 * horizon_index
                + record.assumed_value * (record.bit_index % 11 + 1)
            ),
            propagations=(
                200_000
                + 19 * record.bit_index
                + 5 * horizon_index
                + record.assumed_value * (record.bit_index % 13 + 1)
            ),
            ticks=(
                2_000_000
                + 23 * record.bit_index
                + 7 * horizon_index
                + record.assumed_value * (record.bit_index % 17 + 1)
            ),
        )
        summary_sha256 = canonical_sha256(
            {
                "bit": record.bit_index,
                "assumed_value": record.assumed_value,
                "horizon": horizon,
            }
        )
        result[horizon] = ProofPrefixSummary(
            horizon=horizon,
            snapshot=snapshot,
            exact_conflict_event_present=True,
            frontier_event_gap=0,
            derived_clause_count=10 + horizon_index,
            redundant_clause_count=5,
            derived_literal_count=100 + record.bit_index,
            antecedent_link_count=200 + record.bit_index,
            maximum_ancestry_depth=3,
            motif=motif,
            key_touch=key_touch,
            summary_sha256=summary_sha256,
        )
    return result


class ReaderFeatureTests(unittest.TestCase):
    def test_u3_arx24_m12_column_mapping_and_swap_are_exact(self) -> None:
        unary = np.arange(3 * KEY_BITS, dtype=np.float64).reshape(3, KEY_BITS)
        touches = np.zeros((3, KEY_BITS, KEY_BITS), dtype=np.float32)
        motif = np.zeros((3, KEY_BITS, MOTIF_DIMENSIONS), dtype=np.float32)
        for horizon_index in range(3):
            for bit in range(KEY_BITS):
                for edge, neighbor in enumerate(ARX_NEIGHBORS[bit]):
                    touches[horizon_index, bit, int(neighbor)] = np.float32(
                        1_000 * horizon_index + 10 * bit + edge
                    )
                motif[horizon_index, bit] = np.arange(
                    MOTIF_DIMENSIONS, dtype=np.float32
                ) + np.float32(100 * horizon_index + bit)

        direct = _reader_feature_panel(
            unary_scores=unary,
            key_touch_delta=touches,
            motif_delta=motif,
        )
        swapped = _reader_feature_panel(
            unary_scores=-unary,
            key_touch_delta=-touches,
            motif_delta=-motif,
        )

        self.assertEqual(direct.shape, (KEY_BITS, READER_FEATURES))
        self.assertEqual(direct.dtype, np.float32)
        np.testing.assert_array_equal(direct, -swapped)
        np.testing.assert_array_equal(direct[7, :3], unary[:, 7])
        for horizon_index in range(3):
            first = 3 + 8 * horizon_index
            expected_arx = touches[
                horizon_index,
                7,
                ARX_NEIGHBORS[7],
            ]
            np.testing.assert_array_equal(direct[7, first : first + 8], expected_arx)
            motif_first = 27 + 4 * horizon_index
            expected_motif = (
                motif[horizon_index, 7].reshape(4, 16).sum(axis=1, dtype=np.float32)
            )
            np.testing.assert_array_equal(
                direct[7, motif_first : motif_first + 4], expected_motif
            )

    def test_midrank_quantiles_are_tie_aware(self) -> None:
        values = np.array([[4.0, 1.0, 1.0], [3.0, 4.0, 2.0]])
        expected = np.array(
            [
                [5.0 / 6.0, 1.0 / 6.0, 1.0 / 6.0],
                [7.0 / 12.0, 5.0 / 6.0, 5.0 / 12.0],
            ]
        )

        np.testing.assert_array_equal(midrank_quantiles(values), expected)


class ProbeCoreSyntheticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.cnf = root / "public.cnf"
        self.semantic_map = root / "public.map.json"
        self.executable = root / "cadical-pair-sensor"
        self.cnf.write_text("p cnf 1 0\n", encoding="ascii")
        self.semantic_map.write_text("{}\n", encoding="utf-8")
        self.executable.write_bytes(b"synthetic executable")
        self.executable.chmod(0o700)
        self.provenance = SimpleNamespace(
            variable_count=42,
            clause_count=7,
            describe=lambda: {
                "variable_count": 42,
                "clause_count": 7,
                "cnf_sha256": hashlib.sha256(self.cnf.read_bytes()).hexdigest(),
                "map_sha256": hashlib.sha256(
                    self.semantic_map.read_bytes()
                ).hexdigest(),
            },
        )
        self.config = Full256ProbeCoreConfig(
            public_cnf=self.cnf,
            semantic_map=self.semantic_map,
            native_executable=self.executable,
            sentinel_bit=173,
            sentinel_reruns=1,
            expected_variable_count=42,
            expected_clause_count=7,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _run(self):
        with (
            patch(
                "o1_crypto_lab.full256_probe_core.ClauseProvenanceIndex.load",
                return_value=self.provenance,
            ),
            patch(
                "o1_crypto_lab.full256_probe_core.iter_native_probe_records",
                side_effect=lambda **request: _stream(
                    request["first_bit"], request["last_bit"]
                ),
            ),
            patch(
                "o1_crypto_lab.full256_probe_core.summarize_probe_prefixes",
                side_effect=_summary,
            ),
        ):
            return run_full256_probe_core(self.config)

    def test_complete_public_only_core_is_deterministic_and_bounded(self) -> None:
        first = self._run()
        replay = self._run()

        self.assertTrue(first.success_gate_passed, first.report["gates"])
        self.assertEqual(first.state.state_sha256, replay.state.state_sha256)
        self.assertEqual(first.reader_features_sha256, replay.reader_features_sha256)
        self.assertEqual(
            first.event_index["event_index_sha256"],
            replay.event_index["event_index_sha256"],
        )
        self.assertEqual(len(first.state.to_bytes()), 17_408)
        self.assertEqual(first.reader_features.shape, (256, 39))
        self.assertFalse(first.reader_features.flags.writeable)
        self.assertEqual(len(first.reader_features_bytes()), 256 * 39 * 4)
        self.assertEqual(
            first.report["reader_features"]["reader_features_sha256"],
            first.reader_features_sha256,
        )
        self.assertTrue(
            first.report["reader_features"]["polarity_swap_exactly_negates"]
        )
        self.assertEqual(first.report["probe_stream"]["paired_bit_count"], 256)
        self.assertEqual(first.report["probe_stream"]["branch_count"], 512)
        self.assertEqual(first.report["probe_stream"]["proof_frontier_count"], 1_536)
        self.assertEqual(first.report["resources"]["total_native_solver_branches"], 514)
        self.assertEqual(first.report["input_contract"]["accepted_labels"], 0)
        self.assertEqual(first.report["input_contract"]["accepted_diagnostics"], 0)
        self.assertFalse(first.report["input_contract"]["source_capsule_required"])

        np.testing.assert_array_equal(first.reader_features[:, :3], first.state.unary.T)
        bit = 9
        for horizon_index in range(3):
            expected_arx = np.asarray(
                [2.0 * (horizon_index + 1) * (edge + 1) / 2_000.0 for edge in range(8)],
                dtype=np.float32,
            )
            first_column = 3 + 8 * horizon_index
            np.testing.assert_allclose(
                first.reader_features[bit, first_column : first_column + 8],
                expected_arx,
                rtol=0.0,
                atol=1e-9,
            )

    def test_config_surface_contains_no_label_diagnostic_or_capsule_input(
        self,
    ) -> None:
        names = {row.name for row in dataclasses.fields(Full256ProbeCoreConfig)}

        self.assertFalse(
            any(
                forbidden in name
                for name in names
                for forbidden in ("label", "diagnostic", "capsule", "key")
            )
        )
        for sentinel_reruns in (-1, 2):
            with self.subTest(sentinel_reruns=sentinel_reruns):
                with self.assertRaisesRegex(Full256ProbeCoreError, "zero or one"):
                    dataclasses.replace(self.config, sentinel_reruns=sentinel_reruns)

    def test_incomplete_stream_is_rejected_before_state_freeze(self) -> None:
        def incomplete_stream(**_request):
            yield _header(0, 255)
            yield _record(0, 0)
            yield _record(0, 1)

        with (
            patch(
                "o1_crypto_lab.full256_probe_core.ClauseProvenanceIndex.load",
                return_value=self.provenance,
            ),
            patch(
                "o1_crypto_lab.full256_probe_core.iter_native_probe_records",
                side_effect=incomplete_stream,
            ),
            patch(
                "o1_crypto_lab.full256_probe_core.summarize_probe_prefixes",
                side_effect=_summary,
            ),
        ):
            with self.assertRaisesRegex(
                Full256ProbeCoreError, "lacks 256 paired coordinates"
            ):
                run_full256_probe_core(
                    dataclasses.replace(self.config, sentinel_reruns=0)
                )


NATIVE_EXECUTABLE_VALUE = os.environ.get("O1C_FULL256_PROBE_CORE_EXECUTABLE", "")
NATIVE_EXECUTABLE = Path(NATIVE_EXECUTABLE_VALUE) if NATIVE_EXECUTABLE_VALUE else None
HEAVY_INTEGRATION_ENABLED = bool(
    os.environ.get("O1C_RUN_FULL256_PROBE_CORE_INTEGRATION") == "1"
    and NATIVE_EXECUTABLE is not None
    and NATIVE_EXECUTABLE.is_file()
    and CANONICAL_CNF.is_file()
    and CANONICAL_MAP.is_file()
)


@unittest.skipUnless(
    HEAVY_INTEGRATION_ENABLED,
    "set O1C_RUN_FULL256_PROBE_CORE_INTEGRATION=1 and executable path",
)
class CanonicalProbeCoreIntegrationTests(unittest.TestCase):
    def test_canonical_o1c0012_input_reproduces_frozen_state(self) -> None:
        if NATIVE_EXECUTABLE is None:  # pragma: no cover - skip guard narrows it
            raise AssertionError("native executable path is absent")
        result = run_full256_probe_core(
            Full256ProbeCoreConfig(
                public_cnf=CANONICAL_CNF,
                semantic_map=CANONICAL_MAP,
                native_executable=NATIVE_EXECUTABLE,
                state_plan=CausalBitfieldPlan(),
                seed=0,
                timeout_seconds=180.0,
                sentinel_reruns=0,
                expected_public_cnf_sha256=CANONICAL_CNF_SHA256,
                expected_semantic_map_sha256=CANONICAL_MAP_SHA256,
                expected_variable_count=32_128,
                expected_clause_count=188_010,
            )
        )

        self.assertEqual(result.state.state_sha256, CANONICAL_STATE_SHA256)
        self.assertTrue(result.success_gate_passed, result.report["gates"])
        probe_stream = result.report["probe_stream"]
        self.assertIsInstance(probe_stream, Mapping)
        if not isinstance(probe_stream, Mapping):  # pragma: no cover
            raise AssertionError("probe stream report is not a mapping")
        self.assertEqual(probe_stream["branch_count"], 512)
        self.assertEqual(probe_stream["proof_frontier_count"], 1_536)


if __name__ == "__main__":
    unittest.main()
