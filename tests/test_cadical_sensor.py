from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from o1_crypto_lab.cadical_sensor import (
    PROBE_SCHEMA,
    CaDiCaLSensorError,
    ClauseProvenanceIndex,
    NativeSensorBuild,
    ProbeRecord,
    ProbeStreamHeader,
    build_native_sensor,
    iter_native_probe_records,
    pair_commitment,
    paired_records,
    sha256_file,
    summarize_probe_prefixes,
)


ROOT = Path(__file__).resolve().parents[1]
SOURCE_CAPSULE = (
    ROOT / "runs" / "20260717_054138_O1C-0011_full256-public-cnf-foundation-v1"
)
PUBLIC_CNF = SOURCE_CAPSULE / "artifacts/cnf/public_attacker_instance.cnf"
SEMANTIC_MAP = SOURCE_CAPSULE / "artifacts/cnf/full256_chacha20.map.json"
NATIVE_SOURCE = ROOT / "native/cadical_pair_sensor.cpp"
TRACER_HEADER = ROOT / "native/cadical_tracer_3_0_0.hpp"
CADICAL_INCLUDE = Path("/opt/homebrew/opt/cadical/include")
CADICAL_LIBRARY = Path("/opt/homebrew/opt/cadical/lib/libcadical.a")
CADICAL_HEADER_SHA256 = (
    "b7111690c61935b9c096d3701be59b3c3d26c555eab8e070f19eb2a97dc5d38c"
)
CADICAL_LIBRARY_SHA256 = (
    "44cae3728485b4fd5736ce7cb986021236652daeda9cca227a2c4ac17d3a8a7f"
)
PUBLIC_CNF_SHA256 = "dde6a2791726e148c99064ec71f746fb8803e5d0f6b1996dd8b238c9c9b0a2a0"
SEMANTIC_MAP_SHA256 = "7f7438a6277086787ff2cf9b6d7468367b4edd82a65b9cfc4f9249f7ecda3318"


def _native_dependencies_available() -> bool:
    return bool(
        shutil.which("c++")
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
    )


@unittest.skipUnless(
    _native_dependencies_available(),
    "c++ and the pinned CaDiCaL 3.0.0 development files are required",
)
class NativeCaDiCaLSensorTests(unittest.TestCase):
    temporary: tempfile.TemporaryDirectory[str]
    build: NativeSensorBuild
    header: ProbeStreamHeader
    zero: ProbeRecord
    one: ProbeRecord
    replay_header: ProbeStreamHeader
    replay_zero: ProbeRecord
    replay_one: ProbeRecord
    gap_zero: ProbeRecord
    gap_one: ProbeRecord
    provenance: ClauseProvenanceIndex

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.temporary = tempfile.TemporaryDirectory()
        executable = Path(cls.temporary.name) / "cadical-pair-sensor"
        cls.build = build_native_sensor(
            source=NATIVE_SOURCE,
            tracer_header=TRACER_HEADER,
            cadical_include=CADICAL_INCLUDE,
            cadical_library=CADICAL_LIBRARY,
            output=executable,
            expected_cadical_header_sha256=CADICAL_HEADER_SHA256,
            expected_cadical_library_sha256=CADICAL_LIBRARY_SHA256,
        )
        cls.provenance = ClauseProvenanceIndex.load(PUBLIC_CNF, SEMANTIC_MAP)
        cls.header, cls.zero, cls.one = cls._run_pair(173)
        (
            cls.replay_header,
            cls.replay_zero,
            cls.replay_one,
        ) = cls._run_pair(173)
        _, cls.gap_zero, cls.gap_one = cls._run_pair(6)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()
        super().tearDownClass()

    @classmethod
    def _run_pair(
        cls,
        bit: int,
    ) -> tuple[ProbeStreamHeader, ProbeRecord, ProbeRecord]:
        records = iter_native_probe_records(
            executable=cls.build.executable,
            cnf_path=PUBLIC_CNF,
            first_bit=bit,
            last_bit=bit,
            conflict_limit=96,
            seed=0,
            timeout_seconds=60.0,
        )
        header, pairs = paired_records(records)
        pair_rows = list(pairs)
        if len(pair_rows) != 1:
            raise AssertionError("bit-173 probe did not emit exactly one pair")
        zero, one = pair_rows[0]
        return header, zero, one

    def test_native_build_is_pinned_and_executable(self) -> None:
        self.assertTrue(self.build.executable.is_file())
        self.assertEqual(self.build.cadical_header_sha256, CADICAL_HEADER_SHA256)
        self.assertEqual(self.build.cadical_library_sha256, CADICAL_LIBRARY_SHA256)
        self.assertEqual(sha256_file(PUBLIC_CNF), PUBLIC_CNF_SHA256)
        self.assertEqual(sha256_file(SEMANTIC_MAP), SEMANTIC_MAP_SHA256)
        self.assertEqual(self.provenance.variable_count, 32_128)
        self.assertEqual(self.provenance.clause_count, 188_010)

    def test_bit_173_pair_has_exact_prefixes_and_billed_overshoot(self) -> None:
        self.assertEqual(len(self.header.baseline_events), 667)
        self.assertEqual(self.header.first_bit, 173)
        self.assertEqual(self.header.last_bit, 173)
        self.assertEqual(self.header.conflict_horizon, 96)
        self.assertEqual(self.header.original_clause_count, 188_010)

        for assumed_value, record in enumerate((self.zero, self.one)):
            with self.subTest(assumed_value=assumed_value):
                self.assertEqual(record.bit_index, 173)
                self.assertEqual(record.assumed_value, assumed_value)
                self.assertEqual(record.status, 0)
                self.assertLessEqual(
                    max(event.snapshot.conflicts for event in record.events),
                    96,
                )
                self.assertEqual(
                    record.final_overshoot_conflicts,
                    record.stats["conflicts"] - 96,
                )
                self.assertGreaterEqual(record.final_overshoot_conflicts, 0)

                prefixes = summarize_probe_prefixes(
                    record,
                    self.provenance,
                    (64, 65, 96),
                    baseline_events=self.header.baseline_events,
                )
                self.assertEqual(set(prefixes), {64, 65, 96})
                for horizon, prefix in prefixes.items():
                    self.assertEqual(prefix.horizon, horizon)
                    self.assertEqual(prefix.snapshot.conflicts, horizon)
                    self.assertGreater(prefix.derived_clause_count, 0)
                    self.assertGreater(float(prefix.motif.sum()), 0.0)
                    self.assertGreater(float(prefix.key_touch.sum()), 0.0)

        self.assertEqual(
            (
                self.zero.final_overshoot_conflicts,
                self.one.final_overshoot_conflicts,
            ),
            (1, 0),
        )

    def test_bit_173_pair_replay_is_deterministic(self) -> None:
        self.assertEqual(self.header, self.replay_header)
        self.assertEqual(
            self.zero.deterministic_sha256,
            self.replay_zero.deterministic_sha256,
        )
        self.assertEqual(
            self.one.deterministic_sha256,
            self.replay_one.deterministic_sha256,
        )
        self.assertEqual(
            pair_commitment(self.zero, self.one),
            pair_commitment(self.replay_zero, self.replay_one),
        )
        self.assertEqual(self.zero.events, self.replay_zero.events)
        self.assertEqual(self.one.events, self.replay_one.events)

    def test_closed_prefix_retains_bit_6_without_fabricating_exact_event(self) -> None:
        prefixes = summarize_probe_prefixes(
            self.gap_zero,
            self.provenance,
            (64, 65, 96),
            baseline_events=self.header.baseline_events,
        )
        prefix = prefixes[96]
        self.assertFalse(prefix.exact_conflict_event_present)
        self.assertEqual(prefix.snapshot.conflicts, 93)
        self.assertEqual(prefix.frontier_event_gap, 3)
        self.assertGreater(prefix.derived_clause_count, 0)


class ProbeRecordParserTests(unittest.TestCase):
    def test_terminal_record_retains_conclusion_and_assumption_clause(self) -> None:
        record = ProbeRecord.from_mapping(
            {
                "schema": PROBE_SCHEMA,
                "bit_index": 0,
                "assumed_value": 1,
                "assumption_literal": 1,
                "requested_conflict_horizon": 96,
                "status": 20,
                "reported_status": 20,
                "reported_status_clause_id": 4,
                "solve_query_seen": True,
                "assumptions": [1],
                "original_clause_count": 3,
                "original_literal_count": 5,
                "last_original_id": 3,
                "reserved_original_ids": 3,
                "stats": {
                    "conflicts": 4,
                    "decisions": 5,
                    "propagations": 6,
                    "ticks": 7,
                },
                "final_overshoot_conflicts": 0,
                "proof_counters": {
                    "deleted": 0,
                    "demoted": 0,
                    "weakened": 0,
                    "strengthened": 0,
                    "equivalences": 0,
                    "assumption_resets": 0,
                },
                "conclusion": {
                    "type": 1,
                    "clause_ids": [4],
                    "model_size": -1,
                    "trail_size": -1,
                },
                "assumption_clauses": [
                    {"id": 4, "clause": [-1], "antecedents": [2, 3]}
                ],
                "resources": {
                    "solver_cpu_microseconds": 1,
                    "solver_wall_microseconds": 2,
                    "solver_peak_rss_bytes": 3,
                },
                "events": [],
            }
        )
        self.assertEqual(record.status, 20)
        self.assertEqual(record.conclusion["clause_ids"], [4])
        self.assertEqual(record.assumption_clauses[0].clause, (-1,))
        self.assertEqual(record.assumption_clauses[0].antecedents, (2, 3))
        self.assertEqual(record.events, ())

    def test_unknown_terminal_without_frontier_events_is_rejected(self) -> None:
        malformed = {
            "schema": PROBE_SCHEMA,
            "bit_index": 0,
            "assumed_value": 1,
            "assumption_literal": 1,
            "requested_conflict_horizon": 96,
            "status": 0,
            "reported_status": 0,
            "reported_status_clause_id": 0,
            "solve_query_seen": True,
            "assumptions": [1],
            "original_clause_count": 3,
            "original_literal_count": 5,
            "last_original_id": 3,
            "reserved_original_ids": 3,
            "stats": {
                "conflicts": 96,
                "decisions": 5,
                "propagations": 6,
                "ticks": 7,
            },
            "final_overshoot_conflicts": 0,
            "proof_counters": {
                "deleted": 0,
                "demoted": 0,
                "weakened": 0,
                "strengthened": 0,
                "equivalences": 0,
                "assumption_resets": 0,
            },
            "conclusion": {
                "type": 0,
                "clause_ids": [],
                "model_size": -1,
                "trail_size": 0,
            },
            "assumption_clauses": [],
            "resources": {
                "solver_cpu_microseconds": 1,
                "solver_wall_microseconds": 2,
                "solver_peak_rss_bytes": 3,
            },
            "events": [],
        }
        with self.assertRaisesRegex(
            CaDiCaLSensorError, "UNKNOWN probe must contain frontier events"
        ):
            ProbeRecord.from_mapping(malformed)


if __name__ == "__main__":
    unittest.main()
