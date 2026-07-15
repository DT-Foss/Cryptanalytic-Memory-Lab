import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from o1_crypto_lab.artifacts import ReadOnlyArtifactSource
from o1_crypto_lab.direct12 import (
    A268_PREFLIGHT,
    A271_SIGNED_CHANNEL,
    A272_PROTOCOL,
    A348_RESULT,
    A349_ORDER,
    CHANNEL_NAMES,
    DENIED_MEMBER_FRAGMENTS,
    FINALIZED_CAPSULE,
    HORIZONS,
    RAW_MATRIX_SCHEMA_SHA256,
    READER_CONTRACT_MEMBERS,
    DatasetRole,
    Direct12Adapter,
    Direct12Error,
    Direct12LabelRegistry,
    finalized_direct12_adapter,
)


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _write_source(parent: Path, members: dict[str, bytes]) -> ReadOnlyArtifactSource:
    root = parent / "source_snapshot"
    root.mkdir()
    for member, value in members.items():
        path = root / member
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
    manifest = parent / "copied-ledger.sha256"
    manifest.write_text(
        "".join(
            f"{hashlib.sha256(value).hexdigest()}  {member}\n"
            for member, value in sorted(members.items())
        ),
        encoding="utf-8",
    )
    return ReadOnlyArtifactSource(root, manifest)


def _measurement(
    *,
    attempt_id: str = "A349",
    schema: str = "chacha20-round20-w46-direct12-prospective-a345-validation-a349-slice-v1",
    low4: int = 0,
    model_bit_at: int | None = None,
) -> dict[str, object]:
    cnf_sha = "c" * 64
    prefixes = [f"{index:08b}" for index in range(256)]
    variables = tuple(range(101, 109))
    cells = []
    stages = []
    for cell_index, prefix in enumerate(prefixes):
        assumptions = [
            variable if bit == "1" else -variable
            for variable, bit in zip(variables, prefix, strict=True)
        ]
        cells.append(
            {
                "cell_index": cell_index,
                "prefix8": prefix,
                "assumptions": assumptions,
                "fresh_solver_instance": True,
                "final_status": "unknown",
                "stages_run": 4,
                "terminal_stage_index": None,
                "metric_names": list(("conflicts", "decisions", "search_propagations")),
            }
        )
        for stage_index, horizon in enumerate(HORIZONS):
            stages.append(
                {
                    "cell_index": cell_index,
                    "prefix8": prefix,
                    "assumptions": assumptions,
                    "stage_index": stage_index,
                    "horizon": horizon,
                    "status": "unknown",
                    "terminal": False,
                    "watchdog_fired": False,
                    "returncode": 0,
                    "conflict_budget_exhausted": True,
                    "model_bits_bit0_through_bit19": (
                        [1] if model_bit_at == cell_index and stage_index == 0 else []
                    ),
                    "failed_assumptions": [],
                    "metric_names": [
                        "conflicts",
                        "decisions",
                        "search_propagations",
                    ],
                    "metrics_stage_delta": [horizon, cell_index + horizon, horizon * 10],
                    "active_variables_delta": -cell_index,
                    "irredundant_clauses_delta": -(cell_index + 1),
                    "redundant_clauses_delta": stage_index,
                    "learned_clause_accepted_stage": 2,
                    "learned_clause_offered_stage": 3,
                    "learned_clause_rejected_large_stage": 1,
                    "learned_literal_count_stage": 5,
                    "learned_clause_lengths_stage": [2, 3],
                }
            )
    run = {
        "all_watchdogs_clear": True,
        "base_snapshot_identical_verified": True,
        "fresh_solver_per_candidate_verified": True,
        "learned_clause_identity_complete": True,
        "bounded_variable_addition_enabled": False,
        "conflict_horizons": list(HORIZONS),
        "learned_clause_canonical_order": "absolute_variable_then_signed_literal",
        "learned_clause_maximum_size": 64,
        "cnf_sha256": cnf_sha,
        "order": prefixes,
        "cells": cells,
        "stages": stages,
        "summary": {
            "cells": 256,
            "stages_emitted": 1024,
            "fresh_solver_instances": 256,
            "configured_stages_per_nonterminal_cell": 4,
            "unknown_cells": 256,
            "sat_cells": 0,
            "unsat_cells": 0,
            "base_copy_source_solved": False,
            "base_snapshot_identical": True,
            "bounded_variable_addition_enabled": False,
            "conflict_horizons": list(HORIZONS),
            "metric_names": ["conflicts", "decisions", "search_propagations"],
            "learned_clause_maximum_size": 64,
        },
    }
    if attempt_id == "A272":
        return {
            "schema": schema,
            "attempt_id": attempt_id,
            "label": "a272_channel_p00_fit_s00",
            "label_used_only_after_fixed_measurement": True,
            "complete_candidate_cover": True,
            "cnf_instantiation": {"sha256": cnf_sha},
            "run": run,
        }
    return {
        "schema": schema,
        "attempt_id": attempt_id,
        "low4": low4,
        "target_label_available_to_measurement": False,
        "label_used_for_feature_construction_or_scoring": False,
        "complete_candidate_cover": True,
        "cnf_sha256": cnf_sha,
        "run": run,
    }


@unittest.skipUnless(shutil.which("zstd"), "zstd is required")
class Direct12FixtureTests(unittest.TestCase):
    def test_extracts_exact_typed_13_by_4_raw_matrix(self):
        cells, cnf_sha = Direct12Adapter._validate_run_and_extract(
            _measurement(),
            attempt_id="A349",
            schema_key="A349_MEASUREMENT",
            slice_id="slice_00",
            low4=0,
        )
        self.assertEqual(cnf_sha, "c" * 64)
        self.assertEqual(len(cells), 256)
        self.assertEqual(len(cells[17].values), 13)
        self.assertTrue(all(len(channel) == 4 for channel in cells[17].values))
        self.assertEqual(cells[17].values[0], (1.0, 2.0, 4.0, 8.0))
        self.assertEqual(cells[17].values[10], (2.5, 2.5, 2.5, 2.5))
        self.assertEqual(cells[17].values[11], (0.5, 0.5, 0.5, 0.5))
        self.assertEqual(cells[17].values[12], (3.0, 3.0, 3.0, 3.0))
        self.assertEqual(len(CHANNEL_NAMES), 13)
        self.assertEqual(len(RAW_MATRIX_SCHEMA_SHA256), 64)

    def test_rejects_noncanonical_stage_order_and_model_bits(self):
        reordered = _measurement()
        run = reordered["run"]
        assert isinstance(run, dict)
        stages = run["stages"]
        assert isinstance(stages, list)
        stages[0], stages[1] = stages[1], stages[0]
        with self.assertRaisesRegex(Direct12Error, "canonical cell/horizon"):
            Direct12Adapter._validate_run_and_extract(
                reordered,
                attempt_id="A349",
                schema_key="A349_MEASUREMENT",
                slice_id="slice_00",
                low4=0,
            )
        with self.assertRaisesRegex(Direct12Error, "model/watchdog"):
            Direct12Adapter._validate_run_and_extract(
                _measurement(model_bit_at=7),
                attempt_id="A349",
                schema_key="A349_MEASUREMENT",
                slice_id="slice_00",
                low4=0,
            )

    def test_verified_compressed_slice_and_hard_decode_cap(self):
        measurement = _measurement()
        raw = _json_bytes(measurement)
        compressed = subprocess.run(
            [shutil.which("zstd"), "-q", "-c"],
            input=raw,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout
        member = "research/results/v1/fixture/slice_00.json.zst"
        ledger = {
            "path": member,
            "compressed_bytes": len(compressed),
            "compressed_sha256": hashlib.sha256(compressed).hexdigest(),
            "raw_bytes": len(raw),
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "resumed": False,
            "low4": 0,
        }
        with tempfile.TemporaryDirectory() as temporary:
            source = _write_source(Path(temporary), {member: compressed})
            adapter = Direct12Adapter(source)
            item = adapter._slice(
                role=DatasetRole.SEALED_DEPLOYMENT,
                attempt_id="A349",
                schema_key="A349_MEASUREMENT",
                slice_id="slice_00",
                low4=0,
                ledger=ledger,
                metadata_member="fixture-order.json",
                metadata_sha256="f" * 64,
            )
            self.assertEqual(item.provenance.measurement_raw_bytes, len(raw))
            self.assertEqual(item.provenance.measurement_raw_sha256, hashlib.sha256(raw).hexdigest())
            self.assertEqual(item.global_cell_index(0xAB), 0xAB0)
            capped = dict(ledger)
            capped["raw_bytes"] = len(raw) - 1
            with self.assertRaisesRegex(Direct12Error, "byte cap"):
                adapter._decode_measurement(capped)

    def test_exact_denylist_and_reader_contract_allowlist(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = _write_source(Path(temporary), {"safe.json": b"{}\n"})
            adapter = Direct12Adapter(source)
            for fragment in DENIED_MEMBER_FRAGMENTS:
                with self.assertRaisesRegex(Direct12Error, "denied"):
                    adapter._source_member(f"research/results/v1/{fragment}")
            with self.assertRaisesRegex(Direct12Error, "allowlist"):
                adapter.read_contract_json("safe.json")
            self.assertEqual(len(READER_CONTRACT_MEMBERS), 4)

    def test_reader_contract_and_separate_truth_registry(self):
        model_sha = "9" * 64
        a268 = {
            "schema": "chacha20-round20-prospective-trajectory-shape-preflight-v1",
            "attempt_id": "A268",
            "frozen_model": {
                "model_sha256": model_sha,
                "model": {
                    "feature_names": [f"f{index}" for index in range(532)],
                    "coefficients": [0.0] * 532,
                    "means": [0.0] * 532,
                    "scales": [1.0] * 532,
                    "intercept": 0.0,
                },
            },
        }
        a268_bytes = _json_bytes(a268)
        a271 = {
            "schema": "chacha20-round20-signed-channel-ablation-protocol-v1",
            "attempt_id": "A271",
            "anchors": {
                "A268_preflight_path": A268_PREFLIGHT,
                "A268_preflight_sha256": hashlib.sha256(a268_bytes).hexdigest(),
            },
            "frozen_model": {
                "feature_count": 532,
                "model_sha256": model_sha,
                "nonzero_coefficient_count": 476,
                "signed_semantic_groups": [{"name": f"g{index}"} for index in range(32)],
            },
        }
        a348 = {
            "schema": "chacha20-round20-w46-direct12-sliced-reader-a348-result-v1",
            "attempt_id": "A348",
            "confirmed_prefix12": 0xBAE,
            "confirmed_prefix12_hex": "bae",
            "confirmed_prefix_revealed_only_after_complete_measurement": True,
        }
        a348_bytes = _json_bytes(a348)
        a349 = {
            "schema": "chacha20-round20-w46-direct12-prospective-a345-validation-a349-order-v1",
            "attempt_id": "A349",
            "anchors": {
                "A348_result": {
                    "path": A348_RESULT,
                    "sha256": hashlib.sha256(a348_bytes).hexdigest(),
                }
            },
        }
        a272_protocol = {
            "schema": "chacha20-round20-selected-channel-prospective-validation-protocol-v1",
            "attempt_id": "A272",
            "prospective_design": {
                "rows": [
                    {
                        "label": f"a272_channel_p{index // 4:02d}_fit_s{index % 4:02d}",
                        "prefix8": (index // 4) * 17,
                        "prefix8_binary": f"{(index // 4) * 17:08b}",
                    }
                    for index in range(20)
                ]
            },
        }
        members = {
            A268_PREFLIGHT: a268_bytes,
            A271_SIGNED_CHANNEL: _json_bytes(a271),
            A348_RESULT: a348_bytes,
            A349_ORDER: _json_bytes(a349),
            A272_PROTOCOL: _json_bytes(a272_protocol),
        }
        with tempfile.TemporaryDirectory() as temporary:
            adapter = Direct12Adapter(_write_source(Path(temporary), members))
            contract = adapter.load_reader_contract()
            self.assertEqual(tuple(item.member for item in contract.documents), READER_CONTRACT_MEMBERS)
            self.assertEqual(len(contract.contract_sha256), 64)
            self.assertEqual(contract.get(A268_PREFLIGHT).document["attempt_id"], "A268")
            truths = Direct12LabelRegistry(adapter)
            self.assertEqual(len(truths.a272_training_truths()), 20)
            calibration = truths.a348_calibration_truth()
            self.assertEqual(calibration.correct_high8_cell, 0xBA)
            self.assertEqual(calibration.correct_low4_slice, 0xE)
            with self.assertRaisesRegex(Direct12Error, "SEALED_DEPLOYMENT"):
                truths.a349_truth()


@unittest.skipUnless(
    os.environ.get("O1_CRYPTO_DIRECT12_REAL") == "1"
    and FINALIZED_CAPSULE.is_dir()
    and shutil.which("zstd"),
    "set O1_CRYPTO_DIRECT12_REAL=1 to validate the immutable real snapshot",
)
class Direct12RealSnapshotTests(unittest.TestCase):
    def test_loads_all_role_separated_real_partitions(self):
        adapter = finalized_direct12_adapter()
        contract = adapter.load_reader_contract()
        dataset = adapter.load_dataset()
        description = dataset.describe()
        self.assertEqual(len(contract.documents), 4)
        self.assertEqual(description["counts"]["by_role"], {
            "TRAIN": 20,
            "CALIBRATION": 16,
            "SEALED_DEPLOYMENT": 16,
        })
        self.assertEqual(description["counts"]["slices"], 52)
        self.assertEqual(description["counts"]["cells"], 13_312)
        self.assertEqual(description["counts"]["stages"], 53_248)
        self.assertEqual(description["counts"]["raw_values"], 692_224)
        sealed = dataset.partitions[2]
        self.assertEqual(sealed.role, DatasetRole.SEALED_DEPLOYMENT)
        self.assertEqual(len(sealed.frozen_candidate_order), 4096)
        self.assertFalse(hasattr(sealed.slices[0], "correct_cell"))
        self.assertFalse(hasattr(sealed.slices[0], "label"))
        truths = Direct12LabelRegistry(adapter)
        self.assertEqual(len(truths.a272_training_truths()), 20)
        self.assertEqual(truths.a348_calibration_truth().correct_prefix12, 0xBAE)
        with self.assertRaises(Direct12Error):
            truths.a349_truth()


if __name__ == "__main__":
    unittest.main()

