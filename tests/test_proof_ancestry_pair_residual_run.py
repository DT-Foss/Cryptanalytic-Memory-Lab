from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import numpy as np

from o1_crypto_lab.full256_action_pool import BRANCH_FEATURES, Full256ActionPool
from o1_crypto_lab.living_inverse import canonical_json_bytes
from o1_crypto_lab.proof_ancestry_pair_residual import (
    DIAGNOSTIC_ABLATIONS,
    EXPECTED_HORIZONS,
    FEATURE_WIDTH,
    LEARNED_ARMS,
)
from o1_crypto_lab.proof_ancestry_pair_residual_run import (
    ATTEMPT_ID,
    EXPECTED_ALPHA_EVALUATIONS,
    EXPECTED_DIAGNOSTIC_EVALUATIONS,
    EXPECTED_RIDGE_FITS,
    FAILURE,
    LABEL_BYTES,
    NULL,
    O1C26PreparedSource,
    O1C26Budgets,
    PRESENT,
    PUBLICATION_CPU_RESERVE_SECONDS,
    PUBLICATION_RSS_RESERVE_BYTES,
    PUBLICATION_WALL_RESERVE_SECONDS,
    PROXY_INSTANCE_SCHEMA,
    PROXY_MECHANISM_SCHEMA,
    SCORE_ARMS,
    SELECTION_RECEIPT_SCHEMA,
    SOURCE_INDEX_SCHEMA,
    _authoritative_disposition,
    _final_result,
    _finalize_with_prepared_recovery,
    _fresh_local_source_sha256,
    _operational_failure_disposition,
    _recomputed_budget_checks,
    _verify_o1c26_artifact_index,
    _verify_published_source_bindings,
    _verified_published_summary,
    _scored_report,
    load_o1c26_run_config,
    preflight_o1c26,
    run_o1c26_science,
)
from o1_crypto_lab.proof_ancestry_pair_residual import projection_policy
from o1_crypto_lab.run_capsule import ClaimLevel, RunCapsuleManager


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/proof_ancestry_pair_residual_run_v1.json"


def _token(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _frozen(unsigned: dict[str, object], digest_field: str) -> dict[str, object]:
    return {
        **unsigned,
        digest_field: hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest(),
    }


def _fixture_local_sources() -> dict[str, str]:
    return {
        name: _token(f"fixture-local-{name}")
        for name in (
            "source_config",
            "projection_module",
            "runner_module",
            "run_capsule_module",
            "posterior_logit_module",
            "pyproject",
        )
    }


def _zero_pool(index: int) -> Full256ActionPool:
    return Full256ActionPool(
        horizons=EXPECTED_HORIZONS,
        branch_features=np.zeros((3, 256, 2, BRANCH_FEATURES), dtype=np.float32),
        final_resources=np.zeros((256, 2, 3), dtype=np.uint64),
        pair_sha256=tuple(_token(f"pool-{index}-pair-{bit}") for bit in range(256)),
        source_stream_sha256=_token(f"pool-{index}-stream"),
    )


def _science_source(directory: Path) -> O1C26PreparedSource:
    pools = tuple(_zero_pool(index) for index in range(4))
    episodes = tuple(
        SimpleNamespace(
            ordinal=index,
            target_id=f"build-{index:04d}",
            action_pool_sha256=pool.action_pool_sha256,
            action_pool_bytes=pool.serialized_bytes,
            pool=pool,
        )
        for index, pool in enumerate(pools)
    )
    corpus = SimpleNamespace(episodes=episodes)
    run_config = SimpleNamespace(corpus=corpus)
    label_bits = np.asarray(
        [[(fold + bit) & 1 for bit in range(256)] for fold in range(4)],
        dtype=np.uint8,
    )
    label_payload = np.packbits(label_bits, axis=1, bitorder="little").tobytes()
    label_path = directory / "labels.bitpack"
    label_path.write_bytes(label_payload)
    local_sources = _fixture_local_sources()
    mechanism = _frozen(
        {
            "schema": PROXY_MECHANISM_SCHEMA,
            "proxy_operator_id": "fap_ancestry_touch_bilinear_proxy_v2",
            "selected_parent_operator_id": "proof_ancestry_pair_residual_v1",
            "projection_policy_sha256": hashlib.sha256(
                canonical_json_bytes(projection_policy())
            ).hexdigest(),
            "experiment_sha256": hashlib.sha256(
                canonical_json_bytes({"fixture": True})
            ).hexdigest(),
            "scientific_source_sha256": {
                name: local_sources[name]
                for name in (
                    "projection_module",
                    "runner_module",
                    "posterior_logit_module",
                    "pyproject",
                )
            },
            "fixture": True,
        },
        "proxy_mechanism_sha256",
    )
    held_offsets = np.zeros((4, 256), dtype=np.float64)
    training_offsets = np.zeros((4, 3, 256), dtype=np.float64)
    training_ordinals = tuple(
        tuple((fold + offset) % 4 for offset in range(1, 4)) for fold in range(4)
    )
    instance = _frozen(
        {
            "schema": PROXY_INSTANCE_SCHEMA,
            "proxy_mechanism_sha256": mechanism["proxy_mechanism_sha256"],
            "parent": {
                "operator_id": "proof_ancestry_pair_residual_v1",
                "operator_fingerprint": "b" * 64,
                "decision_sha256": hashlib.sha256(b"{}\n").hexdigest(),
                "operator_graph_sha256": hashlib.sha256(b"{}\n").hexdigest(),
            },
            "evaluation_source": {
                "held_out_offsets_sha256": hashlib.sha256(
                    held_offsets.astype("<f8", copy=False).tobytes(order="C")
                ).hexdigest(),
                "training_offsets_sha256": hashlib.sha256(
                    training_offsets.astype("<f8", copy=False).tobytes(order="C")
                ).hexdigest(),
                "label_payload_sha256": hashlib.sha256(label_payload).hexdigest(),
                "label_payload_bytes": len(label_payload),
                "label_bit_order": "little",
                "training_ordinals_by_outer_fold": [
                    list(values) for values in training_ordinals
                ],
                "offset_source_members_sha256": hashlib.sha256(
                    canonical_json_bytes([])
                ).hexdigest(),
                "o1c18_build_corpus_sha256": "c" * 64,
            },
            "fixture": True,
        },
        "proxy_instance_fingerprint",
    )
    selection_receipt = _frozen(
        {
            "schema": SELECTION_RECEIPT_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "source_attempt_id": "O1C-0023",
            "authoritative_capsule_verified": True,
            "attempt_reservation_authorized": True,
            "selected_parent_operator_id": "proof_ancestry_pair_residual_v1",
            "proxy_operator_id": "fap_ancestry_touch_bilinear_proxy_v2",
            "parent_operator_fingerprint": "b" * 64,
            "proxy_mechanism_sha256": mechanism["proxy_mechanism_sha256"],
            "proxy_instance_fingerprint": instance["proxy_instance_fingerprint"],
            "o1c23_capsule_manifest_sha256": "8" * 64,
            "o1c22_capsule_manifest_sha256": "9" * 64,
            "o1c22_result_sha256": "e" * 64,
            "decision_sha256": hashlib.sha256(b"{}\n").hexdigest(),
            "operator_graph_sha256": hashlib.sha256(b"{}\n").hexdigest(),
            "required_reason_field": "all_real_primary_k256_arms_nonpositive",
            "required_reason_field_value": True,
        },
        "selection_receipt_sha256",
    )
    return O1C26PreparedSource(
        o1c23=None,  # type: ignore[arg-type]
        o1c22=None,  # type: ignore[arg-type]
        o1c22_run_config=run_config,  # type: ignore[arg-type]
        decision={},
        decision_payload=b"{}\n",
        operator_graph={},
        operator_graph_payload=b"{}\n",
        selection_receipt=selection_receipt,
        proxy_mechanism=mechanism,
        proxy_instance=instance,
        held_out_offsets=held_offsets,
        training_offsets=training_offsets,
        training_ordinals=training_ordinals,
        offset_members=(),
        label_payload_path=label_path,
        label_payload_sha256=hashlib.sha256(label_payload).hexdigest(),
        source_artifact_bytes_read=0,
    )


class FormalConfigAndPreflightTests(unittest.TestCase):
    def test_current_config_is_strict_and_pending_preflight_reserves_nothing(
        self,
    ) -> None:
        config = load_o1c26_run_config(CONFIG, root=ROOT)
        self.assertEqual(config.top["attempt_id"], ATTEMPT_ID)
        reservation = ROOT / "runs/.attempt_ids/O1C-0026.json"
        before = reservation.exists()
        preflight = preflight_o1c26(CONFIG, root=ROOT)
        self.assertEqual(preflight.report["status"], "prerequisite-pending")
        self.assertFalse(preflight.report["o1c26_reserved_by_this_preflight"])
        self.assertEqual(reservation.exists(), before)


class FormalScienceTests(unittest.TestCase):
    def test_zero_corpus_completes_exact_lifecycle_as_scientific_null(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = _science_source(root)
            phases: list[tuple[str, str]] = []

            def persist(relative: str, payload: bytes, phase: str) -> Path:
                destination = root / "artifacts" / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(payload)
                phases.append((relative, phase))
                return destination

            outcome = run_o1c26_science(source, persist)
            self.assertEqual(outcome.report["classification"], NULL)
            self.assertFalse(outcome.report["scientific_success_gate_passed"])
            self.assertFalse(
                outcome.report["claim_boundary"]["parent_r07_closed_by_proxy_null"]
            )
            final = _final_result(outcome.report)
            self.assertEqual(final["classification"], NULL)
            self.assertEqual(final["closure_candidate"], "EXACT_PROXY_INSTANCE_NO_LIFT")
            self.assertIsNone(final["closed_operator_fingerprint"])
            disposition = _authoritative_disposition(
                final["classification"],
                True,
                str(source.proxy_instance["proxy_instance_fingerprint"]),
            )
            self.assertEqual(
                disposition["closed_operator_fingerprint"],
                source.proxy_instance["proxy_instance_fingerprint"],
            )
            artifacts = root / "artifacts"
            source_index = _frozen(
                {
                    "schema": SOURCE_INDEX_SCHEMA,
                    "attempt_id": ATTEMPT_ID,
                    "run_config_sha256": "7" * 64,
                    "local_source_sha256": _fixture_local_sources(),
                    "projection_policy_sha256": hashlib.sha256(
                        canonical_json_bytes(projection_policy())
                    ).hexdigest(),
                    "proxy_mechanism": dict(source.proxy_mechanism),
                    "proxy_instance": dict(source.proxy_instance),
                    "source_config": {
                        "relative_path": "configs/fixture.json",
                        "sha256": _fixture_local_sources()["source_config"],
                    },
                    "o1c23": {
                        "attempt_id": "O1C-0023",
                        "capsule_relative_path": "runs/o1c23-fixture",
                        "capsule_manifest_sha256": "8" * 64,
                        "decision_sha256": hashlib.sha256(b"{}\n").hexdigest(),
                        "operator_graph_sha256": hashlib.sha256(b"{}\n").hexdigest(),
                        "selected_parent_operator_id": (
                            "proof_ancestry_pair_residual_v1"
                        ),
                        "parent_operator_fingerprint": "b" * 64,
                    },
                    "o1c22": {
                        "attempt_id": "O1C-0022",
                        "capsule_relative_path": "runs/o1c22-fixture",
                        "capsule_manifest_sha256": "9" * 64,
                        "artifact_index_sha256": "d" * 64,
                        "result_sha256": "e" * 64,
                        "result_file_sha256": "f" * 64,
                        "offset_members": [],
                        "label_member": {
                            "relative_path": "labels.bitpack",
                            "sha256": hashlib.sha256(
                                (artifacts / "post_freeze_labels.bitpack").read_bytes()
                            ).hexdigest(),
                            "bytes": LABEL_BYTES,
                            "opened_before_projection_freeze": False,
                        },
                    },
                    "o1c18": {
                        "capsule_relative_path": "runs/o1c18-fixture",
                        "capsule_manifest_sha256": "a" * 64,
                        "artifact_index_sha256": "1" * 64,
                        "artifact_corpus_sha256": "c" * 64,
                        "build_faps": [
                            {
                                "ordinal": ordinal,
                                "target_id": f"build-{ordinal:04d}",
                                "relative_path": (
                                    f"artifacts/pools/build-{ordinal:04d}.fap"
                                ),
                                "sha256": pool.action_pool_sha256,
                                "bytes": pool.serialized_bytes,
                            }
                            for ordinal, pool in enumerate(source.pools)
                        ],
                        "development_faps_deserialized": 0,
                    },
                    "source_artifact_bytes_read_before_science": 0,
                },
                "source_index_sha256",
            )
            authoritative = {
                "o1c0023_decision.json": b"{}\n",
                "o1c0023_next_operator_graph.json": b"{}\n",
                "selection_receipt.json": canonical_json_bytes(
                    source.selection_receipt
                ),
                "projection_policy.json": canonical_json_bytes(projection_policy()),
                "proxy_mechanism.json": canonical_json_bytes(source.proxy_mechanism),
                "proxy_instance.json": canonical_json_bytes(source.proxy_instance),
                "source_index.json": canonical_json_bytes(source_index),
                "proof_ancestry_pair_residual_result.json": canonical_json_bytes(final),
            }
            for relative, payload in authoritative.items():
                destination = artifacts / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(payload)
            indexed: dict[str, dict[str, object]] = {}
            for candidate in sorted(artifacts.rglob("*")):
                if candidate.is_file() and candidate.name != "artifact_index.json":
                    payload = candidate.read_bytes()
                    relative = candidate.relative_to(artifacts).as_posix()
                    indexed[relative] = {
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "bytes": len(payload),
                        "phase": "TEST",
                    }
            projection = json.loads((artifacts / "projection_freeze.json").read_bytes())
            prediction = json.loads(
                (artifacts / "prediction_set_freeze.json").read_bytes()
            )
            label_access = json.loads(
                (artifacts / "label_access_receipt.json").read_bytes()
            )
            work = json.loads((artifacts / "structural_work_ledger.json").read_bytes())
            index = {
                "schema": "o1-256-o1c26-artifact-index-v1",
                "attempt_id": ATTEMPT_ID,
                "o1c23_capsule_manifest_sha256": "8" * 64,
                "o1c22_capsule_manifest_sha256": "9" * 64,
                "proxy_instance_fingerprint": source.proxy_instance[
                    "proxy_instance_fingerprint"
                ],
                "selection_receipt_sha256": source.selection_receipt[
                    "selection_receipt_sha256"
                ],
                "projection_freeze_sha256": projection["projection_freeze_sha256"],
                "prediction_set_freeze_sha256": prediction[
                    "prediction_set_freeze_sha256"
                ],
                "label_access_receipt_sha256": label_access[
                    "label_access_receipt_sha256"
                ],
                "work_ledger_sha256": work["work_ledger_sha256"],
                "result_sha256": final["result_sha256"],
                "artifacts": indexed,
                "indexed_artifact_count": len(indexed),
                "indexed_artifact_bytes": sum(
                    int(row["bytes"]) for row in indexed.values()
                ),
            }
            (artifacts / "artifact_index.json").write_bytes(canonical_json_bytes(index))
            verified, digest, total, documents = _verify_o1c26_artifact_index(
                artifacts, expected_index=index
            )
            self.assertEqual(verified, index)
            self.assertEqual(documents["result"], final)
            fixture_sources = {
                "config": "7" * 64,
                "projection_policy": hashlib.sha256(
                    canonical_json_bytes(projection_policy())
                ).hexdigest(),
                "proxy_mechanism": source.proxy_mechanism["proxy_mechanism_sha256"],
                "proxy_instance": source.proxy_instance["proxy_instance_fingerprint"],
                "parent_operator": "b" * 64,
                **_fixture_local_sources(),
                "o1c23_capsule_manifest": "8" * 64,
                "o1c23_decision": hashlib.sha256(b"{}\n").hexdigest(),
                "o1c23_operator_graph": hashlib.sha256(b"{}\n").hexdigest(),
                "o1c22_capsule_manifest": "9" * 64,
                "o1c22_artifact_index": "d" * 64,
                "o1c22_result": "e" * 64,
                "o1c22_result_file": "f" * 64,
                "o1c18_capsule_manifest": "a" * 64,
                "o1c18_artifact_index": "1" * 64,
                "o1c18_build_corpus": "c" * 64,
            }
            fixture_config = {
                "experiment": {"fixture": True},
                "source": {
                    "local_source_sha256": _fixture_local_sources(),
                    "source_config_path": "configs/fixture.json",
                    "source_config_sha256": _fixture_local_sources()["source_config"],
                    "source_freeze_commit": "1" * 40,
                },
            }
            _verify_published_source_bindings(
                fixture_sources, fixture_config, documents
            )
            wrong_sources = dict(fixture_sources)
            wrong_sources["o1c22_artifact_index"] = "2" * 64
            with self.assertRaisesRegex(ValueError, "o1c22_index"):
                _verify_published_source_bindings(
                    wrong_sources, fixture_config, documents
                )
            self.assertEqual(
                digest,
                hashlib.sha256(canonical_json_bytes(index)).hexdigest(),
            )
            self.assertGreater(total, int(index["indexed_artifact_bytes"]))
            self.assertLess(total, 32 * 1024 * 1024)
            budget_mapping = json.loads(CONFIG.read_bytes())["budgets"]
            budgets = O1C26Budgets.from_mapping(budget_mapping)
            measurement = {
                "cpu_seconds": 1.0,
                "wall_seconds": 1.0,
                "pre_capsule_wall_seconds": 0.25,
                "peak_rss_bytes": 64 * 1024 * 1024,
                "publication_cpu_reserve_seconds": (PUBLICATION_CPU_RESERVE_SECONDS),
                "publication_wall_reserve_seconds": (PUBLICATION_WALL_RESERVE_SECONDS),
                "publication_rss_reserve_bytes": PUBLICATION_RSS_RESERVE_BYTES,
                "budgeted_cpu_seconds": 1.0 + PUBLICATION_CPU_RESERVE_SECONDS,
                "budgeted_wall_seconds": 1.0 + PUBLICATION_WALL_RESERVE_SECONDS,
                "budgeted_peak_rss_bytes": (
                    64 * 1024 * 1024 + PUBLICATION_RSS_RESERVE_BYTES
                ),
                "source_artifact_bytes_read": LABEL_BYTES,
                "persistent_artifact_bytes": total,
                **{
                    name: getattr(outcome.work, name)
                    for name in (
                        "build_faps_deserialized",
                        "development_faps_deserialized",
                        "ridge_fits",
                        "alpha_bit_evaluations",
                        "diagnostic_bit_evaluations",
                        "fresh_targets",
                        "native_solver_branches",
                        "scientific_entropy_calls",
                        "sibling_reads",
                        "sibling_writes",
                        "mps_calls",
                        "gpu_calls",
                        "maximum_observed_projection_scratch_bytes",
                        "maximum_live_state_bytes",
                        "primary_state_replays",
                        "primary_state_replay_coordinates",
                        "sibling_scope",
                    )
                },
            }
            budget_checks = _recomputed_budget_checks(
                budgets,
                measurement,
                outcome.work.document(),
                total,
                LABEL_BYTES,
            )
            self.assertTrue(all(budget_checks.values()))
            bad_resource = dict(measurement)
            bad_resource["budgeted_wall_seconds"] = 99.0
            with self.assertRaisesRegex(ValueError, "resource envelope"):
                _recomputed_budget_checks(
                    budgets,
                    bad_resource,
                    outcome.work.document(),
                    total,
                    LABEL_BYTES,
                )
            bad_work = dict(measurement)
            bad_work["ridge_fits"] = EXPECTED_RIDGE_FITS - 1
            with self.assertRaisesRegex(ValueError, "metric/work binding"):
                _recomputed_budget_checks(
                    budgets,
                    bad_work,
                    outcome.work.document(),
                    total,
                    LABEL_BYTES,
                )
            bad_source = dict(measurement)
            bad_source["source_artifact_bytes_read"] = LABEL_BYTES - 1
            with self.assertRaisesRegex(ValueError, "source artifact accounting"):
                _recomputed_budget_checks(
                    budgets,
                    bad_source,
                    outcome.work.document(),
                    total,
                    LABEL_BYTES,
                )
            source_unsigned = dict(source_index)
            source_unsigned.pop("source_index_sha256")
            mutated_o1c23 = dict(source_unsigned["o1c23"])  # type: ignore[arg-type]
            mutated_o1c23["capsule_manifest_sha256"] = "a" * 64
            source_unsigned["o1c23"] = mutated_o1c23
            mutated_source = _frozen(source_unsigned, "source_index_sha256")
            mutated_source_payload = canonical_json_bytes(mutated_source)
            (artifacts / "source_index.json").write_bytes(mutated_source_payload)
            mutated_index = json.loads(canonical_json_bytes(index))
            mutated_index["artifacts"]["source_index.json"]["sha256"] = hashlib.sha256(
                mutated_source_payload
            ).hexdigest()
            mutated_index["artifacts"]["source_index.json"]["bytes"] = len(
                mutated_source_payload
            )
            mutated_index["indexed_artifact_bytes"] = sum(
                int(row["bytes"]) for row in mutated_index["artifacts"].values()
            )
            (artifacts / "artifact_index.json").write_bytes(
                canonical_json_bytes(mutated_index)
            )
            with self.assertRaisesRegex(ValueError, "source_o1c23"):
                _verify_o1c26_artifact_index(artifacts)
            (artifacts / "source_index.json").write_bytes(
                canonical_json_bytes(source_index)
            )
            (artifacts / "artifact_index.json").write_bytes(canonical_json_bytes(index))
            (artifacts / "unindexed-extra.bin").write_bytes(b"x")
            with self.assertRaisesRegex(ValueError, "actual artifact inventory"):
                _verify_o1c26_artifact_index(artifacts)
            failed = _authoritative_disposition(
                final["classification"],
                False,
                str(source.proxy_instance["proxy_instance_fingerprint"]),
            )
            self.assertEqual(failed["classification"], FAILURE)
            self.assertEqual(failed["closure_disposition"], "NONE_OPERATIONAL_FAILURE")
            self.assertIsNone(failed["closed_operator_fingerprint"])
            self.assertEqual(outcome.work.ridge_fits, EXPECTED_RIDGE_FITS)
            self.assertEqual(
                outcome.work.alpha_bit_evaluations, EXPECTED_ALPHA_EVALUATIONS
            )
            self.assertEqual(
                outcome.work.diagnostic_bit_evaluations,
                EXPECTED_DIAGNOSTIC_EVALUATIONS,
            )
            self.assertTrue(outcome.work.projection_frozen_before_label_parse)
            self.assertEqual(outcome.work.primary_state_replays, 4)
            self.assertEqual(outcome.work.primary_state_replay_coordinates, 1024)
            self.assertEqual(outcome.work.maximum_live_state_bytes, 8192)
            self.assertGreater(
                outcome.work.maximum_observed_projection_scratch_bytes, 0
            )
            self.assertLessEqual(
                outcome.work.maximum_observed_projection_scratch_bytes, 16384
            )
            self.assertEqual(
                outcome.work.inner_prediction_freezes_persisted_and_reloaded,
                len(LEARNED_ARMS) * 4,
            )
            self.assertTrue(
                outcome.work.every_outer_prediction_frozen_before_own_fold_scoring
            )
            self.assertFalse(outcome.work.own_fold_label_used_in_fit)
            self.assertEqual(
                len(list((root / "artifacts/features").glob("*.f64le"))),
                len(LEARNED_ARMS),
            )
            projection_index = next(
                index
                for index, (relative, _) in enumerate(phases)
                if relative == "projection_freeze.json"
            )
            scoring_copy_index = next(
                index
                for index, (relative, _) in enumerate(phases)
                if relative == "post_freeze_labels.bitpack"
            )
            self.assertLess(projection_index, scoring_copy_index)
            self.assertEqual(
                (root / "artifacts/post_freeze_labels.bitpack").stat().st_size,
                LABEL_BYTES,
            )
            for fold in range(4):
                for arm in LEARNED_ARMS:
                    prefix = root / f"artifacts/folds/build-{fold:04d}/{arm}"
                    self.assertEqual(
                        (prefix / "effective_weights.f64le").stat().st_size,
                        FEATURE_WIDTH * 8,
                    )
                    freeze = json.loads(
                        (prefix / "outer_prediction_freeze.json").read_bytes()
                    )
                    self.assertFalse(freeze["held_out_label_used_in_fit"])

    def test_score_gate_can_distinguish_present_from_flat_null(self) -> None:
        bits = np.asarray(
            [[(fold + bit) & 1 for bit in range(256)] for fold in range(4)],
            dtype=np.uint8,
        )
        signs = bits.astype(np.float64) * 2.0 - 1.0
        predictions = np.zeros((4, len(SCORE_ARMS), 256), dtype=np.float64)
        predictions[:, SCORE_ARMS.index("primary"), :] = signs * 2.0
        predictions[:, SCORE_ARMS.index("pair_identity_shuffled"), :] = signs * 0.2
        predictions[:, SCORE_ARMS.index("additive_factorized_matched"), :] = signs * 0.1
        predictions[:, SCORE_ARMS.index("polarity_even_common_mode"), :] = signs * 0.05
        for ablation in DIAGNOSTIC_ABLATIONS:
            predictions[:, SCORE_ARMS.index(ablation), :] = signs
        report, nll, compression, correct = _scored_report(
            predictions,
            bits,
            signs,
            np.ones((4, 4), dtype=np.float64),
            offset_freeze_sha256="0" * 64,
            projection_freeze_sha256="1" * 64,
            prediction_set_freeze_sha256="2" * 64,
            label_access_receipt_sha256="5" * 64,
            selection_receipt_sha256="3" * 64,
            work_ledger_sha256="4" * 64,
            proxy_instance_fingerprint="6" * 64,
            parent_operator_fingerprint="7" * 64,
        )
        self.assertEqual(report["classification"], PRESENT)
        self.assertTrue(report["scientific_success_gate_passed"])
        self.assertEqual(nll.shape, (4, len(SCORE_ARMS)))
        self.assertEqual(compression.shape, nll.shape)
        self.assertTrue(np.all(correct[:, SCORE_ARMS.index("primary")] == 256))
        final = _final_result(report)
        self.assertEqual(final["classification"], PRESENT)
        disposition = _authoritative_disposition(
            final["classification"], True, "6" * 64
        )
        self.assertEqual(
            disposition["closure_disposition"], "NONE_PRESENT_SUPPORTS_INSTANCE"
        )
        self.assertIsNone(disposition["closed_operator_fingerprint"])


class FormalLifecycleHardeningTests(unittest.TestCase):
    def test_completed_capsule_without_artifact_index_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manager = RunCapsuleManager(root)
            run = manager.start(
                attempt_id=ATTEMPT_ID,
                slug="indexless-completed",
                commit="7" * 40,
                hypothesis="completed requires an evidence graph",
                prediction="indexless completion is rejected",
                controls=("no artifacts",),
                budgets={"wall_seconds": 1},
                source_hashes={
                    "proxy_instance": "5" * 64,
                    "parent_operator": "6" * 64,
                },
                claim_level=ClaimLevel.RETROSPECTIVE,
                next_action="preserve",
                config={"budgets": {"maximum_wall_seconds": 1.0}},
                command=("python", "fixture.py"),
                environment={"backend": "cpu"},
            )
            finalized = run.finalize(
                metrics=_operational_failure_disposition("5" * 64, "6" * 64),
                status="completed",
            )
            with self.assertRaisesRegex(
                ValueError, "completed O1C-0026 metric disposition"
            ):
                _verified_published_summary(manager, finalized, "test-finalized")

    def test_failed_capsule_preserves_unclaimed_partial_index(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manager = RunCapsuleManager(root)
            run = manager.start(
                attempt_id=ATTEMPT_ID,
                slug="partial-index-failure",
                commit="8" * 40,
                hypothesis="partial evidence remains inspectable",
                prediction="failure cannot claim the partial index",
                controls=("no result claim",),
                budgets={"wall_seconds": 1},
                source_hashes={
                    "proxy_instance": "5" * 64,
                    "parent_operator": "6" * 64,
                },
                claim_level=ClaimLevel.RETROSPECTIVE,
                next_action="preserve",
                config={"budgets": {"maximum_wall_seconds": 1.0}},
                command=("python", "fixture.py"),
                environment={"backend": "cpu"},
            )
            run.write_artifact("artifact_index.json", b"{}\n")
            finalized = run.finalize(
                metrics=_operational_failure_disposition("5" * 64, "6" * 64),
                status="failed",
            )
            summary, exit_code = _verified_published_summary(
                manager, finalized, "test-finalized"
            )
            self.assertEqual(exit_code, 2)
            self.assertEqual(summary["capsule_status"], "failed")
            self.assertIsNone(summary["result_sha256"])

    def test_prepared_publication_is_retried_without_metric_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manager = RunCapsuleManager(root)
            run = manager.start(
                attempt_id=ATTEMPT_ID,
                slug="prepared-recovery",
                commit="1" * 40,
                hypothesis="publication is immutable",
                prediction="the prepared content publishes once",
                controls=("no replay",),
                budgets={"wall_seconds": 1},
                source_hashes={
                    "fixture": "2" * 64,
                    "proxy_instance": "5" * 64,
                    "parent_operator": "6" * 64,
                },
                claim_level=ClaimLevel.RETROSPECTIVE,
                next_action="preserve",
                config={"budgets": {"maximum_wall_seconds": 1.0}},
                command=("python", "fixture.py"),
                environment={"backend": "cpu"},
            )
            real_rename = __import__("os").rename
            calls = 0

            def fail_once(*args: object, **kwargs: object) -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise OSError("injected publish fault")
                real_rename(*args, **kwargs)  # type: ignore[arg-type]

            with mock.patch(
                "o1_crypto_lab.run_capsule.os.rename", side_effect=fail_once
            ):
                finalized = _finalize_with_prepared_recovery(
                    run,
                    metrics={
                        **_operational_failure_disposition("5" * 64, "6" * 64),
                        "sentinel": 7,
                    },
                    status="failed",
                    next_action="frozen failure",
                )
            metrics = json.loads((finalized.path / "metrics.json").read_bytes())
            self.assertEqual(calls, 2)
            self.assertEqual(metrics["status"], "failed")
            self.assertEqual(metrics["values"]["sentinel"], 7)
            self.assertEqual(metrics["values"]["classification"], FAILURE)
            self.assertEqual(metrics["next_action"], "frozen failure")
            self.assertNotIn(ATTEMPT_ID, manager.recoverable_attempt_ids())
            summary, exit_code = _verified_published_summary(
                manager, finalized, "test-finalized"
            )
            self.assertEqual(exit_code, 2)
            self.assertEqual(summary["capsule_status"], "failed")

    def test_fresh_local_source_recheck_reopens_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.py"
            source.write_bytes(b"first\n")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            config = SimpleNamespace(
                root=root,
                local_source_paths={"projection_module": source},
                local_source_sha256={"projection_module": digest},
            )
            self.assertEqual(
                _fresh_local_source_sha256(config),  # type: ignore[arg-type]
                {"projection_module": digest},
            )
            source.write_bytes(b"second\n")
            with self.assertRaisesRegex(ValueError, "projection_module"):
                _fresh_local_source_sha256(config)  # type: ignore[arg-type]

    def test_second_publication_fault_leaves_prepared_stage_recoverable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manager = RunCapsuleManager(root)
            run = manager.start(
                attempt_id=ATTEMPT_ID,
                slug="double-publish-fault",
                commit="3" * 40,
                hypothesis="prepared bytes remain immutable",
                prediction="a later process publishes without replay",
                controls=("no metric rewrite",),
                budgets={"wall_seconds": 1},
                source_hashes={
                    "fixture": "4" * 64,
                    "proxy_instance": "5" * 64,
                    "parent_operator": "6" * 64,
                },
                claim_level=ClaimLevel.RETROSPECTIVE,
                next_action="recover publication",
                config={"budgets": {"maximum_wall_seconds": 1.0}},
                command=("python", "fixture.py"),
                environment={"backend": "cpu"},
            )
            with mock.patch(
                "o1_crypto_lab.run_capsule.os.rename",
                side_effect=OSError("injected repeated publish fault"),
            ):
                with self.assertRaisesRegex(OSError, "repeated publish fault"):
                    _finalize_with_prepared_recovery(
                        run,
                        metrics={"sentinel": 9},
                        status="completed",
                    )
            self.assertTrue(run.publication_prepared)
            self.assertIn(ATTEMPT_ID, manager.recoverable_attempt_ids())
            recovered = manager.recover(ATTEMPT_ID).finalize(metrics={})
            metrics = json.loads((recovered.path / "metrics.json").read_bytes())
            self.assertEqual(metrics["status"], "completed")
            self.assertEqual(metrics["values"], {"sentinel": 9})


if __name__ == "__main__":
    unittest.main()
