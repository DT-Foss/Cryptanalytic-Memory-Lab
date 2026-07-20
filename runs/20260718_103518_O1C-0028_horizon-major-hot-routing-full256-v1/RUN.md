# O1C Run O1C-0028

- Schema: `o1c-run-capsule-v1`
- Status: `completed`
- Claim level: `VALIDATION`
- Git commit: `17c02dfdbf56de6a81ae34700b258815bf0b7f88`
- Started (Europe/Berlin): `2026-07-18T10:35:18.621307+02:00`
- Ended (Europe/Berlin): `2026-07-18T10:35:18.765086+02:00`
- Elapsed seconds: `0.143779`
- Command: `/usr/bin/env 'PYTHONPATH=/Users/bhkmie/Documents/Krypto karm/Kryptkram codex/o1-cryptanalytic-memory-lab/src' /opt/anaconda3/bin/python -m o1_crypto_lab.o1c22_polyphase_bridge_run --config '/Users/bhkmie/Documents/Krypto karm/Kryptkram codex/o1-cryptanalytic-memory-lab/configs/o1c22_polyphase_bridge_v1.json'`

## Hypothesis

A complete 256-coordinate H64/H65/H96 packet ledger can be canonically transposed into three dense horizon-major groups, cold-migrated once into a self-describing allocation-invariant V2 successor of the O1C-0027 recurrence, and then queried by hot readout operators without replay; coordinate-major sparse ingestion and every evidence- or basis-changing operator must remain explicitly invalid or replay-required.

## Prediction

Normalized and int8-quantized transports will each have exact float32[3,3,256] geometry, reversed packet-ledger order and 64 allocation repetitions will produce byte-identical dense evidence and V2 state, complement will produce an exactly odd state/readout, an independent complex128 reference will bound production error, two synthetic O1-O-shaped hot-binding contracts will leave state bytes unchanged, all registered cold descriptor classes will raise ReplayRequiredError, and a deterministic BUILD-only nonnegative horizon fit will generalize to a genuinely distinct sealed synthetic holdout while a zero-design fit abstains.

## Controls

- the fixture contains all 256 coordinates and only deterministic synthetic packet deltas; it contains no ChaCha20 output, unknown key, target label, solver result, sibling artifact or entropy
- packet rows are canonically transposed into exactly three dense horizon-major groups in O1C-0022 time order H64/H65/H96 and V2 wavelength lanes H64/H96/H65
- normalized float32 and quantized int8-to-float32 are independent encodings with separate evidence and state commitments
- reversing the packet ledger must change the ledger commitment but not the canonical dense evidence or final state
- coordinate-major sparse ingestion is an inadmissible negative control and must expose order-dependent decay rather than silently pass
- two synthetic O1-O-shaped descriptors validate only the local binding schema and may bind only already-frozen readout weights and temperature; no authoritative O1C-0023 verification or efficacy is claimed
- every currently registered evidence-, addressing-, lifecycle- or basis-changing descriptor class must require replay before reading the V2 state
- synthetic fit labels are generated only for mechanism validation and never support a cryptanalytic-signal or key-recovery claim

## Budgets

```json
{
  "expected_active_set_evaluations": 16,
  "expected_allocation_repeat_trials": 64,
  "expected_canonical_packet_extraction_generations": 1,
  "expected_canonical_packet_groups_constructed": 256,
  "expected_cold_replay_probes": 13,
  "expected_consume_calls": 75,
  "expected_dense_groups_per_encoding": 3,
  "expected_dense_stream_build_calls": 4,
  "expected_derived_packet_extractions": 2,
  "expected_derived_packet_groups_materialized": 512,
  "expected_direct_reference_group_updates": 3,
  "expected_direct_reference_readout_calls": 1,
  "expected_direct_reference_readout_slot_contributions": 3072,
  "expected_direct_reference_resonator_cell_updates": 9216,
  "expected_exact_abstention_prior_calls": 1,
  "expected_fit_calls": 2,
  "expected_gradient_steps": 0,
  "expected_hot_operator_bindings": 2,
  "expected_input_scalar_deliveries": 561408,
  "expected_lineage_verification_consume_calls": 1,
  "expected_lineage_verification_consume_groups": 3,
  "expected_optimizer_steps": 0,
  "expected_packet_codec_roundtrips": 1,
  "expected_packet_extractions_rehydrated": 1,
  "expected_packet_groups_per_extraction": 256,
  "expected_packet_groups_rehydrated": 256,
  "expected_packet_slots_per_extraction": 768,
  "expected_primary_consume_calls": 1,
  "expected_primary_reingested_groups": 0,
  "expected_production_readout_api_calls": 7,
  "expected_resonator_cell_updates": 2245632,
  "expected_state_group_updates": 731,
  "expected_successful_state_readout_calls": 6,
  "expected_synthetic_mechanism_label_values": 1280,
  "expected_total_packet_group_objects_materialized": 1024,
  "expected_total_packet_slot_objects_materialized": 3072,
  "expected_trainable_parameters": 3,
  "maximum_aggregate_validation_state_bytes": 400912,
  "maximum_cipher_target_reads": 0,
  "maximum_cpu_seconds": 5.0,
  "maximum_dense_stream_aggregate_bytes": 36864,
  "maximum_dense_stream_bytes_per_encoding": 9216,
  "maximum_gpu_calls": 0,
  "maximum_mps_calls": 0,
  "maximum_network_calls": 0,
  "maximum_persistent_artifact_bytes": 1048576,
  "maximum_readout_artifact_bytes": 7168,
  "maximum_reference_state_bytes": 74248,
  "maximum_resident_memory_mib": 128,
  "maximum_scientific_entropy_calls": 0,
  "maximum_sibling_reads": 0,
  "maximum_sibling_writes": 0,
  "maximum_simultaneous_live_states": 13,
  "maximum_solver_calls": 0,
  "maximum_sparse_control_chunk_bytes": 786432,
  "maximum_state_bytes_per_arm": 25128,
  "maximum_state_snapshot_bytes": 125640,
  "maximum_unknown_key_reads": 0,
  "maximum_wall_seconds": 5.0
}
```

## Pinned source hashes

- `config`: `7d3f547032c11cfcf879ad97406c946a68e101762279047bfeb81897d0a19a48`
- `module_isolation`: `50399219de30c9f9e3ed23ee1d5b4c434d8736107316a7647276aa481900b652`
- `module_o1c19_causal_vault_bridge`: `82b8f1724ce5c6e348aeb1e100340276bb84c842b9429203f0d2bef25e2cbb55`
- `module_o1c22_packet_codec`: `73f2e8b2b775684427e777e4671c33d7c0ede2c2ae7a90e1f4ebf84c209914ac`
- `module_o1c22_polyphase_bridge`: `0f60d82ccf048661e41943406721c0b85725f21141395f86121bb72a01b4f046`
- `module_o1c22_polyphase_bridge_run`: `a6453b9c2ed9946df8bcd2064bbf53d7c3eb188f9cb4c3069509749c6dcd2c81`
- `module_polyphase_sufficient_state`: `06d338e890a466d7723d60cbb56a63e069cc99f5cc25ecd9916fa4c0072a75c3`
- `module_polyphase_sufficient_state_v2`: `ed97d5a0f7acb7191f2ce5574da2b26c3a03fdb1a2e5f5499e95ccba3b9b65e1`
- `module_run_capsule`: `13681939e0a5cd09d4f32c6d92c9a56894cfe8af90f07d5d4190c96b90a1b664`
- `pyproject`: `0248ec0fe7d42390b62e358fdd52f63d64f7d4e699f0f41ef77c569699716bd0`

## Metrics

```json
{
  "budget_checks": {
    "abstention_prior_calls": true,
    "active_set_evaluations": true,
    "aggregate_validation_state": true,
    "allocation_repeat_trials": true,
    "canonical_packet_generation": true,
    "canonical_packet_groups": true,
    "cipher_targets": true,
    "cold_replay_probes": true,
    "consume_calls": true,
    "cpu": true,
    "dense_groups": true,
    "dense_stream_aggregate": true,
    "dense_stream_build_calls": true,
    "derived_packet_extractions": true,
    "derived_packet_groups": true,
    "direct_reference_cells": true,
    "direct_reference_groups": true,
    "fit_calls": true,
    "gpu": true,
    "gradient_steps": true,
    "hot_bindings": true,
    "input_scalar_deliveries": true,
    "lineage_verification_calls": true,
    "lineage_verification_groups": true,
    "mps": true,
    "network": true,
    "normalized_stream_bytes": true,
    "optimizer_steps": true,
    "packet_codec_roundtrips": true,
    "packet_extractions_rehydrated": true,
    "packet_groups": true,
    "packet_groups_rehydrated": true,
    "packet_slots": true,
    "persistent_artifacts": true,
    "primary_consume_calls": true,
    "primary_reingested_groups": true,
    "production_readout_calls": true,
    "quantized_stream_bytes": true,
    "readout_artifact": true,
    "reference_readout_calls": true,
    "reference_readout_contributions": true,
    "reference_state_bytes": true,
    "resident_memory": true,
    "resonator_cell_updates": true,
    "scientific_entropy": true,
    "sibling_reads": true,
    "sibling_writes": true,
    "simultaneous_live_states": true,
    "solver": true,
    "sparse_control_chunk": true,
    "state_bytes": true,
    "state_group_updates": true,
    "state_snapshots": true,
    "successful_state_readouts": true,
    "synthetic_label_values": true,
    "total_packet_group_objects": true,
    "total_packet_slot_objects": true,
    "trainable_parameters": true,
    "unknown_keys": true,
    "wall": true
  },
  "classification": "HORIZON_MAJOR_HOT_ROUTING_PASS",
  "cpu_seconds": 0.11216500000000007,
  "cryptanalytic_signal_claimed": false,
  "failed_budgets": [],
  "full_round_key_recovery_claimed": false,
  "gates": {
    "allocation_alignment_state_hash_invariant": true,
    "build_only_horizon_fit_generalizes_synthetic_holdout": true,
    "cold_o1o_operators_require_replay_without_mutation": true,
    "complement_state_and_readout_exactly_odd": true,
    "complete_k256_packet_geometry": true,
    "coordinate_major_sparse_negative_control_rejects": true,
    "coordinate_permutation_commutes": true,
    "dense_geometry_and_separate_encodings": true,
    "direct_reference_within_derived_bound": true,
    "hot_o1o_bindings_are_distinct_and_state_immutable": true,
    "packet_extraction_codec_byte_exact": true,
    "packet_order_canonicalized": true,
    "state_serialization_and_size_exact": true,
    "zero_design_abstains_exactly": true
  },
  "mechanism_validation_passed": true,
  "operationally_complete": true,
  "peak_rss_bytes": 44892160,
  "peak_rss_mib": 42.8125,
  "persistent_artifact_bytes": 378809,
  "result_sha256": "ed3517f215be1c06e7b10882f2eeb6d494ab1f75916f9979edd04729c76abc6e",
  "schema": "o1-256-o1c22-polyphase-bridge-cli-result-v1",
  "state": {
    "abi_revision": 2,
    "aggregate_validation_state_bytes": 400912,
    "basis_sha256": "75b0c13e830c2bf586c0df5fd180eb84ff0d7676b2f28759cc3ce0e3c4f579f6",
    "complement_sha256": "ee0257f010fd90cfccabd98be86139599f529020a2668b0c477d9da6b1636bc0",
    "maximum_live_snapshot_bytes": 125640,
    "maximum_simultaneous_live_states": 13,
    "persistent_bytes_per_arm": 25128,
    "primary_sha256": "02837fe664dc8b75b4dc651fc4d5fd6981b4c9a2653d4040c276fbe124047abe",
    "quantized_sha256": "d9b2b7f524f44d6a03876ffb3d2b5ddb0a3fc978f32730d308d9c9e04236ebc3",
    "reference_audit_state_bytes": 74248,
    "schema": "o1-256-polyphase-sufficient-state-v2",
    "stream_groups_per_encoding": 3,
    "stream_length_dependent": false
  },
  "wall_seconds": 0.12393633322790265,
  "work": {
    "active_set_evaluations": 16,
    "allocation_repeat_trials": 64,
    "canonical_packet_extraction_generations": 1,
    "canonical_packet_groups_constructed": 256,
    "cipher_target_reads": 0,
    "cold_replay_probes": 13,
    "consume_calls": 75,
    "dense_groups_per_encoding": 3,
    "dense_stream_aggregate_bytes": 36864,
    "dense_stream_build_calls": 4,
    "derived_packet_extractions": 2,
    "derived_packet_groups_materialized": 512,
    "direct_reference_group_updates": 3,
    "direct_reference_readout_calls": 1,
    "direct_reference_readout_slot_contributions": 3072,
    "direct_reference_resonator_cell_updates": 9216,
    "exact_abstention_prior_calls": 1,
    "fit_calls": 2,
    "gpu_calls": 0,
    "gradient_steps": 0,
    "hot_operator_bindings": 2,
    "input_scalar_deliveries": 561408,
    "lineage_verification_consume_calls": 1,
    "lineage_verification_consume_groups": 3,
    "maximum_sparse_control_chunk_bytes": 786432,
    "mps_calls": 0,
    "network_calls": 0,
    "optimizer_steps": 0,
    "packet_codec_roundtrips": 1,
    "packet_extractions_rehydrated": 1,
    "packet_groups_rehydrated": 256,
    "primary_consume_calls": 1,
    "primary_reingested_groups": 0,
    "production_readout_api_calls": 7,
    "resonator_cell_updates": 2245632,
    "schema": "o1-256-o1c22-polyphase-bridge-work-v1",
    "scientific_entropy_calls": 0,
    "sibling_reads": 0,
    "sibling_writes": 0,
    "solver_calls": 0,
    "state_group_updates": 731,
    "successful_state_readout_calls": 6,
    "synthetic_mechanism_label_values_generated": 1280,
    "total_packet_group_objects_materialized": 1024,
    "total_packet_slot_objects_materialized": 3072,
    "trainable_parameters": 3,
    "unknown_key_reads": 0
  }
}
```

## Next highest-ROI action

If every transport, V2-ABI, reference, lifecycle and resource gate passes, freeze O1C-0028 as a synthetic adapter contract and run the same one-pass V2 path on authoritative O1C-0022 fold packet extractions only after verifying the real O1C-0023 decision graph under a new O1C identity; no synthetic O1C-0028 score or fixture descriptor may be promoted to ChaCha20 or O1-O efficacy evidence.
