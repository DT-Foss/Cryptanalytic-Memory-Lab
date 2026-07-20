# O1C Run O1C-0027

- Schema: `o1c-run-capsule-v1`
- Status: `completed`
- Claim level: `VALIDATION`
- Git commit: `f47a6dacd54a7d9c93bc41c0ee08902bf855e85d`
- Started (Europe/Berlin): `2026-07-18T09:02:48.970659+02:00`
- Ended (Europe/Berlin): `2026-07-18T09:02:49.093504+02:00`
- Elapsed seconds: `0.122845`
- Command: `/usr/bin/env 'PYTHONPATH=/Users/bhkmie/Documents/Krypto karm/Kryptkram codex/o1-cryptanalytic-memory-lab/src' /Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -m o1_crypto_lab.polyphase_sufficient_state_run --config '/Users/bhkmie/Documents/Krypto karm/Kryptkram codex/o1-cryptanalytic-memory-lab/configs/polyphase_sufficient_state_v1.json'`

## Hypothesis

A fixed 25,096-byte bank of stable polyphase resonators is a T-independent sufficient statistic of a once-consumed full-256 evidence stream for late-bound slot and temperature readouts; changing the bound encoder, kernel, or phase basis instead requires replay.

## Prediction

Four distinct hot readouts from one final state hash will match an independent complex128 recurrence within its derived float32 error envelope, leave the state unchanged, remain byte-identical across chunk partitions, and negate exactly under branch swap; three foreign basis descriptors will each raise ReplayRequiredError before computation.

## Controls

- the complete deterministic float32[384,3,256] source is generated once with no entropy, target, label, outcome, solver, sibling, network or accelerator access
- primary, rechunked, branch-swapped and prefix arms each call consume exactly once while only the primary arm defines the one-pass deployment path
- an independent chronological complex128 recurrence uses the exact frozen complex64 pole and float32 gain bytes and a derived roundoff envelope
- the rechunk partition crosses the regime switch and must still serialize to exactly the same 25,096 bytes as the one-chunk arm
- encoder order, one kernel timescale and one phase wavelength are independently changed only through foreign basis commitments and must hard-fail without state mutation
- all readers are bias-free linear odd experts; state counters are branch-even and zero evidence remains an observed group

## Budgets

```json
{
  "maximum_aggregate_algorithmic_state_bytes": 174632,
  "maximum_control_input_chunk_bytes": 3072,
  "maximum_cpu_seconds": 5.0,
  "maximum_deployment_live_state_bytes": 100384,
  "maximum_direct_reference_group_updates": 384,
  "maximum_direct_reference_readout_calls": 4,
  "maximum_direct_reference_readout_slot_contributions": 12288,
  "maximum_direct_reference_resonator_cell_updates": 1179648,
  "maximum_gpu_calls": 0,
  "maximum_input_scalar_deliveries": 1032960,
  "maximum_label_reads": 0,
  "maximum_mps_calls": 0,
  "maximum_network_calls": 0,
  "maximum_outcome_or_progress_reads": 0,
  "maximum_persistent_artifact_bytes": 1048576,
  "maximum_primary_consume_calls": 1,
  "maximum_primary_reingested_groups": 0,
  "maximum_readout_artifact_bytes": 16384,
  "maximum_reference_state_bytes": 74248,
  "maximum_replay_required_probes": 3,
  "maximum_resident_memory_mib": 128,
  "maximum_resonator_cell_updates": 4131840,
  "maximum_scientific_entropy_calls": 0,
  "maximum_sibling_reads": 0,
  "maximum_sibling_writes": 0,
  "maximum_solver_calls": 0,
  "maximum_source_buffer_bytes": 1179648,
  "maximum_source_generation_calls": 1,
  "maximum_source_plus_control_input_bytes": 1182720,
  "maximum_state_bytes_per_arm": 25096,
  "maximum_state_group_updates": 1345,
  "maximum_state_snapshot_bytes": 125480,
  "maximum_successful_state_readout_calls": 12,
  "maximum_target_reads": 0,
  "maximum_wall_seconds": 5.0
}
```

## Pinned source hashes

- `config`: `6fab58bb10101067eecaa7c206f66e0b0463e9032bee6a3aeb7605778993747b`
- `module_isolation`: `50399219de30c9f9e3ed23ee1d5b4c434d8736107316a7647276aa481900b652`
- `module_polyphase_sufficient_state`: `06d338e890a466d7723d60cbb56a63e069cc99f5cc25ecd9916fa4c0072a75c3`
- `module_polyphase_sufficient_state_run`: `41f38290a2ab6595fa633934d39c59188f7944a83df67c0e402eb3c27d743872`
- `module_run_capsule`: `13681939e0a5cd09d4f32c6d92c9a56894cfe8af90f07d5d4190c96b90a1b664`
- `pyproject`: `0248ec0fe7d42390b62e358fdd52f63d64f7d4e699f0f41ef77c569699716bd0`

## Metrics

```json
{
  "budget_checks": {
    "aggregate_algorithmic_state": true,
    "control_input_chunk": true,
    "cpu": true,
    "deployment_live_state": true,
    "direct_reference_group_updates": true,
    "direct_reference_readout_calls": true,
    "direct_reference_readout_slot_contributions": true,
    "direct_reference_resonator_cell_updates": true,
    "gpu": true,
    "input_scalar_deliveries": true,
    "label_reads": true,
    "mps": true,
    "network": true,
    "outcome_or_progress_reads": true,
    "persistent_artifacts": true,
    "primary_consume_calls": true,
    "primary_reingested_groups": true,
    "readout_artifact": true,
    "reference_state": true,
    "replay_required_probes": true,
    "resident_memory": true,
    "resonator_cell_updates": true,
    "scientific_entropy": true,
    "sibling_reads": true,
    "sibling_writes": true,
    "solver": true,
    "source_buffer": true,
    "source_generation_calls": true,
    "source_plus_control_input": true,
    "state_bytes_per_arm": true,
    "state_group_updates": true,
    "state_snapshots": true,
    "successful_state_readout_calls": true,
    "target_reads": true,
    "wall": true
  },
  "classification": "POLYPHASE_SUFFICIENT_STATE_PASS",
  "cpu_seconds": 0.08185599999999998,
  "cryptanalytic_signal_claimed": false,
  "failed_budgets": [],
  "full_round_key_recovery_claimed": false,
  "gates": {
    "basis_changes_require_replay": true,
    "branch_swap_readouts_exactly_odd": true,
    "branch_swap_slots_exactly_odd": true,
    "chunk_partition_byte_exact": true,
    "collapsed_bank_negative_control_rejected": true,
    "coverage_and_clock_exact": true,
    "direct_reference_within_derived_bound": true,
    "hot_readouts_distinct_after_rms_normalization": true,
    "one_pass_primary": true,
    "query_zero_reingest_and_state_immutable": true,
    "serialization_roundtrip_exact": true,
    "state_size_invariant": true
  },
  "mechanism_validation_passed": true,
  "operationally_complete": true,
  "peak_rss_bytes": 41304064,
  "peak_rss_mib": 39.390625,
  "persistent_artifact_bytes": 164132,
  "result_sha256": "6041fbb157cb96c98a988da60b0a88f958507b3c5d0e1b5cd8ebe2733280a568",
  "schema": "o1-256-polyphase-sufficient-state-cli-result-v1",
  "state": {
    "aggregate_algorithmic_state_bytes": 174632,
    "deployment_live_state_bytes": 100384,
    "persistent_bytes_per_arm": 25096,
    "reference_audit_state_bytes": 74248,
    "snapshot_bytes": 125480,
    "states": {
      "prefix_t193": {
        "basis_sha256": "5f578f1917c5f80e662fb2c76e5e176202c9ef68dc492cd23e69c50984a78c33",
        "clock": 193,
        "coverage_max": 193,
        "coverage_min": 193,
        "persistent_bytes": 25096,
        "schema": "o1-256-polyphase-sufficient-state-v1",
        "sha256": "b55ec2c89c4776ddf4f27c8128c2894b3c91c722835777af6e7c71f34b724383",
        "stream_length_dependent": false
      },
      "primary_t384": {
        "basis_sha256": "5f578f1917c5f80e662fb2c76e5e176202c9ef68dc492cd23e69c50984a78c33",
        "clock": 384,
        "coverage_max": 384,
        "coverage_min": 384,
        "persistent_bytes": 25096,
        "schema": "o1-256-polyphase-sufficient-state-v1",
        "sha256": "9d3cf08570f64a31eac9723b10105d5948e5898a2da6ee1b9543d3f10e1046e1",
        "stream_length_dependent": false
      },
      "rechunk_t384": {
        "basis_sha256": "5f578f1917c5f80e662fb2c76e5e176202c9ef68dc492cd23e69c50984a78c33",
        "clock": 384,
        "coverage_max": 384,
        "coverage_min": 384,
        "persistent_bytes": 25096,
        "schema": "o1-256-polyphase-sufficient-state-v1",
        "sha256": "9d3cf08570f64a31eac9723b10105d5948e5898a2da6ee1b9543d3f10e1046e1",
        "stream_length_dependent": false
      },
      "swap_t384": {
        "basis_sha256": "5f578f1917c5f80e662fb2c76e5e176202c9ef68dc492cd23e69c50984a78c33",
        "clock": 384,
        "coverage_max": 384,
        "coverage_min": 384,
        "persistent_bytes": 25096,
        "schema": "o1-256-polyphase-sufficient-state-v1",
        "sha256": "f2e652f5749069428c907580db532d9e38d76af731695bc82c948bba072b3a06",
        "stream_length_dependent": false
      },
      "t000": {
        "basis_sha256": "5f578f1917c5f80e662fb2c76e5e176202c9ef68dc492cd23e69c50984a78c33",
        "clock": 0,
        "coverage_max": 0,
        "coverage_min": 0,
        "persistent_bytes": 25096,
        "schema": "o1-256-polyphase-sufficient-state-v1",
        "sha256": "eeb93314b053584b14e51f692524e25aae4c7889d9bfde3d0b348cbc867adba9",
        "stream_length_dependent": false
      }
    },
    "stream_length_dependent": false
  },
  "wall_seconds": 0.0947189168073237,
  "work": {
    "consume_calls": 4,
    "direct_reference_group_updates": 384,
    "direct_reference_readout_calls": 4,
    "direct_reference_readout_slot_contributions": 12288,
    "direct_reference_resonator_cell_updates": 1179648,
    "generated_float32_evidence_values": 294912,
    "generated_groups": 384,
    "gpu_calls": 0,
    "gradient_steps": 0,
    "input_scalar_deliveries": 1032960,
    "label_reads": 0,
    "maximum_control_input_chunk_bytes": 3072,
    "mps_calls": 0,
    "network_calls": 0,
    "optimizer_steps": 0,
    "outcome_or_progress_reads": 0,
    "primary_consume_calls": 1,
    "primary_reingested_groups": 0,
    "replay_required_probes": 3,
    "resonator_cell_updates": 4131840,
    "schema": "o1-256-polyphase-sufficient-state-work-v1",
    "scientific_entropy_calls": 0,
    "sibling_reads": 0,
    "sibling_writes": 0,
    "solver_calls": 0,
    "source_buffer_bytes": 1179648,
    "source_generation_calls": 1,
    "source_plus_control_input_bytes": 1182720,
    "state_group_updates": 1345,
    "state_readout_scalar_slot_contributions": 36864,
    "successful_state_readout_calls": 12,
    "target_reads": 0,
    "total_query_attempts": 15,
    "trainable_parameters": 0
  }
}
```

## Next highest-ROI action

If every mechanism and resource gate passes, bind O1-O successor operators to immutable PolyphaseReadoutSpec values and feed real O1C-0022 causal packets through the unchanged one-pass state; if a gate fails, preserve the capsule and repair only the first localized mechanism under O1C-0028.
