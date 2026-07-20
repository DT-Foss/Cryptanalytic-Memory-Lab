# O1C Run O1C-0017

- Schema: `o1c-run-capsule-v1`
- Status: `completed`
- Claim level: `VALIDATION`
- Git commit: `22ea4dd0bfedd3134f82624ea434c9b339f35a73`
- Started (Europe/Berlin): `2026-07-17T14:09:53.149980+02:00`
- Ended (Europe/Berlin): `2026-07-17T14:11:13.024488+02:00`
- Elapsed seconds: `79.874508`
- Command: `o1-crypto-lab full256-online-self-discovery --config '/Users/bhkmie/Documents/Krypto karm/Kryptkram codex/o1-cryptanalytic-memory-lab/configs/full256_online_self_discovery_v1.json'`

## Hypothesis

A bounded carried O1 state with a signed holographic carrier, an exact 256-coordinate Bit-Vault and reveal-delayed online learning can autonomously discover and transfer an oriented predictive channel hidden among 330 anonymous raw causal channels without being told the channel identity or a hand-authored scalar signal.

## Prediction

After exactly eight deterministic known-label BUILD episodes, the unchanged O1 reader will attack sixteen disjoint full-256 evaluation episodes before scoring. Its mean key compression will be at least 16 bits; its mean margins over a hidden-channel signal ablation, a shuffled-label learner and its own raw end-of-stream O1 field will each be at least 12 bits; its aggregate bit accuracy will be at least 70 percent; and every evaluation target will have positive compression. Exact polarity-swap antisymmetry, common-only zero orientation, fixed fast-state bytes and complete 256-coordinate coverage must also hold.

## Controls

- all 330 raw channels are presented without the hidden channel index or a prescribed scalar feature
- the hidden-channel ablation reuses every label and every non-hidden raw value byte-for-byte
- the shuffled-label learner has the identical architecture, initialization and training pools but receives coordinate-shifted labels
- an identically initialized untrained reader measures architectural prior output
- the primary raw end-of-stream O1 field is frozen and scored separately from the addressed Bit-Vault to expose crosstalk and the vault retention delta
- this gate uses fixed exhaustive coordinate coverage to isolate autonomous channel discovery; it does not claim learned action-picker efficacy
- all sixteen evaluation seeds are disjoint from BUILD and were not used by exploratory development
- all evaluation predictions are persisted before label scoring
- polarity swapping must negate all 256 posterior logits exactly
- a common-only stream must produce exactly zero oriented evidence
- the carried fast state has fixed serialized bytes independent of stream history
- no ChaCha20, solver, fresh entropy, sibling repository, MPS or GPU claim or use occurs in this synthetic mechanism gate

## Budgets

```json
{
  "maximum_action_observations": 29184,
  "maximum_cpu_seconds": 180,
  "maximum_fresh_entropy_calls": 0,
  "maximum_gpu_calls": 0,
  "maximum_mps_calls": 0,
  "maximum_persistent_artifact_bytes": 4000000,
  "maximum_resident_memory_mib": 512,
  "maximum_sibling_reads": 0,
  "maximum_sibling_writes": 0,
  "maximum_wall_seconds": 180
}
```

## Pinned source hashes

- `module_cadical_sensor`: `af24c17ae98817d6ad5d6fa30be227aecaf4be3753738bda3c34fae12948fa90`
- `module_chacha_trace`: `58b8272f2cdd6665291158cecc2456258d3cb58f2ab3970d1c4c38e749473b01`
- `module_cli`: `8fcdd1f230cd4ba0abc67c487ca54741e410a92242161c9ffba98d2cd364170f`
- `module_full256_action_pool`: `df0d6a0df60d811e7cf674aa1a91b22a80834fab3acee534f77f7e1c289c1883`
- `module_living_inverse`: `16c22a9776b693c40e0d6c3a3196c73c7a4c15913bde0bdb14e8d9fc4dbe127e`
- `module_o1_streaming_core`: `c918789a668d2e4a47f927cfe44e7e0dd3825e84dfa46e29aa48dee14d737fd7`
- `module_online_causal_controller`: `b987f2dc840a284dcbde1ec4849b8d7e904de116764d2086cf1ea3343718b094`
- `module_online_self_discovery`: `3c5aa83fb743b8991112419a093c2c793441bd7da28d475311752824796fab6a`
- `module_orchestrator`: `3351034b5a7fdc59a972834e62e5b469b0e04d7464594a4c954f38c95044b114`
- `module_run_capsule`: `13681939e0a5cd09d4f32c6d92c9a56894cfe8af90f07d5d4190c96b90a1b664`
- `module_types`: `91e3e8116b40fec516b6467dd4e22ae7a4aed9e4343f0dcce80be8b9da6d6693`
- `online_self_discovery_config`: `6bab5437954da6b26e4db0ac3b0a5a613b0a3180c4a406500264615ff908971b`
- `pyproject`: `0248ec0fe7d42390b62e358fdd52f63d64f7d4e699f0f41ef77c569699716bd0`

## Metrics

```json
{
  "action_observations": 29184,
  "arms": {
    "hidden_channel_ablation": {
      "bit_accuracy": 0.49658203125,
      "compression_stddev_bits": 4.643596096448939,
      "conditional_z_score": -3.7838356618610547,
      "correct_bits": 2034,
      "exact_keys": 0,
      "maximum_correct_bits": 137,
      "mean_compression_bits": -4.39265112725557,
      "mean_correct_bits_per_target": 127.125,
      "mean_nll_bits": 260.3926511272556,
      "minimum_correct_bits": 105,
      "name": "hidden_channel_ablation",
      "positive_targets": 2,
      "total_bits": 4096
    },
    "primary_learned": {
      "bit_accuracy": 0.80224609375,
      "compression_stddev_bits": 2.979951882837056,
      "conditional_z_score": 56.79117483378771,
      "correct_bits": 3286,
      "exact_keys": 0,
      "maximum_correct_bits": 213,
      "mean_compression_bits": 42.30874209361853,
      "mean_correct_bits_per_target": 205.375,
      "mean_nll_bits": 213.69125790638148,
      "minimum_correct_bits": 195,
      "name": "primary_learned",
      "positive_targets": 16,
      "total_bits": 4096
    },
    "primary_raw_end_of_stream_o1_field": {
      "bit_accuracy": 0.50244140625,
      "compression_stddev_bits": 9.438050869867006,
      "conditional_z_score": -2.08626923394693,
      "correct_bits": 2058,
      "exact_keys": 0,
      "maximum_correct_bits": 143,
      "mean_compression_bits": -4.922578789557399,
      "mean_correct_bits_per_target": 128.625,
      "mean_nll_bits": 260.9225787895574,
      "minimum_correct_bits": 112,
      "name": "primary_raw_end_of_stream_o1_field",
      "positive_targets": 3,
      "total_bits": 4096
    },
    "shuffled_label_learner": {
      "bit_accuracy": 0.51025390625,
      "compression_stddev_bits": 1.511788568378335,
      "conditional_z_score": -1.2069276079807478,
      "correct_bits": 2090,
      "exact_keys": 0,
      "maximum_correct_bits": 152,
      "mean_compression_bits": -0.45615484015137575,
      "mean_correct_bits_per_target": 130.625,
      "mean_nll_bits": 256.4561548401514,
      "minimum_correct_bits": 109,
      "name": "shuffled_label_learner",
      "positive_targets": 8,
      "total_bits": 4096
    },
    "untrained_reader": {
      "bit_accuracy": 0.49365234375,
      "compression_stddev_bits": 3.5880032049654296,
      "conditional_z_score": -8.17918720873319,
      "correct_bits": 2022,
      "exact_keys": 0,
      "maximum_correct_bits": 141,
      "mean_compression_bits": -7.336737479736733,
      "mean_correct_bits_per_target": 126.375,
      "mean_nll_bits": 263.3367374797367,
      "minimum_correct_bits": 104,
      "name": "untrained_reader",
      "positive_targets": 0,
      "total_bits": 4096
    }
  },
  "budget_checks": {
    "action_observations": true,
    "cpu": true,
    "fresh_entropy": true,
    "gpu": true,
    "mps": true,
    "native_solver_branches": true,
    "persistent_artifacts": true,
    "resident_memory": true,
    "sibling_reads": true,
    "sibling_writes": true,
    "wall": true
  },
  "claim_boundary": {
    "autonomous_signal_channel_discovery_evaluated": true,
    "bit_vault_retention_evaluated": true,
    "cryptographic_inverse_signal_claimed": false,
    "fixed_full_coordinate_coverage": true,
    "holographic_or_streaming_advantage_claimed": false,
    "learned_action_picker_evaluated": false,
    "o1_memory_necessity_evaluated": false,
    "purpose": "online representation integration and Bit-Vault retention gate",
    "raw_holographic_end_state_reported": true,
    "standard_chacha20_target": false,
    "stateless_baseline_evaluated": false,
    "synthetic_full_256_key": true
  },
  "classification": "MECHANISM_PASS",
  "cpu_seconds": 78.088885,
  "evaluation_labels_scored": 16,
  "failed_budgets": [],
  "failure_reasons": [],
  "fresh_entropy_calls": 0,
  "gpu_calls": 0,
  "margins": {
    "primary_minus_channel_ablation_mean_bits": 46.701393220874095,
    "primary_minus_channel_ablation_z": 53.7266887237991,
    "primary_minus_shuffled_mean_bits": 42.764896933769904,
    "primary_minus_shuffled_z": 80.65211750104224,
    "primary_vault_minus_raw_end_state_mean_bits": 47.231320883175925,
    "primary_vault_minus_raw_end_state_z": 16.432665611850812
  },
  "mps_calls": 0,
  "outcome_failed": false,
  "peak_rss_bytes": 300351488,
  "peak_rss_mib": 286.4375,
  "persisted_artifact_count": 9,
  "persistent_artifact_bytes": 285581,
  "planned_action_observations": 29184,
  "predictions_persisted_before_scoring": true,
  "result_sha256": "609014695bc3013bb971d7d05b682d18797af5c9d9cd31561cdc41de120ff28c",
  "schema": "o1-256-online-self-discovery-cli-result-v1",
  "scientific_gates": {
    "all_256_coordinates_observed": true,
    "common_only_orientation_zero": true,
    "constant_fast_state_bytes": true,
    "every_evaluation_target_positive": true,
    "exact_polarity_swap_antisymmetry": true,
    "primary_bit_accuracy_gate": true,
    "primary_mean_compression_gate": true,
    "primary_over_channel_ablation_gate": true,
    "primary_over_shuffled_learner_gate": true,
    "primary_vault_over_raw_end_state_gate": true,
    "success_gate_passed": true,
    "synthetic_only_no_crypto_claim": true,
    "zero_fresh_entropy_calls": true,
    "zero_gpu_calls": true,
    "zero_mps_calls": true
  },
  "scientific_success_gate_passed": true,
  "sibling_reads": 0,
  "sibling_writes": 0,
  "wall_seconds": 79.85265695815906
}
```

## Next highest-ROI action

If the gate passes, preserve the exact learned slow states and replace only the synthetic episode generator with deterministic known-key standard twenty-round ChaCha20 paired proof pools while retaining the anonymous raw-channel input, frozen whole-key evaluation boundary, Bit-Vault, ablation, shuffled-label and untrained controls. Add multiple legal horizons and a strict sub-exhaustive work budget there so the learned pool-blind picker is tested against fixed-order and uniform controls. If this gate fails, use per-arm and per-target artifacts as breadcrumbs and change one representation or learning mechanism rather than lowering the gate.
