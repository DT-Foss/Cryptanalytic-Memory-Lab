# O1C Run O1C-0022

- Schema: `o1c-run-capsule-v1`
- Status: `completed`
- Claim level: `RETROSPECTIVE`
- Git commit: `7846a2789ceb2218128070e5edc49de90d7e67bc`
- Started (Europe/Berlin): `2026-07-18T19:06:29.916204+02:00`
- Ended (Europe/Berlin): `2026-07-18T19:07:40.134152+02:00`
- Elapsed seconds: `70.217948`
- Command: `/opt/anaconda3/bin/python -m o1_crypto_lab.o1c19_causal_vault_bridge_run --config '/Users/bhkmie/Documents/Krypto karm/Kryptkram codex/o1-cryptanalytic-memory-lab/configs/o1c19_causal_vault_bridge_v1.json'`

## Hypothesis

A frozen O1C-0019 reader exposes attacker-valid, coordinate-oriented incremental full-round proof evidence that survives deterministic int8 quantization and bounded addressed accumulation as width grows from 12 to all 256 coordinates.

## Prediction

Across four BUILD leave-one-out folds, quantized accumulation preserves at least 90 percent of positive float compression, reaches at least one mean bit of K=256 compression, is positive in every fold and beats the coordinate-shuffled matched-work control, while duplicate, complement, coordinate and lifecycle invariants remain exact.

## Controls

- The future O1C-0019 capsule is resolved by its reserved attempt identity, verified manifest and exact frozen source config; no O1C-0019 efficacy result participates in this source freeze.
- Every fold loads only its frozen reader and learning receipt plus the four immutable public BUILD action pools before held-out prediction freeze.
- Per-horizon quantizer scales are medians of finite nonzero absolute deltas from the three non-held-out public replays; labels and signed reward never enter scale fitting.
- Nested active sets K=12/52/128/256 are prefixes of one SHA-256-derived coordinate permutation while all 256 target key bits remain unknown.
- Float delta sum, quantized int8 vault, last-horizon-only, unit-sign and coordinate-shuffled arms receive matched public packet slots.
- Immediate duplicate groups must leave the complete 352-byte accumulator byte-identical and accepted-update counts unchanged.
- Polarity swap must negate every finite packet delta and vault logit; coordinate permutation must commute with accumulation to float32 tolerance.
- For every fold, all predictions, delta ledgers, scales and live-state commitments freeze before that fold's held-out BUILD label is used; the held-out ordinal is excluded from its calibration-label ledger.
- No solver regeneration, fresh entropy, sibling access, MPS call or GPU call is permitted.

## Budgets

```json
{
  "expected_existing_build_pools": 4,
  "maximum_accumulator_live_state_bytes": 352,
  "maximum_calibration_value_evaluations": 7391232,
  "maximum_cpu_seconds": 600.0,
  "maximum_gpu_calls": 0,
  "maximum_mps_calls": 0,
  "maximum_native_solver_branches": 0,
  "maximum_o1c19_reader_replays": 32,
  "maximum_packet_slot_observations": 17664,
  "maximum_persistent_artifact_bytes": 33554432,
  "maximum_physical_public_pools_generated": 0,
  "maximum_physical_public_work_units": 1130496,
  "maximum_resident_memory_mib": 768,
  "maximum_scientific_entropy_calls": 0,
  "maximum_sibling_reads": 0,
  "maximum_sibling_writes": 0,
  "maximum_source_artifact_bytes_read": 33554432,
  "maximum_wall_seconds": 600.0
}
```

## Pinned source hashes

- `config`: `ea313fd6bb80384e4ef73e4a72f3705c79b2a98ad5a69552d043657b56f1a10d`
- `module_causal_evidence_stream`: `f1f5c8df9a9481abdcae610d5020cd80b01f96725e5524cb32cac64a18c1fb07`
- `module_causal_evidence_stream_run`: `19bce0f4ee135557489c73252393d0720ed8c10f34f4f0cd2127bc414a3ff79c`
- `module_full256_action_pool`: `df0d6a0df60d811e7cf674aa1a91b22a80834fab3acee534f77f7e1c289c1883`
- `module_full256_multiresolution_build_loo`: `34654f54e66a91ee8ac517c9022d7f41e943b22ebb63304bb463f9730a20a740`
- `module_full256_multiresolution_build_loo_run`: `36f03de45a7841f02feb713e0188c52d5ef9259b8e4d6e40e398c8e804c2c30d`
- `module_living_inverse`: `16c22a9776b693c40e0d6c3a3196c73c7a4c15913bde0bdb14e8d9fc4dbe127e`
- `module_o1_streaming_core`: `c918789a668d2e4a47f927cfe44e7e0dd3825e84dfa46e29aa48dee14d737fd7`
- `module_o1c19_causal_vault_bridge`: `82b8f1724ce5c6e348aeb1e100340276bb84c842b9429203f0d2bef25e2cbb55`
- `module_o1c19_causal_vault_bridge_run`: `330c099b3a569073fa2055292bcfa787e99eb576998fdca5f4dd2c9bf0b082df`
- `module_online_causal_controller`: `e28cd7d43b71040d91ea850d1ff76b700feaa20996825ea35448221c9936f157`
- `module_online_multiresolution_controller`: `4833513502d18ad390b7e5e572f97608d7b31c94c1fa38ceed74b02a7fb79a58`
- `module_run_capsule`: `13681939e0a5cd09d4f32c6d92c9a56894cfe8af90f07d5d4190c96b90a1b664`
- `o1c18_artifact_corpus`: `d137a931782b19e2cd8fdd44f38a9109d239ba332605c3a512078ca314c1be64`
- `o1c18_artifact_index`: `e6b79631057d5a9fa75004ee0b62aea06fe9430c6a9d3cc9b7ae4b3954d8ed85`
- `o1c18_capsule_manifest`: `fcbf43c99994c0debe5b39bb3e734ea1d1e23ba58e89b10ff2bb7e23886493fb`
- `o1c19_artifact_index`: `ba4bdd20c7ab076f73d0fc5705bb7b4b44445c6b5f9f89755e7f0e0c8b4d9705`
- `o1c19_capsule_manifest`: `d636d9359c8e5f85f21e0903334d4a8fb172b4a216ad8413f1578dc471f431d7`
- `o1c19_fold_00_learning_freeze`: `e7e4de3ec1e4732c35ef500cf9a2d5104ada63c966b80f225cb9d8aa58344ed2`
- `o1c19_fold_00_prediction_freeze`: `1e75da35c47cbc75719abd9e23e81a001b360ae644f357fdb5e2a8b5086ac566`
- `o1c19_fold_00_reader`: `8824fefafa56fde83724bf965b8441a3673bb72de4f7f8bcc23d43084193ced0`
- `o1c19_fold_00_slow_state`: `4f2caddc76dcc7a1a83b38f6d5b7ae17ce7b7bc3f1db2a545a2470f3ef7ce98e`
- `o1c19_fold_01_learning_freeze`: `46d17e43e421b3197c3bf3ff063306f7792e3b4fd47313aa5ebe5b22a27eb1d1`
- `o1c19_fold_01_prediction_freeze`: `b69c184e6fa736b7f2038a4d658acb65db360d268374ad68ff8ffc931a5acf97`
- `o1c19_fold_01_reader`: `ab04efeb64bbc2f1d7fd9d78f6a5ef54bc00804d793736105579ab7b0c4cf98e`
- `o1c19_fold_01_slow_state`: `c6cc034e9c98684e602b0f6a25fc26fa5cb3e34c9e0fb1532cb27f37f2747965`
- `o1c19_fold_02_learning_freeze`: `cdf9fb1bf74f313b202be24663c684d7f37a0dacafc7ac90aeed4d9e5e5be3e5`
- `o1c19_fold_02_prediction_freeze`: `0c599fbe92717d423367a526486ed0036a49db3ebae595a1f2a0df071f4aad52`
- `o1c19_fold_02_reader`: `7363dd8661bf56158bbf713c5c8284cd50933f18094f4030caba28ebb36f0028`
- `o1c19_fold_02_slow_state`: `ace27de94e5d6884730dd2fbaf963ed020ccbd460841fb8d2e0b0d7452c1555f`
- `o1c19_fold_03_learning_freeze`: `baa8e55d8aec3339a6e95ee8a47cc8421d218772d720e7365e2da1fbfa20cd73`
- `o1c19_fold_03_prediction_freeze`: `dfdf93e7761baac9601c6bd8813c076d6837b5864f36ffc8051b9a4ce6eef81e`
- `o1c19_fold_03_reader`: `ffff211df0737332a425c091fb47998bf270a3861912b02e712721747fe1869b`
- `o1c19_fold_03_slow_state`: `91c38866c4504ec8ff1621e07cfd9415a7716729db218bc5f17d1a6cfb105166`
- `o1c19_result`: `7546b2a526c20f45dd936c9d9838ddafa72b535ea39a05a81c5e206e5aa56ad8`
- `o1c19_source_config`: `96d9017d2262537281218ccd23b52533c8ed801e245bea6bcb13fa13bd186c61`
- `o1c21_source_config`: `c683237f7f251ffb2314b01cfbfbbfeac9acd557379a3070e982c0bc15b4a39d`
- `pyproject`: `0248ec0fe7d42390b62e358fdd52f63d64f7d4e699f0f41ef77c569699716bd0`

## Metrics

```json
{
  "budget_checks": {
    "calibration_value_evaluations": true,
    "cpu": true,
    "existing_build_pools": true,
    "gpu": true,
    "live_state": true,
    "mps": true,
    "native_solver_branches": true,
    "packet_slots": true,
    "persistent_artifacts": true,
    "physical_public_pools_generated": true,
    "public_work": true,
    "reader_replays": true,
    "resident_memory": true,
    "scientific_entropy": true,
    "sibling_reads": true,
    "sibling_writes": true,
    "source_artifact_bytes_read": true,
    "wall": true
  },
  "calibration_value_evaluations": 7391232,
  "classification": "CROSS_COORDINATE_DILUTION",
  "cpu_seconds": 70.081227,
  "failed_budgets": [],
  "failed_gates": [
    "all_four_final_folds_positive",
    "int8_mean_final_compression_bits_minimum",
    "int8_minus_coordinate_shuffled_mean_compression_positive",
    "int8_minus_last_horizon_only_mean_compression_positive",
    "int8_minus_unit_sign_sum_mean_compression_positive",
    "int8_preserves_float_compression_fraction_minimum",
    "strict_mean_compression_growth_across_k"
  ],
  "gates": {
    "actual_polarity_swapped_pool_delta_and_logit_antisymmetry": true,
    "all_duplicate_groups_full_state_byte_invariant": true,
    "all_fold_calibration_predictions_frozen_before_that_folds_calibration_label_use": true,
    "all_fold_heldout_predictions_frozen_before_that_folds_heldout_label_use": true,
    "all_four_final_folds_positive": false,
    "all_predictions_finite": true,
    "all_primary_live_states_exactly_352_bytes": true,
    "calibration_scales_nonnegative_without_orientation_flip": true,
    "calibration_value_evaluations_exact": true,
    "coordinate_permutation_commutes_with_accumulation": true,
    "every_fold_excludes_its_heldout_label_from_calibration": true,
    "int8_mean_final_compression_bits_minimum": false,
    "int8_minus_coordinate_shuffled_mean_compression_positive": false,
    "int8_minus_last_horizon_only_mean_compression_positive": false,
    "int8_minus_unit_sign_sum_mean_compression_positive": false,
    "int8_preserves_float_compression_fraction_minimum": false,
    "integrity_gate_passed": true,
    "matched_public_packet_work_for_all_derived_arms": true,
    "packet_slot_observations_exact": true,
    "physical_public_work_units_exact": true,
    "reader_replays_exact": true,
    "strict_mean_compression_growth_across_k": false,
    "zero_solver_entropy_sibling_mps_gpu_work": true
  },
  "margins": {
    "coordinate_shuffled_mean_final_compression_bits": 0.0,
    "int8_mean_compression_curve_bits": [
      -0.006771658785368118,
      -0.021456561682271058,
      -0.5804580628450253,
      -1.1818371316239364
    ],
    "int8_mean_final_compression_bits": -1.1818371316239364,
    "int8_minus_coordinate_shuffled_mean_final_compression_bits": -1.1818371316239364,
    "int8_minus_last_horizon_only_mean_final_compression_bits": -1.1174390263477676,
    "int8_minus_unit_sign_sum_mean_final_compression_bits": -1.0666464482869102,
    "int8_preserves_normalized_float_fraction": 0.0,
    "last_horizon_only_mean_final_compression_bits": -0.06439810527616885,
    "normalized_float_mean_final_compression_bits": -1.5775239582612883,
    "raw_float_mean_final_compression_bits": -0.9898077985001521,
    "unit_sign_sum_mean_final_compression_bits": -0.1151906833370262
  },
  "operationally_complete": true,
  "packet_slots": 17664,
  "peak_rss_bytes": 297910272,
  "persistent_artifact_bytes": 11841772,
  "physical_public_work_units": 1130496,
  "reader_replays": 32,
  "result_sha256": "888a9ec9b77d09080b2e896b929d0546f965040848c27d525a0d97965756b7be",
  "schema": "o1-256-o1c19-causal-vault-bridge-cli-result-v1",
  "scientific_success_gate_passed": false,
  "source_artifact_bytes_read": 9211170,
  "wall_seconds": 70.19497245799994
}
```

## Next highest-ROI action

If the float and int8 arms remain positive and control-specific at K=256, freeze the exact reader-plus-vault lineage and spend one untouched full-round DEVELOPMENT pool under a new prospective attempt. If they fail, use the nested width and float-versus-int8 decomposition to change only the identified reader, quantizer or cross-coordinate state mechanism.
