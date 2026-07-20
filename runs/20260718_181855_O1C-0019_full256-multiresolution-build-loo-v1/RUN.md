# O1C Run O1C-0019

- Schema: `o1c-run-capsule-v1`
- Status: `completed`
- Claim level: `RETROSPECTIVE`
- Git commit: `f2285f4a1d2777396d985a248e0839634f0e27e9`
- Started (Europe/Berlin): `2026-07-18T18:18:55.920437+02:00`
- Ended (Europe/Berlin): `2026-07-18T19:00:03.245908+02:00`
- Elapsed seconds: `2467.325471`
- Command: `/opt/anaconda3/bin/python -m o1_crypto_lab.full256_multiresolution_build_loo_run --config '/Users/bhkmie/Documents/Krypto karm/Kryptkram codex/o1-cryptanalytic-memory-lab/configs/full256_multiresolution_build_loo_v1.json'`

## Hypothesis

A packetized q_after-minus-q_before O1 reader with a reader-bound episode-equal stationarity critic can learn transferable full-round 256-bit BUILD structure and autonomously route physical conflict work better than shifted, static, and hash mechanisms.

## Prediction

The fixed exhaustive learned reader beats its untrained twin in mean 256-bit compression, while the true stationary ACTION/STOP policy beats shifted-label, no-STOP, static, and uniform-hash diagnostics in normalized information area without generating any new proof pool.

## Controls

- Four symmetric BUILD leave-one-out folds with a fresh reader and critic lineage per fold.
- Shifted-label stationarity critic with byte-identical final reader and byte-identical contexts.
- True stationary route with STOP disabled to isolate picker routing from abstention.
- Fold-local static mean packet reward recomputed only after the final reader freeze.
- Pool-blind uniform-hash picker under the identical affordability and starvation field.
- Fixed exhaustive learned-reader versus untrained-reader trajectory on the same action order.
- Zero solver regeneration, fresh entropy, sibling access, MPS calls, or GPU calls.

## Budgets

```json
{
  "expected_existing_build_pools": 4,
  "maximum_cpu_seconds": 7200.0,
  "maximum_gpu_calls": 0,
  "maximum_mps_calls": 0,
  "maximum_native_solver_branches": 0,
  "maximum_persistent_artifact_bytes": 50000000,
  "maximum_physical_public_pools_generated": 0,
  "maximum_resident_memory_mib": 1024,
  "maximum_scientific_entropy_calls": 0,
  "maximum_sibling_reads": 0,
  "maximum_sibling_writes": 0,
  "maximum_source_artifact_bytes_read": 16000000,
  "maximum_wall_seconds": 7200.0
}
```

## Pinned source hashes

- `config`: `96d9017d2262537281218ccd23b52533c8ed801e245bea6bcb13fa13bd186c61`
- `module_full256_action_pool`: `df0d6a0df60d811e7cf674aa1a91b22a80834fab3acee534f77f7e1c289c1883`
- `module_full256_multiresolution_build_loo`: `34654f54e66a91ee8ac517c9022d7f41e943b22ebb63304bb463f9730a20a740`
- `module_full256_multiresolution_build_loo_run`: `36f03de45a7841f02feb713e0188c52d5ef9259b8e4d6e40e398c8e804c2c30d`
- `module_full256_proof_pool`: `7fec03dd03ffe61144f836491db9be7094dda20a80e1aedd4e6a7c26a689d30c`
- `module_living_inverse`: `16c22a9776b693c40e0d6c3a3196c73c7a4c15913bde0bdb14e8d9fc4dbe127e`
- `module_o1_streaming_core`: `c918789a668d2e4a47f927cfe44e7e0dd3825e84dfa46e29aa48dee14d737fd7`
- `module_online_causal_controller`: `e28cd7d43b71040d91ea850d1ff76b700feaa20996825ea35448221c9936f157`
- `module_online_multiresolution_controller`: `4833513502d18ad390b7e5e572f97608d7b31c94c1fa38ceed74b02a7fb79a58`
- `module_run_capsule`: `13681939e0a5cd09d4f32c6d92c9a56894cfe8af90f07d5d4190c96b90a1b664`
- `module_stationarity_critic`: `80ad977cb2ad6591866aff77da8ef101f1371a68b3a894a52655b6f376dc0a28`
- `pyproject`: `0248ec0fe7d42390b62e358fdd52f63d64f7d4e699f0f41ef77c569699716bd0`
- `source_artifact_corpus`: `d137a931782b19e2cd8fdd44f38a9109d239ba332605c3a512078ca314c1be64`
- `source_artifact_index`: `e6b79631057d5a9fa75004ee0b62aea06fe9430c6a9d3cc9b7ae4b3954d8ed85`
- `source_capsule_manifest`: `fcbf43c99994c0debe5b39bb3e734ea1d1e23ba58e89b10ff2bb7e23886493fb`
- `source_config`: `a8e19525e62d60977a2c32b822ad169791f021b55633517b14ff831c56e81a7a`
- `source_pool_0000`: `0473112acf83efec096418c90e14aa394fc86ff286b4923dd6caa3c7cba79520`
- `source_pool_0001`: `47c184183f1211bd0a718cccf4ab202446574d9e21d5a969920280b8c0eb6df5`
- `source_pool_0002`: `fcee9c6c05e40c47023417acf7df34bbcf694398b650810b96d6640871ad7b06`
- `source_pool_0003`: `04a4b19797877fd7f6fc6dec9cd7af5b7608a5eab765090600be4567562bde0b`
- `source_result`: `a8e5940edc5887e404725c98631df89e1f91963abd47d1fa51263fc681e9df4d`

## Metrics

```json
{
  "budget_checks": {
    "cpu": true,
    "existing_build_pools": true,
    "gpu": true,
    "mps": true,
    "native_solver_branches": true,
    "persistent_artifacts": true,
    "physical_public_pools_generated": true,
    "resident_memory": true,
    "scientific_entropy": true,
    "sibling_reads": true,
    "sibling_writes": true,
    "source_artifact_bytes_read": true,
    "wall": true
  },
  "classification": "BUILD_LOO_NO_TRANSFER",
  "cpu_seconds": 2519.744295,
  "failed_budgets": [],
  "gates": {
    "all_checkpoint_paths_are_nested": true,
    "all_checkpoint_work_within_caps": true,
    "all_critics_bound_to_exact_reader_sha256": true,
    "all_critics_refit_after_final_reader_freeze": true,
    "all_held_out_predictions_frozen_before_fold_label_access": true,
    "learned_picker_over_all_controls": false,
    "learned_policy_positive_final_compression": false,
    "only_existing_build_action_pools_loaded": true,
    "raw_learned_reader_over_untrained": false,
    "raw_learned_reader_positive_compression": true,
    "raw_reader_paths_share_fixed_action_order": true,
    "reader_isolated_gate_passed": false,
    "source_artifact_index_verified": true,
    "source_finalized_manifest_verified": true,
    "stop_enabled_route_is_no_stop_prefix": true,
    "stop_is_distinct_from_field_exhaustion": true,
    "structural_gate_passed": true,
    "success_gate_passed": false,
    "true_shifted_critic_contexts_are_identical": true,
    "zero_current_held_out_slow_updates": true,
    "zero_gpu_calls": true,
    "zero_mps_calls": true,
    "zero_native_solver_branches": true,
    "zero_physical_public_pools_generated": true,
    "zero_scientific_entropy_calls": true,
    "zero_sibling_reads": true,
    "zero_sibling_writes": true
  },
  "margins": {
    "learned_final_mean_compression_bits": -0.27108980858033505,
    "learned_minus_hash_mean_iauc_bits": -0.17358078280330907,
    "learned_minus_shifted_mean_iauc_bits": -0.2235240027729981,
    "learned_minus_static_mean_iauc_bits": -0.14231448635284685,
    "learned_over_all_policy_controls_folds": 1,
    "learned_stop_minus_no_stop_mean_iauc_bits": 0.0,
    "raw_learned_mean_compression_bits": 0.312763538118368,
    "raw_learned_minus_untrained_mean_compression_bits": -0.05846952102739067
  },
  "native_solver_branches": 0,
  "operational_failure": false,
  "operationally_complete": true,
  "peak_rss_bytes": 362528768,
  "persistent_artifact_bytes": 1538916,
  "physical_public_pools_generated": 0,
  "result_sha256": "307998072a70db9d68811531c72aafc724af5992d16276f7e5f28ca9faca3b95",
  "schema": "o1-256-fullround-multiresolution-build-loo-cli-result-v1",
  "scientific_success_gate_passed": false,
  "source_artifact_bytes_read": 8336169,
  "wall_seconds": 2467.2997065
}
```

## Next highest-ROI action

If reader-isolated transfer and learned policy advantage both survive all four BUILD folds, freeze this exact O1C-0019 lineage and attack one untouched DEVELOPMENT pool under a new disjoint attempt. Otherwise preserve the per-fold reader, stationarity, STOP, and agency breadcrumbs and change only the failed mechanism.
