# O1C Run O1C-0020

- Schema: `o1c-run-capsule-v1`
- Status: `completed`
- Claim level: `VALIDATION`
- Git commit: `3aefaf7a88aaf425bd52bc1c56614348a024ba1c`
- Started (Europe/Berlin): `2026-07-17T21:14:33.663940+02:00`
- Ended (Europe/Berlin): `2026-07-17T21:14:43.578906+02:00`
- Elapsed seconds: `9.914966`
- Command: `/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -m o1_crypto_lab.selective_mqar_run --config '/Users/bhkmie/Documents/Krypto karm/Kryptkram codex/o1-cryptanalytic-memory-lab/configs/selective_mqar_256_v1.json'`

## Hypothesis

A BUILD-trained O1 input gate can route a unified public MQAR token stream into a fixed 256-coordinate packed Bit-Vault without an oracle update mask, preserving all 256 bindings exactly while rejecting at least 2^20 OOD distractors in a stream-length-independent live state.

## Prediction

On four disjoint EVALUATION seeds and every haystack length 0, 65536 and 1048576, the frozen primary gate will produce TP=256, FN=0 and FP=0, the 352-byte O1-plus-vault live state will recall exactly 256/256 bits and remain identical across nested lengths, literal and compacted replay will be byte-exact, and shuffled-label, untrained, cue-rotated, cue-ablated and all-open controls will not all recover exactly.

## Controls

- an oracle update mask is scored only after prediction freeze as an explicit ceiling
- an identically initialized gate receives a deterministic permutation of BUILD route labels with identical examples, class counts and optimizer work
- the trained primary gate is evaluated with a registered family-cue rotation and with all family-cue coordinates ablated
- the byte-identical neutral initialization is evaluated with zero training steps and the primary frozen threshold
- an all-open vault accepts every public token so late distractors honestly overwrite bindings
- 64-slot CountSketch and 64-channel holographic memories receive the same learned-selected writes
- a 2^20-token no-binding stream must produce zero accepts and an unchanged initial live-state digest
- a 4096-token literal masked replay must equal sparse selected-token replay byte-for-byte

## Budgets

```json
{
  "maximum_cpu_seconds": 180,
  "maximum_gate_token_evaluations": 24000000,
  "maximum_gpu_calls": 0,
  "maximum_live_state_bytes": 352,
  "maximum_mps_calls": 0,
  "maximum_native_solver_branches": 0,
  "maximum_persistent_artifact_bytes": 4000000,
  "maximum_resident_memory_mib": 512,
  "maximum_scientific_entropy_calls": 0,
  "maximum_sibling_reads": 0,
  "maximum_sibling_writes": 0,
  "maximum_training_token_exposures": 11000000,
  "maximum_wall_seconds": 180
}
```

## Pinned source hashes

- `config`: `2bd6509696986bf0f77e5b7aef9bbfa843deb85b1ed4a8140f93a60f1e2ae24d`
- `module_isolation`: `50399219de30c9f9e3ed23ee1d5b4c434d8736107316a7647276aa481900b652`
- `module_memory`: `75fa10898fe49dd67aa1294915658e463ce5f7753839a588d080f22022351188`
- `module_o1_streaming_core`: `c918789a668d2e4a47f927cfe44e7e0dd3825e84dfa46e29aa48dee14d737fd7`
- `module_run_capsule`: `13681939e0a5cd09d4f32c6d92c9a56894cfe8af90f07d5d4190c96b90a1b664`
- `module_selective_mqar`: `f197a792d2fbc09a247f2eb42925738b97437269ef2756b95ca8be075c87071a`
- `module_selective_mqar_run`: `dcc347e32d63fa568e11741de45428714951bbbdf435996eba1fbff716e6f9cc`
- `pyproject`: `0248ec0fe7d42390b62e358fdd52f63d64f7d4e699f0f41ef77c569699716bd0`

## Metrics

```json
{
  "budget_checks": {
    "cpu": true,
    "gate_token_evaluations": true,
    "gpu": true,
    "live_state": true,
    "mps": true,
    "native_solver_branches": true,
    "persistent_artifacts": true,
    "resident_memory": true,
    "scientific_entropy": true,
    "sibling_reads": true,
    "sibling_writes": true,
    "training_token_exposures": true,
    "wall": true
  },
  "classification": "EXACT_256_LEARNED_GATE_RETENTION",
  "cpu_seconds": 9.55336,
  "failed_budgets": [],
  "gates": {
    "calibration_positive_margin": true,
    "calibration_zero_errors": true,
    "every_control_fails_every_longest_cell": true,
    "global_public_route_certificate_positive": true,
    "literal_compaction_byte_exact": true,
    "literal_compaction_mixes_all_bindings_and_rejections": true,
    "live_state_width_exact": true,
    "no_binding_state_held": true,
    "no_binding_zero_accepts": true,
    "oracle_all_exact": true,
    "primary_all_cells_exact_256_of_256": true,
    "primary_all_routes_exact": true,
    "primary_core_replay_complete": true,
    "primary_nested_live_state_exact": true,
    "primary_nested_prediction_exact": true,
    "primary_queries_hold_state": true,
    "primary_random_query_projection_exact": true,
    "primary_slow_state_unchanged": true,
    "registered_controls_not_all_exact": true,
    "storage_controls_available_and_not_all_exact": true,
    "truth_revealed_once_after_freeze": true
  },
  "operationally_complete": true,
  "peak_rss_bytes": 438747136,
  "persistent_artifact_bytes": 945387,
  "result_sha256": "6c12a0fcb9e0b58a86b8bea340ea475294b530372c9a9a28ddaa62724cab8cb5",
  "schema": "o1-256-selective-mqar-cli-result-v1",
  "scientific_success_gate_passed": true,
  "state": {
    "audit_evaluator_state_excluded_from_model_live_state": true,
    "audit_masks_persisted_bytes": 688512,
    "audit_masks_retained_in_evaluator_bytes": 3475712,
    "model_external_index_bytes": 0,
    "model_retained_transcript_bytes": 0,
    "model_stream_length_dependent_state_bytes": 0,
    "o1_fast_state_bytes": 288,
    "prediction_freeze_artifact_bytes": 811409,
    "primary_slow_parameter_count": 2216,
    "primary_slow_raw_float32_bytes": 8864,
    "primary_slow_state_bytes": 9767,
    "primary_slow_state_sha256": "853d8e643228924969d4488b6a0925c27eba2f9cf298575b58dcb9bdf6b4e5dd",
    "slow_state_billed_separately": true,
    "total_live_state_bytes": 352,
    "vault_bytes": 64
  },
  "training_token_exposures": 10485760,
  "wall_seconds": 9.889870957937092,
  "work": {
    "gate_token_evaluations": 23366656,
    "gpu_calls": 0,
    "literal_core_token_calls": 4352,
    "literal_core_updates": 512,
    "mps_calls": 0,
    "native_solver_branches": 0,
    "no_binding_core_updates": 0,
    "oracle_public_tokens_replayed_post_freeze": 4459520,
    "primary_core_updates": 3072,
    "primary_vault_writes": 3072,
    "query_tokens": 3072,
    "scientific_entropy_calls": 0,
    "sibling_reads": 0,
    "sibling_writes": 0,
    "unique_evaluation_public_tokens": 4195328
  }
}
```

## Next highest-ROI action

If exact 256/256 learned-mask retention passes through 2^20 distractors, freeze this state API as the retention substrate and move the same no-oracle route/vault interface to synthetic causal evidence streams, then 12/52/128/256-bit real paired solver events. If it fails, preserve the exact FP/FN family, margin, horizon and overwrite breadcrumb and change only the discriminated gate or token observability mechanism.
