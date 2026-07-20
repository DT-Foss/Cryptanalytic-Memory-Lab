# O1C Run O1C-0009

- Schema: `o1c-run-capsule-v1`
- Status: `completed`
- Claim level: `VALIDATION`
- Git commit: `f718e78cf63ee457298288cc80e192b9bc110228`
- Started (Europe/Berlin): `2026-07-17T04:07:41.875365+02:00`
- Ended (Europe/Berlin): `2026-07-17T04:07:48.948122+02:00`
- Elapsed seconds: `7.072757`
- Command: `o1-crypto-lab living-inverse-reader --config '/Users/bhkmie/Documents/Krypto karm/Kryptkram codex/o1-cryptanalytic-memory-lab/configs/living_inverse_reader_v1.json'`

## Hypothesis

A bounded O1 evidence state with coordinate-bound holographic feature banks can extract reproducible sub-key information from standard twenty-round ChaCha20 public block relations when trained on full 256-bit structured and uniform keys, without target traces or target-relative proposals at deployment.

## Prediction

At least one CAL-selected factual reader will compress broker-secret uniform DEV key uncertainty below 256 bits, beat a shuffled-key control by 0.1 bit or more, and retain at least one familywise CAL-preselected bit; all 256 target bits remain unknown, DEV entropy is absent until after the calibration freeze, predictions are persisted before reveal, and every candidate portfolio is generated solely from the public target, frozen direct posterior and frozen seed.

## Controls

- TRAIN key-label rotation with independently calibrated shuffled-key reader
- DEV public-output permutation
- DEV one-bit output flips
- DEV wrong-nonce views with output held fixed
- candidate-key and candidate-trace ablation for the CAL-selected relative arm
- exact 256-bit random-posterior baseline through zero shrinkage
- one predeclared DEV sentinel ranked against one million uniform decoys per arm

## Budgets

```json
{
  "development_openings": 1,
  "maximum_cpu_seconds": 300,
  "maximum_decoys_per_arm": 1000000,
  "maximum_fresh_targets": 128,
  "maximum_gpu_calls": 0,
  "maximum_mps_calls": 0,
  "maximum_resident_memory_mib": 256,
  "maximum_sibling_reads": 0,
  "maximum_sibling_writes": 0
}
```

## Pinned source hashes

- `module_chacha_trace`: `58b8272f2cdd6665291158cecc2456258d3cb58f2ab3970d1c4c38e749473b01`
- `module_cli`: `641c2410afe67f982aee1f1d0c4f04af04050a2f52ea5eae8c82730188b3b40f`
- `module_full256_broker`: `dc1f77300c9f3604ca22f900033c5ec8590234f605e8549376138ee09ae45909`
- `module_living_inverse`: `16c22a9776b693c40e0d6c3a3196c73c7a4c15913bde0bdb14e8d9fc4dbe127e`
- `module_living_inverse_corpus`: `73f722366ae1a52b4d4806fda8929bdd538edb1dcf412af157178a211df9c2ba`
- `module_living_inverse_reader_experiment`: `f293af6e88bb0cb7d497c7728949810c6cf8b9110fe3f8507daa1b638366ad87`
- `module_living_inverse_ridge`: `58455de430403efee6ab457a054483e9df92bed5d3e31e34700af68fa3ae7d45`
- `module_run_capsule`: `13681939e0a5cd09d4f32c6d92c9a56894cfe8af90f07d5d4190c96b90a1b664`
- `pyproject`: `0248ec0fe7d42390b62e358fdd52f63d64f7d4e699f0f41ef77c569699716bd0`
- `reader_config`: `5527ec779455772c456f8402caa173d071a4373d689bb63f175c6f3c6bbc2c80`

## Metrics

```json
{
  "calibration_targets": 64,
  "candidate_training_examples": 6144,
  "cpu_budget_seconds": 300.0,
  "cpu_seconds": 6.923216,
  "development_targets": 128,
  "execution_success_gate_passed": true,
  "fresh_target_count": 128,
  "fresh_target_generated": true,
  "fresh_target_revealed": true,
  "gpu_calls": 0,
  "maximum_persistent_live_state_bytes": 2056,
  "mps_calls": 0,
  "peak_rss_mib": 182.90625,
  "primary_arm": "direct",
  "primary_development_compression_bits": 0.0,
  "primary_development_mean_key_nll_bits": 256.0,
  "primary_transferable_bits": 0,
  "resident_memory_budget_mib": 256.0,
  "result_sha256": "40276d71516d4d150b02cc8235c08d00fb8ceb28daf64d1316826b38fd094bf9",
  "schema": "o1-256-living-inverse-reader-metrics-v1",
  "scientific_inverse_signal_claimed": false,
  "scientific_signal_gate_passed": false,
  "shuffled_control_development_compression_bits": 0.0,
  "sibling_reads": 0,
  "sibling_writes": 0,
  "target_trace_fields_in_deployment": 0,
  "train_targets": 512,
  "unknown_target_key_bits": 256
}
```

## Next highest-ROI action

Use O1C-0009 per-bit, proposal and ablation breadcrumbs to build O1C-0010 at the same full 256-bit attacker contract; open a broker-random sealed target only after a factual arm clears the frozen signal gate.
