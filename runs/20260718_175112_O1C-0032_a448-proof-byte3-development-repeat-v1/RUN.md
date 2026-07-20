# O1C Run O1C-0032

- Schema: `o1c-run-capsule-v1`
- Status: `completed`
- Claim level: `TEST`
- Git commit: `4f9393eb57575c763087334d30a5f7284b60c185`
- Started (Europe/Berlin): `2026-07-18T17:51:12.750499+02:00`
- Ended (Europe/Berlin): `2026-07-18T17:52:02.074866+02:00`
- Elapsed seconds: `49.324367`
- Command: `PYTHONPATH=src python -m o1_crypto_lab.o1c32_a448_transfer_run`

## Hypothesis

The unchanged A448/A442 byte-3 reader repeats its better-than-median ordering on one disjoint consumed uniform DEVELOPMENT target while the other 248 key bits remain unknown.

## Prediction

The true byte ranks <= 128/256 with no refit, target selection, or label input.

## Controls

- the measurement API receives only the previously frozen PublicTargetView
- the deterministic target reconstruction is matched to the prior zero-label public receipt
- the A448 reader, candidate order, byte coordinate and all source hashes are unchanged from O1C-0031
- the other 248 key bits receive no CNF units and remain unassigned
- the target byte is read only after all 256 ranks and raw telemetry are frozen

## Budgets

```json
{
  "MPS_or_GPU": false,
  "candidate_cells": 256,
  "device": "CPU",
  "external_timeout_seconds": 1800.0,
  "solver_stages": 1024,
  "target_count": 1,
  "target_role": "CONSUMED",
  "watchdog_seconds_per_stage": 2.0
}
```

## Pinned source hashes

- `a296_cube`: `bbc41d0d1e85263a6113b714e746eb24778e08e0bc6f0bb6c024e4582ce7378c`
- `a448_transfer`: `b65ce097502603a7fcdf3c90f43f8b7bd85bf7d48c99d6c2997383e1c8e511a2`
- `consumed_public_receipt`: `e8e1e249f0f2fcc7862f9ae0fd837d0e1633ef8a8d5eba3897f8865f4ea61b10`
- `full256_cnf`: `76572366adbcadf1525cb25f4c84f5b78ff99be9b63acd721530e53532d9a0e0`
- `o1c31_runner`: `7ff3bb1f62f24113aec3cdfe4d267a2b13a8f41ac17aee893b1477fb14cf7f04`
- `o1c32_runner`: `eca5f1f1b2422c17ac1ee7940aa48045f8d109e2bba78230078d0de35208309d`
- `run_capsule`: `13681939e0a5cd09d4f32c6d92c9a56894cfe8af90f07d5d4190c96b90a1b664`
- `semantic_map`: `7f7438a6277086787ff2cf9b6d7468367b4edd82a65b9cfc4f9249f7ecda3318`
- `shape532`: `f41e657ea8414e94431ad431a31248202d322e4a762e9d42bf28d95d3f406aaf`
- `sibling_helper`: `9d0d5cbd6e523e248023fb080c206fa14d8bbb2c89d3cd8f1273eaaa1a99de67`
- `sibling_identity_wrapper`: `3a1d63d223712997519f72143ebcc3e5725a8f8659eadbd9389465dd0fe654f6`
- `sibling_multihorizon_wrapper`: `55e1722d8478bf0aea95a544e5942fa6f6a3b17e8c9c54906e2ba34ddc2be386`
- `sibling_proof_features`: `52700bb0a2442caf24ef123c745915fd7b2e2a27ca2f797886b141a640fc4c05`
- `sibling_shape532`: `44056b27937c1b4f1ab9af2dfaf904ad3b5f239deda05519c2e9a16f9f1e8160`
- `sibling_wrapper`: `bf2798e72e1c2ff7872ea262335d4500cf82e1e46cbdf110f9628f713d4af61b`
- `template`: `c293d36cab270b28ab2e89c073227fd50b75a6b357b9994d27c3acf7c01a0d52`

## Metrics

```json
{
  "candidate_cells": 256,
  "descriptive_gain_vs_uniform_mean_log_rank_bits": -1.32275631101116,
  "other_key_bits_assigned": 0,
  "pass_max_rank": 128,
  "passed": false,
  "public_key_label_inputs": 0,
  "rank_bit_gain_from_worst_rank": 0.09913319201925132,
  "raw_artifact_bytes": 306263,
  "raw_artifact_sha256": "40cf3a8f258e4d9d12ea20497dca5bc7bfb5edc7d740bf28765ce07322bb85a6",
  "self_maxrss_after": 214024192,
  "solver_stages": 1024,
  "stable_run_sha256": "039d2865d9a388cf578d2bad9f9d0bbd50b6844d829e2b7af28ae686acce207c",
  "stdout_sha256": "fac9a6d0692d77a98f037b4360a431357944d24059cc19020b4c6dab9e79e0ab",
  "target_byte": 15,
  "target_id": "development-0000",
  "target_rank": 239,
  "target_role": "CONSUMED",
  "wall_seconds": 48.29753787499976
}
```

## Next highest-ROI action

Close A448 full256 transfer once; do not resweep it, and transfer the next exact sibling recovery mechanism.
