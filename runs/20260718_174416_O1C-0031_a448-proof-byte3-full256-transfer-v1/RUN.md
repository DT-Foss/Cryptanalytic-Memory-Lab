# O1C Run O1C-0031

- Schema: `o1c-run-capsule-v1`
- Status: `completed`
- Claim level: `TEST`
- Git commit: `7799e6cc38b363b70123c947144a25949e55cbf6`
- Started (Europe/Berlin): `2026-07-18T17:44:16.018180+02:00`
- Ended (Europe/Berlin): `2026-07-18T17:45:12.463166+02:00`
- Elapsed seconds: `56.444986`
- Command: `PYTHONPATH=src python -m o1_crypto_lab.o1c31_a448_transfer_run`

## Hypothesis

A448's unchanged proof-antecedent top4 plus exact A442 Borda tie backbone retains better-than-median byte ordering when all other 248 key bits are unknown.

## Prediction

On the consumed RFC8439 full-round public target, key byte 3 ranks at or above the median (rank <= 128/256).

## Controls

- measurement API receives PublicTargetView only; key and target byte are revealed after rank freeze
- other 248 key bits have no CNF units and remain unassigned
- A375/A442/A447 models, helper, wrapper and feature source are hash-frozen with zero refits
- numeric 0..255 order and H1/H2/H4/H8 cover every candidate before reveal
- single-pass raw backbone was matched exactly against stored A447/A359 source telemetry

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
- `full256_cnf`: `76572366adbcadf1525cb25f4c84f5b78ff99be9b63acd721530e53532d9a0e0`
- `o1c31_runner`: `7ff3bb1f62f24113aec3cdfe4d267a2b13a8f41ac17aee893b1477fb14cf7f04`
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
  "candidate_order_uint8_sha256": "34f1289689ff9cc254135ff3d78581e60a739f0d63af01a5d83184ad57acbc08",
  "descriptive_gain_vs_uniform_mean_log_rank_bits": 1.023521645291951,
  "other_key_bits_assigned": 0,
  "pass_max_rank": 128,
  "passed": true,
  "public_key_label_inputs": 0,
  "rank_bit_gain_from_worst_rank": 2.4454111483223624,
  "raw_artifact_bytes": 297014,
  "raw_artifact_sha256": "8098c6438a0e2264242733a554b0956ee2e49701bb84979b947bd16d201860bf",
  "self_maxrss_after": 188841984,
  "solver_stages": 1024,
  "stable_run_sha256": "1a376baa490e726de553fe6f3f30e2260a32be1059d33351ba94fbfd9578a266",
  "stdout_sha256": "3c014405b91d9c315c4ab669d8aa1d059f286985fdc3508410a21527acb80665",
  "target_byte": 3,
  "target_rank": 47,
  "target_role": "CONSUMED",
  "wall_seconds": 55.29026987499992
}
```

## Next highest-ROI action

Repeat the unchanged A448 reader on exactly one disjoint consumed DEVELOPMENT target; use a fresh target only if the consumed repeat also ranks <=128.
