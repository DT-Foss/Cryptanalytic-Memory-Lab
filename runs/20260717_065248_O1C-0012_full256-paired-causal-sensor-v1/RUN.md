# O1C Run O1C-0012

- Schema: `o1c-run-capsule-v1`
- Status: `completed`
- Claim level: `TEST`
- Git commit: `08535f94ae3c1de17f3622aa032b945233b0ee92`
- Started (Europe/Berlin): `2026-07-17T06:52:48.316759+02:00`
- Ended (Europe/Berlin): `2026-07-17T06:53:37.536086+02:00`
- Elapsed seconds: `49.219327`
- Command: `o1-crypto-lab full256-paired-sensor --config '/Users/bhkmie/Documents/Krypto karm/Kryptkram codex/o1-cryptanalytic-memory-lab/configs/full256_paired_causal_sensor_v1.json'`

## Hypothesis

A single immutable full-round ChaCha20 public-output relation can support all 512 symmetric key-bit assumption branches directly at 256 unknown bits, expose complete closed proof-ancestry prefixes at conflict cutoffs 64/96/65, and stream their signed differences into a nonzero coordinate-bound unary-plus-ARX-interaction-plus-holographic O1 state below 18,000 bytes.

## Prediction

The COW-native CaDiCaL sensor will cover all 256 bits and both polarities from the same public root state; every branch will reach conflict cutoffs 64, 65 and 96 and yield the complete set of proof events at or below each cutoff, while any gap from the cutoff to the last emitted event and all final solver overshoot remain explicit; the full 768-event state will serialize deterministically below budget, negate its signed components under assumption swap, retain no transcript or candidate keys, and produce a fully billed post-freeze known-key diagnostic without claiming cross-key inverse signal.

## Controls

- immutable O1C-0011 capsule and member hashes verified before and after the sweep
- one public-only propagation prefix shared by every copy-on-write branch
- all k_i=0 and k_i=1 branches start from the identical single-threaded solver image
- evidence is the complete closed proof-event prefix at conflict cutoffs 64, 96 and 65; last-event gaps and final overshoot are billed and excluded
- bit-173 native payload is replayed and must match its full-sweep deterministic commitment
- assumption-swap control must exactly negate unary, interaction and holographic arrays while preserving unsigned mass
- known RFC key is used only after the bounded state is frozen and never enters a target solver branch
- no sibling reads or writes, no MPS/GPU calls and no fresh random target

## Budgets

```json
{
  "maximum_cpu_seconds": 300,
  "maximum_fresh_random_targets": 0,
  "maximum_gpu_calls": 0,
  "maximum_mps_calls": 0,
  "maximum_native_solver_branches": 514,
  "maximum_persistent_artifact_bytes": 5000000,
  "maximum_resident_memory_mib": 384,
  "maximum_sibling_reads": 0,
  "maximum_sibling_writes": 0,
  "maximum_wall_seconds": 300
}
```

## Pinned source hashes

- `module_cadical_sensor`: `af24c17ae98817d6ad5d6fa30be227aecaf4be3753738bda3c34fae12948fa90`
- `module_causal_bitfield`: `54ac8c9b78b9e3ba2aabf5676fcce730a52aee345db4713c54f9c7c054b84e8a`
- `module_chacha_trace`: `58b8272f2cdd6665291158cecc2456258d3cb58f2ab3970d1c4c38e749473b01`
- `module_cli`: `ee030338ef0a8026a868909c9d41598b800be4e42172f77b37dc5fb82837bfa7`
- `module_full256_paired_sensor`: `8117048a9ea05b138974602c26f58e69fcf51add9b22a837e4cfa0e8a9794175`
- `module_living_inverse`: `16c22a9776b693c40e0d6c3a3196c73c7a4c15913bde0bdb14e8d9fc4dbe127e`
- `module_run_capsule`: `13681939e0a5cd09d4f32c6d92c9a56894cfe8af90f07d5d4190c96b90a1b664`
- `native_pair_sensor`: `67c094e069e8884e4761f82d2d797b594ef326a6ddcf0243dacd8019ae235669`
- `native_tracer_header`: `36e1983eb865800aec1c042c4df4abfbcbc8ced3c82e2bf4baad340639c887fe`
- `paired_sensor_config`: `be22dba148a9a12cc410e97ed4fb6d3573a4d6f7843e969f5c5c938e3acd6264`
- `pyproject`: `0248ec0fe7d42390b62e358fdd52f63d64f7d4e699f0f41ef77c569699716bd0`
- `source_capsule_manifest`: `b7a07e6461805946897adbfb90da9e9f55ff1074e9aa1343f602eecb0645b7b4`
- `source_public_cnf`: `dde6a2791726e148c99064ec71f746fb8803e5d0f6b1996dd8b238c9c9b0a2a0`
- `source_semantic_map`: `7f7438a6277086787ff2cf9b6d7468367b4edd82a65b9cfc4f9249f7ecda3318`

## Metrics

```json
{
  "budget_checks": {
    "cpu": true,
    "fresh_targets": true,
    "gpu": true,
    "mps": true,
    "native_branches": true,
    "persistent_artifacts": true,
    "resident_memory": true,
    "sibling_reads": true,
    "sibling_writes": true,
    "state": true,
    "wall": true
  },
  "corrected_correct_bits": 119,
  "corrected_effective_compression_bits": -86.77999008466566,
  "corrected_key_nll_bits": 342.77999008466566,
  "cpu_seconds": 58.03172300000001,
  "exact_key_recovered": false,
  "fresh_random_targets": 0,
  "gpu_calls": 0,
  "hamming_distance": 137,
  "million_decoy_rank": 999898,
  "mps_calls": 0,
  "native_cpu_seconds": 11.933953,
  "native_solver_branches": 514,
  "paired_bit_count": 256,
  "parent_cpu_seconds": 43.828364,
  "peak_rss_bytes": 332693504,
  "peak_rss_mib": 317.28125,
  "persistent_artifact_bytes": 554653,
  "proof_frontier_count": 1536,
  "schema": "o1-256-paired-causal-sensor-metrics-v1",
  "sibling_reads": 0,
  "sibling_writes": 0,
  "state_bytes": 17408,
  "state_sha256": "aea9d4c0bd88d2c8480fb51b98d5524bc8c6fc319dd612c9dc345aa03035b664",
  "success_gate_passed": true,
  "unknown_target_key_bits": 256,
  "wall_seconds": 49.19916533399373
}
```

## Next highest-ROI action

Use the frozen O1C-0012 event contract on a deterministic multi-key full-256 build/calibration corpus, learn orientation without target access, freeze the unary-plus-proof reader, and attack a fresh broker-sealed standard ChaCha20 output-only panel at all 256 unknown bits.
