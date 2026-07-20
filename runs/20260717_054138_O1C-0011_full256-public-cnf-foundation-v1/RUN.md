# O1C Run O1C-0011

- Schema: `o1c-run-capsule-v1`
- Status: `completed`
- Claim level: `VALIDATION`
- Git commit: `b9f514a33386066706d1b023cc97487595ed63c4`
- Started (Europe/Berlin): `2026-07-17T05:41:38.786307+02:00`
- Ended (Europe/Berlin): `2026-07-17T05:41:47.767266+02:00`
- Elapsed seconds: `8.980959`
- Command: `o1-crypto-lab full256-cnf-foundation --config '/Users/bhkmie/Documents/Krypto karm/Kryptkram codex/o1-cryptanalytic-memory-lab/configs/full256_cnf_foundation_v1.json'`

## Hypothesis

A target-independent symmetric CNF can encode the complete RFC 8439 twenty-round ChaCha20 block relation with all 256 key bits free, only public counter, nonce and output units, and stable round/lane/operator ranges suitable for paired-assumption O1 evidence streams.

## Prediction

The compiler will reproduce the frozen 32128-variable, 187370-clause and 656-operator artifact byte-for-byte; an attacker instance will add exactly 640 public units and zero key units; paired bit-173 instances will differ only by one opposite key literal; the RFC fixed-key vector and a second full-width vector will be SAT, while a one-bit output flip under the same RFC key will be UNSAT.

## Controls

- byte-identical two-pass compilation in independent directories
- full semantic-map reconstruction rather than self-consistent metadata only
- RFC 8439 fixed-key SAT self-test
- same fixed key with one public output bit flipped must be UNSAT
- second deterministic 256-bit key, nonce and counter SAT self-test
- public attacker instance contains no key unit clauses
- paired keybit-173 assumptions use equal public evidence and opposite final literals

## Budgets

```json
{
  "maximum_cpu_seconds": 120,
  "maximum_fresh_random_targets": 0,
  "maximum_gpu_calls": 0,
  "maximum_mps_calls": 0,
  "maximum_persistent_artifact_bytes": 24000000,
  "maximum_resident_memory_mib": 256,
  "maximum_sibling_reads": 0,
  "maximum_sibling_writes": 0,
  "maximum_solver_formula_calls": 3,
  "maximum_working_bytes": 32000000
}
```

## Pinned source hashes

- `foundation_config`: `b4146c57aa4e652402200f75ed6ff8e7de91aacc99c52544fdb809e1de8d4204`
- `module_chacha_trace`: `58b8272f2cdd6665291158cecc2456258d3cb58f2ab3970d1c4c38e749473b01`
- `module_cli`: `df3dd73b842bf7ca25ae9de1ca0f1635be76ecee595ee447e9a276fd1bf7966d`
- `module_full256_cnf`: `76572366adbcadf1525cb25f4c84f5b78ff99be9b63acd721530e53532d9a0e0`
- `module_full256_cnf_foundation`: `9f8b71e6d38fddbc1f671da4fd11a39ecf7e66afd995666f6883b5af9839519e`
- `module_living_inverse`: `16c22a9776b693c40e0d6c3a3196c73c7a4c15913bde0bdb14e8d9fc4dbe127e`
- `module_run_capsule`: `13681939e0a5cd09d4f32c6d92c9a56894cfe8af90f07d5d4190c96b90a1b664`
- `pyproject`: `0248ec0fe7d42390b62e358fdd52f63d64f7d4e699f0f41ef77c569699716bd0`

## Metrics

```json
{
  "byte_identical_double_compile": true,
  "cpu_budget_seconds": 120,
  "cpu_seconds": 8.692029,
  "flipped_output_status": "UNSAT",
  "fresh_random_targets": 0,
  "gpu_calls": 0,
  "map_sha256": "13c0dd32b1c0eec0b9b95e9c7c0f2a8390b8be6f98bd59e3b7d021c23762bfaf",
  "maximum_working_bytes": 25414624,
  "mps_calls": 0,
  "paired_assumption_instances": 2,
  "peak_rss_mib": 163.59375,
  "persistent_artifact_bytes": 21069379,
  "public_instance_clause_count": 188010,
  "public_key_unit_clauses": 0,
  "resident_memory_budget_mib": 256,
  "result_sha256": "6c4fd7becd5307d60b30e16ea1fae8d3f4739b06c888204d638950c94b53adfe",
  "rfc_fixed_key_status": "SAT",
  "rounds": 20,
  "schema": "o1-256-full-cnf-foundation-metrics-v1",
  "scientific_inverse_signal_claimed": false,
  "second_fixed_key_status": "SAT",
  "semantic_operation_count": 656,
  "sibling_reads": 0,
  "sibling_writes": 0,
  "solver_formula_calls": 3,
  "success_gate_passed": true,
  "template_clause_count": 187370,
  "template_sha256": "c293d36cab270b28ab2e89c073227fd50b75a6b357b9994d27c3acf7c01a0d52",
  "unknown_target_key_bits": 256,
  "variable_count": 32128
}
```

## Next highest-ROI action

Build O1C-0012 as an incremental CaDiCaL paired-assumption sensor over this exact template: stream bounded propagation, conflict, decision and clause-ancestry deltas for k_i=0 versus k_i=1 into a coordinate-bound unary-plus-interaction O1 state, beginning directly with full 256-bit public-output instances.
