# O1C Run O1C-0034

- Schema: `o1c-run-capsule-v1`
- Status: `completed`
- Claim level: `TEST`
- Git commit: `2fbb235dac644c5c2d0cc45aaf05394a796bc17e`
- Started (Europe/Berlin): `2026-07-18T18:10:54.761103+02:00`
- Ended (Europe/Berlin): `2026-07-18T18:10:54.772019+02:00`
- Elapsed seconds: `0.010916`
- Command: `PYTHONPATH=src python -m o1_crypto_lab.o1c34_a469_retained_transfer_run`

## Hypothesis

A469's unchanged sparse bucket-local correction improves A465's two retained all256 byte-3 rankings without crossing any A465 bucket.

## Prediction

Both consumed targets rank <= 128/256; only then may the exact A469 reader earn one fresh blind target.

## Controls

- input is O1C-0033's verified label-free two-target A465 prediction freeze
- A469 copula tables, residual table, selected gate and tie policy are hash-frozen
- both A469 fields are persisted before either target byte is reconstructed
- A469 may reorder only within eight fixed A465 rank buckets
- zero new solver stages, fits, targets, coefficients, bytes or operators

## Budgets

```json
{
  "MPS_or_GPU": false,
  "maximum_resident_memory_mib": 512,
  "maximum_wall_seconds": 10.0,
  "new_solver_stages": 0,
  "new_target_count": 0,
  "target_count": 2,
  "target_role": "CONSUMED"
}
```

## Pinned source hashes

- `a469_transfer`: `45db09b2ae29c3947d7de7ca15d613f4411dd261c54c62b7402a4e49a20c9b7c`
- `o1c33_prediction_freeze`: `eecb077ff59fbd92386936909fbcefbca9f541694dac463356abf230ab559e34`
- `o1c34_runner`: `1bfd411220c4143823f7223f24ccf5736076f66ae96867ce9e3b519577dc981f`
- `sibling_A467_source`: `d20560089cc5a7639b3b9f1e4f1ace5b65884d726f3c7df7e817bf4fb392929e`
- `sibling_A469_result`: `dc33384c0c4e65bf57a9e0bdb8297b16737df0494e2af1036a85f49e7ececc01`
- `sibling_A469_source`: `5b0e12688ab526ff36841d9e4bdfa8b1bcb45b20c8a1e1653418f3d9c2f0194f`

## Metrics

```json
{
  "both_passed_median_gate": false,
  "elapsed_seconds": 0.0025205839992850088,
  "new_solver_stages": 0,
  "new_targets": 0,
  "ranks": [
    56,
    239
  ],
  "self_maxrss_after": 196820992,
  "target_count": 2
}
```

## Next highest-ROI action

Close A469 all256 byte transfer; do not resweep and move to the next exact all-unknown sibling channel.
