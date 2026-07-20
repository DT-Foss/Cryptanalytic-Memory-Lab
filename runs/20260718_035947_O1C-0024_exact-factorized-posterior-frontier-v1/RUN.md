# O1C Run O1C-0024

- Schema: `o1c-run-capsule-v1`
- Status: `completed`
- Claim level: `RETROSPECTIVE`
- Git commit: `36133bc6e75349c2cd3999f60eee08f2cbeb903a`
- Started (Europe/Berlin): `2026-07-18T03:59:47.535575+02:00`
- Ended (Europe/Berlin): `2026-07-18T03:59:50.012118+02:00`
- Elapsed seconds: `2.476543`
- Command: `/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -m o1_crypto_lab.posterior_frontier_run --config '/Users/bhkmie/Documents/Krypto karm/Kryptkram codex/o1-cryptanalytic-memory-lab/configs/posterior_frontier_v1.json'`

## Hypothesis

The current least-uncertain-bit cube is not the global top-K of a 256-bit factorized posterior; an exact all-coordinate best-first frontier can recover a full-round ChaCha20 key that the restricted cube excludes, while honestly reporting whether a burned real posterior produces any actionable search concentration.

## Prediction

The exact frontier will match exhaustive product-posterior ordering on deterministic low-width proofs, emit the synthetic full-round truth at rank four while the legacy two-bit cube cannot contain it, report the true best Hamming distance at each configured K, and find no exact O1C-0016 target-0000 key inside the first 65,536 global candidates. Candidate generation and its freeze must occur before the single selected burned reveal is opened.

## Controls

- the legacy least-uncertain-bit cube is evaluated unchanged as the matched restricted-frontier control
- deterministic exhaustive low-width enumeration proves global score ordering and candidate uniqueness
- a full-round twenty-round ChaCha20 target has a constructed rank-four truth outside the legacy two-coordinate cube
- wrong-nonce and one-bit-output public controls receive the identical synthetic frontier and must produce zero exact matches
- the O1C-0016 target-0000 posterior is consumed retrospectively without fitting, rescaling, reader selection or fresh entropy
- all burned candidates and scores are persisted and hash-frozen before the revealed key is read
- candidate generation receives probabilities and public target data only; truth is accepted only by the post-freeze evaluator
- zero solver branches, sibling reads or writes, MPS calls and GPU calls

## Budgets

```json
{
  "maximum_burned_public_verifications": 4096,
  "maximum_burned_reveal_reads": 1,
  "maximum_cpu_seconds": 30.0,
  "maximum_frontier_candidates": 65544,
  "maximum_full_source_capsule_scans": 0,
  "maximum_gpu_calls": 0,
  "maximum_legacy_cube_assignments": 65540,
  "maximum_mps_calls": 0,
  "maximum_native_solver_branches": 0,
  "maximum_other_outcome_payload_reads": 0,
  "maximum_persistent_artifact_bytes": 4194304,
  "maximum_proof_candidate_evaluations": 2192,
  "maximum_resident_memory_mib": 256,
  "maximum_scientific_entropy_calls": 0,
  "maximum_sibling_reads": 0,
  "maximum_sibling_writes": 0,
  "maximum_source_evaluation_payload_reads": 1,
  "maximum_source_manifest_reads": 1,
  "maximum_source_payload_reads": 5,
  "maximum_source_reveal_payload_reads": 1,
  "maximum_synthetic_public_verifications": 24,
  "maximum_wall_seconds": 30.0
}
```

## Pinned source hashes

- `burned_capsule_manifest_expected`: `fd0469885ee436414f94d708006cc40d86fc730d25b618167c7d664b3fe195ea`
- `burned_evaluation_json_expected`: `bae26cec9275806870e46dbb1e9c55726230e123a44fc4eb3a7785287ecc2010`
- `burned_prediction_freeze_json_expected`: `169252f77e0e66e1afab1c486692c27dc2217c40d566c1468241266141fecbdc`
- `burned_probabilities_f64le_expected`: `0f9c3b9f99af49f7b2a03a3a2c89e5ac81ba1ebcdad3e9db8e9b83265f129c7d`
- `burned_publication_json_expected`: `577f10a7cf69d58eeb842fe9dba903f27499dfb6be4fa5a7366e2b22f3a44b81`
- `burned_reveal_json_expected`: `19cf8b133bf217ec277966394ee9576c4ed16af878d0d970dbfe6cd23367efe9`
- `config`: `d0b393ea14fc3594907b2ed1abf63f2ef7a5cbdecf6dc1bf29701a6c4889f84d`
- `module_chacha_trace`: `58b8272f2cdd6665291158cecc2456258d3cb58f2ab3970d1c4c38e749473b01`
- `module_full256_broker`: `1929006561400bb4091b39955a4b15cc73e492ab5b0bd56788afd58e6a28ea7e`
- `module_living_inverse`: `16c22a9776b693c40e0d6c3a3196c73c7a4c15913bde0bdb14e8d9fc4dbe127e`
- `module_posterior_frontier`: `f57f20ae32311f1c5291953e9619a0bd32c31fa04ab969c8bf3a787dfd800fb8`
- `module_posterior_frontier_run`: `11d9a9a340dbc6a17ea32255c7a3a73fd989444f3d18b3930cb8827edc778652`
- `module_run_capsule`: `13681939e0a5cd09d4f32c6d92c9a56894cfe8af90f07d5d4190c96b90a1b664`
- `pyproject`: `0248ec0fe7d42390b62e358fdd52f63d64f7d4e699f0f41ef77c569699716bd0`

## Metrics

```json
{
  "budget_checks": {
    "burned_public_verifications": true,
    "burned_reveal_reads": true,
    "cpu": true,
    "frontier_candidates": true,
    "full_source_capsule_scans": true,
    "gpu": true,
    "legacy_cube_assignments": true,
    "mps": true,
    "native_solver_branches": true,
    "other_outcome_payload_reads": true,
    "persistent_artifacts": true,
    "proof_candidate_evaluations": true,
    "resident_memory": true,
    "scientific_entropy": true,
    "sibling_reads": true,
    "sibling_writes": true,
    "source_evaluation_payload_reads": true,
    "source_manifest_reads": true,
    "source_payload_reads": true,
    "source_reveal_payload_reads": true,
    "synthetic_public_verifications": true,
    "wall": true
  },
  "classification": "EXACT_GLOBAL_FRONTIER_VALIDATED_BURNED_NULL",
  "cpu_seconds": 2.438174,
  "cryptanalytic_signal_claimed": false,
  "failed_budgets": [],
  "mechanism_validation_passed": true,
  "operationally_complete": true,
  "peak_rss_bytes": 115261440,
  "peak_rss_mib": 109.921875,
  "persistent_artifact_bytes": 2890445,
  "result_sha256": "0bdf0eb3c20b1d9f8e2b121aa7a2eb3bed883bbb45e399251a3bc8f4c3eeb7ad",
  "schema": "o1-256-posterior-frontier-cli-result-v1",
  "science_gates": {
    "burned_candidates_frozen_before_reveal": true,
    "exhaustive_orders_match": true,
    "full_source_capsule_was_not_scanned": true,
    "outcome_reads_are_exact_and_post_freeze": true,
    "selected_source_manifest_and_members_verify": true,
    "synthetic_discriminator_passes": true,
    "zero_fresh_entropy_solver_sibling_or_accelerator_work": true
  },
  "science_gates_passed": true,
  "scientific_result_claimed": true,
  "terminal_c_achieved": false,
  "wall_seconds": 2.4539934997446835,
  "work": {
    "burned_frontier_candidates": 65536,
    "burned_legacy_cube_assignments": 65536,
    "burned_public_verifications": 4096,
    "burned_semantic_reveal_reads": 1,
    "frontier_memory_scales_with_explicit_candidate_budget": true,
    "frontier_memory_scales_with_stream_length": false,
    "full_source_capsule_scans": 0,
    "global_frontier_candidates": 65544,
    "gpu_calls": 0,
    "legacy_cube_assignments": 65540,
    "mps_calls": 0,
    "native_solver_branches": 0,
    "other_outcome_payload_reads": 0,
    "proof_best_first_candidates": 1096,
    "proof_candidate_evaluations": 2192,
    "proof_exhaustive_candidates": 1096,
    "schema": "o1-256-posterior-frontier-work-ledger-v1",
    "scientific_entropy_calls": 0,
    "sibling_reads": 0,
    "sibling_writes": 0,
    "source_evaluation_payload_reads": 1,
    "source_manifest_reads": 1,
    "source_payload_reads": 5,
    "source_reveal_payload_reads": 1,
    "synthetic_frontier_candidates": 8,
    "synthetic_legacy_cube_assignments": 4,
    "synthetic_public_verifications": 20
  }
}
```

## Next highest-ROI action

Use the exact global frontier, never the restricted uncertainty cube, for future beam/rank/time-to-hit claims. If O1C-0022 later yields stable entropy reduction, stream its frozen posterior through this decoder and exact ChaCha20 verification; if not, keep the decoder fixed and repair evidence orientation rather than tuning search.
