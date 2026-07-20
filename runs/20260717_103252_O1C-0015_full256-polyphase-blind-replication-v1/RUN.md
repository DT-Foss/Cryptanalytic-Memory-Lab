# O1C Run O1C-0015

- Schema: `o1c-run-capsule-v1`
- Status: `failed`
- Claim level: `VALIDATION`
- Git commit: `2f53cc775d316c719482c4cb64fa2e5d108f7647`
- Started (Europe/Berlin): `2026-07-17T10:32:52.710326+02:00`
- Ended (Europe/Berlin): `2026-07-17T11:01:50.165244+02:00`
- Elapsed seconds: `1737.454918`
- Command: `o1-crypto-lab full256-polyphase-replication --config '/Users/bhkmie/Documents/Krypto karm/Kryptkram codex/o1-cryptanalytic-memory-lab/configs/full256_polyphase_replication_v1.json'`

## Hypothesis

A preregistered equal-logit ensemble of the exact O1C-0013 h96 reader and a deterministic h65 reader reconstructed only from O1C-0013 BUILD/CAL can remove reproducible code length from 32 fresh broker-sealed standard twenty-round ChaCha20 keys with all 256 bits unknown and only public counter, nonce and one 512-bit output block visible.

## Prediction

Exactly 32 fresh targets and the exact three public-evidence controls reuse one unchanged 512-branch causal probe each. The h96+h65 ensemble and its arm-matched shuffled-label control are frozen before fresh entropy; all 32 predictions are frozen before any reveal. Directional evidence requires positive ensemble aggregate compression, positive exact-h96 baseline compression, at least 18 positive ensemble targets and a positive matched-control margin; strong evidence additionally requires both conditional z scores at least 1.6448536269514722, at least 22 positive targets and positive leave-one-target-out compression. Polyphase architecture promotion is reported separately and requires both positive ensemble-minus-h96 mean compression and a paired conditional z score of at least 1.6448536269514722.

## Controls

- O1C-0013 manifest, result, evaluation, reader freeze, BUILD/CAL tensors, BUILD/CAL labels, BUILD/CAL index and exact h96 binary are hash-pinned before and after execution
- O1C-0014 contributes design lineage through its manifest and result-file hashes only; none of its features, labels, targets or fitted values are read
- h65 and both arm-matched shuffled readers are deterministically reconstructed from only the pinned four BUILD and two CAL targets over the exact O1C-0013 arm-specific grid
- the primary h96 binary is the exact byte-roundtripped O1C-0013 reader; the reconstructed h96 candidate must reproduce its weights exactly
- the ensemble is fixed to logit equals 0.5 times h96 plus 0.5 times h65 and exposes no target-time fit or selection path
- the legacy global O1C-0013 shuffled reader is retained as provenance only and is never substituted for the arm-matched ensemble control
- the protocol freeze is persisted before exactly 32 fresh target entropy calls
- all 32 factual prediction sets and all three controls are persisted before the first reveal
- assumption-swap logits negate and probabilities complement exactly
- conditional-uniform, paired matched-control, component, robustness, byte, 16-bit, million-decoy and exact-verification metrics are all reported
- no target key or target internal-round state enters any pre-reveal artifact
- no sibling reads or writes and no MPS or GPU calls

## Budgets

```json
{
  "maximum_cpu_seconds": 1600,
  "maximum_fresh_random_targets": 32,
  "maximum_gpu_calls": 0,
  "maximum_mps_calls": 0,
  "maximum_native_solver_branches": 17920,
  "maximum_persistent_artifact_bytes": 24000000,
  "maximum_resident_memory_mib": 384,
  "maximum_sibling_reads": 0,
  "maximum_sibling_writes": 0,
  "maximum_wall_seconds": 1400
}
```

## Pinned source hashes

- `design_lineage_manifest`: `741718cbc6b63de24f4d9c89cd2aedc8e9779a0ebb38adc4d40666e97ce24bcf`
- `design_lineage_result`: `01d5057577d4e69b51e7d25802e9d2dfa6e307c28a75963cce38099ac59c1c61`
- `module_cadical_sensor`: `af24c17ae98817d6ad5d6fa30be227aecaf4be3753738bda3c34fae12948fa90`
- `module_causal_bitfield`: `54ac8c9b78b9e3ba2aabf5676fcce730a52aee345db4713c54f9c7c054b84e8a`
- `module_causal_orientation_reader`: `69a1ee798be631cad2295d45ee25aea3a584077451dff0d36736a1250fa1e714`
- `module_chacha_trace`: `58b8272f2cdd6665291158cecc2456258d3cb58f2ab3970d1c4c38e749473b01`
- `module_cli`: `35a0e5e068edf1136449f13753d263cbb9f7a6300e2a7fe273339c6372619ead`
- `module_full256_broker`: `1929006561400bb4091b39955a4b15cc73e492ab5b0bd56788afd58e6a28ea7e`
- `module_full256_cnf`: `76572366adbcadf1525cb25f4c84f5b78ff99be9b63acd721530e53532d9a0e0`
- `module_full256_frozen_reader_replication`: `b03bb910dcd59adf627bfcc44fea39c21ba19429a43d0952a1e04e30b38619ef`
- `module_full256_multikey_calibration`: `3f1c169f8189836a3ae8fc8adbe0926caaca5cb63bb873f362b76678e1fab14b`
- `module_full256_paired_sensor`: `8117048a9ea05b138974602c26f58e69fcf51add9b22a837e4cfa0e8a9794175`
- `module_full256_polyphase_replication`: `2b97de2beddb5c1c343cbcfcbd83f3e33342e8a453cba9fd09216cbe7b570761`
- `module_full256_probe_core`: `b49bd942d7df053c505ab23693d6e89cf25b1a9d01b7b701da22ec97086b1f32`
- `module_living_inverse`: `16c22a9776b693c40e0d6c3a3196c73c7a4c15913bde0bdb14e8d9fc4dbe127e`
- `module_living_inverse_corpus`: `73f722366ae1a52b4d4806fda8929bdd538edb1dcf412af157178a211df9c2ba`
- `module_living_inverse_reader_experiment`: `b117004cbb24044c3915b7987f503996c831ff8b9c30665edf6a8f9d21776e8c`
- `module_living_inverse_ridge`: `58455de430403efee6ab457a054483e9df92bed5d3e31e34700af68fa3ae7d45`
- `module_run_capsule`: `13681939e0a5cd09d4f32c6d92c9a56894cfe8af90f07d5d4190c96b90a1b664`
- `module_signed_direct_replication`: `6124c3fd073db2567105e08954bb5af7922c2eb36b7c6421f9becd750be933c5`
- `native_cadical_header`: `b7111690c61935b9c096d3701be59b3c3d26c555eab8e070f19eb2a97dc5d38c`
- `native_cadical_library`: `44cae3728485b4fd5736ce7cb986021236652daeda9cca227a2c4ac17d3a8a7f`
- `native_pair_sensor`: `67c094e069e8884e4761f82d2d797b594ef326a6ddcf0243dacd8019ae235669`
- `native_tracer_header`: `36e1983eb865800aec1c042c4df4abfbcbc8ced3c82e2bf4baad340639c887fe`
- `polyphase_replication_config`: `5084c24909cc344cb37587b3eb544f107ce3676b40fdbbb72f9df2643cc470c7`
- `pyproject`: `0248ec0fe7d42390b62e358fdd52f63d64f7d4e699f0f41ef77c569699716bd0`
- `source_build_cal_features`: `43768789558a9c064c862db81437ea8a17274fea88f46fe5ba88ec70fb7d8227`
- `source_build_cal_index`: `78d6fb8bbe586dfb71cc6acd52e167d28908ee2064b5fe0884dfb4de99dd1654`
- `source_build_cal_labels`: `8541cd6dbb9f57c344c22014d58c037f101be9534936ed671b28b48d457ad274`
- `source_evaluation`: `869020e3393b60dfb1c312bb6943b15e9601eb67c6f59344161d9a5c4b95be22`
- `source_foundation_manifest`: `b7a07e6461805946897adbfb90da9e9f55ff1074e9aa1343f602eecb0645b7b4`
- `source_foundation_semantic_map`: `7f7438a6277086787ff2cf9b6d7468367b4edd82a65b9cfc4f9249f7ecda3318`
- `source_foundation_template`: `c293d36cab270b28ab2e89c073227fd50b75a6b357b9994d27c3acf7c01a0d52`
- `source_manifest`: `a0d4df5c01f7de3c65a429f9589e46d784f802bc1f8e0aa90dffb011be46922c`
- `source_primary_reader`: `796e79ec932b990a59ecbc34216c4878b9279bae3bb136fe0832e580bcb2e9f8`
- `source_reader_freeze`: `f8c99cbb376a2d9adc04ac3cc6dcda85b91ea49765808c4ce33b0e62f236bbbf`
- `source_result`: `38674b9c49e2463471a35fddb8d0b7d2218567cab7251e8a275e74ccace156a5`
- `source_shuffled_reader`: `87bd132c44be5c788444088465780f227315dddde84ac42f5474092c664e19d0`

## Metrics

```json
{
  "error": "polyphase resource budget exceeded: cpu_under_budget, resident_memory_under_budget, wall_under_budget",
  "error_type": "Full256PolyphaseReplicationError",
  "fresh_target_state": "possibly-generated-after-protocol-freeze",
  "gpu_calls": 0,
  "mps_calls": 0,
  "prediction_set_persisted": true,
  "protocol_freeze_persisted": true,
  "schema": "o1-256-polyphase-replication-failure-v1",
  "scientific_inverse_signal_claimed": false,
  "sibling_reads": 0,
  "sibling_writes": 0,
  "target_internal_trace_inputs": 0,
  "target_key_units": 0,
  "unknown_target_key_bits": 256
}
```

## Next highest-ROI action

Preserve the failed O1C-0015 capsule, fix the exact protocol, source, reader, native, or budget invariant under a new attempt ID, and never replay any sealed target from this attempt.
