# O1C Run O1C-0008

- Schema: `o1c-run-capsule-v1`
- Status: `completed`
- Claim level: `SMOKE`
- Git commit: `826149ded68f0c9afbdd7a1c4f9ea90235f1ef56`
- Started (Europe/Berlin): `2026-07-17T03:11:13.507616+02:00`
- Ended (Europe/Berlin): `2026-07-17T03:11:14.504030+02:00`
- Elapsed seconds: `0.996414`
- Command: `o1-crypto-lab living-inverse-foundation --config '/Users/bhkmie/Documents/Krypto karm/Kryptkram codex/o1-cryptanalytic-memory-lab/configs/living_inverse_foundation_v1.json'`

## Hypothesis

A strict full-256 public-output attacker type, physically separate teacher labels, exact traced ChaCha20 contrasts and a complete non-recovery progress vector can be made executable without reading or competing with the sibling W52 project.

## Prediction

Every target declares 256 unknown bits; no target key or target trace enters a deployment document or feature vector; all six contrast families execute; the random posterior is exactly 256 bits; the oracle ceiling verifies the metric and beam harness.

## Controls

- uniform 0.5 posterior with exact 256-bit key NLL
- one-bit public-output flip
- one-bit wrong-nonce view with unchanged output
- registered shuffled-key control for the first trained reader
- 0.99 truth-posterior oracle metric ceiling

## Budgets

```json
{
  "maximum_cpu_seconds": 120,
  "maximum_decoys": 1000000,
  "maximum_fresh_targets": 0,
  "maximum_gpu_calls": 0,
  "maximum_mps_calls": 0,
  "maximum_sibling_reads": 0,
  "maximum_sibling_writes": 0
}
```

## Pinned source hashes

- `chacha_trace`: `58b8272f2cdd6665291158cecc2456258d3cb58f2ab3970d1c4c38e749473b01`
- `config`: `cda1b20f6e02e98ad5e64a92a65d2462f89267832f0004bf439bbe4b0f0a0e3c`
- `foundation_runner`: `ef81235879f697e6a78e565e5cf6194632d8bf1178ed6e40543ff222ab0e5829`
- `full256_broker`: `cb0d6c2ab6ade5b56db42ef630650c678d743374d4615ca7659ec9d652ff3e6c`
- `living_inverse`: `cbfc48feaf5b1b2ac695e7a03e274e5419b9176750fbc9116e9a3fa2a91b8a5c`

## Metrics

```json
{
  "build_targets": 4,
  "decoy_count": 1000000,
  "deployment_contrasts": 72,
  "deployment_feature_dimension": 2576,
  "development_targets": 2,
  "fresh_target_revealed": false,
  "oracle_ceiling_key_nll_bits": 3.7118898419494637,
  "random_baseline_key_nll_bits": 256.0,
  "result_sha256": "14bfa1dd9e4593cac223a779562ff8b591bf88c485486814be62e6f73baa79a2",
  "schema": "o1-256-living-inverse-foundation-metrics-v1",
  "scientific_inverse_signal_claimed": false,
  "sibling_reads": 0,
  "sibling_writes": 0,
  "success_gate_passed": true,
  "target_trace_fields_in_deployment": 0,
  "unknown_target_key_bits": 256
}
```

## Next highest-ROI action

Train O1C-0009 output-only, candidate-relative and teacher-distilled full-256 readers on the frozen deployment schema, then compare uniform development-key NLL and controls before sealing a target.
