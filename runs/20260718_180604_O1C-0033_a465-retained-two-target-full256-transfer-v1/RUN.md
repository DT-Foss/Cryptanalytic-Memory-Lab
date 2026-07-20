# O1C Run O1C-0033

- Schema: `o1c-run-capsule-v1`
- Status: `completed`
- Claim level: `TEST`
- Git commit: `4bb7739a9fdef2666a20b526e3d088d4d23e2ae3`
- Started (Europe/Berlin): `2026-07-18T18:06:04.140371+02:00`
- Ended (Europe/Berlin): `2026-07-18T18:06:05.217484+02:00`
- Elapsed seconds: `1.077113`
- Command: `PYTHONPATH=src python -m o1_crypto_lab.o1c33_a465_retained_transfer_run`

## Hypothesis

A465's unchanged A460/A462/A463 rank-space Product-of-Experts improves or preserves byte-3 ordering on both retained all256 A448 streams.

## Prediction

Both consumed targets rank <= 128/256; only then may the exact A465 reader earn one fresh blind target.

## Controls

- all A465 weights, waves, feature order and ties are loaded from hash-frozen sibling results
- only retained target-key-free A448 raw streams enter prediction
- both complete rank fields are persisted before either target byte is reconstructed
- no new solver stage, fit, target, coefficient, byte or operator selection is used
- all other 248 key bits were unassigned in the retained public CNF measurements

## Budgets

```json
{
  "MPS_or_GPU": false,
  "maximum_resident_memory_mib": 512,
  "maximum_wall_seconds": 30.0,
  "new_solver_stages": 0,
  "new_target_count": 0,
  "target_count": 2,
  "target_role": "CONSUMED"
}
```

## Pinned source hashes

- `a448_transfer`: `1e04ac9fbce5165e33f5590fda6e2b060ba0233a62919dd50a0359013dcbceea`
- `a465_transfer`: `b81e89a5c7cecc5cecba75eb41aad61a2cc0759b5565234c276171023e9596b6`
- `o1c33_runner`: `a5e3703d8d5b387311385c8af1b1c403c2a3d646a027231d096c8057a1a43fda`
- `retained_RFC8439_manifest`: `b89b3ea4452b74a4da38a73764d34278e918008fdf59f14983a18b48aceca919`
- `retained_RFC8439_raw`: `8098c6438a0e2264242733a554b0956ee2e49701bb84979b947bd16d201860bf`
- `retained_development-0000_manifest`: `93b25facb9099e10d1c13bfc44a542cab1b04607d19eb48ebb0dd919a7ef1892`
- `retained_development-0000_raw`: `40cf3a8f258e4d9d12ea20497dca5bc7bfb5edc7d740bf28765ce07322bb85a6`
- `run_capsule`: `13681939e0a5cd09d4f32c6d92c9a56894cfe8af90f07d5d4190c96b90a1b664`
- `sibling_A447_source`: `732579d73de55d8f544f5acd99104b581bedcf51956d773b3652b3e4ae786ca4`
- `sibling_A448_source`: `33cf14799282e52a6e23857d15dba096ba61e003fdef8b53a2b6a93a5dcd9d60`
- `sibling_A458_source`: `9b24dce3b2b0f3eff5ad9b7d623dc6b1982968088396114e6ac9286ad24ae159`
- `sibling_A460_result`: `5d1d8c24e9ac161660e07ce48a92d88d6a3e135ac24efb9090fcf1cdea2ef88c`
- `sibling_A462_result`: `c8a94bf3ce721730e24e21739506005bc4a0f3b6b6e1ed7a6d2274ff7b60d461`
- `sibling_A463_result`: `568281979795264bdf1d0f3f35746114e7e91ada9d05d472f50797d3bccdcb75`
- `sibling_A463_source`: `58aadd5aba3a0fcd76d6244da02522e5d5554fbca6f18917e363d4632dc882bc`
- `sibling_A465_result`: `a22ddbc7c204506980847bf0856b0f806f84f79d169551e08d713920afe28a62`
- `sibling_A465_source`: `87e95be3355ae9e16015fded326458a6effa89fc873978e15838289f5d87ef4f`

## Metrics

```json
{
  "both_passed_median_gate": false,
  "elapsed_seconds": 1.0688373330003742,
  "new_solver_stages": 0,
  "new_targets": 0,
  "ranks": [
    47,
    239
  ],
  "self_maxrss_after": 298795008,
  "target_count": 2
}
```

## Next highest-ROI action

Close A465 all256 byte transfer; do not resweep and inspect the exact A469 input contract next.
