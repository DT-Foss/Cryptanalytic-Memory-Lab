# Apple-view result: no full-round attraction detected

Reference run: 2026-07-19, deterministic seed
`apple-view-full256-v1-20260719`.  Machine-readable measurements are in
`apple_view_result.json`.

## Validity checks

- The lean implementation reproduced the RFC 8439 ChaCha20 block vector.
- The repository's independent ChaCha helper reproduced that vector and all 32
  generated targets (33 checks total).
- Every search received a counter, nonce, one output block, and an unrelated
  32-byte start; no part of the generated key entered a search interface.
- Every evaluated candidate was a full 256-bit key for standard 20-round
  ChaCha20.  No reduced-round or partial-key result is mixed into the metrics.
- No sealed target, GPU, MPS, or sibling-repository write was used.

## Measurements

The fixed-point diagnostic used 128 target/start observations, 64 of them in
the predeclared holdout.  Its intervals are formed over 16 holdout target means,
so four starts on the same target are not counted as independent targets.  The
landscape diagnostic scored all 256 bit flips on each of 32 starts (8,192 flips
total; 4,096 on holdout).

| Holdout measurement | Result | Null / gate |
|---|---:|---:|
| Full `F_y(k)` key-distance improvement | -0.484 bit, 95% CI [-3.846, 2.877] | gate: >=2 and CI >0 |
| Full `F_y(k)` resulting key distance | 128.281 bits | random: 128 |
| Public selector advantage over uniform candidate choice | -0.258 bit, CI [-1.781, 1.266] | null: 0 |
| One-bit fitness direction accuracy (ties half) | 0.49854, CI [0.48113, 0.51594] | null: 0.5 |
| One-bit fitness AUC for identifying a wrong key bit | 0.50572, CI [0.48731, 0.52414] | gate: >=0.53 and CI >0.5 |
| Apparent sign/label mutual information | 0.000434 bit | descriptive, in-sample |
| Exact 256-bit recoveries | 0 | requires 512/512 output verification |

Neither continuation gate passed.  The four fixed 128-bit partial projection
masks also remained at random-scale key distance; their complete values and
confidence intervals are retained in the JSON result.

The public-only projection chains are a useful warning about the objective.
Across 128 chains and 3,072 executed projections, keeping the best photographed
match reduced output mismatch by 23.906 bits on average, yet its mean true key
distance was 128.789 bits (random null 128).  Six best-one-bit descents reduced
output mismatch by 33.0 bits while changing true key distance by only +0.5 bit
toward the key, CI [-0.48, 1.48].  Picking the best of many avalanche-random
outputs therefore creates visible score progress without transferable key
information.

## Resources

- 21,108 total 20-round ChaCha core permutations: 17,875 lean full-block
  evaluations, 3,200 lean projection-only evaluations, and 33 independent
  project-helper full-block evaluations (validation work included)
- 10.478 s wall time; 10.425 s CPU time
- 2,015 core permutations/s
- 6,420,387-byte peak traced Python allocation
- 43,433,984-byte process maximum RSS
- macOS 26.5 arm64, Python 3.13.1, single CPU process

## Decision

Stop scaling this fixed-point/local-output-Hamming direction at 20 rounds.  The
bounded result is negative evidence about this search signal, not a proof that
full-256 inversion is impossible.  A next apple-view experiment should require
an exact-equation structural observable that survives a new-seed holdout;
simply adding starts, projection depth, or greedy score descent is rejected
because it demonstrably buys output-score improvement without key-entropy
improvement.
