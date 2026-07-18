# Apple-view full-256 experiment protocol

## Scope and isolation

- Primitive: standard RFC 8439 ChaCha20 block, all 20 rounds.
- Unknown to every search routine: all 32 key bytes (256 bits).
- Public input: one counter, one 96-bit nonce, and one 64-byte output block.
- Data: reproducible build data derived with SHAKE-256 from the public seed
  `apple-view-full256-v1-20260719`; no fresh sealed target is opened.
- Hardware: one CPU process, standard-library implementation, no GPU/MPS.
- Writes: only JSON files whose names begin with `apple_view_` directly in this
  directory; the CLI resolves and rejects any output path outside that boundary.

The harness stores each generated key only beside its public target so it can
score an experiment after a search decision.  `project_key`,
`projection_chain_search`, and `coordinate_greedy_search` accept no secret-key
argument.  Thus search uses exactly the stated public target even though the
measurement harness can calculate distance to truth.

## Implementation validation

The lean evaluator is checked against the RFC 8439 block-function vector.  All
generated target blocks are also checked against the repository's existing
exact ChaCha helper.  An exact recovery requires both candidate equality to the
generated 256-bit key and reproduction of all 512 output bits; a low Hamming
mismatch is not recovery.

## Tests

### 1. Feed-forward projection

For each of 32 deterministic targets and four unrelated deterministic starts,
compute the proposed fixed-point update

```
F_y(k)[j] = y[4+j] - P20(s(k))[4+j] mod 2^32.
```

Measure key Hamming distance before and after full replacement.  Also test four
fixed 128-bit partial-update masks (even bits, odd bits, low word halves, high
word halves).  The masks are fixed before seeing outcomes.  Select among the
start and five updates using only the public 512-bit output mismatch, then test
whether this selection saves true key bits relative to uniform selection among
the same candidates.

Target IDs 0..15 are reported as training/descriptive data.  IDs 16..31 are a
fixed holdout.  The direction proceeds only if the full projection improves the
holdout by at least 2.0 key bits on average and its approximate target-clustered
95% confidence interval excludes zero.  Multiple starts on one target are
averaged before forming the interval, so they are not treated as independent
targets.

### 2. All-256 one-bit landscape

At a separate start for every target, flip each of all 256 key bits once.  The
public score is reduction in output-block Hamming mismatch.  Only afterward,
use the harness key to ask whether each proposed flip would correct an actually
wrong key bit.  Report directional accuracy (ties count one half), ROC AUC,
top-1/top-8/top-32 enrichment, a sign contingency table, and empirical mutual
information.  The same target split is retained.

This direction proceeds only if holdout mean AUC is at least 0.53 and its
approximate target-level 95% confidence interval excludes 0.5.

### 3. Bounded public-only searches

- 128 independent fixed-point chains, up to 24 projections each; the returned
  key is the visited candidate with least public output mismatch.
- Six best-one-bit coordinate descents, up to six steps; every step scans all
  256 unknown bits and uses only public output mismatch.

Report any exact matches, final key distance for measurement only, and separate
counts for lean full-block, projection-only, and independent-helper work
(including RFC/helper validation and final candidate checks), plus wall/CPU
time, Python allocation peak, and process maximum RSS.

## Commands

From this directory:

```
PYTHONPATH=../../src python3 -m unittest -v apple_view_test_full256_projection.py
PYTHONPATH=../../src python3 apple_view_full256_projection.py \
  --output apple_view_result.json
```

The default result file is the committed reference run.  Re-running with the
same seed reconstructs every target and start exactly; timing fields may differ.
