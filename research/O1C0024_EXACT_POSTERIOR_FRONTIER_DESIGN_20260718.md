# O1C-0024 — Exact Global Full-256 Posterior Frontier

- Recorded: `2026-07-18T03:55:38+02:00`
- Attempt: `O1C-0024`
- Claim level: `RETROSPECTIVE`
- Fresh targets, solver branches, sibling reads/writes, entropy, MPS and GPU: `0`
- Formal execution: not yet reserved at source-design freeze

## Decision

The existing `uncertainty_beam_metrics` is a restricted diagnostic, not a global
posterior beam. It selects the `m` coordinates closest to probability `0.5`, fixes
all other bits to MAP and enumerates only that one `2^m` cube. A globally better
candidate can flip a coordinate just outside that cube and therefore never be
emitted. Its truncated-K `best_hamming_distance` also describes the complete
local cube rather than the candidates actually emitted. That legacy function is
left byte-for-byte unchanged because it belongs to the already frozen O1C-0019
source surface.

O1C-0024 adds a separate exact decoder. For a factorized Bernoulli posterior,
every key is the MAP key plus a subset of flips. Each flip has the non-negative
penalty

```text
abs(log2(p_i) - log2(1-p_i)).
```

The decoder sorts the 256 penalties once and lazily emits the globally smallest
subset sums. Binary64 penalties are converted once to a common exact power-of-two
integer scale; add/replace child costs are then O(1), while the heap gives
`O(K log K)` decoding and memory proportional to explicit K, never `2^256`.
Candidate generation receives only posterior probabilities and K. Truth enters a
separate evaluator after the frontier is frozen; exact ChaCha20 verification uses
only the public counter, nonce and output.

## Deterministic discriminator

A constructed 256-bit, standard 20-round ChaCha20 case assigns the first three
flip penalties `0.10008`, `0.20067`, `0.24116` bits and all others `20` bits. The
true key differs from MAP only at the third coordinate. Therefore:

```text
global top four:  MAP, flip 0, flip 1, flip 2 (truth)
legacy m=2 cube: MAP, flip 0, flip 1, flip 0+1 (truth impossible)
```

The same eight candidates are checked against the factual public target, a wrong
nonce and a one-bit output flip. Only the factual target may match. Exhaustive
widths `3/6/10` independently compare the best-first order against the complete
factorized space, including uniform-probability ties.

## Burned O1C-0016 diagnostic

The real diagnostic consumes only target `o1c0016-replication-0000` from the
already finalized O1C-0016 capsule. It performs no fitting, rescaling, reader
selection or fresh target generation. Before the reveal is opened it reads and
hash-verifies exactly:

1. the pinned source manifest;
2. `publication.json`;
3. `probabilities.f64le`;
4. the original `prediction_freeze.json`.

The source manifest is parsed but the 680-member source capsule is never scanned.
Only the five selected member commitments are checked against the pinned manifest
and config. The global 65,536-key frontier, scores, frontier index and selected
manifest index are then persisted and hash-frozen. A durable checkpoint is
written before the one selected reveal read; a second checkpoint records verified
completion. The selected evaluation payload is read once under the same
started/completed protocol. Crashes recover read counts from the durable phase;
unknown state is recorded as unknown, never fabricated as zero.

The revealed publication must equal the pre-freeze publication byte-semantically;
the source evaluation must bind the same target and reveal hash. All selected
members are read through an `O_NOFOLLOW` directory-fd walk and verified against
both config and manifest hashes.

## Exact work and budgets

- global candidates: `65,544` (`8 + 65,536`)
- proof candidate evaluations: `2,192`
- legacy matched-cube assignments: `65,540`
- public ChaCha20 verifications: at most `24 + 4,096`
- source manifest reads: exactly `1`
- selected source payload reads: exactly `5`
- reveal/evaluation payload reads: exactly `1/1`
- other outcome payload reads and full source-capsule scans: exactly `0/0`
- CPU/wall: `30/30` seconds
- process peak RSS: `256 MiB`
- persistent artifacts: `4 MiB`

Final classification is computed only after every work and resource check. A
budget failure is `OPERATIONAL_BUDGET_FAILURE`, never an
`EXACT_GLOBAL_FRONTIER_*` success with a failed outer capsule.

## Claim boundary and next transition

The synthetic rank-four recovery validates the decoder and public verifier, not
a ChaCha20 weakness. The burned target is retrospective and can only diagnose
whether the already frozen O1C-0016 posterior concentrated useful search mass.
No exact burned hit means terminal condition (c) remains open. The resulting
decoder becomes the fixed downstream search operator for any later O1C-0019 or
O1C-0022 posterior that shows portable entropy reduction; evidence orientation,
not beam geometry, remains the upstream bottleneck.

