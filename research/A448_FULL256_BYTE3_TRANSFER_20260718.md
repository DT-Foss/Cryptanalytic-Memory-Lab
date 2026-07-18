# A448 exact proof-byte transfer — 2026-07-18

The exact sibling A448 proof-antecedent reader and its A442 Borda backbone now
run directly on a standard full-round ChaCha20 public relation with all 256 key
bits unknown. One byte-3 cube uses 256 candidates and 1,024 solver stages,
assigns none of the other 248 key bits and takes 48–55 seconds on this Mac.

The unchanged reader ranked the consumed RFC8439 byte at `47/256`, then ranked
the disjoint consumed DEVELOPMENT-0000 byte at `239/256`. On the repeat, the
A442 baseline, proof-only arm and frozen hybrid ranked the truth `242`, `236`
and `239`; none transferred useful orientation. The two final ranks have mean
log-rank `6.727728` versus the exact uniform expectation `6.578110`.

Decision: **closed; not replicated**. No fresh target was spent and there will
be no byte, sign, coefficient, horizon, operator or target resweep. This is a
failed recovery transfer, not a milestone. The reusable output is only the
exact public-only one-pass adapter.

Machine-readable result:
[`A448_FULL256_BYTE3_TRANSFER_20260718.json`](A448_FULL256_BYTE3_TRANSFER_20260718.json).

Next: transfer the next exact sibling mechanism that accepts all 256 bits
unknown. Keep A325/W46 and A526/W52 unchanged as terminal residual backends;
invoke them only after an upstream completion satisfies their 210/210 or
204/204 complement gate.
