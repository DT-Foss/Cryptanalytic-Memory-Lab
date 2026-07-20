# O1C-0094 — Page-14 nine-axis quotient

## Outcome

O1C-0094 builds a deterministic, lossless quotient of all 261 sealed O1C-0092 Page-14 emissions. Reconstruction preserves row order, every canonical clause identity, every exact witness identity, and aggregate `dad3883312e769efb4a650557a8cd0fdf0e53e0ca6ecbc840fb335c76730fce0`.

No solver, preflight, target, truth, reveal, refit, public-verification, MPS, or GPU call occurred.

## Exact quotient

- Shared signed core: `2709` literals (`245` key, the remainder internal), SHA-256 `80778216ca840ef50729fe16c146c235841e16e70bd86b87ba37edd674e16b19`.
- Prefix rows `0..4` remain separate and losslessly reconstructible.
- Tail rows `5..260`: `256` equal-support rows of `2898` literals with a `2780`-literal signed core.
- Ordered axes: `(15, 18, 23, 28, 100, 118, 181, 216, 238)`.
- Exact decoder: `118` switching variables, `18` observed copy/complement functions, and 256 unique nine-bit codewords.
- Canonical quotient object: `31029` bytes, SHA-256 `0f6eb084847a0a4b2f0556dcae7c5d172e69c4fb1ef8555538c445a215af9e7b`. This is an artifact seal, not the format-independent compression ratio.

## Eight-axis cube multiplicities

Across all 261 rows, the eight-axis projection covers every one of the 256 cells: 253 cells occur once, `00000000` and `10000000` occur twice, and `00000110` occurs four times.
The multiplicity histogram is `{'1': 253, '2': 2, '4': 1}`. Tail-only holes `00000110` and `01000110` are supplied by the five prefix rows; rows 259 and 260 are the two `-238` intrusions.

## Exact subsumption

There is one proper signed-set relation: clause `3` subsumes clause `2` by `17` literals. Removing row 2 would preserve the conjunction, but this lossless quotient deliberately retains it so the original row multiplicity and aggregate remain exact.

## Storage and live-state bounds

The conservative pre-bit-packing accounting is `756414` → `47514` literal entries: `93.7185192236%` removed and `15.9198131077x` smaller. It is exactly 14,526 prefix entries + 2,780 tail-core entries + 30,208 tail residual entries.
A purpose-built packed streaming decoder retains at most `18034` bytes and uses at most `11732` bytes for one canonical row, for a bounded total of `29766` bytes. Offline parsing of the sealed source JSON is excluded from this live decoder bound.

## Claim boundary

This is compression only. Co-variation in 256 observed rows does not prove a CNF equivalence, authorize internal-variable substitution, or establish a key bit, entropy gain, posterior, closure, model, or domain reduction. Logical substitution remains forbidden until the same bound CNF supplies a checkable proof for every copy/complement relation.

## Sealed inputs

- O1C-0092 vault: `5265088` bytes / `8cb5123d0867923a778ef08d64f73b71f51f8c41003b913da183f21e91dbd61b`
- O1C-0092 capsule manifest: `b91e23706c1a019c30f4de016f4f78e8da3494416e9a5fc69043b5c2fb890eae`
- O1C-0092 capsule result: `04c4d7673898dd35d9c613ed0f1676dd8f3a60f01b04167b02660b93adfcc16c`
- O1C-0092 emitted aggregate: `dad3883312e769efb4a650557a8cd0fdf0e53e0ca6ecbc840fb335c76730fce0`
