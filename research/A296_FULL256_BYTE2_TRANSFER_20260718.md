# A296 exact shallow byte-cube transfer — 2026-07-18

The literal A291/A296 H1/H2/H4/H8 selected-eight reader is now executable on a
standard full-round ChaCha20 relation with all 256 key bits unknown. One byte
cube costs 46–56 seconds on this Mac and assigns none of the other 248 bits.

The unchanged byte-2 reader produced ranks `118`, `61`, and `9` on three consumed
targets, then failed the single fresh EVALUATION target at `230/256`. Across all
four ranks the geometric mean is `62.13`; the descriptive `0.621` ranking-bit
advantage is ordinary under a uniform order (rank-product lower-tail `p=0.1766`).

Decision: **closed null; does not generalize**. The fresh rank is negative and
there will be no coefficient, sign, byte, or target resweep. Keep the exact
measurement adapter because it gives cheap real full-256 cubes; do not keep this
reader as an active recovery candidate.

Full machine-readable result:
[`A296_FULL256_BYTE2_TRANSFER_20260718.json`](A296_FULL256_BYTE2_TRANSFER_20260718.json).

Next: consume the sibling session's actual partial-recovery state and attach its
exact residual evaluator/ChaCha verifier as a terminal backend. Do not recreate
that mechanism from approximate cached fields.
