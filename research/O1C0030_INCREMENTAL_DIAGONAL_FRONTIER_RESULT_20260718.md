# O1C-0030 incremental diagonal frontier — result

- **Completed:** `2026-07-18T13:44:13.789583+02:00`
- **Classification:** `RETROSPECTIVE_BREADCRUMB_NO_STRONG_GATE`
- **Source freeze:** `e7c1bf551f2abf3c00a82c46d48b021452dfd417`
- **Capsule:** `runs/20260718_134406_O1C-0030_incremental-diagonal-frontier-v1`
- **Manifest:** `ed6ef945e0e05ebf3199b3526c71d70da8402cc07bd8d7c4ec6c66bed483b04e`
- **Result:** `d1aa33be2852f83e923fb29dd4b13ebd3340e466b624bf4fc5efe17ea2f73715`

## Outcome

The same-coordinate exact-frontier lamp is null.  Primary mean compression is
`-0.680620` bit/key and trails cumulative replacement in all four folds, with a
mean margin of `-0.582832` bit.  It also loses every frozen mean-control gate.
No exact key occurs in any of the four exact global top-65,536 frontiers.

| Arm | Mean compression (bit/key) | Positive folds | Correct bits by fold |
|---|---:|---:|---|
| primary | `-0.680620` | 3/4 | 135 / 135 / 144 / 134 |
| cumulative replace | `-0.097788` | 3/4 | 136 / 135 / 144 / 134 |
| legacy reintegrated | `+0.035626` | 3/4 | 136 / 135 / 144 / 134 |
| deranged confidence | `+0.779642` | 3/4 | 135 / 135 / 144 / 134 |
| polarity-even common mode | `-0.262728` | 3/4 | 139 / 137 / 138 / 132 |

The deranged arm is a **control win**, not a primary signal.  Moving the same
confidence flags away from their own coordinate improves code length by
`1.460262` mean bits relative to primary.  Therefore the precommitted causal
claim — an exact-cutoff event should amplify its own self-ancestry innovation —
is contradicted on these four consumed fields.

## Breadcrumb

The all-bit accuracy superficially looks stronger than the code length because
the diagonal is sparse: cumulative replacement is nonzero on only
`131/135/131/177` coordinates.  On those 574 active rows it is correct on
`60/76/81/95 = 312/574` (`54.3554%`).  This descriptive post-result statistic is
not a precommitted gate and is not corrected for the tested arms.  It preserves
one narrow clue — three episodes orient the active diagonal above chance — while
the fourth reverses its magnitude-weighted correlation and makes LOO confidence
harmful.

Exact-conflict asymmetry is also strongly nonstationary.  H64/H65/H96 counts are
`21/87/22`, `10/2/9`, `93/88/14`, and `5/22/20` across the four episodes.  A
coordinate-local hard multiplier cannot calibrate that field.  The next useful
mechanism is therefore learned global/live routing, not another scalar or clip
sweep over this diagonal.

## Resources and boundary

The complete run took `7.381760` CPU seconds and `7.455637` measured wall
seconds at `65,748,992` bytes (`62.70 MiB`) peak RSS.  It read `8,331,098` pinned
source bytes, fit 20 scalars, scored 5,120 heldout logits and streamed 262,144
exact global candidates.  Persistent artifacts occupy `168,648` bytes.  Solver,
entropy, target generation, sibling, MPS and GPU work are all zero.  A repeated
formal invocation returns the verified capsule without replay.

This closes only summarized diagonal self-ancestry plus same-coordinate
exact-frontier amplification.  It does not close raw antecedent identity,
signed interaction pairs, the pending full 330D O1C-0019 reader or O1-O's future
live scout-to-focus loop.  Once authoritative packet deltas exist, compare
recurrent live re-ranking against the identical frozen one-shot priority at
matched work; if packet evidence remains null, move the sensor to raw
antecedent/signed-pair identity rather than resweeping O1C-0030.

See the exact post-result accounting in
[`O1C0030_POSTRESULT_DIAGNOSTIC_20260718.json`](O1C0030_POSTRESULT_DIAGNOSTIC_20260718.json).
