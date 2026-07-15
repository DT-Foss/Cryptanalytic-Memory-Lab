# Dead Ends and Breadcrumbs

This file records mechanism-level conclusions, not every failed parameter setting.

## B-0001 — Plain equal-cell holographic superposition

- **Evidence:** five-seed MQAR-256 result at 65,536 distractors.
- **Result:** 83.5938% mean bit accuracy and 0/5 exact keys despite a frozen state.
- **Conclusion:** the state retains address-dependent information but crosstalk
  prevents exact 256-bit recall at this budget.
- **Do not repeat:** identical single-state phase superposition with cosmetic seed or
  length changes.
- **Breadcrumb:** test structural separation—fixed slots, polyphase reads,
  multi-slot binding or learned routing—rather than more of the same channel.

## B-0002 — Duplicate-confidence inflation

- **Evidence:** 1,024 repeats of one 55%-correct error orientation.
- **Result:** 55.8594% mean bit accuracy and 0/5 exact keys, while genuinely
  independent evidence reaches 99.8438%.
- **Conclusion:** relation count is not effective sample size.
- **Breadcrumb:** estimate diversity/dependence and gate repeated evidence by
  novelty or surprise before adding log-odds.

## B-0003 — Raw cipher-distance shortcut

- **Status:** untested as a positive mechanism and intentionally deprioritized.
- **Reason:** full-round raw output distance is expected to be pseudorandom and does
  not expose where nonlinear evidence arose.
- **Breadcrumb:** instrument carry geometry, propagation conflicts and temporal
  solver deltas before revisiting any aggregate output metric.

## B-0004 — Two-target selection over 119 raw readers

- **Evidence:** `O1C-0002`, with the exact selection procedure replayed for every
  possible pair of validation labels.
- **Result:** observed best validation gain 3.348 bits; familywise `p=0.664139`;
  the null selection itself averages 3.823 bits.
- **Conclusion:** the attractive validation score is fully explained by selection
  multiplicity at this sample size.
- **Do not repeat:** more raw-feature candidates or tie-break changes on the same two
  validation targets.
- **Breadcrumb:** shrink the operator family using independent semantic selection,
  then test joint temporal profiles, XOR orbit residuals and fixed spectral slots.

## B-0005 — Standalone horizon-8 propagation rank

- **Evidence:** frozen plan `ae2bda0e…` evaluated after pre-reveal order hashing.
- **Result:** positive but weak holdout gains (0.801 A296; 1.104 W32), with ranks
  240/90 and 41/244/245/82; it failed the all-control gate.
- **Conclusion:** late propagation count is not a stable scalar sufficient statistic.
- **Breadcrumb:** preserve it inside a multi-horizon shape vector and test whether
  curvature/neighborhood structure stabilizes it.
