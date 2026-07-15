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

## B-0006 — Sparse support learned from one calibration field

- **Evidence:** `O1C-0005`, global Walsh masks ranked by A348 coefficient energy and
  transferred unchanged to A349.
- **Result:** K=2,048 retains only `0.797225` A349 rank-Spearman. Even K=3,072 remains
  materially below the dense low-precision bank; near-exact sparse reconstruction
  requires almost the complete float64 basis.
- **Conclusion:** the individual high-energy modes are calibration-specific. Useful
  Direct12 geometry is distributed across the basis rather than concentrated in a
  small globally sparse support.
- **Do not repeat:** more top-energy cutoffs or cosmetic mask tie-breaks on A348.
- **Breadcrumb:** preserve dense structured coverage and compress precision; when
  pruning is necessary, learn support across multiple independent training fields.

## B-0007 — Precision allocation beats coefficient pruning

- **Evidence:** `O1C-0005` quantized 16-slot bank with all 255 non-DC high8 modes per
  low4 slot and A348-frozen scales.
- **Result:** 4-bit inputs with 1.25 headroom use 6,668 online bytes, clip zero A348
  values and retain A349 at Spearman `0.990198`; 6-bit reaches `0.999616`. O1-O chose
  4-bit because it was the smallest arm crossing every fidelity gate.
- **Conclusion:** for this score stream, keeping the distributed representation and
  lowering per-register precision dominates keeping high precision on sparse modes.
- **Boundary:** this is a 4,080-register full-rank bank, constant in stream length;
  it is not a sublinear-capacity or 256-bit key-recovery result.
- **Breadcrumb:** freeze the 16 scales as the portable primitive and test one truly
  untouched field before any more precision tuning.

## B-0008 — Candidate dictionary is a ceiling, not an O1 mechanism

- **Evidence:** fourteen direct quantized-table controls persisted alongside valid
  O1C-0005 orders.
- **Result:** a candidate-indexed table can be smaller in raw bytes, but it retains
  all 4,096 key/value entries and is structurally excluded from O1-O selection.
- **Conclusion:** byte size alone does not make a dictionary an admissible bounded
  associative state.
- **Do not repeat:** promote a direct table, alphabet-indexed register bank or
  candidate cache as the mechanism win.
- **Breadcrumb:** keep it only as an information/quantization ceiling and compare
  valid mechanisms against it explicitly.
