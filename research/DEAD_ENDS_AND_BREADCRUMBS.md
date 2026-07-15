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
