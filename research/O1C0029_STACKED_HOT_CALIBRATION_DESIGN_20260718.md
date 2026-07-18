# O1C-0029 — Outcome-independent stacked hot calibration

Date: 2026-07-18 (Europe/Berlin)

Status: conditional source instrument complete and preflight-clean; no attempt
reserved, no label scored, no target consumed. Activation remains pending on the
manager-authoritative finalized O1C-0022 capsule.

## Highest-ROI question

Can the complete real O1C-0022 H64/H65/H96 packet field acquire portable key
orientation when each outer-fold reader's public evidence is consumed once into
the O1C-0028 V2 sufficient state and only the final horizon weights and global
temperature are fitted hot?

This is the first direct real-packet test of the constant-streaming boundary. It
does not regenerate a solver trace and does not replay the packet stream while
trying reader weights.

## Exact scientific boundary

O1C-0029 is retrospective `OUTER_FOLD_STACKED_HOT_CALIBRATION`, not an inner
cross-fit. For outer owner A:

- the O1C-0019 base reader was trained on B/C/D;
- A's B/C/D public K256 packet extractions and A-owned quantizer train the hot
  readout;
- A's A packet state is the only held-out prediction input;
- A's label cannot enter A's fit, state or inherited ancestry;
- the same rule rotates over B, C and D.

True nested cross-fitting would require twelve additional inner readers trained
on episode pairs. Those readers do not exist, so no such claim is made.

## Outcome-independent operator precommitment

Both arms execute for every fold regardless of the O1C-0022 result and regardless
of the eventual O1C-0023 selection:

1. `horizon_nonnegative_simplex_v1`: fixed-alpha nonnegative horizon fit;
2. `magnitude_confidence_calibration_v1`: the identical frozen slot weights with
   only a global temperature selected from a fixed config grid.

An actual O1C-0023 decision hash may be recorded only as context after logits are
formed. It cannot choose an arm, change a fit, or authorize a scientific claim.
This avoids using a four-fold post-result selector on the same four folds it
inspected.

## Mandatory lifecycle

1. Resolve the manager-authoritative finalized O1C-0022 capsule.
2. Verify its exact 384-member publication once inside an isolated trusted child.
   That integrity pass necessarily reads `labels.bitpack` once, but transfers only
   a nonce-bound, path-free packet corpus plus manifest/index/label commitments;
   no label payload enters the parent or scientific protocol.
3. Project only twelve calibration packet ledgers, four held-out K256 ledgers and
   four public quantizers into a path-free, label-free capability.
4. Freeze and durably persist all sixteen `(reader owner, source episode)`
   normalized V2 states in canonical 4x4 order before the first scientific label
   opening.
5. Revalidate the authoritative artifact index and `labels.bitpack`; expose only
   an owner-excluding calibration broker. For each outer fold, grant exactly the
   other three labels, fit both precommitted hot readers and read the held-out
   owner state without mutation.
6. Persist all four fits, four prediction receipts, eight 256-logit vectors and
   the complete prediction result before held-out scoring authority can exist.
7. Independently re-read and revalidate the index and `labels.bitpack`; mint a
   lineage-bound post-prediction label capability only for that complete result.
8. Score both arms and the exact factorized top-K frontier without refitting or
   selecting an arm from those scores. Score objects are factory-only and
   revalidate every fold, rank, count, aggregate, tie policy and receipt hash.

The live state is 25,128 bytes per owner/episode edge and independent of packet
stream length. Sixteen persisted states total 402,048 bytes before receipts.
The trusted manager pass, label-excluding producer pass, 128-byte placeholder
projection, packet projection, accounting probe and two scientific label opens
have separate exact byte and open counters.

## Frozen producer/consumer repair

Static and semantic contract comparison found exactly one O1C-0022 to O1C-0023
break:

- the frozen O1C-0022 producer writes `scientific_entropy_calls: 0` in every
  held-out prediction freeze;
- the frozen O1C-0023 exact field inventory omits that member and therefore
  rejects producer-authentic output before composition.

Calibration, result, resource, metrics, source-module and artifact inventories
otherwise align. O1C-0029 must recognize only the exact producer form: omission,
nonzero entropy and unknown extra fields all fail. Historical source and capsules
remain unchanged.

## Required metrics

For each fixed arm and each fold:

- full 256-bit NLL and compression relative to exactly 256 bits;
- bit accuracy and number of positive folds;
- true byte and 16-bit block ranks;
- exact full-key rank/hit within the factorized top 65,536 frontier;
- byte-exact state, fit, binding and prediction commitments;
- state bytes, persistent bytes, CPU, wall and peak RSS.

The first retrospective promotion gate requires positive compression in all four
folds and no held-out-lineage violation. Passing it authorizes one newly sealed
DEVELOPMENT target under a new attempt identity; it is not itself a fresh-target
result.

## Current implementation anchors

- `o1c29_packet_corpus.py`: exact producer packet/quantizer projection;
- `o1c29_stacked_hot_calibration.py`: 16-state barrier, one-shot fold label grants,
  fixed simplex/temperature fits and immutable hot predictions;
- `o1c29_real_protocol.py`: index-bound two-stage label authority, factory-only
  input/manager/score capabilities and exact byte/block/full-key ranks;
- `o1c29_runtime_freeze.py`: fresh-process closure over 25 application modules
  plus its separately pinned verifier, CPython 3.13.1 and NumPy 2.2.6 ABI/build
  fingerprints;
- `o1c29_stacked_hot_calibration_run.py`: no-reservation conditional preflight,
  attempt-spanning execution lease, persist-before-reveal lifecycle and exact
  source/work accounting;
- `o1c23_selection_authority.py`: manager-authoritative compatibility seam for
  the single producer/verifier ABI mismatch;
- O1C-0028 V2 basis SHA:
  `75b0c13e830c2bf586c0df5fd180eb84ff0d7676b2f28759cc3ce0e3c4f579f6`.

The final focused verification is 44 tests plus 25 subtests; 45 neighboring
packet/state/composer tests plus 12 subtests also pass under the pinned runtime.
The live preflight is `prerequisite-pending`, creates no O1C-0029 reservation or
run directory, and does not inspect O1C-0023.

## Activation condition

Do not reserve O1C-0029 while W52 is active or before O1C-0019 and O1C-0022 have
finalized and verified. O1C-0023 may be attached only as optional metadata and
never selects an O1C-0029 arm. Until activation, only source work, synthetic
fixtures and lightweight tests are allowed.
