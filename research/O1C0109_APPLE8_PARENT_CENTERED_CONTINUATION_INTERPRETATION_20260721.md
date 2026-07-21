# O1C-0109 — Third Full-256 clause gain and bounded prune breadcrumbs

- **Completed:** `2026-07-21T10:34:58.616343+02:00` (`Europe/Berlin`).
- **Classification:** `PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN`.
- **Parent:** certified Page 22 / lineage 35, SHA-256 `18387804…162f`.
- **Result SHA-256:**
  `22ec1c6a2f67c0ec89c85347865c4fc248c43ad2dacc8955fd76a72940a52c28`.
- **Capsule inventory SHA-256:**
  `050a073b24fb2866b87e8353c1c8357c6598fa2eb9cf54119ee2991d7a99f2d0`.

## Full-256 science result

The one authorized native call emitted 267 distinct score-threshold no-goods.
All 267 are globally novel against the complete 3,111-identity logical
registry and all are new relative to Page 22. The batch contains 749,811
literals and has canonical clause aggregate SHA-256
`228da2ac7fc7f66e36dec68de31925860ceaec1525ec27cf8f8a701d49847603`.
There are zero within-batch duplicates, zero Page-22 duplicates and zero empty
clauses.

All witnesses are strict below `tau=14.606178797892962`. Their upper-bound
minimum / median / maximum is
`13.765196844130042 / 14.318085873700698 / 14.602921373872835`; the closest
strict margin is `0.0032574240201270754`. Clause lengths range from 2,797 to
2,832 literals with median 2,798.

The stop is again the exact bounded-state edge: Page 22 has 246 clauses and
`246 + 267 = 513`, one above the 512-clause native cap. The complete new batch
is archived; no oversized successor vault is serialized. Page 22 and lineage
35 are burned forever and must not be retried or replayed.

## Runtime and living state

The scientific native work used requested/actual/billed conflicts
`128/34/34`, 552 decisions and 1,761,683 propagations. Native wall time was
`0.716391 s`, CPU time `1.435968 s`, and peak RSS `371,752,960 B`.

The live reader made 33,569 exact probes / 67,138 child-bound evaluations and
returned 255 one-shot failure-first actions. Every action confirmed; ten
released and none released unobserved. Direct certified crossing actions remain
zero.

The 24,576-byte bank evolves from `62360d82…87f` to
`efffdc2021d3c62bd92e4557a8515f1728bd3350582010b0b4a90a0d2fc65951`.
Its count sum grows exactly `416,094→449,663`, equal to the 33,569 probes;
255/256 records change, variable 241 remains the sole zero record, and output
nonzero counts span 240 to 4,006.

## What the new breadcrumb sidecar reveals

O1C-0109 retained all local-prunable probes in a fixed 256-row sidecar. The
result is complete: 100/100 rows retained, zero overflow, canonical record
digest `74e34b57…80f5`. It contains 37 `ONE_PRUNABLE` and 63
`BOTH_PRUNABLE` observations. All 100 occur on already-consumed coordinates;
none was crossing-eligible. This proves that the previous zero direct-crossing
counter hid real local threshold structure behind the one-shot mask.

The 100 rows are not 100 independent key bits. They collapse to two coordinates
over 57 distinct parent states:

- coordinate 193 / variable 194: 57 rows, 8 one-prunable, primary
  `fsum(U1-U0)=-1.1698760390366978`;
- coordinate 196 / variable 197: 43 rows, 29 one-prunable, primary
  `fsum(U1-U0)=-5.826575973980701`.

Every one-prunable row has `U1<U0` and losing literal `+variable`, so the frozen
relative-bound reader points to bit 0 for both coordinates. This direction was
fixed before any truth read in O1C-0111 design commit `619410e`; it is not yet a
posterior or recovered bit.

## Claim boundary and next tests

This is the third compounding Full-256 native-clause gain in the live bounded
continuation. It is not a recovered key, calibrated posterior, beam hit,
attacker-valid entropy/domain reduction or realized direct crossing. O1C-0109
read zero target or truth bytes and used no refit, MPS or GPU call.

Two zero-call consequences now run separately:

1. O1C-0110 losslessly appends all 267 native clauses, recomputes exact
   resolution and real-v8 type safety, and constructs fresh Page 23.
2. O1C-0111 evaluates the two pre-frozen bit directions against the already
   sealed historical reveal. Even 2/2 is only a retrospective breadcrumb with
   fair-coin tail 0.25 and requires unchanged fresh replication.
