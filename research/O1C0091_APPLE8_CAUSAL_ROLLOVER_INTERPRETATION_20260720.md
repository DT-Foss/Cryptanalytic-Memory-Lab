# O1C-0091 — Page-14 causal rollover

Recorded 2026-07-20 CEST. O1C-0091 is terminal
`CAUSAL_ATTIC_PAGE14_ROLLOVER_PREPARED`. It performs no science or solver call;
it atomically preserves O1C-0090's complete harvest and derives fresh Page 14 /
lineage 27.

## Result

- All 260 O1C-0090 clauses / 743,794 literals enter one immutable chunk,
  SHA-256
  `75778121b2cf9277e861057eafec70a8fca649feef38d635fdfae1b2626ed3df`.
  Every occurrence is unique, globally novel against the prior 1,291-clause
  attic, `source=trail_upper_bound` and `classification=new`.
- The attic reaches 17 chunks, 1,551 unique clauses, 1,559 occurrences and
  1,541 undominated clauses. Its union is 4,334,114 literals / 17,342,851 B,
  SHA-256
  `3db1ae23e3aa7b99196905f13234c2001aa75407af322eba1fc431f7a5540475`.
- The ten prior strict subsumption relations are preserved exactly. Three new
  strict relations are added: `1296→1295`, `1298→1297` and `1328→1327`.
  Each subsumer is resident and shorter by 2, 15 or 17 literals respectively.

## Fresh Page 14

Page 14 / lineage 27 is fresh and unburned at the minimal active limit 252:

```text
clauses              252
literals             704,145
serialized bytes     2,817,779
SHA-256              00a5a4a7b33f1c09c8df24162709b17994bad5825d92476a5f5283a3bf025c7e
categories           8 structural roots + 43 pinned core + 201 new debt
headroom             260 clauses + 895,855 literals + 5,570,829 bytes
```

The clause headroom exactly equals the measured O1C-0090 burst and is four
slots above the 256-action capacity. Literal and byte headroom are measured
residuals; future emission safety under those two caps is not claimed.

All 260 new clauses remain in the attic. Of them, 190 are live-resident and 70
are explicitly nonresident. Three of the 70 are dominated by resident new
clauses; 67 are undominated. Across the full history, 107 undominated clauses
have never been resident. These populations are deliberately distinct and are
sealed separately rather than collapsed into one missing-clause count.

Fourteen prior Page-13 nonresidents become resident, leaving 40 prior missing
clauses. The three new subsumers create three additional structural roots, so
the root set grows `5→8`; the 43-clause pinned core remains exact.

## Live continuation state

The exact 24,576-byte bank is SHA-256
`715bfbc22fa2162ec8546eed21cf609318d3c5be806092dc4fe4b07cc4d9d654`;
its 52,016-byte receipt is SHA-256
`4e13df322e5c30b0022e4a6346ceb4db239628d317f4c9480cb81177b8ab53dd`.
The embedded bank is byte-identical. Aggregate observation count is 249,671;
255 coordinates are eligible, variable 241 remains the sole zero coordinate,
the minimum nonzero count is 224 and variable 15 has the maximum 2,180. The
fresh-seed parser is incompatible by design; live continuation is mandatory.

## Claim boundary

This is an enabling/mechanism result. It adds no new science evidence beyond
the sealed O1C-0090 clauses and makes no key, model, closure, bit-posterior,
entropy or attacker-valid domain claim. Native solver/science/target/truth/
reveal/refit/MPS/GPU calls are all zero. No intent exists; Page 14 and lineage
27 remain unburned and unauthorized.

## Decision

The four-burst audit selects the unchanged one-shot parent-centered operator.
O1C-0090 has zero exact predecessor overlap and zero cross-burst subsumption,
raises conflict efficiency, preserves probe efficiency and stops only at the
first capacity crossing. O1C-0091 removes that censorship without raising RAM
or caps.

Bind native v25, adapter v28 and the O1C-0092 runner to this manifest and the
`715bfbc2...` bank. After one focused non-solver gate and one owned sealed
preflight, authorize at most one fresh seed-0 lineage-27 call at 128 requested
conflicts. Do not replay Page 13, alter the action objective or add a comfort
control. Change residency alone only if Page 14 returns zero global novelty and
no stronger certified output.

## Provenance

The canonical preparation manifest is 20,129 B, SHA-256
`e46ca7373bc3a94efc30dcd309728005e3bee8b93983dc2c396f45bd487dd458`.
The ten-artifact bundle is
`research/o1c91_page14_causal_rollover_seed_20260720`. Source SHA-256 is
`f06db12a5792075d0c861f1b687a393b95e957f771cccfab2ab6cf9c30235035`;
focused-test SHA-256 is
`b736d7f8327737cd35558de859798e3167e81028c9966d084b6881a21b38d6d7`.
The focused gate passed 10 tests; Ruff passed and Pyright reported zero errors.
Independent publication verification matched all nine payload rows and the
manifest seal.
