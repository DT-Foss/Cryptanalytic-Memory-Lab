# O1C-0089 — Page-13 causal rollover

Recorded 2026-07-20 CEST. O1C-0089 is terminal
`CAUSAL_ATTIC_PAGE13_ROLLOVER_PREPARED`. It performs no science or solver call;
it atomically preserves O1C-0088's complete harvest and derives fresh Page 13 /
lineage 26.

## Result

- All 259 O1C-0088 clauses / 744,973 literals enter one immutable chunk,
  SHA-256
  `d02b2ca0fa8d54b11572427bdc1f450fb34fe52016ccbb197f14f0fefd2c0370`.
  Every occurrence is unique, globally novel against the prior 1,032-clause
  attic, `source=trail_upper_bound` and `classification=new`.
- The attic reaches 16 chunks, 1,291 unique clauses, 1,299 occurrences and
  1,284 undominated clauses. Its union is 3,590,320 literals / 14,366,635 B,
  SHA-256
  `d4ea6d6d1bf1dfa3560aa81737914624c40c2dd9dacfb7fee38badc2aabab726`.
- The ten existing strict subsumption relations are preserved exactly. The new
  burst adds zero strict subsumption pair; no exclusion is silently replaced by
  a stronger new clause.

## Fresh Page 13

Page 13 / lineage 26 is fresh and unburned at the minimal one-slot active limit
253:

```text
clauses              253
literals             711,355
serialized bytes     2,846,623
SHA-256              4c1b7d5a6d40fad9439d95433bcc7a60ff3e7ddc0e4542b0cf003cdf4581e546
categories           5 structural roots + 43 pinned core + 205 new debt
headroom             259 clauses + 888,645 literals + 5,541,985 bytes
```

The headroom is exactly the measured O1C-0088 burst and three clauses beyond
the 256-action capacity. Literal and byte headroom are measured residuals;
future emission safety under those two caps is not claimed.

All 259 clauses remain in the attic. Of them, 205 are solver-resident and 54 are
explicitly recorded as nonresident. This is bounded O(1)-state projection, not
evidence loss. Structural roots and the 43-clause pinned core are retained.

## Live continuation state

The exact 24,576-byte bank remains SHA-256
`0203de9f1732b095bf30062cb8a07b018ded829ee99f18ffbca715c653c0cc6a`;
its 52,009-byte receipt remains SHA-256
`9ecec7df26d93de464bc779b19f5ccab22588b8f809c443987e62ce6265a8eb8`.
The receipt's embedded bank is byte-identical. Aggregate observation count is
215,781; 255 coordinates are eligible, variable 241 remains the sole zero
record, and variable 21 has the maximum count 1,752. The fresh-seed parser is
incompatible by design; the next runner must use the live-continuation parser.

## Claim boundary

This is an enabling/mechanism result. It adds no new science evidence beyond
the sealed O1C-0088 clauses and makes no key, model, closure, bit-posterior,
entropy or attacker-valid domain claim. Native solver/science/target/truth/
reveal/refit/MPS/GPU calls are all zero. No intent exists; Page 13 and lineage
26 remain unburned and unauthorized.

## Decision

The independent O1C-0085/86/88 cross-burst audit finds monotonically rising
yield per probe, zero cross-burst clause/witness overlap, zero subsumption and a
new coherent O1C-0088 signed family. Because Page 12 was capacity-censored,
unchanged continuation remains the highest-ROI discriminating experiment.

Bind the unchanged one-shot parent-centered operator and `0203de9f...` bank to
this Page-13 manifest, perform one focused native/adapter/runner gate and one
real sealed preflight, then authorize at most one fresh lineage-26 call at 128
requested conflicts. Do not replay Page 12, alter the action objective, rearm
crossings or raise caps/RAM for this test.

Only if that call emits zero global novelty and no stronger formal result should
the next fresh page change residency alone to the predeclared max-min
signed-diversity K253 projection.

## Provenance

The canonical preparation manifest is 15,590 B, SHA-256
`467e519df281db4fc10de9223195dfedba9fd51edc93b40883f59fd3821e29ec`.
The ten-artifact bundle is
`research/o1c89_page13_causal_rollover_seed_20260720`. Source SHA-256 is
`9b856cafa90ccefd1e35d1987ae097f790827f11a1d72adc86e2f3e1c4c38bac`;
focused-test SHA-256 is
`86c78cf9d944116219d6f072b7422b2430a0d3eb798815b845771c91fbffd8e4`.
The focused gate passed 9 tests; Ruff passed and Pyright reported zero errors or
warnings. Atomic publication revalidated all final artifact seals.
