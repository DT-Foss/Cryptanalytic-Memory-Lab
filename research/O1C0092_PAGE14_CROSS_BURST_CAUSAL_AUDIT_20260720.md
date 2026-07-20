# O1C-0092 — Page-10/11/12/13/14 cross-burst causal audit

Recorded 2026-07-20 CEST. This is a read-only recomputation from the five
sealed episode `vault.json` artifacts, supplemented only by the sealed result
counters for conflicts, decisions, probes and global novelty. No solver,
preflight, target or truth payload was read and no solve was issued.

Clauses are canonical signed-literal sets. Signed Jaccard is
`|A intersect B| / |A union B|`; subsumption is proper signed-set inclusion.
Counts below are exact. Floating summaries use the ordinary sample median
(the mean of the two middle values for an even population) and are rounded
only for display.

## Efficiency progression and censoring

| Metric | O1C-0085 / P10 | O1C-0086 / P11 | O1C-0088 / P12 | O1C-0090 / P13 | O1C-0092 / P14 |
|---|---:|---:|---:|---:|---:|
| Prior attic clauses | 807 | 830 | 1,032 | 1,291 | 1,551 |
| Active clauses | 254 | 254 | 254 | 253 | 252 |
| Globally novel clauses | 23 | 202 | 259 | 260 | 261 |
| Novel literals | 67,130 | 546,864 | 744,973 | 743,794 | 756,414 |
| Actual conflicts | 128 | 131 | 55 | 46 | 10 |
| Decisions | 430 | 1,009 | 570 | 540 | 521 |
| Exact probes | 32,840 | 100,038 | 33,413 | 33,890 | 33,398 |
| Clauses / conflict | 0.179687500 | 1.541984733 | 4.709090909 | 5.652173913 | 26.100000000 |
| Clauses / 1,000 probes | 0.700365408 | 2.019232692 | 7.751473977 | 7.671879611 | 7.814839212 |
| Probes / clause | 1,427.8261 | 495.2376 | 129.0077 | 130.3462 | 127.9617 |

The five bursts contain 1,005 clauses and 2,859,175 literals. Relative to
O1C-0090, O1C-0092 adds one archived clause, uses 36 fewer conflicts and 492
fewer probes. Measured conflict efficiency is `4.617692x` higher and measured
probe efficiency is `1.018634x` higher (+1.863%). The conflict rate must not be
extrapolated to 128 conflicts: O1C-0092 stopped at the first clause-cap
crossing after only 10 actual conflicts:

```text
252 active + 260 emitted = 512
252 active + 261 emitted = 513 > 512
```

The 261st clause is complete and archived, `pending_clause_exported=false`,
and the next vault is unavailable with terminal reason
`capacity_clause_count`. Thus 261 is a capacity-censored lower bound on the
burst, not a natural yield endpoint. O1C-0088 and O1C-0090 were censored by the
same arithmetic (`254+259=513`, `253+260=513`); the recent `259 -> 260 -> 261`
sequence largely tracks one extra slot of headroom and cannot establish a
fixed point or saturation.

## Exact identity and subsumption

All 1,005 clause hashes are distinct and all 1,005 witness hashes are
distinct, both within vaults and across the ten cross-burst pairs. Literal-set
equality independently agrees with the clause hashes. Across all 382,945
cross-burst clause pairs there are exactly:

- zero exact clause overlaps;
- zero exact witness overlaps;
- zero proper subsumptions in either direction for every burst pair.

Within-burst proper subsumption counts are `1 / 0 / 0 / 3 / 1` for
O1C-0085/86/88/90/92 over `253 / 20,301 / 33,411 / 33,670 / 33,930`
unordered pairs. The sole O1C-0092 relation is vault clause index 3 (2,916
literals) properly subsuming index 2 (2,933 literals). This one internal
relation is 0.002947% of O1C-0092 pairs and does not create cross-burst logical
repetition.

## Signed-Jaccard geometry

The following summaries cover every clause cross-product.

| Burst pair | Pair count | Minimum | Median | Mean | Maximum |
|---|---:|---:|---:|---:|---:|
| O1C-0085 / 0086 | 4,646 | 0.304471 | 0.311696 | 0.362299 | 0.880026 |
| O1C-0085 / 0088 | 5,957 | 0.610619 | 0.632457 | 0.632442 | 0.654649 |
| O1C-0085 / 0090 | 5,980 | 0.552852 | 0.584199 | 0.584493 | 0.621674 |
| O1C-0085 / 0092 | 6,003 | 0.578087 | 0.598185 | 0.599176 | 0.630175 |
| O1C-0086 / 0088 | 52,318 | 0.326394 | 0.337919 | 0.365771 | 0.656938 |
| O1C-0086 / 0090 | 52,520 | 0.321722 | 0.342570 | 0.367978 | 0.640777 |
| O1C-0086 / 0092 | 52,722 | 0.312544 | 0.321114 | 0.351472 | 0.654085 |
| O1C-0088 / 0090 | 67,340 | 0.703339 | 0.731891 | 0.732888 | 0.779407 |
| O1C-0088 / 0092 | 67,599 | 0.606297 | 0.634387 | 0.634341 | 0.670118 |
| O1C-0090 / 0092 | 67,860 | 0.697522 | 0.737675 | 0.737870 | 0.776911 |

| Within burst | Pair count | Minimum | Median | Mean | Maximum | Common signed core |
|---|---:|---:|---:|---:|---:|---:|
| O1C-0085 | 253 | 0.924312 | 0.970907 | 0.966378 | 0.995296 | 2,794 |
| O1C-0086 | 20,301 | 0.311168 | 0.964074 | 0.852094 | 0.999246 | 1,246 |
| O1C-0088 | 33,411 | 0.919447 | 0.966701 | 0.966551 | 0.999310 | 2,704 |
| O1C-0090 | 33,670 | 0.873892 | 0.950408 | 0.947291 | 0.999292 | 2,642 |
| O1C-0092 | 33,930 | 0.894168 | 0.965412 | 0.965176 | 0.995868 | 2,709 |

For each O1C-0092 clause, the next table summarizes its maximum signed
Jaccard against each predecessor burst.

| Candidate predecessor | Minimum | Median | Mean | Maximum |
|---|---:|---:|---:|---:|
| O1C-0085 | 0.602130 | 0.615808 | 0.615908 | 0.630175 |
| O1C-0086 | 0.622548 | 0.637936 | 0.638119 | 0.654085 |
| O1C-0088 | 0.639943 | 0.652112 | 0.651658 | 0.670118 |
| O1C-0090 | 0.752734 | 0.762909 | 0.762883 | 0.776911 |

All 261 global closest predecessors are in O1C-0090, with no cross-burst tie;
therefore the overall closest-predecessor distribution is exactly the last
row. O1C-0092 is an adjacent, tight signed family, but not a replay: even its
closest match is below 0.777 and cross-burst identity and subsumption remain
zero.

## Unsigned support, lengths and margins

O1C-0085 already spans the full 2,981-variable union seen in these bursts, so
no later burst introduces a new unsigned variable.

| Burst | Unsigned support | New vs prior measured union | Omitted from 2,981-union |
|---|---:|---:|---:|
| O1C-0085 | 2,981 | baseline | 0 |
| O1C-0086 | 2,981 | 0 | 0 |
| O1C-0088 | 2,897 | 0 | 84 |
| O1C-0090 | 2,977 | 0 | 4 |
| O1C-0092 | 2,953 | 0 | 28 |

O1C-0092 uses 99.0607% of the predecessor union and shares 2,709 signed
literals across every one of its clauses. Its novelty is signed arrangement
over known support, not variable discovery.

All witnesses use `trail_upper_bound`, threshold
`tau=14.606178797892962` (vault hex `2ef540115d362d40`), and the strict rule
`witness_score < tau`. Every margin below is `tau-score`.

| Burst | Length min / median / mean / max | Margin min / median / mean / max | Margins <= .01 / .05 / .10 | Spearman length-margin |
|---|---:|---:|---:|---:|
| O1C-0085 | 2,892 / 2,913 / 2,918.6957 / 2,981 | 0.010832816 / 0.288005251 / 0.353303409 / 0.974155393 | 0 / 2 / 6 | -0.088127 |
| O1C-0086 | 2,650 / 2,652 / 2,707.2475 / 2,974 | 0.001986911 / 0.229890766 / 0.725114800 / 6.336270947 | 4 / 20 / 37 | 0.579227 |
| O1C-0088 | 2,833 / 2,868 / 2,876.3436 / 2,897 | 0.000285769 / 0.198719017 / 0.527761058 / 1.231383294 | 11 / 30 / 62 | 0.766744 |
| O1C-0090 | 2,787 / 2,853 / 2,860.7462 / 2,900 | 0.000192092 / 0.614357812 / 0.587819791 / 1.549127677 | 5 / 15 / 24 | 0.401902 |
| O1C-0092 | 2,879 / 2,898 / 2,898.1379 / 2,933 | 0.567899098 / 1.444317484 / 1.464095719 / 3.052875714 | 0 / 0 / 0 | 0.158209 |

The O1C-0092 length histogram is
`2879x1, 2883x1, 2898x256, 2915x1, 2916x1, 2933x1`. Unlike the near-threshold
tails in the earlier bursts, all 261 O1C-0092 clauses clear the threshold by
more than 0.5. The standard even-population median also corrects the earlier
lower-middle-only O1C-0086 margin figure: it is `0.229890766`, not
`0.229424647`.

## Decision

Keep the parent-centered operator unchanged for one fresh Page-15 call; do
not pivot residency yet. Capacity censorship prevents a saturation inference,
probe efficiency is stable-to-improving, every clause and witness identity is
new across the measured bursts, cross-burst subsumption is zero, and O1C-0092
has materially stronger certification margins. Zero unsigned support novelty
is expected after O1C-0085 covered all measured variables and is not evidence
that signed exclusions are exhausted.

Use the standard fresh rollover with `active_limit=251`, which provides 261
in-range clause slots; clause 262, rather than the already measured clause 261,
would be the first cap crossing. Carry the sealed O1C-0092 bank
`97a325c91b9a853a094fcc8b7fd9fafdafe6b5ec4022952e1a86af068c834fca`
and otherwise hold the operator, threshold, seed and caps fixed. This one-slot
headroom adjustment is cap accommodation, not a residency-strategy pivot.
Reserve a residency-only pivot for an uncensored call that returns zero
globally novel clauses and no stronger certified result; a cap-terminated call
cannot establish that trigger.

This decision concerns exact-exclusion compounding only. It makes no key,
complete-model, closure, posterior, entropy-gain or attacker-valid domain
reduction claim.

## Sealed inputs

| Attempt | Episode vault SHA-256 | Sealed result SHA-256 |
|---|---|---|
| O1C-0085 | `899d3ac156cff2de6e31b4c736d037ca13ac57c044cbf52bb3fae21835c0cc40` | `d65fcaa76caa50905b5061b99cdf3ea10841449bdec6e9d20344e17bbe1e2ca4` |
| O1C-0086 | `6d5ba22a5f17f67d9c5b6c2e58bde925461ee014232634d93a03039cbabb1a34` | `535b8fa095013d4b87cadfc5e54e62698a21ab285d92becfbba88dc9c6f0ee6e` |
| O1C-0088 | `202d0a0059058e5d2b9d181a98c7cd8b77a6f873327928714bfa346e1e2cdadd` | `f1f6807c99951eff9a274a882753e5d18867b56490de2f5dbd9646bf0cbe4ba0` |
| O1C-0090 | `53394695c7aab70e5a4f07e2a827faaa5c805bc660766946a16219a69c0ea446` | `7089f78809de90007a4914f0cdaebeef7491d04a46871d05e8a2598e30676886` |
| O1C-0092 | `8cb5123d0867923a778ef08d64f73b71f51f8c41003b913da183f21e91dbd61b` | `04c4d7673898dd35d9c613ed0f1676dd8f3a60f01b04167b02660b93adfcc16c` |
