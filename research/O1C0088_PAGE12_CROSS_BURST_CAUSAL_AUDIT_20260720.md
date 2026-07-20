# O1C-0088 — Page-10/11/12 cross-burst causal audit

Recorded 2026-07-20 CEST. This is a read-only comparison of the sealed O1C-0085,
O1C-0086 and O1C-0088 capsules. It uses no solver, native, target, truth-key,
reveal, refit, MPS or GPU call.

## Efficiency progression

| Metric | O1C-0085 / Page 10 | O1C-0086 / Page 11 | O1C-0088 / Page 12 |
|---|---:|---:|---:|
| Prior attic clauses | 807 | 830 | 1,032 |
| Active clauses | 254 | 254 | 254 |
| Globally novel clauses | 23 | 202 | 259 |
| Novel literals | 67,130 | 546,864 | 744,973 |
| Actual conflicts | 128 | 131 | 55 |
| Decisions | 430 | 1,009 | 570 |
| Exact probes | 32,840 | 100,038 | 33,413 |
| Releases | 6 | 255 | 9 |
| Post-action probes | 200 | 67,398 | 773 |
| Clauses per conflict | 0.1796875 | 1.541984733 | 4.709090909 |
| Clauses per 1,000 probes | 0.700365408 | 2.019232692 | 7.751473977 |
| Probes per clause | 1,427.8261 | 495.2376 | 129.0077 |

The absolute bursts rise `23 -> 202 -> 259`. O1C-0088 uses almost the same
probe count as O1C-0085 but emits `11.2609x` as many clauses. Probe efficiency
rises `11.0678x`; conflict efficiency rises `26.2071x`.

O1C-0088 terminates exactly at the first clause-cap crossing:

```text
254 active + 259 emitted = 513 > 512
```

Its 55-conflict endpoint is therefore capacity-censored, not an observed yield
fixed point.

## Population identity and geometry

The three bursts contain 484 pairwise distinct clauses and 1,358,967 literals.
Across every pair there are:

- zero identical clause hashes;
- zero identical witness hashes;
- zero subsumption pairs;
- zero input or current duplicates.

| Pair | Signed-Jaccard mean | Median | Maximum |
|---|---:|---:|---:|
| O1C-0085 vs O1C-0086 | 0.362299 | 0.311676 | 0.880026 |
| O1C-0085 vs O1C-0088 | 0.632442 | 0.632457 | 0.654649 |
| O1C-0086 vs O1C-0088 | 0.365771 | 0.337919 | 0.656938 |

Within-burst signed-Jaccard medians are `0.970907`, `0.964074` and `0.966701`.
Every burst is a tight signed family. For each O1C-0088 clause, its closest
predecessor in O1C-0085/86 has signed Jaccard
`0.624331..0.656938`, median `0.641033`. O1C-0088 is a new coherent signed
family, not a replay of prior exclusions. Its unsigned support has 2,897
variables, all already present earlier; the gain is new sign geometry over
known support rather than new variables.

## Length and certification margin

| Metric | O1C-0085 | O1C-0086 | O1C-0088 |
|---|---:|---:|---:|
| Clause length min / median / max | 2,892 / 2,913 / 2,981 | 2,650 / 2,652 / 2,974 | 2,833 / 2,868 / 2,897 |
| Mean clause length | 2,918.6957 | 2,707.2475 | 2,876.3436 |
| Minimum `tau-score` margin | 0.010832816 | 0.001986911 | 0.000285769 |
| Median margin | 0.288005251 | 0.229424647 | 0.198719017 |
| Mean margin | 0.353303409 | 0.725114800 | 0.527761058 |
| Maximum margin | 0.974155393 | 6.336270947 | 1.231383294 |
| Margin at most 0.01 | 0 | 4 | 11 |
| Margin at most 0.05 | 2 | 20 | 30 |
| Margin at most 0.10 | 6 | 37 | 62 |
| Spearman length vs margin | -0.0881273 | 0.5792273 | 0.7667436 |

O1C-0088 length counts are
`2833x1, 2852x1, 2861x44, 2862x67, 2867x10, 2868x14, 2891x101,
2897x21`. The population contains more near-threshold but still strictly
certified clauses, alongside robust longer families.

## Live-state evolution

Probe categories `BOTH / NEITHER / ONE / ZERO` are:

- O1C-0085: `4 / 32,836 / 0 / 0`;
- O1C-0086: `300 / 99,630 / 103 / 5`;
- O1C-0088: `90 / 33,302 / 18 / 3`.

Every category sum equals the exact probe count; child evaluations are always
twice the probe count. Each call confirms 255 failure-first actions and has zero
certified action crossing.

| Bank metric | O1C-0085 | O1C-0086 | O1C-0088 |
|---|---:|---:|---:|
| Total count input -> output | 49,490 -> 82,330 | 82,330 -> 182,368 | 182,368 -> 215,781 |
| Exact count delta | 32,840 | 100,038 | 33,413 |
| Mean priority input -> output | 8.832677 -> 10.802354 | 10.802354 -> 14.933734 | 14.933734 -> 15.721375 |
| Final median priority | 8.685987 | 9.400952 | 10.429804 |
| Rising / falling records | 217 / 38 | 163 / 92 | 177 / 78 |
| Input/output priority Spearman | 0.925345 | 0.678469 | 0.937782 |

Action-order Spearman falls from `0.978821937` for O1C-0085/86 to
`0.732834935` for O1C-0086/88, while Page-12 yield rises. O1C-0088 also obtains
the largest burst with only nine releases and 773 post-action probes. Complete
release/reobservation is not necessary; fresh residency and accumulated bank
state both remain plausible contributors.

## Decision

There is no evidence that the unchanged operator is saturated:

- absolute yield and yield per probe rise monotonically;
- Page 12 stops at the first clause-cap crossing;
- its population is globally new, non-subsumed and signed-geometrically
  distinct;
- changing the action objective now would confound the active mechanism.

After O1C-0089 seals Page 13, authorize exactly one unchanged lineage-26 call
with `active_limit=253`, 128 requested conflicts, bank `0203de9f...c0cc6a`,
unchanged caps and no replay/sweep arm. Page 13 has exactly 259 clause slots of
headroom. Primary success is at least one globally novel clause against the
1,291-clause attic; reaching clause 260 and capacity again is a positive burst,
not failure.

Only if the call emits zero globally novel clauses and no stronger formal
output, preserve its final bank, burn Page 13 and change residency alone: build
a fresh K253 page by greedy max-min signed-Jaccard diversity over the three
burst families, with deterministic ties by shorter clause, larger certification
margin and SHA-256. Keep structural roots, pinned core and the action operator
unchanged so the follow-up isolates residency geometry.

## Sealed inputs

| Attempt | Result SHA-256 | Capsule artifact-manifest SHA-256 |
|---|---|---|
| O1C-0085 | `d65fcaa76caa50905b5061b99cdf3ea10841449bdec6e9d20344e17bbe1e2ca4` | `c6f4cb50ab5e7b0e57afbe5bbaccf53106008094be824c35bb7f849a8d4be492` |
| O1C-0086 | `535b8fa095013d4b87cadfc5e54e62698a21ab285d92becfbba88dc9c6f0ee6e` | `d4ff926b1c2183ca2c70b499acd9e3aa00e9c6575aee43479dc6238e690953fb` |
| O1C-0088 | `f1f6807c99951eff9a274a882753e5d18867b56490de2f5dbd9646bf0cbe4ba0` | `8ae16f758ee4c5e1f489c7f9c5d40d2dc001037a9b215ca60f973432af953f84` |
