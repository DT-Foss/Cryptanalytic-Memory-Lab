# O1C-0090 — Page-10/11/12/13 cross-burst causal audit

Recorded 2026-07-20 CEST. This is a read-only extension of the sealed O1C-0088
cross-burst audit through O1C-0090. It reads the four immutable episode vaults
and uses no solver, native, target, truth-key, reveal, refit, MPS or GPU call.

## Efficiency progression

| Metric | O1C-0085 / Page 10 | O1C-0086 / Page 11 | O1C-0088 / Page 12 | O1C-0090 / Page 13 |
|---|---:|---:|---:|---:|
| Prior attic clauses | 807 | 830 | 1,032 | 1,291 |
| Active clauses | 254 | 254 | 254 | 253 |
| Globally novel clauses | 23 | 202 | 259 | 260 |
| Novel literals | 67,130 | 546,864 | 744,973 | 743,794 |
| Actual conflicts | 128 | 131 | 55 | 46 |
| Decisions | 430 | 1,009 | 570 | 540 |
| Exact probes | 32,840 | 100,038 | 33,413 | 33,890 |
| Releases | 6 | 255 | 9 | 11 |
| Post-action probes | 200 | 67,398 | 773 | 1,250 |
| Clauses per conflict | 0.1796875 | 1.541984733 | 4.709090909 | 5.652173913 |
| Clauses per 1,000 probes | 0.700365408 | 2.019232692 | 7.751473977 | 7.671879611 |
| Probes per clause | 1,427.8261 | 495.2376 | 129.0077 | 130.3462 |

The four bursts contain 744 distinct clauses / 2,102,761 literals. O1C-0090
adds one clause over O1C-0088 while using nine fewer conflicts. Conflict
efficiency rises another 20.03%; probe efficiency changes by -1.03% and is
effectively flat. O1C-0090 again terminates at the first clause-cap crossing:

```text
253 active + 260 emitted = 513 > 512
```

The 46-conflict endpoint is capacity-censored, not an observed yield fixed
point. The 260th clause is complete and archived; no pending clause is exported.

## Population identity and geometry

Every O1C-0090 clause and witness identity is new against the complete
1,291-clause attic. Direct signed-set comparison against the three measured
predecessor bursts gives zero exact clause overlap, zero exact witness overlap
and zero subsumption pairs.

| Pair | Signed-Jaccard minimum | Median | Mean | Maximum |
|---|---:|---:|---:|---:|
| O1C-0085 vs O1C-0090 | 0.552852 | 0.584199 | 0.584493 | 0.621674 |
| O1C-0086 vs O1C-0090 | 0.321722 | 0.342570 | 0.367978 | 0.640777 |
| O1C-0088 vs O1C-0090 | 0.703339 | 0.731891 | 0.732888 | 0.779407 |
| O1C-0090 within burst | 0.873892 | 0.950408 | 0.947291 | 0.999292 |

For each O1C-0090 clause, its closest predecessor across all three earlier
bursts has signed Jaccard `0.723589..0.779407`, median `0.743752`. O1C-0090 is
more closely related to O1C-0088 than O1C-0088 was to its predecessors, but it
is not repetition: exact identities and subsumption remain zero, and the new
burst forms another tight signed family. Its unsigned support contains 2,977
variables, all already present in the 2,981-variable predecessor union. The
gain is fresh sign geometry over known support, not new variable discovery.

The common signed intersection inside O1C-0090 contains 2,642 literals.
Clause lengths are `2,787..2,900`, median `2,853`, mean `2,860.746154`.

## Certification margin

All 260 witness scores use the same fixed threshold and direction:

```text
witness score < tau = 14.606178797892962
```

Margins `tau-score` range `0.0001920924223774989..1.5491276772485136`,
median `0.6143578123253075`, mean `0.5878197914125401`. Counts with margin at
most `0.01 / 0.05 / 0.10` are `5 / 15 / 24`. Therefore every emitted clause is
strictly certified under the sealed trail-upper-bound rule; none is an equality
or direction reinterpretation.

## Live-state conservation

O1C-0090 evolves the bank from `0203de9f...c0cc6a` to
`715bfbc2...d654`. Total counts move `215,781 -> 249,671`; the delta 33,890
equals the exact probe count. Outcomes `BOTH / NEITHER / ONE / ZERO` are
`153 / 33,693 / 35 / 9`, also summing to 33,890, and 67,780 child evaluations
equal exactly twice the probe count. Variable 241 remains the sole zero
coordinate. The call confirms 255 failure-first actions and zero certified
action crossing.

## Decision

The evidence selects one unchanged Page-14 continuation after O1C-0091:

- absolute yield remains at the measured cap boundary;
- conflict efficiency improves and probe efficiency stays stable;
- all 260 clauses are globally new, non-subsumed signed exclusions;
- the endpoint is capacity censorship, not saturation;
- changing action logic or raising RAM/caps would confound the active mechanism.

Prepare Page 14 / lineage 27 at `active_limit=252`, giving exactly 260 clause
slots, carry bank `715bfbc2...d654`, and authorize at most one unchanged seed-0,
tau-identical, 128-conflict call after the focused seal gate and one owned real
preflight. Do not use K253: 259 slots would re-censor the already measured
260-clause burst. Change residency alone only if that fresh call returns zero
globally novel clauses and no stronger certified output.

## Claim boundary

This audit strengthens the exact-exclusion compounding decision only. It does
not produce a key, complete model, closure, key-bit posterior, entropy gain or
attacker-valid domain reduction. `threshold_prunes=260` and
`actual_certified_prunes=0` remain separate certification paths.

## Sealed inputs

| Attempt | Result SHA-256 | Capsule artifact-manifest SHA-256 |
|---|---|---|
| O1C-0085 | `d65fcaa76caa50905b5061b99cdf3ea10841449bdec6e9d20344e17bbe1e2ca4` | `c6f4cb50ab5e7b0e57afbe5bbaccf53106008094be824c35bb7f849a8d4be492` |
| O1C-0086 | `535b8fa095013d4b87cadfc5e54e62698a21ab285d92becfbba88dc9c6f0ee6e` | `d4ff926b1c2183ca2c70b499acd9e3aa00e9c6575aee43479dc6238e690953fb` |
| O1C-0088 | `f1f6807c99951eff9a274a882753e5d18867b56490de2f5dbd9646bf0cbe4ba0` | `8ae16f758ee4c5e1f489c7f9c5d40d2dc001037a9b215ca60f973432af953f84` |
| O1C-0090 | `7089f78809de90007a4914f0cdaebeef7491d04a46871d05e8a2598e30676886` | `d4088eddb3cf671b908ebbc2d19e6e0159eac149b4b882bb21cca62635df1df0` |
