# O1C-0076 — APPLE8 causal-frontier interpretation

- **Started:** 2026-07-20T01:36:32+02:00 (`Europe/Berlin`).
- **Recorded:** 2026-07-20T01:37:20+02:00 (`Europe/Berlin`).
- **Classification:** `CAUSAL_FRONTIER_NO_ACTIVATION_NO_GAIN`.
- **Source/execution:** `f78424e92b1035a07a70350f0ad5666f2c9459e4`.
- **Capsule:**
  [`runs/20260720_013632_O1C-0076_apple8-causal-frontier-v1`](../runs/20260720_013632_O1C-0076_apple8-causal-frontier-v1/RUN.md).
- **Seals:** authoritative result SHA-256
  `9459f80444b2dc196251623dfc1f59f014e6593b3b5cd7d8bbaaa5c62f0b671e`;
  capsule artifact-manifest SHA-256
  `875655a95a30a4f0df01e130a074b0b6a82b98c683575818ad5110cc6a6f1366`.

## Result

O1C-0076 consumes its only predeclared local-0 / lineage-16 call with exactly
`128/128` requested and billed conflicts and no retry. It returns native status
`0`, makes 2,288 decisions and 2,890,144 propagations, and records zero safe
threshold prunes, fully emitted occurrences, globally novel clauses or model.
The native trace remains the frozen fixed-point SHA-256
`f64441a20619d788ab935a870d86f8df8fa07caf4ac4fdda26cc95d10363aa70`.

The classification is negative for both gates. No frontier literal substitutes
for a parent zero, so the mechanism does not activate. With no trace change or
science output, there is also no cryptanalytic gain, recovery, entropy
reduction, UNSAT result or threshold-region exhaustion.

## Why the reader never activated

The causal-frontier wrapper is parent-first. Across 2,288 decision callbacks,
the parent returns 510 nonzero decisions and 1,778 zeros; its first zero is
callback 256. At that first delegation, the wrapper consumes all 29 frontier
rows, but every residual variable is already assigned:

- 18 rows already carry the planned falsifying sign;
- 11 rows already carry the clause-satisfying rescue sign; and
- zero rows are unassigned, so the wrapper returns no frontier decision.

The cursor therefore advances directly to `29/29` with zero initial returns,
zero substitutions, zero initial releases, zero queued contrasts and zero
contrast returns. `first_frontier_return_call` is null. The wrapper continues
delegating for the remainder of the call and cannot change the parent trace.

Only five residual variables occur in the parent's 255 ranked rows:
`105, 106, 129, 130, 131`. The parent rank assigns the first three in the
falsifying sign and the last two in the rescue sign. Propagation has already
assigned the other 24 residual variables by callback 256, accounting for the
remaining 15 falsifying-signed and nine rescue-signed rows. The failure is
therefore event order: a parent-zero-only intervention arrives after parent
decisions and propagation have closed every planned slot.

The clause telemetry records `prior_distance_reached=true` but
`unit_distance_reached=false`. It reaches at least the already known
29-unassigned, zero-true distance; it never reaches a zero-true state with at
most one unassigned literal. This does not qualify as activation or frontier
gain.

## Threshold boundary

Let `S(x)` be the compiled complete-key score and

`R_tau = {x : S(x) >= tau}`, with `tau = 14.606178797892962`.

For a visited partial trail `a`, the admissible upper bound `U(a)` and `tau`
use the same score units and retained direction. They are not the same statistic
or population: `tau` is a fixed membership cutoff, whereas reported minimum UB
is `min_{a in V} U(a)` over a run-specific visited-trail population `V`.

For any particular trail, strict `U(a) < tau` safely removes only that trail's
descendants from `R_tau`. O1C-0076 reaches minimum UB
`14.67138759145431 > tau` and records zero safe prunes; root UB remains
`262.68644197084643`. The historical `7.973483108047071` belongs to O1C-0066
episode 1, not O1C-0068. O1C-0068 reports minimum UB
`12.8607806294803` and none of its artifacts is changed here. O1C-0066 episode
1 separately records seven actual trail-threshold prunes. Thus `7.973...` is
not itself a prune count or a global bound; it is the minimum witness value in
that episode, while the seven native events are the realized local prunes.

## Exact next breadcrumb

O1C-0076's public skip bitsets identify the 11 rescue-signed residual clause
literals at first delegation:

```text
-130 131 -31874 -63746 -190565 -190566 -190569
-191212 -191213 -191216 -191234
```

Their falsifying opposites are:

```text
130 -131 31874 63746 190565 190566 190569
191212 191213 191216 191234
```

The highest-ROI immediate successor is O1C-0077 residual-polarity staging. Only
five of the 29 residual variables intersect the immutable 255-row rank. Three
already receive their clause-falsifying sign: rank indices 28/131/235 return
`-105`, `106`, and `129`. The two upstream rescue decisions are rank index 224
`131` and rank index 226 `-130`; stage their effective original signs as `-131`
and `130` before constructing the existing release-contrast reader. Rank order
is unchanged, and the later contrast stage still exposes each effective
opposite once. This moves only two polarities, immediately before the recorded
292-assignment burst after callback 235, while keeping the exact 11-row set
above as the next stronger preemptor if staging alone cannot remove the
propagation-created rescues. Derive the overlay only from sealed O1C-0076
telemetry, retain target-free one-call discipline, and use fresh Page 4 SHA-256
`b57e3091df7eca20137f4c63e3bc125aa8978c2ff183a7396de3a2a4a79acf33`.
Page 4 contains exactly 256 clauses / 718,231 literals / 2,874,139 bytes and has
not been used as a science input.

Activation must require at least one actual staged return and a trace change;
science still requires a new exact exclusion, safe prune/frontier contraction,
formal exhaustion or publicly verified candidate. Do not replay lineage 16,
retry the parent-zero-only operator, rotate another passive page, or sweep K,
rank, phase, horizon, seed, threshold, RAM or caps.

## Resources and publication

Runner elapsed time is `47.79094816700672 s`; runner peak RSS is
`408,141,824 B`. Native wall/CPU are `0.566478/1.346263 s`, and native peak RSS
is `408,944,640 B`. Persistent artifacts occupy `15,055,265 B`. There are zero
publication-recovery solver calls, truth reads, reveal calls, fresh targets,
refits, rank/K/horizon sweeps, phase calls, MPS calls or GPU calls.

Capsule `result.json` is byte-identical to the authoritative research result,
and all `35/35` artifact-manifest entries validate. Cite the sealed result above
for the classification and resource totals.

## Direct resume point

Resume from the negative activation diagnosis, not from the original 29-row
parent-zero reader. Preserve the immutable 550-clause / 558-occurrence attic,
the separate 202-clause rank source, the consumed lineage-16 billing and fresh
Page 4. Freeze O1C-0077 as one target-free two-row residual-polarity-staging
call before any science execution; retain the exact 11-row preemptor as the
predeclared escalation, not as a sweep.

The authoritative machine result is
[`O1C0076_APPLE8_CAUSAL_FRONTIER_RESULT_20260720.json`](O1C0076_APPLE8_CAUSAL_FRONTIER_RESULT_20260720.json).
