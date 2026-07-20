# O1C-0077 — APPLE8 residual-polarity-staging interpretation

- **Started:** 2026-07-20T02:55:50+02:00 (`Europe/Berlin`).
- **Recorded:** 2026-07-20T02:56:38+02:00 (`Europe/Berlin`).
- **Classification:** `RESIDUAL_POLARITY_STAGING_MECHANISM_ONLY`.
- **Source freeze:** `d4f9b3aa066b22a38ead63d83cbb76b4ead673de`.
- **Execution:** `8eba8614fc9d19ef893a0e7f093737ed6b23dc68`.
- **Capsule:**
  [`runs/20260720_025550_O1C-0077_apple8-residual-polarity-staging-v1`](../runs/20260720_025550_O1C-0077_apple8-residual-polarity-staging-v1/RUN.md).
- **Seals:** authoritative result SHA-256
  `8b87d7cdc39f6380a887b2e45d4879544ff88cd7c53e22f44876e46c334cf103`;
  capsule artifact-manifest SHA-256
  `6b8526c5eaa2c318d4eef1e8c4dc87e744307c95f30699a90e4444021d2dbece`;
  frozen config SHA-256
  `500b5db10558661ec92f7672c7e6bbd80bed523d0c0b56d96a0002241c91d5ab`.

## Result

O1C-0077 consumes its sole predeclared local-0 / lineage-17 call with exactly
`128/128` requested and billed conflicts and no retry. The two-row operator
activates: both effective originals and both later source contrasts are
returned, and the native trace changes from the frozen O1C-0076 baseline
`f64441a20619d788ab935a870d86f8df8fa07caf4ac4fdda26cc95d10363aa70`
to
`706ad4fa13a8a47cd81f99bc693c1bede46612112214e6f77dc52ee61d32bf15`.
The runner therefore records `qualified_mechanism_activated=true`.

This is a real mechanism result, not yet a cryptanalytic science gain. The call
records zero safe threshold prunes, zero fully emitted occurrences, zero
globally novel clauses, zero complete models and no public key. Unit activation
is false, and a changed trace alone is explicitly insufficient. The immutable
causal attic remains 550 unique clauses / 1,488,224 literals / 558 occurrences
/ 8 duplicates; no new evidence is added.

## Exact four-event intervention

The immutable source rank is preserved position-for-position. Only source rows
224 and 226 (zero-based) are reinterpreted before constructing the existing
release-contrast reader:

| Callback | Rank row | Source | Effective | Return kind | Returned |
|---:|---:|---:|---:|---|---:|
| 225 | 224 | `131` | `-131` | effective original | `-131` |
| 227 | 226 | `-130` | `130` | effective original | `130` |
| 574 | 224 | `131` | `-131` | source contrast | `131` |
| 576 | 226 | `-130` | `130` | source contrast | `-130` |

Both overlay returned-state bits and both contrast-observed bits are set. The
first activation is callback 225. Across the complete call, the staged reader
returns 510 nonzero decisions and delegates 374 times; the two overlays account
for exactly four of those returns. This directly establishes that changing the
two upstream polarities can redirect the full-256 search before the former
29-row parent-zero frontier becomes reachable.

The original assignments are observed released after callback 348 at level
zero; their contrasts are observed released after callback 643 at level zero.
The frozen reader event stream matches O1C-0076 through callback 224, and its
first divergence is exactly the planned row-224 return at callback 225. The
later contrasts are delayed by 40 callbacks relative to the source-sign
counterparts.

## Search displacement versus the frozen reference

The public instance, score potential, grouping, threshold, seed, 128-conflict
budget and immutable rank source remain fixed. The live input advances from
O1C-0076 Page 3 to fresh O1C-0077 Page 4, so whole-call telemetry is not a
same-input counterfactual and must not be attributed solely to the overlay.
O1C-0077 nevertheless changes the frozen reference trajectory materially:

| Metric | O1C-0076 baseline | O1C-0077 | Delta |
|---|---:|---:|---:|
| Decisions | 2,288 | 884 | -1,404 (-61.36%) |
| Propagations | 2,890,144 | 4,754,555 | +1,864,411 (+64.51%) |
| Backtracks | 137 | 140 | +3 |
| Minimum visited-trail UB | 14.67138759145431 | 14.656823218163392 | -0.014564373290918 |
| Safe threshold prunes | 0 | 0 | 0 |
| Native wall | 0.566478 s | 0.838922 s | +48.09% |

The work effect is mixed rather than a speed win: far fewer decisions coexist
with more propagation and native time. The minimum UB moves toward the cutoff,
shrinking the observed positive margin above `tau` from
`0.065208793561348` to `0.050644420270430` (22.33%), but remains above it.
This is a useful directional breadcrumb, not a prune or domain-compression
claim. The directly isolated causal fact is the exact first divergence at
callback 225. At the unchanged first parent-zero callback 256, all 29 clause
residuals are still assigned, but their split moves from O1C-0076's
18 falsifying / 11 rescue signs to 23 falsifying / 6 rescue signs. The outer
frontier still returns nothing and unit activation remains false.

The output live projection changes to fresh Page 5 SHA-256
`07c73013705898e228a05b0578b0f8090a6f094c427dbd8f32d856467b08e208`
(256 clauses / 654,465 literals / 2,619,075 bytes). Because no new exact clause
was emitted, this is deterministic attention rollover over the unchanged attic,
not new cryptanalytic evidence.

## Threshold boundary: 14.61 versus 7.973

Let `S(k)` be the compiled complete-candidate score, let
`tau=14.606178797892962`, and retain candidates satisfying `S(k)>=tau`.
For a visited partial trail `a`, the grouped bound `U(a)` is admissible:
`S(k)<=U(a)` for every completion `k` extending `a`.

The threshold and every reported UB therefore have the same underlying score
units and the same retained/maximization direction. They are not the same
statistic or population: `tau` is one fixed complete-score membership cutoff,
whereas `min_{a in V} U(a)` is the minimum over the run-specific population
`V` of visited partial trails.

Consequently, an actual trail with strict `U(a)<tau` is a formally safe local
prune:

```text
for every k extending a: S(k) <= U(a) < tau
therefore no such k belongs to the retained region
```

The number `7.973483108047071` is the historical minimum visited-trail UB in
O1C-0066 episode 1, whose native ledger separately records seven realized
trail-threshold prunes. It is not the current minimum, not an O1C-0068 metric,
not a bound on the root population and not by itself global exhaustion. Root UB
there remains `262.68644197084643>tau`. O1C-0068's own minimum is
`12.8607806294803`, and none of its artifacts is changed. O1C-0077's minimum
`14.656823218163392>tau` yields zero local prunes.

## Exact next breadcrumb

The two-row staging result supports the intervention primitive but does not
cross a science gate. Per the predeclared escalation, do not retry it or replay
lineage 17. Move once to the sealed 11-row rescue preemptor. The rescue-signed
residual clause literals are:

```text
-130 131 -31874 -63746 -190565 -190566 -190569
-191212 -191213 -191216 -191234
```

Their exact falsifying prefix is:

```text
130 -131 31874 63746 190565 190566 190569
191212 191213 191216 191234
```

Its signed-i32le identity is
`b5debc5f55f7cbc1e728d00ce1d14d0c437249793f8c10e8b80e614a00ed155c`.
O1C-0078 should stage this one immutable prefix before the inherited rank so
that the nine formerly propagation-created rescue assignments become explicit
upstream interventions. Use fresh Page 5 `07c73013…`, one lineage-18 call,
exactly 128 conflicts, no retry/sweep/truth/reveal/refit/MPS/GPU. Activation
requires the outer reader to consume all 11 rows before its first parent call,
leave every row falsifying at handoff
(`once_returns + preassigned_falsifying = 11`, zero rescue skips), return at
least one exact prefix literal once, and produce a trace distinct from O1C-0077.
Requiring all 11 literal returns would wrongly reject causal propagation that
assigns later prefix rows in the falsifying sign. Science still requires a
certified safe prune, globally novel exact clause, formal exhaustion or
publicly verified model.

## Resources and publication

Runner elapsed time is `48.2352461249975 s`; runner peak RSS is
`402,210,816 B`. Native wall/CPU are `0.838922/1.600825 s`, and native peak
RSS is `423,968,768 B`. Persistent artifacts occupy `15,291,549 B`. There
are zero publication-recovery solver calls, truth reads, reveal calls, fresh
targets, refits, rank/K/horizon sweeps, phase calls, MPS calls or GPU calls.

Capsule `result.json` is byte-identical to the authoritative research result,
and all `39/39` artifact-manifest entries validate. Cite the sealed result
above for the classification and resource totals.

## Direct resume point

Resume from the activated four-event polarity operator and fresh Page 5, not
from O1C-0076 or a retry of O1C-0077. Preserve the immutable 550-clause /
558-occurrence attic, the separate 202-clause rank source, consumed lineages
through 17 and the exact 11-row signed prefix. Freeze O1C-0078 target-free
before its one science call.

The authoritative machine result is
[`O1C0077_APPLE8_RESIDUAL_POLARITY_STAGING_RESULT_20260720.json`](O1C0077_APPLE8_RESIDUAL_POLARITY_STAGING_RESULT_20260720.json).
