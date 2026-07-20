# O1C-0080 APPLE8 exact one-bit bound crossing — interpretation

Recorded at `2026-07-20T12:46:05+02:00` from the sole authorized Page-7 /
lineage-20 production call. The immutable result is
[`O1C0080_APPLE8_BOUND_CROSSING_RESULT_20260720.json`](O1C0080_APPLE8_BOUND_CROSSING_RESULT_20260720.json),
SHA-256 `e2ceb375c2fb83469db8eb537459b223d8e7f63e4bb58882882f8cdd8bdb22a5`.
The sealed capsule is
[`20260720_124516_O1C-0080_apple8-bound-crossing-v1`](../runs/20260720_124516_O1C-0080_apple8-bound-crossing-v1/RUN.md),
artifact-manifest SHA-256
`400b79b01ed54addbd99db53b2cf5ad36afd388a18d1435dcd7ef850c8532c44`.

## Outcome

O1C-0080 proves that the exact same-parent child-bound reader operates in the
full K256 APPLE8 search context across all `255` score-observed, probe-eligible
key coordinates. The frozen potential has no entry for key variable `241`, so
the result must not be described as 256 distinct coordinate probes. It does
**not** establish a
threshold crossing, safe prune, closure, clause, model, entropy reduction or key
recovery. The terminal classification is `BOUND_PROBE_OPERATION_ONLY` and the
stop reason is `exact-probes-operated-without-crossing-or-science`.

- exactly one native call, exact requested/actual/billed conflicts
  `128/128/128`;
- `1,587` parent scans, `285,725` exact one-bit probes and `571,450` exact child
  bound evaluations over all `255` score-observed ranked candidates (`256` key
  variables in the search context; variable `241` is not in the potential);
- all `285,725` probes are `NEITHER_PRUNABLE`; all crossing and closure classes
  are zero;
- global minimum child UB `18.464862193097684`, which remains
  `3.8586833952047215` above `tau=14.606178797892962`;
- minimum witness: callback `413`, parent level `330`, probe `37,567`, coordinate
  index `252`, key variable `115`,
  `U0=19.10564473318062`, `U1=18.464862193097684`; the complete native state
  hashes are identical before and after the probe;
- zero bound-origin proposals, level bindings, releases, interventions, realized
  prunes, fully emitted prunes, globally novel clauses, public models or keys;
- no target, truth, reveal, refit, retry, MPS or GPU use.

The full deterministic trace covers all `285,725` probes, is `16,286,325` bytes,
and has SHA-256
`c6f6c2a9ecf17bdd8f74891f5ffc7fba7f9658c4c95310d0c2f00f8b65093f5c`.
Only the first `16,384` event objects are retained in the JSON evidence; the
remaining `269,341` are committed by the full trace count, byte count and digest.
Any follow-up statistics must label that distinction and must not reconstruct or
claim values for omitted events.

## Threshold and upper-bound audit

The threshold and every reported UB use the same compiled complete-score metric,
floating-point units and retained maximization direction. They are not the same
statistic or population:

- `tau=14.606178797892962` is a fixed cutoff on the score of complete key
  assignments;
- `U(a)` is an admissible upper bound over complete descendants of one particular
  visited partial assignment `a`;
- a run-level minimum UB is the minimum of those local `U(a)` observations over
  that run's visited trail population.

For a maximization objective with admissibility

`score(k) <= U(a)` for every complete descendant `k` of `a`,

the strict condition `U(a) < tau` proves that no descendant of `a` can reach the
retained region `score >= tau`. That particular subtree is therefore safe to
prune. Equality remains live. A minimum below threshold does not by itself prove
root or global exhaustion, and it is not a prune count; the corresponding trail
must actually be the measured parent and its exclusion must be realized by the
solver/no-good lifecycle.

The historical `7.973483108047071` is O1C-0066 episode 1's minimum over its own
visited partial trails. It is the same metric and direction as `tau`, but a
different statistic/population from the fixed threshold and from O1C-0080's
Page-7 children. O1C-0066 separately records seven realized trail-threshold
prunes. O1C-0080 has no `U0` or `U1` below `tau`, so it produces no safe prune.

## Comparison and resource boundary

O1C-0080's minimum child UB is numerically `0.277360473683121` below
O1C-0079's `sieve.minimum_upper_bound=18.742222666780805`, but the latter is a
visited-parent statistic, not a same-parent child minimum. This is not an
improvement claim. It is also `10.961533514412096` below the inexact O1C-0079
recorded-marker child envelope `29.42639570750978`; that replay covers only 549
nonzero markers / 81,632 pairs, excludes 1,038 zero returns and is a different
population. The archived exact-terminal census had already observed a closer
child at `14.842606678748025` (`+0.2364278808550626` above tau, O1C-0074 episode
1). None of these populations is interchangeable and none turns O1C-0080 into a
science gain.

Native work takes `6.803373 s` wall / `7.618434 s` CPU and peaks at
`467,042,304 B`. The effective `480 MiB` watchdog limit leaves only
`36,274,176 B` of native headroom. The complete runner takes `48.718023834 s`,
uses `40.98647 s` CPU, peaks at `582,172,672 B`, and persists `14,998,858 B`.
The event-cap reduction to `16,384` was necessary: the operator fits, but another
blind event/RAM expansion is not justified.

## Retained breadcrumb and next operator

The hard one-bit crossing line is closed without retry: Page 7 and lineage 20 are
burned, and the minimum margin `+3.8586833952047215` is not a genuine near
crossing. Depth 2 is therefore not authorized.

The recorded `16,384`-event prefix nevertheless exposes a distinct mechanism
question. The signed child differential `d=U0-U1` is overwhelmingly positive in
the raw prefix, while several coordinates preserve stable opposite or unusually
small residuals across parents. Raw sign is therefore not a key posterior: it is
dominated by a parent-level common mode. The next target-free analysis is
O1C-0081:

1. center `d` within each parent by its median and robustly scale the residual;
2. stream only bounded O(256) per-coordinate moments, sign consistency and
   surprise into the living state;
3. keep **belief orientation** separate from **query priority**;
4. compare against deterministic within-parent/coordinate-label controls;
5. use the resulting field only to define a genuinely new Page-8/lineage-21
   operator, never to reinterpret Page 7 or claim a key bit from this consumed
   prefix.

This reuses the expensive exact probes as a new O1-compatible observation stream
without spending another solver call. Any production successor still requires a
fresh page, fresh lineage and a predeclared attacker-valid outcome gate.
