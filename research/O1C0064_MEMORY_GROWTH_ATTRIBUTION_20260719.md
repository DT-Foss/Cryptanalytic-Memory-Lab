# O1C-0064 memory-growth attribution

- **Recorded:** 2026-07-19T12:09:54+02:00 (`Europe/Berlin`).
- **Scope:** read-only attribution from the immutable O1C-0064 failure evidence,
  APPLE-VIEW-0008 result, public potential and APPLE-VIEW-0009 diagnostics.
- **New calls:** zero solver, truth, entropy, fresh-target, MPS or GPU calls.

## Exact evidence

- O1C-0064 was stopped by the Darwin physical-footprint watchdog after
  `29.804627625 s`: observed `1,040,285,696 B` at the guarded
  `1,040,187,392 B` (`992 MiB`) threshold.
- The APPLE-VIEW-0008 independent-factor sieve reports only `99,227 B` bounded
  persistent logical state, `99,143 B` maximum live persistent state and
  `60,456 B` derived factor cache. Trail and pending clause storage are bounded
  by the `2,981` observed variables.
- The frozen public potential has `7,557` factors, `104,432` table rows and
  `28,168` variable-factor incidences. Under the same diagnostic accounting
  rule used by APPLE-VIEW-0009, its independent index is approximately
  `1,346,600 B` (`1.284218 MiB`).
- APPLE-VIEW-0009 width 6 has `176,912` grouped rows and an estimated grouped
  index of `1,710,776 B` (`1.631523 MiB`). Its `799,232 B` reduction is versus
  the legacy pair index (`2,510,008 B`), not versus O1C-0064's independent
  representation. On one consistent partial ledger, immutable original energy
  rows contribute `835,456 B`; independent derived maxima/incidences add
  `511,144 B`, for the `1,346,600 B` independent total. The grouped native
  replaces those derived structures but retains the original rows for exact
  complete-model scoring: `835,456 + 1,710,776 = 2,546,232 B`, or
  `1,199,632 B` more than the independent representation. These estimates omit
  common variable/local-index arrays, container metadata/capacity and allocator
  slack. The pair-relative saving is only `0.076835%` of the 992-MiB kill
  threshold.

## Attribution

The bounded O1 sieve state and every plausible immutable factor/group index are
orders of magnitude smaller than the observed process footprint. O1C-0064's
growth therefore belongs primarily to CaDiCaL's CNF/search/learned-clause state
or allocator retention, not the live O1 cache, trail or pending no-good.

Width-6 remains the highest-ROI next mechanism because its root bound is
`29.619671474028735` tighter than the independent relaxation and it may emit
safe cuts earlier. It does **not** carry a static-RSS-reduction prediction versus
O1C-0064. Any process-memory improvement must be an indirect consequence of a
changed search path. Direction is empirical: more early pruning may reduce
CaDiCaL growth, while more long non-forgettable external no-goods may instead
increase it.

## Direct next measurement

1. Run the lifecycle-safe width-6 successor first at the matched
   APPLE-VIEW-0008 requested 512/billed-at-most-513 conflict budget.
2. Compare safe trail cuts, first-cut position, decisions, propagations, wall,
   CPU and peak RSS against the immutable APPLE-VIEW-0008 result.
3. Preserve a bounded time-indexed external RSS trace with at least elapsed
   time, resident/physical footprint, peak and terminal sample. Promote to 4,096
   conflicts only if the matched efficacy call is positive or exposes a
   distinct mechanism boundary.

This diagnosis supersedes any wording that treats the pair-index byte reduction
as a direct explanation or solution for O1C-0064's 992-MiB process wall.
