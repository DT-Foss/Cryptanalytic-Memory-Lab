# O1C-0082 APPLE8 parent-centered proof mining — interpretation

The sole authorized Page-8 / lineage-21 production call started at
`2026-07-20T14:30:11.622922+02:00` and was recorded at
`2026-07-20T14:30:55.059730+02:00`. The authoritative
[`result`](O1C0082_APPLE8_PARENT_CENTERED_RESULT_20260720.json) has SHA-256
`013692cf836e594c8580734e0c95a9f0dd18ad7536c457274a1fe5684df1ad4f`.
The sealed
[`capsule`](../runs/20260720_143008_461948_O1C-0082_apple8-parent-centered-v1/RUN.md)
has artifact-manifest SHA-256
`3256a85e1095ffeaee349d3248035cb53470b1921abd58dd230e1617696134e6`.

## Outcome and claim boundary

O1C-0082 is a real, narrowly scoped science gain:
`PARENT_CENTERED_NOVEL_CLAUSE_GAIN`, with publication stop reason
`globally-novel-clause`. The run fully emitted `257` strict-threshold
no-goods, all `257` were new relative to Page 8 and globally novel relative to
the prepared causal attic, and there were no input or within-run duplicates.
All came from visited-trail upper-bound witnesses; together they contain
`743,129` literals, have lengths `2,870..2,892`, witness UBs
`13.019691682287633..14.556639837436045`, and canonical aggregate SHA-256
`bcc424b009ff132348d5ac73227162395853d894c68ced65f9cd6494c3c0868d`.

The gain is **only** those reusable exact threshold clauses. Native status is
`0` / `INCONCLUSIVE`, `key_model_sha256=null`, complete-model checks are zero,
certified closure is false, attacker-valid entropy gain is `0.0` bits and
attacker-valid domain reduction is zero. No key, key bit, posterior, model,
root exhaustion, UNSAT result or recovery follows. Target and truth bytes were
not read; reveal, refit, retry, replay, MPS and GPU calls were all zero.

The clauses are score-threshold no-goods, not unconditional CNF consequences.
Their validity is tied to the exact CNF, potential, grouping, observed-variable
set, bound rule and binary64 threshold identity. They safely remove only the
descendants of their witnessed partial assignments from the retained region
`score >= tau`.

## Operator, probes and work

The live parent-centered mechanism operated exactly as frozen:

- `512` parent scans/callbacks yielded `255` nonzero actions and `257` zero/
  delegate returns. All `255` actions were confirmed, level-bound, one-shot
  `FAILURE_FIRST_PROOF_MINING` actions; there were `9` observed releases and no
  unobserved releases.
- There were `0` certified crossing actions and `0` action-linked actual
  certified prunes. Failure-first orientation selected the current lower-UB
  child for proof mining only; it was not a key-bit belief and emitted no
  posterior.
- The exact same-parent reader made `33,106` probes / `66,212` child-bound
  evaluations. Every probe was `NEITHER_PRUNABLE`; all `ONE_PRUNABLE`,
  `ZERO_PRUNABLE` and `BOTH_PRUNABLE` counts were zero. The complete fixed-width
  trace is `1,887,042 B`, SHA-256
  `e7c4256be98162394e0751ac6362b8e0049c6efdac2f298c62222d81ee560033`;
  the action trace is `11,475 B`, SHA-256
  `e0fc33c40380abe26f2675f1fa2de9675403a3197330488d08050e1bfc5c62f9`.
- The independent base sieve made `1,267` bound checks and certified `257`
  visited-trail threshold prunes, each fully emitted as a clause. This explains
  why `science.threshold_prunes=257` coexists with
  `science.actual_certified_prunes=0`: the former are ordinary trail-UB
  exclusions; the latter field is reserved for realized parent-centered
  crossing actions, of which there were none.

The one call requested `128` conflicts but terminated at exact
requested/actual/billed `128/9/9`, with `119` unused and no overshoot. It made
`512` decisions and `3,209,096` propagations. Native work was `778,217 us` wall
/ `1,572,724 us` CPU and peaked at `320,897,024 B`; the complete runner used
`43.43645295800525 s` wall / `41.286125 s` CPU, with child user/system time
`1.5304579999999999/0.09027400000000002 s`. Exactly one native solver call was
consumed. Peak native headroom under the `536,870,912 B` watchdog was
`215,973,888 B`; the persistent-artifact budget was `134,217,728 B`.

## Threshold and capacity terminal

The exact threshold is `tau=14.606178797892962`, binary64 little-endian
`2ef540115d362d40`; strict `U(a) < tau` prunes, while equality remains live.
The run-level visited-trail minimum UB was `13.019691682287633`; the root and
maximum UB remained `262.68644197084643`. Thus the `257` local exclusions are
certified, but the live root does not certify closure.

Page 8 entered with `256` clauses / `692,034` literals / `2,769,351 B`, SHA-256
`89e085e7323ea9aaaa31ad1430c3f20ac03f9c21a49c6404374b75ddf59330f4`.
After the `257` new clauses were fully emitted, a direct successor vault would
contain `513` clauses, one above the `512` clause cap. Its `1,435,163` literals
and computed `5,742,895 B` serialization would remain below the respective
`1,600,000` and `8,388,608 B` caps. Therefore
`next_vault_available=false` and `capacity_clause_count`—not the literal,
payload, conflict, timeout or memory limit—terminated the native episode. No
pending clause was lost. Native capacity termination and the publication
stop `globally-novel-clause` describe different layers and are consistent.

## Zero-call clause-geometry audit

A deterministic read-only audit of the archived clauses adds structure without
changing the production claim. All `257` clauses contain literals for all `255`
action coordinates. Action sequence positions `1..247` retain their original
polarity in every clause. The tail positions `248..255` are variables
`[100,55,66,153,49,24,90,21]`: their key projection spans all `2^8=256`
orientations exactly once, plus one additional distinct clause at the
all-original key pattern. The exact action-coordinate agreement histogram is
`247:1, 248:8, 249:28, 250:56, 251:70, 252:56, 253:28, 254:8, 255:2`.

Across all clauses, the common signed intersection is `2,764` literals: `247`
key literals and `2,517` internal literals. Exactly `2,870` variables occur in
every clause, but `106` of those variables switch sign. The projected cube has
`1,024` Hamming-1 edges; counting clause pairs, including the extra clause at
the duplicate all-original key projection, gives `1,032`. None yields a
non-tautological simple resolvent: every candidate pair has `6..23` other
complementary non-pivot literals, with median `10` and mean `12.25`. Thus this
audit proves no prefix closure, key recovery, tail-free no-good or resolution
compression.

The exact grouped upper bound of the common signed core is
`18.66656376905567`, against `tau=14.606178797892962`, for margin
`+4.0603849711627085`. The core therefore is not prunable; deleting assignments
can only increase grouped `U`, so no subset of this already-above-threshold core
can certify under the same bound. Its canonical SHA-256 is
`9aa383f819d1aa4b1216937ee341aa6a773d1d3456e1ea622494ef1a4345ea06`.
This audit made zero solver, native, target, truth or reveal calls.

## Seals and comparison with O1C-0080

Execution-critical seals include config SHA-256
`715adb7db1fe87ad1f77846a7ca7e7cc3e3a5ad1b449444a54191f0d57919f6b`,
intent `d17fb44b4227da8104f0955d5bf6d0e33230f601ec9f2854948c43e03d396eae`,
invocation `52d44be895f3bedc73aa3f5c1efc881e213ac554877b3a812410e66004e8345c`,
native source `823832d9f5aa6dfae85c3bdf55bb738187405323bdc418851de8654de0a64a28`
and executable `81dfe72f7ecf012db1bd31657bd1447384c24c616adf372b673a012b958027ee`.
The initial query-priority bank was `24,576 B`, SHA-256
`86787bda89f29587525ffbc071d2229608a5bff5c3243361086794379f77e21c`;
the final continuation bank is the same size, SHA-256
`05b8acf3ecd5423016e5d7ef7d649f790e758e3477a943fe7306280064a4c630`.
The archived native result / raw stdout SHA-256 values are respectively
`98cb8327590117972f6d5e69cdcf7c9a30ddab3249db576cc5534a5cef604c0e`
and `c184505a76fa0aaa647c1c79e3b1a55d92a21f052ee57cc379d9e9c6e92edd71`.

O1C-0080 used `1,587` scans, `285,725` probes and `128` conflicts; all probes
were also `NEITHER_PRUNABLE`, its minimum same-parent child UB was
`18.464862193097684` (`3.8586833952047215` above `tau`), and it emitted no new
clause. O1C-0082 used fewer scans/probes, exhausted all `255` one-shot
coordinates, and its separate trail sieve reached below threshold and emitted
`257` clauses after only `9` conflicts.

This is explicitly an observational, **non-counterfactual** comparison. O1C-0082
used a different active page (Page 8 versus Page 7), a different clause
population, a stateful priority bank and interventions that changed the solver
trajectory; there is no matched no-action Page-8 call. O1C-0080's child minimum
and O1C-0082's visited-trail minimum are also different statistics. The evidence
therefore does not identify how O1C-0080 would have behaved on Page 8, nor does
it causally assign all `257` clauses to the parent-centered ordering. It proves
only that the frozen operator ran and that this sealed trajectory produced the
globally novel clauses.

## Decision

Page 8 and lineage 21 burned when the durable intent was persisted. Never retry
or replay them. The highest-ROI successor is a causal-attic Page-9 rollover:
archive all `257` clauses and their witnesses in the immutable attic, derive a
fresh bounded Page-9 projection under a predeclared capacity policy, and pair it
with the final `05b8acf3...` bank solely as a continuation seed on a fresh
lineage 22. Belief orientation must remain disabled. This preserves both
gains—the new certified clause corpus and the learned bounded query-priority
state—without misrepresenting a fresh Page-9 continuation as a Page-8 retry.

The current O1C-0083 projection is a design expectation only: it is
**unsealed, unimplemented and has not made a production call**. Immutable
ingestion comes first. If implementation confirms exact identity and capacity,
set explicit `next_active_limit=255`; this is the minimal one-slot sacrifice
from hard-inheriting `256` clauses and provides `257`, rather than `256`, clause
slots of headroom. The expected Page-9 projection is `255` live clauses /
`721,187` literals / `2,885,959 B`, SHA-256
`8c3b8cc33badd4aa23920caabc5ea3fc5006675d93805578b74b2b20788c8204`,
partitioned as `roots=4`, `pinned=43`, `new_debt=208`. These values must be
recomputed and sealed by the implementation before any fresh lineage-22 call.
