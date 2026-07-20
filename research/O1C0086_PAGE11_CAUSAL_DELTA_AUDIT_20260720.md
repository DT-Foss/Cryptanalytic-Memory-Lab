# O1C-0086 — Page-10 to Page-11 causal delta audit

Read-only, zero-call audit recorded 2026-07-20. Both O1C-0085 and O1C-0086
capsules pass all 29 artifact seals. No solver, target, truth, reveal, refit,
MPS or GPU path was used.

## Exact state continuity

- O1C-0085 final bank SHA-256
  `2c0c4ccba476bc642778b68234cc497c1776d144092ea9f1aead367559f59b07`
  is byte-identical to O1C-0086's
  initial bank.
- O1C-0085 final priority state SHA-256
  `288d91298200ae69f84e6616c9a445c87b092ff56ac8671033ae3c3b4dd8b0a9`
  is byte-identical to the
  O1C-0086 initial state receipt.
- Both packed banks decode to exactly 24,576 bytes under the published 96-byte
  record layout. O1C-0086's final bank is
  `658fd2856b83d1a0ff8d28e92a604c99b3843a49a589811bf9b61845959ec31f`;
  its final priority state is
  `e5ffda54ec91dc325abe0d87051e4045aecebd9e9d89655fc9a9b5539dafeeec`.

## What changed

| Metric | O1C-0085 | O1C-0086 |
|---|---:|---:|
| Parent/callback scans | 430 | 1,009 |
| Probe records | 32,840 | 100,038 |
| Child-bound evaluations | 65,680 | 200,076 |
| Returned failure-first actions | 255 | 255 |
| Released actions | 6 | 255 |
| Post-action probes | 200 | 67,398 |
| Globally novel clauses | 23 | 202 |

The yield increase decomposes exactly:

```text
202/23
= (1,538/643) * [(202/1,538) / (23/643)]
= 2.3919129082 * 3.6717928422
= 8.7826086957
```

Thus the Page-11 trajectory supplies about 2.39x more bound-check
opportunities, while each opportunity is 3.67x more likely to prune. Bound
checks per decision stay nearly constant (`1.495349 -> 1.524281`), so the
decomposition is not a counting-unit change.

The first 255 calls are structurally identical in both runs: one action per
call with `255,254,...,1` probes, totaling 32,640. O1C-0085 then records only
200 later probes over five released coordinates. O1C-0086 releases all 255
coordinates and records 67,398 later probes. Its conservation identities close
exactly:

```text
sum(final_count - initial_count) = 100,038
probe_trace.count                = 100,038
300 + 99,630 + 103 + 5          = 100,038
child_bound_evaluations          = 200,076 = 2 * 100,038
```

The outcome counts in the third line are respectively `BOTH_PRUNABLE`,
`NEITHER_PRUNABLE`, `ONE_PRUNABLE` and `ZERO_PRUNABLE`. None becomes a direct
certified action crossing; `actual_certified_prunes` remains zero.

## State and order stability

- Action-sequence Spearman correlation is `0.9788219372394628`; Kendall tau-a
  is `0.8868612011733827`. Top-10 membership is identical and top-20 overlap is
  19/20. A radically different initial order does not explain the yield jump.
- Final-priority Spearman falls to `0.6784694881889763`, showing that extensive
  post-action observations materially refresh the state after the action
  sequence.
- O1C-0086 updates all 255 nonzero records; variable 241 remains the sole
  all-zero record. Total observation count grows `82,330 -> 182,368`.
- Mean recomputed priority grows `10.802353512259643 -> 14.933733548915274`;
  163 coordinates rise and 92 fall. Observation-count delta is negatively
  correlated with final priority (`-0.31647851406989647`), so raw frequency is
  not itself the priority signal.
- Clause geometry develops a localized shallow basin: 164/202 O1C-0086 clauses
  (81.188119%) have length 2,650–2,653, whereas O1C-0085 emits no clause shorter
  than 2,892. The two output sets share neither clause hashes nor witness hashes.

## Interpretation and next decision

Observation: the initial/action ordering is stable, while full-coordinate
release and post-action re-observation create the large state delta that
coincides with the `23 -> 202` clause-yield increase.

Inference: the best supported mechanism is live-state refresh, not action-order
randomness or blind cap scaling. Page 12 must therefore seed from the exact
`658fd285...` final bank and `e5ffda54...` receipt, recompute priority from those
records, and never replay O1C-0086's frozen action sequence. Its preflight must
retain the count/probe/outcome/child-evaluation conservation checks and preserve
variable 241 as the sole zero record.

This audit does not establish isolated causality: Page composition also changes
between runs. It does identify the cheapest discriminating continuation. Carry
the refreshed bank and all 202 clauses into fresh bounded Page 12 under H091;
do not spend a call on an old-order replay or a cap/RAM sweep.
