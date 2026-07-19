# O1C-0049 — bounded online pair-credit screen

- **Recorded:** 2026-07-19T02:37:28+02:00
- **Classification:** `ONLINE_PAIR_CREDIT_NO_ABSOLUTE_PRIMARY_GAIN`
- **Gate:** failed (`no-strict-conflict-gain`)
- **Target:** consumed O1C-0044 Full-256 target; public Full-256 call ran before
  reveal; no fresh target, sibling read, GPU or MPS use
- **State:** 63 pair groups × 10 bytes = exactly 630 persistent bytes
- **Resources:** 7.952809 s wall, 66,043,904 B peak RSS, five native calls,
  2,560 requested conflicts

## Exact comparison

| Boundary | Frozen static O1C-0048 | Online credit | Change |
|---|---:|---:|---:|
| Full-256 | unresolved; 513 conflicts / 10,802 decisions | unresolved; 513 / 10,802 | none |
| Residual W8 | exact in 75 conflicts | exact in 65 conflicts | -13.3% |
| Residual W9 | exact in 155 conflicts | exact in 128 conflicts | -17.4% |
| Residual W10 | exact in 310 conflicts | exact in 320 conflicts | +3.2% |

The registered absolute gate compares exact Full-256 recovery, then maximum
exact residual width, then conflicts at that frontier. Both methods recover W10
and the online arm is slower there, so no rotation control or fresh target is
authorized.

## Mechanism boundary

The update was

```text
sat_i16(credit + 4*assigned + min(dprop/64,31)
                  - 8*min(dconf,31) - 12*backtrack)
```

and selection used static pair gap plus `credit/1024`. In Full-256 all 3,301
action tickets closed on the next decision (`closed_on_advance`), before any of
the solver's 590 later backtracks reached the ticket. Ticket-attributed conflict
and backtrack counts were therefore both zero. Sixty-two of 63 groups converged
to identical credit 424; the remaining group received 120. The bounded state was
real, but its causal horizon was too short to distinguish responsible groups.

Close this exact short-ticket update. Retain the W8/W9 work reductions only as
evidence that target-time scheduling can affect exact completion. The next
single change is a bounded delayed eligibility trace that survives `Advance`
and assigns a later backtrack to the pair-group decisions actually undone by it.
Do not tune weights, pairs or the conflict cap first.

Authoritative JSON SHA-256:
`01643f5949020d08b914919e3a465c5c05644ca6422cb44bf23edd5be17795a4`.
Attacker-freeze SHA-256:
`1b975d2eff39009379e812fc0f6575f1914cab52991524d13e08e42edc95af96`.

