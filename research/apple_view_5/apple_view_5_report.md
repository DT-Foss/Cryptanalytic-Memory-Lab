# Apple view 5: 336 carry switches contain exact sparse rejection certificates

## The simple picture

APPLE-VIEW-0004 showed a sharp cliff: at carry depth 30, every complete wrong
256-bit probe survived; at depth 31, all four were rejected.  The only
difference is one equation in each of ChaCha20's 336 additions:

```text
switch j:  c31[j] = majority(a30[j], b30[j], c30[j])
```

This run stops treating depth as one global knob.  It compiles the depth-30
relation once, leaves all 336 equations dormant, and enables them individually.
After each switch, exact bidirectional truth-table propagation runs to a fixed
point.  There is no CDCL, Boolean decision, or unrestricted search.

The matrix uses the exact fixed APPLE-VIEW-0004 public target and its four
output-independent complete wrong probe keys.  The fixed orders are
early-to-final, final-to-early, deterministic public random, and an online order
driven only by public propagation gain.  A fifth bounded picker also sees the
complete candidate currently being filtered, which is attacker-valid.  Wrong
probes are measured first.  The true key is used only afterward to check that
every ordering retains the real execution.

## Exact result

The task gate was an independently replayed conflict using at most 268 of 336
switches, leaving at least 20% absent.  A stricter stretch gate kept the earlier
25% cutoff: at most 252 switches.

| Switch strategy | First conflict prefix | Replayed proof slice | Identities absent from proof | Stretch passes |
|---|---:|---:|---:|---:|
| early to final | 258–262 | 258–259 | 77–78 | 0/4 |
| final to early | 257–261 | 251–257 | 79–85 | 2/4 |
| deterministic public random | 334 | 255–260 | 76–81 | 0/4 |
| online public gain | 269–272 | **250–265** | **71–86** | 2/4 |
| online candidate-local gain | 258–262 | 258–259 | 77–78 | 0/4 |

All 20 order/probe runs rejected their wrong candidate exactly.  More
importantly, all 20 conflict proofs replayed with at most 268 identities.  The
best certificate used **250/336** switches and omitted **86 exact c31
identities**.  Four certificates also passed the stricter 252-switch stretch
gate.  All five true-key controls completed consistently with all 336 switches.

The reason-DAG slice is not a statistical score.  Every inferred assignment
records the constraint and antecedent assignments that forced it.  Starting at
the empty-domain conflict, the run walks that dependency graph backward,
retains only participating dormant switches, then starts a fresh propagator and
replays that subset.  Every reported slice produced a fresh exact conflict.

Thus the APPLE-VIEW-0004 statement “one free carry per addition absorbs every
local contradiction” was too coarse.  All 336 identities are sufficient, but
not necessary: on this fixed Full20/Full256 candidate-filter matrix, exact
contradictions already exist with 71–86 of them completely absent.

## What did and did not work

The order matters sharply before proof slicing: random order needed 334 enabled
switches, while structural forward/reverse orders needed about 260.  Immediate
candidate-local gain did not improve this.  Its available switches repeatedly
tied at the same local score (`one forced variable / three known positions / one
viable row`), so deterministic tie-breaking collapsed back to early-to-final.

The public-only greedy order initially chose feed-forward additions 320–323 and
332–335.  Its raw prefix was worse than structural order, but its proof slice
contained the best 250-switch certificate.  That separation is the useful
breadcrumb: immediate assignment gain is a weak attention signal, whereas
eventual participation in the exact conflict proof is a much better credit
signal.  A bounded exhaustive hypothetical-next-switch picker was tested as a
pilot but stopped before the 45-second boundary; it was not part of the result.

This is a candidate filter, not key recovery.  It assumes a complete candidate
key, generates no candidates, recovers zero key bits, and makes no global
entropy-reduction claim.  Four probes are not used to estimate a rejection
rate.

## Next expert step

Stream the exact proof-participation events as live credit over the 336 named
addition identities.  O1 should learn which carry switches repeatedly survive
the backward proof slice across build targets, then schedule those switches on
a new held-out target.  The measurable objective is certificate size and work,
not one-step propagation gain.  A second cheap branch can group the 336 switches
by quarter-round/round and learn small correlated cuts, because this run shows
that the useful signal is global proof relevance rather than raw chronological
position.

## Reproduction ledger

Reference run: 2026-07-19 02:55:06–02:55:37 CEST.

- one compiled network: 31,666 variables; 31,072 depth-30 base constraints;
  31,408 constraints with all switches;
- 46 propagation states, 20 independently replayed proof slices, 4,232,814
  constraint visits, and 28,771,680 truth-table rows checked;
- 30.686913 CPU seconds / 30.812515 wall seconds;
- 56,573,952 bytes peak process RSS;
- fixed public target SHA-256:
  `fa12050df20cc4c4d2f33a1b1d88e52f6194ee72bc01b928d00ca4d0d161c527`;
- source SHA-256:
  `0af2ab363e8c3d1d824c4c5de9f58f194ee121f6e03e079a7f9934f41f77a83a`;
- tests SHA-256:
  `80f6f43664eaba65bc9e5ff0205db44aedcea3f91301659d156892f44e7ca36d`;
- result SHA-256:
  `fcfb558981fdb230b72cf77447a946e9dbeba313d75cfaaf83eb3faab22f07fc`;
- scientific payload SHA-256:
  `409c6786255942100c7fd168a3352e385a68cfea17fba21b6630e1151f07133f`.

The machine JSON contains every order hash, first-conflict prefix, exact switch
certificate, replay status, assignment count, constraint-visit count, truth
control, and resource field.
