# O1C-0080 — APPLE8 exact one-bit bound crossing

- **Status:** zero-call design and implementation gate; no O1C-0080 science
  call is authorized.
- **Predecessor:** O1C-0079
  `DECISION_OWNERSHIP_QUALIFIED_PREFIX_MECHANISM_ONLY`.
- **Attacker surface:** unchanged public APPLE8 Full-256 CNF, potential,
  grouping, threshold, K256 causal projection and public reader inputs.
- **Fresh state:** Page 7 / lineage 20 / local episode 0 only.
- **Maximum science work after a separate authorization:** one native call,
  exactly 128 requested conflicts, no retry or sweep.

## Why this is the next distinct mechanism

O1C-0079 proves that one typed owner can compose prefix, rank and frontier
decisions without stale-sign aliasing. The unchanged prefix activates, but the
minimum visited upper bound remains
`18.742222666780805 > tau=14.606178797892962`; it emits no prune, clause, model
or key. More prefix, rank, residency or conflict-budget scaling would repeat an
operational mechanism that has not crossed the scientific boundary.

O1C-0080 changes the decision question. It does not ask which sign is ranked
first. At one live parent assignment `a` and one unassigned key coordinate `i`,
it computes both exact admissible child bounds:

```text
U0(a,i) = U(a union {k_i = 0})
U1(a,i) = U(a union {k_i = 1})
```

The calculation must use the same compatibility groups, exact group maxima,
upward-rounded exact sum and frozen score threshold as the unchanged v6
certifier. A child is dead only under strict `Ub < tau`; equality remains live.

## Intervention rule

| Exact child state | Reader action |
|---|---|
| `U0 >= tau` and `U1 >= tau` | return no bound decision |
| `U0 < tau <= U1` | propose losing literal `-v` |
| `U1 < tau <= U0` | propose losing literal `+v` |
| `U0 < tau` and `U1 < tau` | classify `BOTH_PRUNABLE`; propose the lower-bound child, with bit 0 / `-v` on an exact tie |

The deliberate losing-child proposal is proof-producing. If CaDiCaL actually
assigns that literal, the unchanged v6 assignment path independently observes
the same strict threshold violation and queues its canonical falsifying
no-good. Merely steering into the surviving child would be safe as a heuristic
but would not materialize the excluded child as reusable evidence.

A proposal is not a realized safe prune until all of the following match:

1. the same token and level-bound ownership lifecycle;
2. an observed assignment of the predicted losing literal;
3. unchanged v6 threshold-prune evidence for that exact trail; and
4. the corresponding canonical no-good lifecycle.

An unobserved proposal released by backtrack is operational telemetry only.

## Non-mutation contract

The `U0/U1` probe is logically const. Before and after every probe, the adapter
must establish identical assignment, trail, cache, pending-clause, trace and v6
counter state. The implementation must not probe through `notify_assignment`,
`evaluate_current_bound`, temporary live-shadow mutation or private-access
hacks. It rejects assigned, unobserved and non-key variables.

The bound selector runs before the five inherited readers. A no-crossing probe
must not advance a legacy cursor, create ownership, change a return sequence or
consume the coordinate. Currently unassigned coordinates are reconsidered at
each new parent. The frozen scan order is effective rank order followed by any
omitted key variables in ascending variable order.

## Fresh Page-7 boundary

Completed O1C-0079 telemetry contains zero fully emitted clauses. The fresh
projection must therefore:

1. validate the sealed O1C-0079 result, capsule, compressed evidence and
   zero-call erratum;
2. replay the real Page-6 causal state;
3. append the identity-bound empty rollover vault at lineage 20; and
4. call `advance_causal_residency` with zero emitted union indices.

The empty rollover is a required lineage receipt, not fabricated evidence. It
contains zero clauses, occurrences and emissions and has SHA-256
`43377d8b5c116f2e3deac2064a16bbc526ae2c31bb2999c074084b81faa4ce94`.
No failed-call reprojection, invented assignment or synthetic occurrence is
permitted.

The precommitted Page-7 identities are:

- active projection: 256 clauses / 663,409 literals;
- active SHA-256:
  `92b6e547e143cdaf2f28fe731fd356bc69806926ee569205d6def432144258ff`;
- selection-order SHA-256:
  `776819396914179fe1a0ae9b443a6c0775e32c70bf36658b6dfe7043002dc723`;
- occurrence count: 558;
- attic chunks: 10 before, 11 after;
- fully emitted union indices: empty.

If legacy frontier/staging fallbacks remain enabled, their documents must be
derived anew against Page 7; Page-6-bound bytes cannot be reused.

## Archived Page-6 lower-envelope census

Before authorizing a fresh call, the complete O1C-0079 ownership stream was
replayed without invoking CaDiCaL.  The stream exposes every observed
assignment and all 549 nonzero proposal markers, but it does not record the 138
native backtrack callbacks individually when no ownership token is released.
Consequently the replay can retain an assignment after the native trail has
already released it.  Its reconstructed states are therefore an
**over-constrained lower envelope**, not byte-exact native parent snapshots.

On the 549 visible proposal parents, the exact width-6 incident-group oracle
examined 81,632 unassigned, observed key-coordinate pairs (163,264 child
bounds).  It found zero child bounds below `tau`.  The smallest reconstructed
child bound was `29.42639570750978`, at callback 667 / level 253 / coordinate
158.  This no-crossing result is conservative for those examined pairs: removing
a stale assignment can only increase the admissible upper bound.  It does not
cover coordinates that the lower envelope still marked assigned, nor the 1,038
zero-return callback parents.

The largest reconstructed parent-to-best-child reduction was
`4.335772097681144`; the distance from O1C-0079's native visited minimum to the
threshold is `4.136043868887843`.  This is an alignment breadcrumb showing that
the one-bit operator has sufficient observed amplitude somewhere in the
archived path.  Because parent and child were both evaluated on the
over-constrained replay state, it is not a certified claim that this reduction
occurred at a native near-threshold parent.

This census changes the implementation gate in one important way: the live
oracle must use one exact parent group-max/sum cache and replace only groups
incident to the candidate coordinate.  Rescanning all 2,885 groups / 176,912
rows for both signs of every coordinate would add no information and would make
the all-parent census needlessly intractable.  The optimized result must remain
bit-identical to an independent full-scan oracle in fixtures.

A separate census used only archived terminal snapshots whose assignment and
group-cache bytes are actually present.  Across 19 compatible snapshots / 13
unique parent states, it evaluated 1,580 eligible parent-coordinate pairs and
3,160 child bounds.  It again found zero crossings and zero both-prunable
pairs, but the closest child was only `0.2364278808550626` above the threshold:

```text
source: O1C-0074 episode 1 terminal state
coordinate: 105
parent U: 15.531057646608152
U0:       15.224559961355952
U1:       14.842606678748025
tau:      14.606178797892962
```

This exact terminal fixture is the production-scale native/Python equivalence
case.  It also predeclares a narrow alignment regime in which depth 2 may be
eligible if the fresh depth-1 census misses: depth 2 is not authorized merely
because depth 1 returns zero proposals, but a live, exact margin in this range
is qualitatively different from the archived proposal lower envelope's
14.82-point gap.

## Target-free implementation gate

Before source freeze, focused fixtures must prove:

- native `U0/U1` byte-for-byte/numerically match an independent Python exact
  oracle for the same parent and both signs;
- probe order does not change either bound;
- every pre/post state digest is identical;
- strict threshold, equality, one-dead, both-live and both-dead cases;
- exact bit/spin/DIMACS sign mapping;
- no clause exists before actual losing-child assignment;
- actual losing-child assignment causes unchanged v6 to queue the exact
  no-good;
- backtrack releases ownership and restores state;
- unobserved release records zero realized prunes;
- the Python adapter rejects every float/hex, sign, variable, token, origin,
  call, state-digest and v6-evidence mismatch; and
- Page 7 builds byte-identically twice and rejects any nonempty fabricated
  O1C-0079 emission list.

All preparation and fixture work is zero science: no solver target, reveal,
truth, entropy, refit, MPS or GPU call.

## Three-axis result gate

The future one-call runner must archive independent conclusions:

1. **Exact probe operation:** at least one valid same-parent `U0/U1` probe with
   no state mutation.
2. **Bound-crossing activation:** at least one certified dead child proposed and
   correctly owned.
3. **Cryptanalytic science:** at least one realized safe prune, certified
   two-child closure, globally novel exact no-good or independently verified
   public model/key.

Only axis 3 is scientific gain. A lower minimum UB, different trace, fewer
propagations, more callbacks or bound-crossing proposal without authoritative
v6 prune evidence is mechanism telemetry, not recovery progress.

## Stop and successor rules

- Never replay Page 6 / lineage 19 or any earlier consumed ordinal.
- Never tune `tau`, scorer, K, rank, phase, seed, horizon, RAM or conflict cap
  after seeing O1C-0080.
- If no depth-1 crossing exists, measure the exact nearest margin once. Depth 2
  is eligible only for a genuine predeclared near-crossing; it is not an
  automatic expansion.
- If neither depth 1 nor a justified depth 2 produces a crossing, close the
  Apple decision-order line and move to a different public evidence operator.
