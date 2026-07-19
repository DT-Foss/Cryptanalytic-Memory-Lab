# O1C-0076 — APPLE8 live causal-frontier reader design

- **Frozen:** 2026-07-20T00:49:35+02:00 (`Europe/Berlin`).
- **Hypothesis:** `H-CAUSAL-FRONTIER-080`.
- **Direct parent:** O1C-0075 authoritative result SHA-256
  `1307be5e1c140f27ec76873a212785f7dae9b5dd986ca8f953e94809e31639c9`;
  capsule-manifest SHA-256
  `3a421ee236af5afe46011314d74c25b726a2e7f35e9963ae8d4a862e070327f9`.
- **Isolation:** this attempt adds only O1C-0076-owned files inside this lab.
  O1C-0068 and sibling projects remain unchanged.

## Why this call

O1C-0075 proves that clause residency is no longer the active bottleneck. Two
byte-distinct K256 pages, together covering all `545/545` undominated attic
clauses, reproduce the same native trace and emit nothing. A third passive page
therefore has negligible expected value.

The sealed public terminal assignment instead exposes an exact local boundary.
In unused fresh Page 3, exactly 12 clauses have no true literal. The deterministic
rule

1. retain only clauses with `true_count = 0`;
2. minimize `unassigned_count`;
3. break any remaining tie by clause SHA-256 and active index

selects one unique clause:

| field | frozen value |
|---|---|
| Page 3 SHA-256 | `5b459ea4a10bcb8183e5aaf1e93a91e0e7e4bfc89c58b3e65efaf8d4838c8d91` |
| union / active / occurrence ordinal | `526 / 232 / 534` |
| clause SHA-256 | `c4a9c471f9eb45829764a841fb8c6971eecdc8b9a9e251732d65875647f25322` |
| clause state | `2,409 false / 0 true / 29 unassigned` |
| clause length | `2,438` |
| witness score | `14.554563483898708 < 14.606178797892962` |
| source assignment SHA-256 | `c62a8e3c41694b25c86aa8e66dfc9072cec7d23b7efd39fc4c766ef8ea2418d2` |
| residual i32le SHA-256 | `ed2056882fd69ed2fc6ffb502ae251e3d7876fa4131b0fa35396d73305deccd7` |
| falsifying i32le SHA-256 | `71de3130c414926ba0527d1d427b99400454a90e40152b20c68ff02c06c7fe48` |
| canonical frontier plan | `6da2702b6840a2c24a2fc09a3a49ab34d913cc55cc3135c1087880a9461860f1` / `4,479 B` |
| zero-call seed manifest | `e10c90ee8d2cd37516fe093c3833c7cdc59d64ac513d0a9ec17afb051bd057d6` |

Residual clause literals, in immutable clause order, are:

```text
105 -106 -129 -130 131 -31873 -31874 63009 63745 -63746
-190563 -190565 -190566 -190568 -190569 -191209 -191210
-191211 -191212 -191213 -191214 -191215 -191216 -191233
-191234 222434 223063 223081 -223106
```

The clause is already resident and certified. O1C-0076 does not inject it again;
it makes its boundary active in the decision stream.

## Reader composition

The frozen release-contrast reader remains first. Every native decision callback
must invoke it exactly once:

- a nonzero parent decision passes through unchanged;
- only a parent zero/delegation may be replaced by the next unassigned residual's
  falsifying literal;
- a residual is consumed at most once;
- if a returned falsifying assignment is genuinely released by backtrack, its
  satisfying opposite may be returned at most once on a later parent-zero
  callback;
- otherwise zero passes through to CaDiCaL.

This is a bounded two-slot causal operator: approach the exact no-good boundary,
then sample the released opposite as contrast. It does not alter the score,
threshold, grouping, rank source, active K, seed, phase or clause-validity path.
All native score-bound no-goods remain certified by the frozen parent adapter.

## One-call protocol

- local episode `0`, lineage ordinal `16`;
- exactly one seed-0 call;
- exactly `128` requested conflicts;
- active input: unused Page 3 only;
- rank source: immutable 202-clause vault SHA-256
  `cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858`;
- timeout `45 s`, memory cap `536,870,912 B`;
- no retry, second page, rank/K/phase/horizon/threshold/seed sweep or RAM increase;
- zero truth, reveal, fresh-target, entropy, refit, MPS and GPU calls.

Intent is durable before the subprocess. An incomplete or invalid returned call
consumes lineage 16 and blocks replay. Publication recovery may issue zero
solver or verifier calls.

## Predeclared readout

Mechanism activation requires all of the following:

- at least one frontier literal actually replaces a parent zero;
- exact outer callback telemetry reconstructs every substitution;
- native trace differs from the frozen `f64441a2...` fixed point;
- the active input, rank source, selected clause and source assignment retain
  their frozen identities.

Trace change alone is not a scientific win. Science promotion requires at least
one of:

1. a publicly verified key/model;
2. formal threshold-region exhaustion or a safe new bound prune/frontier
   contraction;
3. at least one globally novel certified exact exclusion;
4. another predeclared attacker-valid entropy, rank, residual-width or matched
   work improvement.

If the reader changes the path but produces none of these, record a
mechanism-only result and move to the event telemetry it exposes. If no frontier
literal can activate, close this exact reader without retry. In either case,
preserve all emitted occurrences and globally novel clauses in the immutable
causal attic.

## Explicitly deferred compiler breadcrumb

The ten non-tautological exact pair resolvents remain valid, but under the same
terminal assignment each has 572 unassigned and `1,219..1,257` true literals.
They are much farther from the live boundary than union clause 526 and are not
the O1C-0076 science input. Their vault SHA-256
`01811dd834b6ec4fc4dd65a8c94e65fb985320a6c4af34cd43c0e67f8564b8b6`
is retained for a later compiler/operator test.

## Threshold note

O1C-0075 already seals the requested audit: threshold and upper bound use the
same score units and retained direction, but a fixed cutoff and a minimum over
run-specific visited trails are not the same statistic or population. A strict
`U(a) < tau` safely prunes only descendants of that visited trail. The historical
`7.973483108047071` belongs to O1C-0066 episode 1; O1C-0068's minimum is
`12.8607806294803`, and O1C-0068 remains untouched.
