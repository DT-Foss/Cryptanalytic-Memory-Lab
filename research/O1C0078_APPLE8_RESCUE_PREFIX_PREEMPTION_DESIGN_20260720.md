# O1C-0078 — APPLE8 rescue-prefix preemption design

- **Frozen:** 2026-07-20T03:13:42+02:00 (`Europe/Berlin`).
- **Hypothesis:** `H-RESCUE-PREFIX-PREEMPTION-082`.
- **Direct parent:** O1C-0077 authoritative result SHA-256
  `8b87d7cdc39f6380a887b2e45d4879544ff88cd7c53e22f44876e46c334cf103`;
  capsule-manifest SHA-256
  `6b8526c5eaa2c318d4eef1e8c4dc87e744307c95f30699a90e4444021d2dbece`.
- **Isolation:** O1C-0078 may add only attempt-owned files in this lab.
  O1C-0068 and sibling projects remain unchanged.

## Why this call

O1C-0077 proved that an upstream polarity intervention is operationally real:
its first divergence occurs exactly at callback 225, it returns all four
predeclared staged literals and changes the 128-conflict trace. The terminal
callback-256 state moves from `18 false / 11 rescue` to `23 false / 6 rescue`,
but the selected frontier never becomes unit, no threshold prune fires, no
novel exact clause is emitted and no public model appears.

The remaining question is timing, not another polarity fit. O1C-0078 puts the
complete, previously sealed 11-row falsifying rescue set in front of the
inherited O1C-0077 reader stack. It asks whether making those public causal
coordinates available before ordinary propagation can turn the already active
operator into an exact search-space output.

## Frozen prefix operator

The prefix is exactly this signed literal sequence:

```text
130 -131 31874 63746 190565 190566 190569 191212 191213 191216 191234
```

Its signed-i32le payload is 44 bytes with SHA-256
`b5debc5f55f7cbc1e728d00ce1d14d0c437249793f8c10e8b80e614a00ed155c`.
No row may be added, removed, reordered or polarity-flipped. In particular, the
six rescues remaining after O1C-0077 do not authorize a post-result subset: the
complete 11-row order was sealed before O1C-0077 executed, and O1C-0077 did not
test prefix timing.

At each decision callback, the outer reader scans the fixed sequence from its
monotone cursor:

1. an already assigned row is consumed and classified as falsifying or rescue;
2. the first unassigned row is returned once and consumed;
3. the inherited parent is not called while any prefix row remains;
4. after all 11 rows are consumed, the parent is called exactly once per
   callback and its return is passed through without replacement or discard.

There is no prefix contrast, second pass, same-sign reassertion, retry,
adaptive subset or adaptive order. Earlier prefix decisions may propagate
later rows, so activation does not require all 11 rows to be actual returns.

## Fresh Page 5 and inherited stack

The direct residency parent is O1C-0077:

| binding | frozen value |
|---|---|
| parent capsule | `runs/20260720_025550_O1C-0077_apple8-residual-polarity-staging-v1` |
| canonical parent native JSON | `8980046510cd80417260436d73fdbe3cb24da6d233e136aff616972f92aadfd0` |
| parent native gzip | `e13e98d14af49978a8afaeebb36d4d854f21f92ffa29efcbec323e7a20ec5a15` |
| consumed lineage | `17` |
| fresh Page 5 | `07c73013705898e228a05b0578b0f8090a6f094c427dbd8f32d856467b08e208` |
| Page 5 clauses / literals / bytes | `256 / 654,465 / 2,619,075` |
| frozen parent trace | `706ad4fa13a8a47cd81f99bc693c1bede46612112214e6f77dc52ee61d32bf15` |

The inner frontier plan deliberately retains the sealed O1C-0076 canonical
source assignment. Re-deriving a frontier from O1C-0077's terminal assignment
against Page 5 deterministically has no unsatisfied active clause, so that is
not a compatible source semantics. This is not a science-call observation and
does not change the selected mechanism. The unchanged clause-526 control plan
is rebound to Page 5 using canonical native result
`5cee812cc99b824b43b345f20b2eed253a09090a69866de2f3c4fa074c95e198`
and source assignment
`c62a8e3c41694b25c86aa8e66dfc9072cec7d23b7efd39fc4c766ef8ea2418d2`.

The zero-call derivation must reproduce:

| plan | required binding |
|---|---|
| frontier binary | `8a263e555b4b5a69d3c9a937cac3e7702a1f8e3de27db4feffc2d21563a24da1` / `4,479 B` |
| frontier winner | active `232`, union `526`, `2,409 false / 0 true / 29 residual` |
| staging binary | `ecbca2bd3ab2e5196d4cae76a968c7957909ada49e4d225d28841a4c21d2e023` / `4,477 B` |
| effective rank order | `6ab071e611809ee898e81d0659ff0736453dd390d26c739383826c94276ad086` |
| rank/frontier intersections | `28 / 131 / 224 / 226 / 235` |

O1C-0078 adds only the outer prefix reader. The inherited O1C-0077 staging,
O1C-0076 frontier and earlier release/contrast readers remain available as
parent telemetry and are not re-fit.

## One-call protocol

- local episode `0`, fresh lineage ordinal `18`, seed `0`;
- exactly one native call and exactly `128` requested/billed solve conflicts;
- fresh Page 5 is the sole active input;
- timeout `45 s`, per-process memory cap `536,870,912 B`, CPU only;
- no retry, sweep, phase, truth, reveal, fresh target, entropy, refit, MPS or
  GPU call;
- an incomplete or invalid execution consumes lineage 18; publication recovery
  may issue zero native, solver and verifier calls.

No science call is authorized until the final source tree, config, execution
gate and native executable are commit-bound, all target-free fixtures pass,
the worktree is clean and system resources are safe.

## Predeclared activation readout

Qualified prefix activation requires every condition below:

1. the native and adapter both recover the exact 11-row plan, order, count and
   signed-i32le hash;
2. all 11 rows are consumed before the first parent call;
3. `once_returns + skipped_preassigned_falsifying = 11`;
4. `skipped_preassigned_rescue = 0`;
5. returned prefix literals are an exact order-preserving subsequence of the
   plan and each is returned once;
6. at least one prefix literal is actually returned; and
7. the outer trace differs from O1C-0077's frozen trace
   `706ad4fa13a8a47cd81f99bc693c1bede46612112214e6f77dc52ee61d32bf15`.

A rescue-direction preassignment is a partial/nonqualified intervention. A
trace change alone, a Page change, inherited staging/frontier activity, unit
telemetry or minimum-upper-bound movement cannot satisfy this activation gate.

## Science-gain priority

The first true condition determines the classification:

1. public candidate independently verifies under exact ChaCha20 (`status 10`);
2. the frozen score region is formally exhausted (`status 20`);
3. at least one actual admissible safe threshold prune is recorded;
4. at least one globally novel certified exact clause remains after attic
   deduplication;
5. the complete prefix activation gate passes: mechanism only;
6. otherwise: no qualified activation and no science gain.

Decision count, propagation count, callback count, trace shape, Page 6
projection and a smaller minimum visited bound remain diagnostics. They are not
substitutes for a real search-space output.

## Zero-call seed

Directory:
`research/o1c78_rescue_prefix_preemption_seed_20260720`

- 22 immutable artifacts plus the manifest: ten attic chunks, fresh Page 5,
  occurrence/relation/activation ledgers, the O1C-0076 control assignment,
  all three plan documents/binaries and parent provenance;
- manifest SHA-256
  `ee1a2144b2eb30ac3f69012f4e5085de1c6f668625f85b31e73c0aa188cfd30d`
  (`40,957 B`);
- frontier-plan document SHA-256
  `6803988ec27395b9fa584af9dc44effe1b9dafacb120c5e0e3931d808be6ddb0`;
- staging-plan binary/document SHA-256
  `ecbca2bd3ab2e5196d4cae76a968c7957909ada49e4d225d28841a4c21d2e023` /
  `14f4c77e07b48ca4565eb0aeb008476ab43c4883e927ab9b47cd666e1441c17a`;
- prefix-plan binary/document SHA-256
  `b5debc5f55f7cbc1e728d00ce1d14d0c437249793f8c10e8b80e614a00ed155c` /
  `0e72531b68b2ecca5862c3566aec9f6439a32e029aaeef1d40264745012fb6ba`;
- parent-provenance SHA-256
  `5193c7a263c89225768db9365413b78e7172592787e45bf9f151d86966cb8dec`;
- zero native, science, truth, reveal, entropy, refit, MPS and GPU calls.

## Formal threshold boundary

Let `S(k)` be the compiled complete-key score and retain candidates satisfying

```text
S(k) >= tau,  tau = 14.606178797892962.
```

For a visited partial trail `a`, the solver's admissible upper bound obeys

```text
S(k) <= U(a)  for every complete k extending a.
```

Therefore the strict test `U(a) < tau` proves that no retained candidate
extends that particular trail, and pruning that subtree is safe. Equality does
not suffice because the retained direction includes `S(k) = tau`.

Threshold and upper bound use the same compiled score metric, units and
maximization direction, but they do not have the same statistic or population:
`tau` is a fixed complete-score cutoff, whereas a reported minimum upper bound
is the minimum over partial trails actually visited in that episode. The
historical minimum `7.973483108047071` belongs to O1C-0066 episode 1 and
coincides there with seven actual local prunes. It is not a global domain bound,
not O1C-0068 and not the current episode. O1C-0068 reports
`12.8607806294803` and remains untouched. O1C-0077 reports
`14.656823218163392 > tau` with zero safe prunes.
