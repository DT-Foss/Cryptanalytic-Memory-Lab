# O1C-0075 — APPLE8 causal-residency stream interpretation

- **Started:** 2026-07-20T00:27:24+02:00 (`Europe/Berlin`).
- **Recorded:** 2026-07-20T00:28:57+02:00 (`Europe/Berlin`).
- **Classification:** `CAUSAL_RESIDENCY_STREAM_NO_NOVEL_GAIN`.
- **Source/execution:** `1b30cc06b3ab28d94df773cc854a7814af9fb210`.
- **Capsule:**
  [`runs/20260720_002724_O1C-0075_apple8-causal-residency-stream-v1`](../runs/20260720_002724_O1C-0075_apple8-causal-residency-stream-v1/RUN.md).
- **Seals:** authoritative result SHA-256
  `1307be5e1c140f27ec76873a212785f7dae9b5dd986ca8f953e94809e31639c9`;
  capsule artifact-manifest SHA-256
  `3a421ee236af5afe46011314d74c25b726a2e7f35e9963ae8d4a862e070327f9`.

## Result

O1C-0075 completes both predeclared calls at local ordinals `0..1` / lineage
ordinals `14..15`. Each requests and bills exactly `128` conflicts, for `2/2`
calls and `256/256` aggregate requested/billed work. Both return status `0`
with zero threshold prunes, zero emitted occurrences, zero globally novel
clauses and no model, key or operational failure.

The attempt changes only bounded active residency over O1C-0074's immutable
causal attic and separate 202-clause rank source. The two science inputs are
byte-distinct K256 projections:

| local / lineage | input active SHA | decisions | propagations | minimum / root UB | prunes / emissions / novel |
|---:|---|---:|---:|---:|---:|
| `0 / 14` | `82b1512a…` | 2,288 | 2,890,144 | `14.67138759145431 / 262.68644197084643` | `0 / 0 / 0` |
| `1 / 15` | `db3acd5e…` | 2,288 | 2,890,144 | `14.67138759145431 / 262.68644197084643` | `0 / 0 / 0` |

Both calls produce native trace SHA `f64441a2…`. Their decisions,
propagations, bounds, prunes, emissions and model state are also identical to
O1C-0074 episodes 2 and 3. The no-repeat rule therefore changes serialized
solver input without changing behavior at this reader, seed and 128-conflict
horizon.

## Residency result

The target-free pager itself passes its exact contract. The inherited parent
projection, Page 1 (`82b1512a…`) and Page 2 (`db3acd5e…`) jointly cover all
`545/545` undominated attic clauses. Remaining never-resident debt falls to
zero while every page stays at exactly 256 clauses and no science-input SHA is
reused. After the second call, deterministic reprojection produces the unused
next page `5b459ea4a10bcb8183e5aaf1e93a91e0e7e4bfc89c58b3e65efaf8d4838c8d91`
with 256 clauses / 670,647 literals / 2,683,803 bytes.

The complete attic is unchanged at 550 unique clauses / 1,488,224 literals /
558 occurrences, including eight duplicate occurrences. This cleanly
separates two conclusions:

1. bounded rotating residency can expose the entire undominated corpus without
   enlarging K256, losing attic evidence or repeating an input page;
2. pure coverage rotation is inert at the tested horizon because distinct
   clause populations collapse to the same native trajectory.

The first is an operational mechanism success. The second controls the science
classification: there is no new exact exclusion, recovery, entropy reduction,
UNSAT result or threshold-region exhaustion to promote.

## Formal threshold boundary

Let `S(x)` be the compiled complete-key score and

`R_tau = {x : S(x) >= tau}`, with `tau = 14.606178797892962`.

For a visited partial trail `a`, the admissible upper bound satisfies

`U(a) >= max {S(x) : x extends a}`.

Threshold and UB therefore use the same score units and retained direction.
They are not the same metric object or population: `tau` is the fixed
membership cutoff, whereas reported minimum UB is
`min_{a in V} U(a)` over a run-specific visited-trail population `V`.

For each particular visited trail,

`U(a) < tau  =>  no completion of a belongs to R_tau`.

That implication is a safe local prune, not a global result. O1C-0075 reaches
minimum UB `14.67138759145431 > tau` in both calls and records zero threshold
prunes; root UB remains `262.68644197084643 > tau`. The historical
`7.973483108047071` is O1C-0066 episode 1, not O1C-0068; O1C-0068 reports
`12.8607806294803`. No O1C-0068 artifact is changed by this clarification.

## Exact next breadcrumb

Zero-call structure analysis supplies a higher-leverage successor than another
page. The ten non-tautological exact pair resolvents remain valid reusable
consequences (29,702 literals / 119,039 bytes; vault SHA-256
`01811dd834b6ec4fc4dd65a8c94e65fb985320a6c4af34cd43c0e67f8564b8b6`), but
they are not the closest live boundary: under the frozen terminal assignment
each already has `1,219..1,257` true literals and exactly 572 unassigned
literals. Directly preloading them is therefore not the next paid call.

The sharper target-free signal is already inside the unused Page 3
`5b459ea4...`. Exactly 12 resident attic clauses have zero true literals under
the public O1C-0075 terminal assignment. The unique nearest is union index 526,
clause SHA-256
`c4a9c471f9eb45829764a841fb8c6971eecdc8b9a9e251732d65875647f25322`:
2,409 literals are false, 29 are unassigned and none is true. Its certified
witness score is `14.554563483898708 < tau`. The clause was already resident,
so the missing mechanism is not storage or page coverage but live reader
activation.

The direct successor is one frozen causal-frontier reader. On callbacks where
the existing release-contrast reader delegates, it should drive those 29 public
residual coordinates toward falsifying the selected no-good and, after genuine
backtrack release, expose each opposite once as bounded contrast. Use only the
fresh Page 3, lineage 16 and one 128-conflict call. A changed trace proves
activation; science gain still requires a new exact exclusion, a safe bound
prune/frontier contraction, public recovery or formal exhaustion.

## Resources and publication

End-to-end elapsed time is `93.29592229200352 s`; runner peak RSS is
`482,541,568 B`. Native episode peaks are `411,435,008 B` and `408,993,792 B`.
Persistent artifacts occupy `20,788,748 B`. There are zero publication-recovery
solver calls, truth reads, reveal calls, fresh targets, refits, rank/K/horizon
sweeps, phase calls, MPS calls or GPU calls.

Capsule `result.json` is byte-identical to the published authoritative result,
and all `41/41` capsule-manifest entries validate. Cite the sealed result above
for the final classification and resource totals.

## Direct resume point

Do not replay lineages `14/15`, resweep residency pages or enlarge K, horizon,
rank, phase, threshold, RAM or caps. Preserve the immutable 550-clause /
558-occurrence attic, the complete activation ledger, the zero-debt coverage
proof and the separate rank source.

The next distinct attempt should freeze and test the nearest-clause live
causal-frontier reader above. Preserve the exact resolvents as a later compiler
bread crumb, but do not spend the next call on them: their terminal distance is
far larger than the selected 29-literal frontier. The pass gate remains native
novelty, public recovery, formal exhaustion or a measured attacker-valid
frontier improvement; trace change alone establishes activation, not science
gain.

The authoritative machine result is
[`O1C0075_APPLE8_CAUSAL_RESIDENCY_STREAM_RESULT_20260720.json`](O1C0075_APPLE8_CAUSAL_RESIDENCY_STREAM_RESULT_20260720.json).
