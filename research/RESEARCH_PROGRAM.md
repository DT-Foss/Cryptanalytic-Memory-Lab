# Research Program

## Objective

Produce an end-to-end O1/O1-O living inverse for standard full-round ChaCha20 with
all 256 key bits unknown and only the public counter, nonce and output visible at
attack time.  The objective is measured entropy removal and ultimately exact key
verification on sealed uniform targets, not a larger reduced-width scaffold.

## ROI definition

Research priority is proportional to expected frontier impact, information gain,
reuse and downstream leverage, divided by implementation cost, compute cost and
contamination risk. Green tests and document count are not research outcomes.

## Current milestone

O1C-0009/O1C-0010 closed linear full-round end-output regression. O1C-0011/O1C-0012
then built the exact public-only full-256 relation and complete 512-branch causal
state. O1C-0013 learned shared orientation from four BUILD and two CAL keys, froze
an h96 reader, and attacked two fresh sealed output-only keys. It produced the first
positive prospective seed: 259/512 bits, `+0.0889215` bit/key and a
`+3.3062538`-bit/key margin over its shuffled reader, with all three transformed
controls negative. The targets split negative/positive and no key was recovered,
so the active milestone is O1C-0014: an exact-byte, no-refit replication on eight
new sealed keys. No W12/W52 residual target is part of the result ladder.

## Evidence ladder from here

1. Pin O1C-0013's exact primary and shuffled reader binaries plus source-capsule
   manifest before any O1C-0014 target entropy is requested.
2. Predeclare eight fresh targets, three anchor controls, aggregate NLL, frozen-
   shuffled margin, conditional-null z and target-level sign robustness; prohibit
   BUILD/CAL replay or any reader change.
3. Run each public relation sequentially through the unchanged h96 branch/prefix
   contract and persist every state/posterior before the first reveal.
4. Reveal once, recompute every public block, and report total code length from the
   exact 2,048-bit random baseline plus bits/blocks, decoy ranks and coordinate map.
5. If fixed-reader signal transfers, scale the same bytes to a larger blind panel,
   then spend the replicated posterior on O1-O scheduling, Attic compounding and a
   bounded verification beam.
6. If it fails, use the frozen eight-key residuals to choose one new proof-motif or
   ARX-local sensor family; do not retune h96 on the revealed replication panel.

## Operating contract

- Work only inside this lab; sibling projects are read-only.
- Continue from `STATUS.md`; do not restart broad audits.
- Every substantive experiment receives a monotone `O1C-NNNN` ID and immutable,
  timestamped run directory.
- Every result records hypothesis, prediction, controls, work budget, exact command,
  source hashes, start/end times, metrics, interpretation and next action.
- A negative result must yield explicit breadcrumbs before its family is abandoned.
- Repetition requires a new mechanism, variable, dataset, scaling question or
  replication purpose.
- One targeted validity review per milestone is enough unless a concrete defect is
  discovered.

## Non-negotiable scientific boundaries

- all 256 target key bits unknown from the first outcome-bearing experiment;
- target-time inputs limited to public relation data and attacker-computable
  self-generated candidate traces;
- bounded state in stream length;
- no KV cache or full `O(T)` attention except a named ceiling;
- no alphabet-indexed dictionary presented as a memory breakthrough;
- no full-rank fixed-domain transform presented as compression when a matched direct
  table has equal information and lower serialized logical state;
- monotone provenance and no target/post-reveal leakage into discovery;
- disjoint train, validation, frozen test and post-test audit;
- matched work accounting and appropriate null/correlation/capacity controls;
- exact independent full-round confirmation for terminal recovery claims.

## Terminal condition

Completion requires exact 256/256 long-stream retention, reproducible entropy or
search reduction on sealed uniform full-round 256-bit targets, and ultimately a
full key emitted by the bounded-state/beam path and independently verified against
the public ChaCha20 relation. Instrumentation or reduced-width recovery alone is not
completion.
