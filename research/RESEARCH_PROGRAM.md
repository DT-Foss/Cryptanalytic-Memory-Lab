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
state. O1C-0013 learned shared h96 orientation and produced a two-key positive seed.
O1C-0014 reloaded those exact bytes on eight independent keys: `1053/2048` bits,
`+0.233784` bit/key and conditional `z=1.819`, but only `4/8` positive targets,
paired `z=0.838`, mixed controls and zero recovery. Its predeclared classification
is `NOT_REPLICATED`. The active milestone is O1C-0015: exact h96 plus one fixed
equal-logit h96+h65 two-wavelength reader on 32 new sealed keys. No W12/W52
residual target is part of the result ladder.

## Evidence ladder from here

1. Preserve O1C-0014 as immutable negative validation and O1C-0013 h96 as the exact
   primary baseline; reconstruct h65 from O1C-0013 BUILD/CAL only.
2. Serialize and freeze exactly one fixed
   `0.5*logit(h96)+0.5*logit(h65)` reader and matched shuffled control before any
   O1C-0015 entropy. O1C-0014 can choose this architecture but never fit it.
3. Generate 32 fresh sealed targets and reuse every public 512-branch h96-prefix
   field for all readers with no extra solver branches.
4. Persist all predictions before any reveal, then report 8,192-bit total NLL,
   conditional/paired nulls, target robustness, blocks, decoy ranks and controls.
5. If the unary direction transfers, compound independent challenge evidence in
   the surprise-gated Attic and bounded verification beam.
6. If it fails, implement one query-rooted carry/proof-cone sensor; do not tune
   weights, coordinates or coarse ARX/motif sums on O1C-0014.

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
