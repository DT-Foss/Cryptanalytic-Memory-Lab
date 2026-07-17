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

O1C-0009/O1C-0010 closed linear full-round end-output regression. O1C-0011 then
compiled the exact public-only full-256 ChaCha20 relation, and O1C-0012 executed the
entire upstream mechanism: 512 symmetric assumptions, 1,536 closed proof frontiers
and a 17,408-byte coordinate-bound unary/ARX/holographic state. Its structural and
resource gates pass, while the single-known-key `(7,1,4)` diagnostic is negative at
119/256 bits and -86.779990-bit compression. The active milestone is O1C-0013:
learn event orientation and horizon mixing across multiple known full-256 keys,
freeze the reader, and attack a fresh sealed target. No W12/W52 residual target is
part of the result ladder.

## Evidence ladder from here

1. Generate deterministic known-key full-256 BUILD/CAL public instances and run
   them one at a time through the frozen O1C-0012 branch/prefix contract.
2. Persist each bounded state before reading its known label; fit only portable
   per-horizon, proof-motif and ARX-orbit orientation across keys.
3. Compare single wavelengths, a small regularized unary mixture and an
   identity-preserving local-interaction arm against swap/output/ancestry controls.
4. Freeze model bytes, data split, control transforms and all commitments before a
   broker produces a fresh uniform output-only 256-bit target.
5. Measure sealed full-key NLL against 256 bits, correct bits/blocks, million-decoy
   rank and exact public verification once; reveal only after predictions persist.
6. If signal transfers, spend it on O1-O scheduling, Attic compounding and a bounded
   uncertainty beam; if not, localize the failed sensor context and iterate upstream.

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
