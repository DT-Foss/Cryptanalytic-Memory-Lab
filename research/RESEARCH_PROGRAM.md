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

O1C-0016 closed the fixed global h96/h65 reader family on 32 independent keys.
O1C-0017 then established the replacement architecture on anonymous synthetic
full-256 streams: O1 learned the useful channel without being told its identity,
and the bounded addressed Bit-Vault retained it at `+42.308742` bits mean
compression. O1C-0018 moved the mechanism to real full-round paired-proof streams.
Its raw reader failed at `-1.284644` mean bits, but its early true-reward picker
beat the shifted critic in every checkpoint cell. Forensics localized the blockers
to cumulative-query double integration, stale credit, hash shortlisting, compulsory
breadth and forced spending.

The active milestone is O1C-0019, implementation-frozen at `dc249ad`: a
packet-local incremental/gated O1 reader and reader-bound episode-equal critic are
cross-fitted over the four immutable BUILD pools. Every affordable address is
queried; finite starvation replaces compulsory breadth; ACTION/STOP is compared
with an exact no-STOP twin, shifted critic, fold-local static reward and uniform
hash. The scientific run is intentionally waiting for the active sibling W52
resource interlock to clear.

## Evidence ladder from here

1. Preserve O1C-0018 and its six pools byte-exact; use only the four BUILD artifacts
   for retrospective cross-fit and keep DEVELOPMENT outside the O1C-0019 gate.
2. After W52 clears, execute the frozen three-checkpoint, four-fold O1C-0019 config
   from a clean commit with zero new solver branches, entropy, sibling or GPU work.
3. Persist each fold's final reader/critics and every policy/raw trajectory before
   reconstructing that fold's key; report compression, IAUC, agency, stationarity,
   STOP/no-STOP and exact bounded-state/resource ledgers.
4. If the reader transfers and the learned route beats shifted/static/hash, freeze
   the architecture and attack one disjoint full-256 target. Do not tune on it.
5. If reader transfer fails, preserve the packet/state API and replace only the
   coarse branch feature stream with assumption-rooted carry/proof ancestry.
6. If routing alone fails, retain the reader and change only critic context,
   delayed credit or abstention. Do not conflate a picker failure with no signal.
7. After stable entropy reduction, add surprise-selected Causal Attic summaries,
   bounded beam concentration and exact ChaCha20 verification toward recovery.

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
