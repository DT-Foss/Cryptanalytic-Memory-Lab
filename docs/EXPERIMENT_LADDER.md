# Experiment Ladder

Each stage isolates one uncertainty. A later stage starts only after the preceding
gate is reproducible across seeds and held-out data.

## Stage 0 — MQAR-256 closed-gate storage qualification

Input: 256 shuffled `(position, bit)` bindings, a length sweep of irrelevant tokens,
then shuffled queries.

Relevance is supplied by the harness: irrelevant tokens invoke an exact closed gate.
This stage measures storage/crosstalk after selection, not a learned selective GSSM
gate. A later Stage 0b must mix bindings and distractors in one token grammar and
learn the routing decision on disjoint lengths.

Arms:

- full-context attention: exact `O(T)` validity ceiling, never a bounded-state win;
- direct 256-register vault: exact-address ceiling;
- 128-complex-channel holographic state: equal scalar-cell count;
- 64-slot CountSketch: deliberate capacity/collision control.

Metrics: per-bit accuracy, exact-all-256 rate, state digest before/after haystack,
state cells, numeric precision and canonical serialized bytes. Haystack lengths replay the same
bindings and query order within a seed.

Pass meaning: the mechanism retains information. It says nothing about whether a
cipher makes key evidence observable.

## Stage 1 — weak-evidence integration

A fixed 256-dimensional log-odds state receives a nested stream of relations.
One relation contains 256 scalar evidence values; the result therefore reports both
relation vectors and total evidence scalars. At 1,024 relations the state consumes
262,144 scalar observations per seed.

Controls:

- independent evidence with 55% per-observation correctness;
- a matched no-signal stream at 50%;
- a 55% stream whose error orientation is perfectly correlated and merely repeated.

The first arm should improve with relation count, the no-signal arm should remain at
chance and the correlated arm should not gain new information through repetition.
This distinguishes accumulation from duplicate-confidence inflation.

## Stage 2 — O1-O session replay

The stored session `O1-O/2026-02-18_013412` is normalized offline into immutable
`EvidenceEvent` records. Task envelopes plus the hashed engagement summary validate
the combined event grammar, aggregate retry/recovery/chaining counts and a neutral,
bounded TargetModel ingestion over a real 16-task adaptive run before any
cryptanalytic data is used.

Gate:

- no generated program is imported or executed;
- raw output is omitted from events; its unsalted fingerprint is integrity metadata,
  not protection for low-entropy output;
- generation, process, capability and mission outcomes stay separate;
- repeated replay yields the same source and event hashes.

The historical schema records aggregate retry and chained-tool counts but no parent
task IDs. The adapter therefore does not invent edge-level ancestry; new runs should
store explicit `parent_task`, `retry_index` and `followup_reason` fields.

## Stage 3 — frozen recovery-artifact ingestion

The clean `fullround-key-recovery` snapshot is verified against
`provenance/ARTIFACTS.sha256` before any byte is read. A derived dataset records the
source commit, manifest hash, member hash and split assignment.

Only immutable public challenge material and explicitly attacker-computable solver
features may enter evaluation. Recovered keys and post-result ranks are audit-only
labels and cannot reach the discovery ledger.

## Stage 4 — intervention atlas on training keys

Instrumented training worlds may expose keys, carries, rounds and solver internals.
O1-O searches a finite typed registry for cheap transformations that predict a key-
bit intervention or distinguish factual from matched control trajectories.

Candidate families:

- carry propagation geometry;
- conflict/propagation deltas under `bit_i=0` versus `bit_i=1` assumptions;
- solver progress and learned-constraint signatures;
- cross-round phase consistency;
- execution-description and trajectory-compression proxies.

Operators are selected on training keys, calibrated on validation keys, frozen and
hashed. Test keys are never used by Failure-Memory or operator search.

## Stage 5 — public observability gate

The frozen operator receives only public relations and solver state that an attacker
can recompute from public equations under billed candidate assumptions.

Controls include:

- independent new random keys;
- matched ideal-PRF or random-permutation data where appropriate;
- shuffled key-bit labels;
- factual-versus-control symmetry;
- same compute and candidate budgets.

Any positive result first triggers a leakage audit. Only a result that survives that
audit becomes evidence for a cipher-level signal.

## Stage 6 — target-blind ordering

The O1 state emits a frozen bit belief or cell order. It may improve an existing
complete-domain or strict-subset search, but it cannot change the declared success
boundary after execution begins.

Report:

- target cell rank and gain bits;
- all solver/cipher calls used to build the order;
- complete state and index cost;
- matched control behavior;
- prospective freeze hash.

## Stage 7 — exact recovery

The normal full-round backend executes the frozen plan, reconstructs a complete key
and independently confirms the complete output. A memory or ranking win alone is
not key recovery.

The end-to-end result is retained only if it beats the declared baseline after all
training, operator-search, solver, storage and execution work is included.

## Immediate next experiment

The next safe real-data step is Stage 3: verify the clean 570-member publication
manifest, select a small frozen public/config/result fixture, and emit a provenance-
typed event dataset inside this lab. The active Threefish-1024 run remains entirely
outside this sequence until its own protocol has completed and published immutable
artifacts.
