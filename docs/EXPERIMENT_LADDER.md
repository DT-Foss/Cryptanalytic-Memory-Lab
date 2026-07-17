# O1-256 Living Inverse Experiment Ladder

Every attacked target in this ladder has all 256 ChaCha20 key bits unknown.  A
12-bit window is an internal contrast/proof operator, never a reduced-key target.
The earlier MQAR, Direct12 and bounded-memory stages remain in immutable O1C-0000
through O1C-0007 capsules and are prerequisites, not the current width ladder.

## L0 — Full-width attacker and teacher boundary (`O1C-0008`)

Build exact twenty-round ChaCha20 plus feed-forward with two disjoint types:

- deployment: public counter, nonce and output plus self-generated candidate key,
  output and trace;
- teacher: known target key, target round/carry trace and correction labels.

Generate six proposal families: single-bit, Gray-window, repeated-word,
low-complexity, posterior sample and uniform random.  Register shuffled-key,
one-bit-output and wrong-nonce controls.

Gate:

- public target declares 256 unknown bits;
- target key/trace fields cannot be represented by deployment;
- RFC vector and full trace agree exactly;
- random posterior NLL is exactly 256 bits;
- byte/16-bit rank, decoy rank and beam harness pass an oracle ceiling;
- no sibling read, fresh target, GPU or MPS work.

## L1 — First full-width inverse readers (`O1C-0009`)

Train three equal-data CPU arms on 256 structured plus 256 uniform known 256-bit
keys:

1. direct public-output student;
2. candidate-relative target/candidate residual reader;
3. identical deployment reader with privileged round/carry auxiliary losses.

Structured contrasts form a curriculum, but the held-out distribution is always
uniform random full-width keys.  Freeze all readers, calibration scales, proposal
policy, primary arm and any claim-relevant bit coordinates on 64 known calibration
keys.  Only then create the 128-key broker-secret development panel.  Persist all
factual and control posteriors before one reveal.  Report total NLL, per-bit
calibration, familywise transferable-bit count and the complete control vector.  A
negative result is split by output word, key orbit, round-teacher task, proposal
distance and feature family.

Gate to L2: a repeated development gain in key code length or a stable bit that is
not present in shuffled-key/output-flip/wrong-nonce controls.  If no arm passes,
retain the best observability map and change the reader mechanism without changing
the target distribution.

## L1b — Signed direct no-refit replication (`O1C-0010`)

Copy the exact O1C-0009 direct and shuffled model bytes, freeze the two exploratory
negative scales and all gates before creating 2,048 new broker-secret uniform keys.
Persist direct, shuffled, output-permutation, output-flip, wrong-nonce and reverse-
polarity posteriors before a single reveal.  Require absolute code-length gain,
conditional uniform-key alignment and independent-target lower bounds; a clean
negative result still closes the breadcrumb and feeds the causal build.

Result: completed negative on 2,048 new keys. Direct compression `-0.019088` bit,
conditional `z=-0.946`, shuffled margin `-0.017541` and output-permutation margin
`+0.000962`; every efficacy gate failed. This layer is now a frozen negative
sentinel, not an active model-scaling branch.

## L2 — O1 Causal Bitfield Crystallizer (`O1C-0011`)

Stream L1 event logits through the fixed initial state:

- 256 `{logit, precision, age}` vault entries;
- H1/H2/H4/H8 GSSM timescales;
- eight 256-slot complex holographic banks;
- switching wavelengths 64/96/65;
- A465 cubic Product-of-Experts backbone;
- A469 positive bucket-local residual with an exact identity branch.

The initial living plus scratch/scorer budget is 20,492 logical bytes, invariant in
the number of contrasts.  Every candidate event is discarded after its update.  The
external attic is disabled.

Gate: the streamed state matches batch reduction, stays flat in stream length and
improves minimum held-out bit/block metrics over the strongest L1 arm at matched
cipher calls.

## L3 — O1-O adaptive proposal organism

Select the next `(anchor, orbit, contrast family, horizon, reader, phase)` by

```text
uncertainty * expected information gain * expert disagreement / work
```

Failure memory is contextual; it suppresses only the measured dead combination.
Compare against fixed round-robin and uniform proposal schedules at equal cipher
calls.  Only high-surprise compact motifs may enter a separately billed capped
causal attic.

Gate: better held-out entropy reduction per cipher call without state/index budget
escape.

## L4 — Sealed full-256 development attack

After the L1 secret-panel result has selected a complete architecture, persist its
model hash, O1 state plan, proposal scheduler, work budget, controls and complete
output posterior.  Generate a new uniform 256-bit key through a new one-shot
full-256 broker.  Attack receives only its public relation.  This is distinct from
the sealed L1 panel used to measure generalization.

Report:

- key NLL and `256 - NLL` effective compression;
- calibrated stable bits;
- byte/16-bit ranks;
- true-key rank among at least one million decoys;
- posterior-mode and best-beam Hamming distance;
- exact key in beam and public verification;
- state, attic and complete work accounting.

After reveal, the challenge may enter the O1/O1-O learning attic.  It cannot alter
its own result.

## L5 — Living challenge sequence

Repeat L4 with a new sealed random target.  Challenge `n` may teach mechanisms used
on `n+1`, never itself.  Promote the result when entropy removal and stable bits
replicate across target sequences and controls.

## L6 — Exact recovery frontier

Use the factorized/interaction posterior to generate a bounded uncertainty beam.
Every member is checked by exact standard ChaCha20.  Terminal success is the full
256-bit key in the beam with independent public-relation confirmation and a
material total-work advantage over the declared baseline.

## Resource rule

The active sibling W52 recovery queue has priority.  L0 and small L1 diagnostics are
CPU-only.  MPS/GPU training requires a short explicit window after checking memory
pressure and active workers; no large proof-corpus copy or concurrent accelerator
job is allowed while recovery is active.
