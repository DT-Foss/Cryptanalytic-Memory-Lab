# O1 Cryptanalytic Memory Lab

An isolated research harness for combining three already-existing systems without
changing any of them:

- the full-round recovery backend supplies immutable evidence and exact confirmation;
- O1 supplies bounded recurrent evidence accumulation;
- O1-O supplies deterministic operator composition and failure memory.

This directory is a sibling of the active repositories. It never writes into
`arx-carry-leak`, `f8-causal-cryptanalysis`, `fullround-key-recovery`, O1, or O1-O.
Published evidence is consumed only through SHA-256-verified, read-only adapters.

## What the first benchmark proves

The initial benchmark deliberately separates three questions that are easy to
confound:

1. **Closed-gate storage qualification.** Once relevance has already been decided,
   can a fixed state retain 256 binary bindings through a long haystack?
2. **Evidence amplification.** If each public observation already contains a weak,
   independent bit signal, does a streaming accumulator amplify it? Does the same
   apparent per-observation accuracy fail when errors are correlated?
3. **Information-flow safety.** Can a typed operator chain produce a frozen
   target-blind order while structurally rejecting any path that uses a revealed
   model or target secret?

It does **not** claim that a full-round cipher exposes such a signal. That is the
next and substantially harder observability gate.

The full-context attention arm is an explicitly invalid `O(T)` attack but an exact
harness ceiling. The direct 256-register vault is an intentionally honest bounded
baseline. It is constant in stream length, but it is a position-indexed register
bank and therefore does not
demonstrate holographic compression. The holographic arm receives the same number
of scalar cells (`128` complex channels = `256` real scalars), while the undersized
CountSketch arm is a capacity control. Precision and serialized byte size are still
reported separately before any efficiency claim; equal cell count is not equal
information budget.

The current haystack transition is an explicit ideal no-op for bounded arms. This
isolates storage capacity and holographic crosstalk; it does not claim to have
trained O1's selective input gate. Learned unified-token routing is the next memory
stage, not a hidden property of this smoke test.

## Run

The package has no runtime dependencies outside the Python standard library.

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/o1-crypto-lab benchmark \
  --config configs/quick.json \
  --output runs/quick.json
```

Inspect the operator compiler and its leakage rejection:

```bash
.venv/bin/o1-crypto-lab compose
.venv/bin/o1-crypto-lab boundary
```

Replay the supplied real O1-O session as normalized evidence without importing or
executing any generated program:

```bash
.venv/bin/o1-crypto-lab replay-o1o \
  --session ../O1-O/2026-02-18_013412 \
  --output runs/o1o-2026-02-18-replay.json \
  --include-events
```

The replay intentionally distinguishes generation success, process success,
capability evidence and mission progress. Raw stdout/stderr is never copied into
the O1 stream; only its length and an unsalted integrity fingerprint remain until a
domain-specific parser has validated its semantics. That fingerprint is not a
confidentiality guarantee for guessable output. `engagement_report.json` contributes
hashed aggregate retry/recovery/chaining counts, and every normalized event is fed
neutrally into a capped TargetModel without being mislabeled as research success.
The February format did not retain explicit retry-parent IDs, so the replay reports
aggregate topology rather than inventing edges.

Verify a published snapshot before an adapter reads it:

```bash
.venv/bin/o1-crypto-lab verify-source \
  --root ../fullround-key-recovery \
  --manifest ../fullround-key-recovery/provenance/ARTIFACTS.sha256 \
  --output runs/fullround-source-verification.json
```

## Integration contract

- No imports from the dirty live O1, O1-O, or `arx-carry-leak` trees.
- No writes outside this lab's `runs/` directory.
- No GPU/Metal use.
- No target label, recovered model, post-reveal rank, or target-internal state may
  flow into a `TARGET_BLIND_ORDER`.
- Training-time internal round states may teach an operator, but evaluation-time
  features must be public or recomputable from public equations under an explicitly
  billed candidate assumption.
- Every learned operator is selected on training/validation keys, frozen and hashed,
  then evaluated once on disjoint test keys with matched controls. The lifecycle is
  enforced as `DISCOVERY -> FROZEN -> TEST_CONSUMED -> AUDIT`; the exact proposal and
  plan hashes are bound at freeze time.
- State size, external-index growth, samples and total cipher/solver work are reported
  separately. `O(1)` always means constant in stream length unless another axis is
  named explicitly.

See [Architecture](docs/ARCHITECTURE.md),
[Experiment ladder](docs/EXPERIMENT_LADDER.md), and
[Scientific boundaries](docs/SCIENTIFIC_BOUNDARIES.md). The first reproducible
smoke-test measurements are recorded in [First results](docs/FIRST_RESULTS.md).

## Repository map

```text
configs/                 deterministic benchmark configurations
docs/                    architecture, gates and claim boundaries
src/o1_crypto_lab/       memory, composer, replay, TargetModel, adapters and CLI
tests/                   unit, leakage and reproducibility gates
runs/                    generated local results only
```

The design is derived from the Apache-2.0 O1 and O1-O projects. No source from
their offensive modules is executed or imported here; only the domain-agnostic
bounded-state, typed-composition, verification and failure-memory ideas are used.
