# O1 Cryptanalytic Memory Lab

An isolated research harness for combining three already-existing systems without
changing any of them:

- the full-round recovery backend supplies immutable evidence and exact confirmation;
- O1 supplies bounded recurrent evidence accumulation;
- O1-O supplies deterministic operator composition and failure memory.

This directory is a sibling of the active repositories. It never writes into
`arx-carry-leak`, `f8-causal-cryptanalysis`, `fullround-key-recovery`, O1, or O1-O.
Published evidence is consumed only through SHA-256-verified, read-only adapters.

The live research cockpit is [STATUS.md](STATUS.md). It points to the last immutable
run, the strongest supported claim, active uncertainty and the ranked next action.
Historical outcomes—including negative mechanisms—are indexed in
[RESULTS_INDEX.md](RESULTS_INDEX.md) and the append-only files under `research/`.

## Active Moonshot: O1-256 Living Inverse

The active target is no longer a progressively wider residual-key benchmark.  Every
serious target is standard twenty-round ChaCha20 plus feed-forward with **all 256
key bits unknown**.  Deployment sees only public counter, nonce and output.  It may
also evaluate keys it generated itself and inspect those candidate traces; target
round states, carry paths and key labels are training-only.

The system streams structured and uniform Contrast-Keys into a bounded O1 state,
binds bit coordinates and operator families holographically, composes complementary
wavelength readers with an A465-style Product-of-Experts, applies only A469-style
positive bucket-local corrections, and emits `q(K_0..K_255 | Y)` plus a bounded
verification beam.  It reports key NLL from the exact 256-bit random baseline,
predictable bits, byte/16-bit ranks, million-decoy full-key rank, effective domain
compression and exact public verification.

The complete attacker contract and architecture are in
[O1-256 Living Inverse](docs/O1_256_LIVING_INVERSE.md).  The W52 mechanisms were
inspected read-only and are summarized in
[the 2026-07-17 transfer map](research/W52_TRANSFER_20260717.md).

The strongest immutable scientific result remains O1C-0014. It reloaded
O1C-0013's exact h96 reader bytes without refit or rescaling and attacked eight new
OS-random sealed keys using only public counter/nonce/output. It obtained
`1053/2048` bits and `+0.233784` bit/key aggregate compression (`z=1.819`) while
its shuffled reader obtained `-1.290981` bit/key. The preregistered result is
nevertheless `NOT_REPLICATED`: only `4/8` targets were positive, the paired
control comparison was `z=0.838`, the three public-evidence controls were mixed,
and no exact key was emitted.

That negative classification is retained together with its mechanism breadcrumb.
All three pre-existing unary proof horizons remain aggregate-positive, while the
richer coarse ARX24/Motif12 readers turn negative. O1C-0015 ran the exact h96 plus
equal-logit h96+h65 successor on 32 new targets, but exceeded its CPU, wall and RSS
ceilings after all 32 targets had been revealed in process memory. Because no
reveal/evaluation artifacts survived, it is an immutable operational failure, not
a scientific result; all 32 targets are burned and will never be replayed.

O1C-0016 is the clean successor at implementation commit
`4f4c5280ecf876083222138db4cb55dae9e2dfca`. It keeps the scientific mechanism,
readers, controls, 17,920 branches and 32-target contract unchanged, uses 32
entirely new keys, raises only the soft ceilings to 3,000 CPU-s, 3,000 wall-s and
768 MiB RSS, and fixes pre-reveal resource accounting plus terminal truth
persistence. Canonical v2 config SHA-256:
`054e8b05c7824cf4c47f509d6a4977e3feac7e5df5ce006f55948b93554daaa6`.
No O1C-0016 entropy has been drawn. Only after O1C-0016, O1C-0017 will test adaptive
h65-all/top32-h96 live-causal deepening; the deterministic work model predicts `19.79%`
requested conflict-work saving.

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

The package pins NumPy `2.2.6` because exact reproduction of the historical
Direct12 floating-point reader is part of the evidence contract; the remaining
harness uses the Python standard library.

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/o1-crypto-lab benchmark \
  --config configs/quick.json \
  --output runs/quick.json
.venv/bin/o1-crypto-lab living-inverse-foundation \
  --config configs/living_inverse_foundation_v1.json
.venv/bin/o1-crypto-lab full256-paired-sensor \
  --config configs/full256_paired_causal_sensor_v1.json
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

Run the manifest-pinned Stage-3 ingestion and frozen retrospective reader protocol:

```bash
.venv/bin/o1-crypto-lab stage3-ingest \
  --config configs/stage3_a296_a297_ingest_v1.json
.venv/bin/o1-crypto-lab stage3-reader \
  --config configs/stage3_reader_retrospective_v1.json
```

Each command creates a new read-only directory named
`runs/YYYYMMDD_HHMMSS_O1C-.../` with `RUN.md`, exact config and command,
environment, metrics, logs, checkpoints, retained artifacts and a complete
SHA-256 manifest. Attempt IDs are permanently reserved and cannot overwrite a
prior result. Verify any capsule with:

```bash
.venv/bin/o1-crypto-lab verify-run runs/<capsule-name>
```

The Direct12 dependency chain originally lived in a dirty sibling worktree. It is
therefore curated honestly into its own immutable capsule instead of being called
a clean Fullround-manifest artifact:

```bash
.venv/bin/o1-crypto-lab direct12-snapshot \
  --config configs/direct12_source_snapshot_v1.json
```

Reproduce the frozen 133-to-532 trajectory reader from that capsule, then run
the bounded-memory mechanism tournament:

```bash
.venv/bin/o1-crypto-lab direct12-reproduce \
  --config configs/direct12_reproduction_v1.json
.venv/bin/o1-crypto-lab bounded-memory-tournament \
  --config configs/bounded_memory_tournament_v1.json
.venv/bin/o1-crypto-lab corrected-codec-bridge \
  --config configs/corrected_codec_bridge_v1.json
.venv/bin/o1-crypto-lab upstream-ising-freeze \
  --config configs/upstream_ising_retrospective_v1.json
```

The tournament compares global Walsh state, sixteen fixed low4/high8 slot banks,
and a dense 2–8-bit integer Bit-Vault. O1-O sees only A348 target-blind fidelity,
serialized online-state bytes, update work and clip counts. It persists one future
template before the A349 score member is opened; all complete A349 orders are then
persisted before the separate A348 truth API is called. Direct candidate tables and
full spectral banks remain clearly labeled ceilings and cannot win the mechanism
gate. The dense Bit-Vault is a full-rank 4,080-register mechanism, not a claim of
sublinear capacity.

The corrected-codec bridge reproduces A355/A356 exactly and retains the selected
6-bit DC-complete bank only as a validation ceiling. Its 4,096 spectral degrees of
freedom are information-equivalent to the fixed candidate table, and its 8,014-byte
maximum serialized logical state is larger than the matched 3,918-byte direct
baseline.

The upstream freeze replaced the dense final-field representation with a
12-register unary solver-evidence memory. Its conservative logical-state bound is
266 bytes and its frozen binary is 162 bytes. The complete target-blind A355 panel
contained 672 orders; the frozen decoder ranked the retrospective target at 73,
but the exact conditional random-label tail was `2431/4096 = 0.593505859375`.
That is a structurally eligible compact mechanism and a negative efficacy result,
not SOTA. The same decoder emitted a complete A356 order before any A356 target or
outcome read, but A356 still came from the same opened source capsule and is not a
source-unseen holdout.  That planned narrow W46 follow-up is now superseded.
O1C-0008 instead freezes the full-256 public-output attacker type, separately typed
teacher labels, exact traced relation generator, six Contrast-Key families, sealed
full-256 broker and the complete non-recovery progress vector.  The unary decoder
remains one matched baseline inside the new architecture.

The expensive immutable-snapshot integration gates are opt-in:

```bash
O1_CRYPTO_DIRECT12_REAL=1 \
  .venv/bin/python -m unittest discover -s tests -v
O1_CRYPTO_CORRECTED_REAL=1 \
  .venv/bin/python -m unittest discover -s tests -v
O1_CRYPTO_UPSTREAM_REAL=1 \
  .venv/bin/python -m unittest discover -s tests -v
```

## Integration contract

- No imports from the dirty live O1, O1-O, or `arx-carry-leak` trees.
- Runtime experiment bytes are confined to `runs/`. A separate symlink-safe writer
  may update only the seven enumerated cockpit Markdown files at the lab root and
  under `research/`; it cannot write arbitrary lab or sibling paths.
- CPU-only by default. MPS/GPU use requires a short explicit resource-checked window
  and cannot compete with the active sibling recovery queue.
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
[O1-256 Living Inverse](docs/O1_256_LIVING_INVERSE.md),
[Experiment ladder](docs/EXPERIMENT_LADDER.md), and
[Scientific boundaries](docs/SCIENTIFIC_BOUNDARIES.md). The first reproducible
smoke-test measurements are recorded in [First results](docs/FIRST_RESULTS.md).

## Repository map

```text
configs/                 deterministic benchmark configurations
docs/                    architecture, gates and claim boundaries
provenance/              lab-owned byte ledgers and source-boundary records
research/                hypotheses, append-only attempts, breadcrumbs, next actions
src/o1_crypto_lab/       memory, composer, replay, TargetModel, adapters and CLI
tests/                   unit, leakage and reproducibility gates
runs/                    immutable timestamped capsules (ignored by Git, never overwritten)
```

The design is derived from the Apache-2.0 O1 and O1-O projects. No source from
their offensive modules is executed or imported here; only the domain-agnostic
bounded-state, typed-composition, verification and failure-memory ideas are used.
