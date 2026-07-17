# O1-256 Living Inverse

Last updated: 2026-07-17T09:03:05+02:00 (`Europe/Berlin`).

## Moonshot contract

The attacked object is standard ChaCha20 with all 256 key bits unknown, twenty
rounds plus feed-forward, a public counter and nonce, and one or more public output
blocks.  The attack path receives exactly that public view.  It never receives an
internal state, carry, round trace, target-key prefix, reduced-width assignment or
target-derived solver trace.

Training may use known keys and privileged teacher labels.  The deployment API is
separate and smaller:

```text
public target (counter, nonce, output)
    + self-generated proposal K_t
    + ChaCha20(K_t) and trace(K_t)
    -> streamed contrast event
    -> O1-256 living state
    -> q(K_0..K_255 | public target)
    -> exact public ChaCha20 verification
```

Candidate traces are attacker-computable because the candidate key is chosen by
the attacker.  Target traces are teacher-only and cannot cross into the deployment
event schema.

The model is 256-bit from the first experiment.  Width-12 objects may be used as
internal interventions or randomized local operators, but never as a reduced-key
target or a staged claim that W12/W52 recovery equals the 256-bit task.

## Why contrast streaming is the scalable object

The living inverse does not store or rank `2^256` keys.  It generates a stream of
experiments around anchors proposed from the current posterior:

- one-bit and sparse flips;
- Gray-code walks and randomized coordinate windows;
- repeated-word and low-Kolmogorov-complexity anchors;
- posterior samples and uncertainty-directed flips;
- eventually fully uniform random keys.

For a known training target, the correction mask `K* xor K_t` and target round/carry
trace are labels.  For a sealed target, only public output residuals and the trace
of `K_t` exist.  A learned point reader converts each attacker-valid contrast into
signed bit evidence and a declared information mass.  O1 accumulates the evidence
without retaining the proposals.

## Living state

The first implemented causal-reader budget is fixed in stream length:

| State | Shape | Logical bytes | Role |
|---|---:|---:|---|
| Causal bitfield | unary + ARX + holographic banks | 17,408 | streamed paired-proof evidence |
| Bounded reader feature bank | `256 x 39 float32` | 39,936 | per-coordinate U3/ARX/motif reduction |
| Posterior logits | `256 float32` | 1,024 | current 256-bit posterior |

Implemented total: **58,368 live logical bytes**, independent of the number of
streamed contrasts. The 281,764-byte O1C-0013 primary reader is a separately billed
static model, not live state. The external `.causal` attic is disabled. If enabled
later, its retained bytes and growth are reported separately.

For a local assignment stream with score `ell(x)`, candidate rows are reduced
online:

```text
Z[e,j,x_j] <- logaddexp(Z[e,j,x_j], ell_e(x))
delta_j    <- PoE_e(Z[e,j,1] - Z[e,j,0])
M[i]       <- gamma[i] * M[i] + gate[i] * delta_j
```

The `4,096` local assignments are observations, never resident memory.  Randomized
global-to-local mappings prevent a solver-position artifact from being mistaken
for a global key coordinate.

## W52 mechanisms retained, not copied

The read-only 2026-07-17 intake from `arx-carry-leak` changes the architecture in
five concrete ways:

1. A447-A449 proof ancestry, conflict path and propagation depth become the primary
   causal sensor.  Clause-output provenance alone remains only a secondary feature.
2. H1/H2/H4/H8 become explicit GSSM timescales.
3. A460/A462/A463 supply complementary switching wavelengths `64/96/65`.
4. A465 supplies the backbone Product-of-Experts:
   `7*(rank64+1)^3 + (rank96+1)^3 + 4*(rank65+1)^3`.
5. A469 supplies a safe interaction rule: positive, bucket-local corrections only;
   preserve the backbone and use the identity branch everywhere else.

No W52 target order, key label, active progress file or 64 MiB pair permutation is
an input to the living inverse.  The scientific transfer is the event and update
mechanism.

## O1-O role

O1-O chooses the next attacker-valid intervention from
`(anchor, coordinate/orbit, contrast family, horizon, reader, phase)` using:

```text
ROI = uncertainty * expected_information_gain * expert_disagreement / work
```

Its failure memory is contextual.  A negative result suppresses the measured
combination, not an entire mechanism family.  Rare high-surprise motifs may later
enter the bounded external index; ordinary events disappear after updating state.

## Data lifecycle

1. Unlimited build stream with known keys and privileged teacher labels.
2. A disjoint known-key calibration split freezes readers, scales, selected bit
   coordinates, proposal policy and the primary arm.
3. Only after that persisted freeze does the full-256 broker create a secret
   uniform development panel.  The attack receives verified public views only.
4. Every factual/control posterior is stored in one immutable binary artifact
   before the broker reveals any key; the panel can be opened only once.
5. Shuffled-key, output-permutation, output-flip, wrong-nonce and candidate
   key/trace ablations run at declared matched work.
6. A later serious architecture freeze receives a new broker-random target; only
   after reveal may a completed challenge enter O1/O1-O failure memory.

The earlier W46 broker remains a tested historical artifact.  O1C-0009 uses a
separate full-256 broker whose publication contains only counter, nonce, standard
twenty-round output and a commitment; its reveal requires the exact frozen
prediction SHA-256.

## Progress vector

Full recovery remains terminal, but every freeze reports the complete vector:

- true-key cross-entropy/code length in bits; random baseline exactly `256`;
- calibrated predictable bits on uniform held-out keys;
- byte and 16-bit block rank;
- true full-key rank among at least one million matched decoys;
- effective compression `256 - key_nll_bits` with calibration stated;
- Hamming distance of posterior mode and best beam member;
- whether exact public verification appears in the generated beam;
- state bytes, index bytes, generated proposals, cipher calls and wall/CPU work.

One stable unseen bit is a structural result.  Eight independent transferable bits
are a factor-256 domain reduction.  Exact key verification is the terminal signal.

## Immediate experiment sequence

1. `O1C-0008`: implement the full-256 attacker/teacher boundary, structured and
   uniform contrast generator, trace instrumentation and all progress metrics.
2. `O1C-0009`: train direct, candidate-relative and teacher-distilled readers from
   512 known full-width keys, freeze on 64 calibration keys, then persist every
   prediction before revealing a 128-key broker-secret uniform panel.  Selection
   of bit coordinates is familywise and calibration-only.
3. `O1C-0010` (completed negative): prospectively tested the exact post-reveal
   signed-direct breadcrumb with no refit on 2,048 newly sealed uniform full-width
   keys. Direct compression was `-0.019088` bit and all efficacy controls failed,
   closing the raw end-output reader family.
4. `O1C-0011` (completed infrastructure validation): compiled the exact full-256
   public ChaCha20 CNF, 656 x 32 causal bit ranges and opposite-assumption
   instances; fixed-key SAT, flipped-output UNSAT and independent-vector SAT pass.
5. `O1C-0012` (completed mechanism): streamed all 512 paired branches into the
   17,408-byte causal bitfield; the imported fixed W52 orientation was negative.
6. `O1C-0013` (completed prospective seed): learned shared orientation from four
   BUILD/two CAL keys, froze h96, then obtained 259/512 bits and `+0.0889215`
   bit/key on two sealed targets; shuffled and three transformed controls were
   negative, but the panel is too small for a stable claim.
7. `O1C-0014` (completed negative validation): reloaded those exact reader bytes
   on eight new keys and obtained `+0.233784` bit/key with conditional `z=1.819`,
   but only `4/8` positive targets, paired `z=0.838`, mixed controls and zero exact
   keys; the predeclared class is `NOT_REPLICATED`.
8. `O1C-0015` (operational failure): completed the frozen 32-target computation
   but crossed its old resource ceilings after reveal before persisting truth. All
   targets are burned and no scientific metric exists.
9. `O1C-0016` (completed negative validation): repeated the identical science on
   32 entirely new keys under corrected accounting. The ensemble reaches
   `-0.078249` bit/key, only `11/32` targets positive, paired `z=-0.555` and zero
   exact keys. Exact h96/h65 are also negative; class
   `NOT_REPLICATED / DO_NOT_PROMOTE`.
10. `O1C-0017`: spend zero fresh sealed entropy. Cross-fit a bounded online
    nuisance projector, residual event encoder and O1-O learned sensing policy on
    self-generated known full-256 keys. Optimize unseen-key NLL and information
    gain per work, not fidelity to h96.
11. `O1C-0018`: only after O1C-0017 beats common-mode and norm/spectrum-matched
    coordinate-destroying controls, freeze the continuous fast/slow organism and
    attack entirely new sealed keys. The detailed design is in
    `docs/O1_ONLINE_MOBIUS_CONTROLLER.md`.
