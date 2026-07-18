# O1C-0030 — Incremental diagonal frontier lamp

- **Frozen:** `2026-07-18T13:23:56+02:00` (`Europe/Berlin`)
- **Claim:** `RETROSPECTIVE_MECHANISM`
- **Input:** exactly four consumed O1C-0018 BUILD action pools
- **Machine path:** CPU/NumPy only; zero solver, target generation, entropy, sibling,
  MPS or GPU work

## Question

Does the first-encounter innovation on a key coordinate's own proof-ancestry
channel carry portable branch orientation, and can a public, polarity-even exact
conflict frontier amplify it without repeatedly counting cumulative evidence?

This is the smallest real-artifact version of the streaming lamp hypothesis.  A
coordinate always retains its cumulative signal.  A one-sided exact-cutoff event
may make one chronological increment brighter, but no coordinate is assigned
zero probability or removed from the stream.

## Frozen observation

The immutable FAP horizon order is `(64, 96, 65)` and is first transposed to the
chronological order `(64, 65, 96)`.  For episode `f`, coordinate `i`, horizon
`h`, branch `p`, and self-ancestry column `74+i`, define

```text
psi(x) = x / (1 + abs(x))
a[h,i] = (psi(F[h,i,1,74+i]) - psi(F[h,i,0,74+i])) / 2
e[h,i] = (psi(F[h,i,1,74+i]) + psi(F[h,i,0,74+i])) / 2
q[h,i] = XOR(F[h,i,1,9], F[h,i,0,9])
d_odd[i]  = (a[64,i], a[65,i]-a[64,i], a[96,i]-a[65,i])
d_even[i] = (e[64,i], e[65,i]-e[64,i], e[96,i]-e[65,i])
```

`q` is public and invariant under a complete branch swap.  The five frozen arms
are

```text
primary                = sum_h (1 + q[h,i]) * d_odd[h,i]
cumulative_replace     = a[96,i]
legacy_reintegrated    = a[64,i] + a[65,i] + a[96,i]
deranged_confidence    = sum_h (1 + q[h,pi(i)]) * d_odd[h,i]
polarity_even_common   = sum_h (1 + q[h,i]) * d_even[h,i]
```

`pi` is one fixed-point-free SHA-256-derived permutation of all 256 coordinate
identities, frozen without labels.  With every `q=0`, `primary` telescopes
exactly to `cumulative_replace`.  A complete branch swap negates the first four
odd observations exactly and leaves `q` and the even control unchanged.

## Retrospective protocol

The source is the finalized O1C-0018 capsule with manifest
`fcbf43c99994c0debe5b39bb3e734ea1d1e23ba58e89b10ff2bb7e23886493fb`.
Only `build-0000..0003.fap` are admissible; DEVELOPMENT pools are forbidden.

1. Verify the complete source capsule and every pinned BUILD member.
2. Deserialize all four FAPs with the lightweight NumPy ABI.  Freeze every arm,
   structural gate and feature hash before deriving any BUILD label.
3. Reconstruct the historically consumed BUILD labels from corpus seed
   `180018180018`; verify each key and public-view commitment against O1C-0018.
4. For each arm and each outer fold, divide by the training-only RMS and fit one
   no-intercept scalar L2 logistic reader on the other `3 x 256` observations.
   The mean-loss regularizer is fixed at `1/768 = 0.0013020833333333333`, which
   is a unit L2 penalty in the equivalent summed-loss objective.  The held-out
   feature sets neither scale nor coefficient and its label is excluded from
   the fit.  Freeze all 20 readers and all `20 x 256` logits before scoring.
5. Report per-fold and aggregate NLL, compression, correct bits, byte rank,
   16-bit rank and primary-minus-control margins.  After prediction freeze,
   stream the exact native-logit global top-65,536 frontier for each primary
   posterior and record exact-hit/best-Hamming diagnostics.

This is BUILD-LOO architecture selection over previously consumed targets, not
a fresh or prospective ChaCha20 result.  It neither executes nor changes the
frozen O1C-0019/O1C-0022 chain and cannot authorize O1C-0026 or O1C-0029.

## Decision

The strong mechanism gate is precommitted as:

- positive primary compression in `4/4` folds;
- mean primary compression at least `+0.25` bit per 256-bit key;
- primary beats `cumulative_replace` in `4/4` folds;
- mean primary-minus-cumulative margin at least `+0.10` bit per key; and
- mean primary compression exceeds every deranged, legacy and even control.

Passing names a precise sensor upgrade: preserve chronological self-ancestry
innovations and attach exact-cutoff asymmetry as an even confidence gate.  A
null closes only this summarized diagonal-frontier amplifier.  It does not close
raw antecedent identity, signed interaction pairs, the learned O1 reader or the
future live O1-O scout-to-focus loop.

## Architectural continuation

After O1C-0019 has produced authoritative packet deltas, the direct O1/O1-O
integration test is a bounded `scout -> focus` replay: stream H64 for all 256
coordinates, assign every possible deepening a strictly positive priority
`epsilon + softplus(delta-NLL/work + surprise + uncertainty + age)`, consume the
selected H65/H96 packet, update O1 state and rank again.  Comparing that live
re-score against the identical frozen one-shot ranking distinguishes genuine
online adaptation from a static priority list.  O1C-0030 supplies a cheap real
sensor discriminator while that authoritative packet stream remains gated by
the active W52 run.
