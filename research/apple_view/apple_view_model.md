# Apple view: frozen physical model of full-256 ChaCha20 inversion

Frozen before reading `GOAL.md`, `HYPOTHESES.md`, `ATTEMPT_LOG.md`, or any
project-specific attack taxonomy.  This document intentionally starts from the
standard ChaCha20 block construction only.

## The machine I picture

Picture sixteen 32-bit mechanical odometers in a 4 by 4 tray.  Four odometers
start at public engraved constants, eight are hidden key dials, and four are
public counter/nonce dials.  A quarter-round is a rigid linkage that repeatedly:

1. adds one odometer into another (including physical carry cascades),
2. toggles teeth according to XOR, and
3. rotates the whole 32-tooth ring.

Twenty rounds alternately connect columns and diagonals.  At the end, each
odometer is added to a photographed copy of its own starting value.  The public
64-byte block is the final tray.  Only the eight starting key dials are hidden.

In symbols, with public constants/counter/nonce fixed and key `k` occupying
state words 4..11,

```
s(k) = constants || k || counter || nonce
y    = P20(s(k)) + s(k)                 (wordwise modulo 2^32)
```

The exact task is to find all 256 bits of `k` from one public `(counter, nonce,
y)` tuple.  A proposed key counts only if an independent standard ChaCha20
block evaluation reproduces every one of the 512 output bits.

## What the picture says before any project-specific expertise

The final self-addition gives eight unusually simple equations at the key
positions:

```
k[j] = y[4+j] - P20(s(k))[4+j] mod 2^32,  j = 0..7.
```

This does not make the equations easy: the right-hand side still depends on
all 256 key bits after the mixing machine.  But it suggests a cheap physical
operation: set all eight hidden dials to a guess, run the linkage without the
last self-addition, subtract the resulting internal key-row odometers from the
photographed output, and use those eight differences as the next dial setting.

Define the full-width projection

```
F_y(k)[j] = y[4+j] - P20(s(k))[4+j] mod 2^32.
```

The true key is a fixed point of `F_y`.  Every update always changes (or keeps)
all 256 candidate bits; no key prefix, reduced keyspace, leaked key bit, or
sealed oracle is used.

## Cheap hypothesis H-Apple-1

Despite 20-round diffusion, the explicit self-addition may leave a small local
attraction or bitwise alignment in `F_y`: starting from an unrelated 256-bit
key, either `F_y(k)` itself, a partial XOR step toward it, or selecting between
`k` and `F_y(k)` by full-block Hamming mismatch may reduce expected Hamming
distance to the hidden key by a reproducible amount above the random baseline.

This is falsifiable without claiming recovery:

- generate deterministic ordinary ChaCha20 targets and then hide their entire
  256-bit keys from the search procedure;
- compare input and projected key distance over many independent targets and
  starts;
- measure per-bit correctness, transition correlation, output-mismatch change,
  exact standard-block verification, time, and peak memory;
- additionally iterate the best cheap update under a fixed, small evaluation
  budget to see whether any one target reaches exact recovery.

Null expectation for an ideal-looking 20-round map: projected keys are
independent uniform 256-bit values, about 128 key bits match by chance, update
improvement is symmetric, and exact recovery never occurs at this scale.  A
direction is worth continuing only if a holdout run shows a statistically and
practically meaningful transferable advantage (not merely one lucky target).
