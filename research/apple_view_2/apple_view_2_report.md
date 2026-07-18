# Apple view 2: the free-carry quotient is empty at 20 rounds

## One different mechanism

This experiment does not iterate a key, score output Hamming distance, or use
the feed-forward fixed point tested in `research/apple_view/`.  It turns the
entire standard 20-round block into one exact linear system after lifting the
nonlinear carries.

For every 32-bit addition and bit position,

```text
z_i = x_i XOR y_i XOR c_i,       c_0 = 0.
```

Keep every real key bit, but temporarily regard each `c_1..c_31` as an
independent nuisance bit.  XOR and rotation then make the whole block affine:

```text
                             hidden carries c
                                    |
unknown key k ---> [full lifted ChaCha20 circuit] ---> public block b
                         b = A k XOR B c XOR d
                                    |
                              eliminate B
                                    v
                 H B = 0  =>  (H A) k = H (b XOR d)
```

The rank of `H A` is the exact number of independent linear key parities
exposed by this relaxation.  Real carries are never supplied to elimination;
they are used only afterward to validate that the lifted equations are exact.

## Attacker boundary and protocol

- Each attack gets constants, one counter, one 96-bit nonce, and one 512-bit
  output from RFC 8439 ChaCha20 with all 20 rounds.  It never combines blocks.
- All 256 key bits are unknown.  `extract_key_information(target, carry_mode,
  meter)` has no truth-key or intermediate-value parameter.
- Eight cases come from the fixed public seed
  `apple-view-2-carry-quotient-v1-20260719`.  Keys are deliberately unsealed in
  the JSON for audit, but enter only post-extraction scoring.
- There is no fitting, target-specific tuning, key enumeration, reduced-round
  claim, network access, GPU, or MPS.
- The continuation gate was frozen as exact key rank at least 1 on every target
  with every emitted relation passing post-attack truth validation.

Matched arms use the same full-round target and circuit schedule:

1. Primary: exact `c_0=0`, with `c_1..c_31` free.
2. Null control: make all 32 sum-bit corrections free.  This is a looser exact
   relaxation and should expose nothing.
3. Optimistic control: force every carry to zero.  This is a deliberately
   non-exact XOR surrogate; it checks that apparent rank is rejected when the
   equations are inconsistent or fail truth scoring.

## Reference result

| Arm, eight independent one-block targets | carry rank | exact key rank | exact key bits | verified full keys |
|---|---:|---:|---:|---:|
| Primary, `c0` fixed and other carries free | 512 | 0 | 0 | 0 |
| All 32 sum bits free control | 512 | 0 | 0 | 0 |
| No-carry XOR control (non-exact) | 0 | apparent 256 | 0 | 0 |

The primary carry columns span all 512 public equations on every target, so
the left nullspace is empty: there is no key parity to rank, no exact bit to
recover, and no candidate key to verify.  The gate failed.

The controls behaved sharply.  Concrete key-and-carry assignments satisfied
all 4,096/4,096 lifted primary equations and all 4,096/4,096 looser-null
equations.  Removing carries manufactured rank 256, but all eight resulting
systems were inconsistent; its raw equations agreed with truth only
2,045/4,096 times (0.49927), and its 2,048 unit-bit suggestions got 1,028 bits
right.  Those are invalid, random-scale suggestions, not partial recovery.
The synthetic eliminator test separately exposes a known one-bit key parity,
so the zero primary result is not an implementation that always returns zero.

The structural profile is stronger than the aggregate rank: final
feed-forward carries alone span 496 output dimensions, while the carries from
each individual ChaCha double-round span all 512 dimensions after propagation
to the output.  Thus exact-modeling only a suffix while leaving any complete
double-round's carries independent cannot rescue this quotient.

## Resource ledger and reproduction

Reference command, from this directory:

```text
python3 -m unittest -v apple_view_2_test_carry_quotient.py
python3 apple_view_2_carry_quotient.py --output apple_view_2_result.json
```

Ten tests passed.  The reference experiment used one CPU process, 24 symbolic
full-block circuits, 8,064 symbolic word additions, 169,344 lifted carry
variables, 12,288 output equations, 5,612,256 GF(2) row XORs, and 16 concrete
full-circuit carry validations.  It consumed 5.78855 CPU seconds, 5.851181 wall
seconds, 34,553,856 bytes maximum RSS, and 2,562,508 bytes peak traced Python
allocation—below the 30 CPU-second and 128 MiB limits.  Exact target records,
per-arm measurements, platform data, and timing are in
`apple_view_2_result.json`.

## Interpretation and next discriminating step

Close only this mechanism: **independently freeing all non-LSB addition carries
destroys every output constraint at full 20 rounds.**  This says nothing about
the information in the real, correlated carry recurrences and is not evidence
that inversion itself is impossible.

The next clean test is global carry-depth lifting: substitute the exact
majority recurrence for `c_1` in all 336 additions, then `c_2`, and continue one
depth at a time while measuring exact Boolean domain pruning of key bits.  It
must act globally; the stage profile proves that leaving even one whole
double-round free retains a 512-dimensional nuisance mask.  Do not spend more
budget on independent-carry elimination.
