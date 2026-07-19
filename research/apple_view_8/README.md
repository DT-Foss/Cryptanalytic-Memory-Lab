# APPLE-VIEW-0008 — cross-block consequences

This isolated build path turns one simple property of contiguous ChaCha20
blocks into clauses the solver can consume immediately.

For output word `Y`, final pre-feedforward word `P`, and initial word `X`,
ChaCha20 has

```text
Y = P + X  (mod 2^32).
```

That gives two public consequences:

- On lanes `0..3` and `12..15`, `X` is public, so every bit of
  `P = Y - X (mod 2^32)` can be added as a direct internal-wire unit.
- On key lanes `4..11`, every block uses the same unknown key word.  Eliminating
  it between block `b` and block `0` gives
  `P_b = P_0 + (Y_b - Y_0) (mod 2^32)`.

These clauses are redundant with the exact full-round relation; their purpose
is to expose short propagation paths instead of asking CDCL to rediscover the
same consequences through long resolution chains.  They reveal no key bit and
contain no target trace or truth assignment.

## Contents

- `apple_view_8_crossblock_consequences.py` reconstructs the sixteen final P20
  words from the canonical 656-operation semantic map, compiles the public
  consequences, atomically appends them to a verified shared-key multiblock
  CNF, writes a strict hash-bound report, and verifies every output byte by
  recomputation.
- `apple_view_8_test_crossblock_consequences.py` proves final-wire
  reconstruction, exhaustively checks the real constant-adder encoder at four
  bits, checks known-key forward assignments at 1/2/8 blocks, and covers exact
  counts, tampering, report forgery, path collision, and immutable no-overwrite.
- `preflight_o1c57_consumed_public_build(...)` is a read-only build preflight.
  It consumes only O1C57's manifest, config, sealed public publication, and
  frozen Full256 template/map.  It does not open the reveal/result, generate a
  target, write a large CNF, or call a solver.

The specialized ripple adder retains one fresh constrained carry per result
bit, including the final overflow carry.  A 32-bit relation uses exactly 32 new
variables and `220 + (delta & 1)` clauses.  Its modulo-`2^32` result is exact;
retaining overflow only makes the internal encoding explicit.

## Frozen O1C57 build preflight

For the consumed eight-block O1C57 public view, the pure preflight reports:

| quantity | exact count |
|---|---:|
| canonical shared-key base variables | 255,232 |
| canonical shared-key base clauses | 1,504,080 |
| direct public P20 units | 2,048 |
| cross-block key-lane relations | 56 |
| fresh retained carry variables | 1,792 |
| ripple clauses | 12,344 |
| total added clauses | 14,392 |
| consequence-CNF variables | 257,024 |
| consequence-CNF clauses | 1,518,472 |

The 56 public deltas contain 24 odd values, hence
`56 * 220 + 24 = 12,344` ripple clauses.  This is a build result, not a solver
or recovery result.

## Reproduce the build tests

From the lab root:

```text
nice -n 10 env PYTHONPATH=src:research/apple_view_8 \
  python3 -m unittest -v \
  research/apple_view_8/apple_view_8_test_crossblock_consequences.py

python3 -m ruff check research/apple_view_8
```

The test suite writes only temporary files.  It never mutates the frozen O1C57
capsule or the Full256 foundation capsule.

## Prospective matched science

The next experiment is deliberately paired, not adaptive:

1. **Baseline arm:** canonical O1C59 shared-key multiblock CNF.
2. **APPLE-VIEW-0008 arm:** the byte-identical baseline body plus only these
   direct P20 units and cross-block ripple consequences.

Both arms must consume the same O1C57 public target, joint-score potential,
threshold, conflict budget, wall/RSS limits, native build, and verification
logic.  Each arm gets exactly one solver call.  There is no fresh target and no
parameter tuning between arms.

Report SAT only after extracting the complete key and verifying all eight
ChaCha20 blocks directly.  Otherwise compare early exact score-prune counts,
first-prune conflict position, potential-bound drop, maximum assigned key bits,
maximum assigned consequence/internal bits, and final assigned progress.  The
matched run can establish whether these logically redundant public clauses
actually shorten the live search path; this build alone makes no such claim.
