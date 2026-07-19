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

## Matched science result

The paired experiment ran without adaptation:

1. **Baseline arm:** terminal O1C61 canonical shared-key multiblock CNF.
2. **APPLE-VIEW-0008 arm:** the byte-identical baseline body plus only these
   direct P20 units and cross-block ripple consequences.

Both arms consumed the same O1C57 public target, joint-score potential,
threshold, requested 512-conflict budget, native build, and verification logic.
Both were billed 513 conflicts. The result is
`APPLE_VIEW_0008_STRICT_INCREMENTAL_EFFECT_NO_RECOVERY`:

| quantity | O1C61 baseline | APPLE-VIEW-0008 | delta |
|---|---:|---:|---:|
| minimum safe upper bound | 24.7944466611 | 13.1979307788 | -11.5965158823 |
| safe trail-threshold prunes | 0 | 6 | +6 |
| decisions | 9,166 | 4,471 | -4,695 |
| propagations | 1,227,877 | 1,178,185 | -49,692 |

The augmented bound crossed below the frozen threshold `14.6061787979` while
the matched baseline remained above it. This is the first certified Full-256
trail pruning and actual search-branch removal in this line. It is not key
recovery: both arms ended `UNKNOWN`, no complete key was returned, and the
APPLE arm did not read the committed truth or reveal. The six emitted pruning
clauses are deep (`2,964..2,974` literals), so this is genuine trail exclusion,
not a complete-model-only rejection. Native context was 0.451725 s and
388,644,864 B peak RSS.

The immutable result is
[`apple_view_8_matched_result.json`](apple_view_8_matched_result.json), with its
capsule at
[`runs/20260719_095509_APPLE-VIEW-0008-MATCHED_crossblock-consequence-sieve-v1`](../../runs/20260719_095509_APPLE-VIEW-0008-MATCHED_crossblock-consequence-sieve-v1/RUN.md).

## 4K promotion boundary and next action

The frozen 4,096-conflict promotion is complete as an operational chain, not a
science result:

- O1C-0062 exposed an external-propagator callback/lifecycle failure after the
  single authorized native call.
- O1C-0063 repaired teardown and pending no-good backtracking. It remained in the
  real Full-256 path for `17.763142674 s`, then most likely reached its guarded
  `736 MiB` ceiling; the old wrapper discarded the exact cause.
- O1C-0064 kept the science unchanged, preserved the cause chain, and confirmed
  `watchdog_memory` after `29.804627625 s`: observed `1,040,285,696 B` against
  the guarded `1,040,187,392 B` threshold. It returned no native result/key and
  read no truth.

None is retried or interpreted as cryptanalytic evidence. A third pure RAM-cap
increase is not the next action.

APPLE-VIEW-0009 supplied the distinct exact width-6 mechanism. O1C-0065 has now
compiled grouping hash
`3da85bae132d829252a68f0e3fd99220ea7d1ef365042806af810ff02f75f636`
into the repaired native path and completed one matched requested 512/billed 513
call. Root UB falls `292.30611344510277→262.68644197084643`, minimum UB falls
`13.197930778790159→12.934208247009447`, and live cache falls
`60,456→23,080 B`; emitted cuts remain `6→6`, decisions `4,471→4,471`, and
propagations `1,178,185→1,178,185`. This is retained efficacy, not a strict gain,
and it is not retried or promoted directly to 4K.

The next action changes the execution shape: fixed short fresh solver episodes
with a bounded causal vault of canonical threshold-certified emitted clauses.
Every clause is valid across restarts only for the identically bound augmented
problem `CNF ∧ score_potential >= threshold`, not as a CNF-only consequence, so
the vault binds CNF/variable numbering, potential, grouping, score semantics and
threshold bits and rejects drift. Solver-local assignments, trail, group cache
and allocator state die after every episode. The first experiment uses a fixed
8×512 schedule; O1/O1-O adaptation waits for evidence that simple persistence
actually produces novel cumulative cuts.
