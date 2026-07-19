# O1C-0048 — Soft pair-envelope search

- Recorded: `2026-07-19T01:46:25+02:00`
- Classification: `PAIR_ENVELOPE_NO_STRICT_PRIMARY_GAIN`
- Frozen gate: **failed**
- Source commit: `72d7a9b14cba31bc7033490994c8da1580d6a027`
- Capsule: `runs/20260719_014625_O1C-0048_pair-envelope-search-v1`

## Question

Can O1C-0047's complete-state rank signal survive live exact search when the
unchanged potential chooses coordinated key pairs through a reversible global
max-envelope, rather than collapsing each factor to a one-variable marginal?

The primary pair plan was compiled once before reveal from the public field and
unchanged primary potential. It contains 63 disjoint pairs over 126 key
coordinates: 41 genuine interaction pairs and 22 deterministic support-order
fillers. Key rotation maps the same plan by `v -> 1 + v % 256`; clause rotation
uses the identical pair plan. Every scored arm observes all potential variables,
adds no clauses or implications, and can be repaired by normal CDCL backtracking.

## Frozen result

All four attacker-valid Full-256 calls remained unresolved at 512 requested
conflicts. The public CNF contained zero key units and zero assumption units, and
all four calls completed before the reveal or either consumed-result file was
read.

| Residual width | Internal | Primary | Key rotation | Clause rotation |
|---:|---:|---:|---:|---:|
| 8 | SAT / 217 | **SAT / 75** | SAT / 195 | SAT / 89 |
| 9 | UNKNOWN / 512 | **SAT / 155** | SAT / 331 | SAT / 167 |

Every SAT row reconstructed the exact revealed 256-bit key, honored every
truth-fixed complement bit, and independently verified the public ChaCha20
block. Maximum exact widths are therefore internal `8`, primary `9`, key
rotation `9`, and clause rotation `9`.

The precommitted global gate compares conflicts only at a width recovered by
every arm. That shared width is 8, but the arm frontiers are not tied because
internal search stops there while all potential arms reach 9. The conflict tier
is consequently blocked and the formal gate remains negative. Full-256 recovery
is `0/4`.

## What changed mechanically

The negative gate does not make the measured work pattern zero:

- At width 8, primary uses 65.44% fewer conflicts than internal, 61.54% fewer
  than key rotation, and 15.73% fewer than clause rotation.
- At width 9, primary reaches a frontier internal cannot close and uses 53.17%
  fewer conflicts than key rotation and 7.19% fewer than clause rotation.
- Relative to O1C-0046, absolute primary work is worse (`43 -> 75`, `87 -> 155`),
  but target specificity reverses: clause rotation previously beat primary
  (`22 < 43`, `46 < 87`), whereas primary now beats clause rotation at both
  widths (`75 < 89`, `155 < 167`).

Thus disjoint global pair envelopes restore a small primary-specific ordering
that unary marginals erased, but they do not satisfy the frozen all-arm gate and
do not improve Full-256 recovery. A post-result per-comparator lexicographic
reading would place primary above internal by width and above both rotations by
conflicts at width 9; that fact was **not** the registered O1C-0048 pass rule and
is retained only as the next-mechanism breadcrumb.

## Boundary and resources

- Full-256 rows: attacker-valid, all 256 key bits unknown, zero reveal reads.
- Residual rows: explicit post-reveal ceilings with 248/247 truth units.
- Reader refits, fresh targets, sibling reads/writes, GPU and MPS calls: zero.
- Work: 12 native calls and 6,144 requested conflicts.
- Runtime: `9.362067` s elapsed; `6.590456` child CPU seconds.
- Peak RSS: `128,122,880` bytes.
- Persistent capsule payload: `50,256` bytes.

Reproducibility anchors:

- Config SHA-256: `e5a9c1f5f6c68ee16f4f3313b6521763cab1f3f2ee6abca80e0b6b53815ff679`
- Runner SHA-256: `c1d6f63a2cee8535cd79debd363d8c1c155387bf39b320ceee2e7ff27d69a85d`
- Attacker freeze SHA-256: `5069eb94d31be393ca4324477073fe54fd303764182603f18733c517529327c3`
- Result SHA-256: `eb5ffc29dbadb0f3722204425309d16b6befe82ea5aabc1075226f856d599663`
- Capsule manifest SHA-256: `bfb086fc000037b03b0c8fcbbe4aa83f4555e95ffc49bd577faf55266f8462f6`

## Decision

Close this exact disjoint pair/max-envelope adapter on the consumed target. Do
not tune pair membership, raise the conflict cap, or spend a fresh target on it.
Preserve the demonstrated specificity reversal and move to a genuinely new live
mechanism: bounded O1/O1-O group credit from attacker-visible propagation and
backtrack outcomes, with the static O1C-0048 arms retained as frozen baselines.
The next gate should compare primary lexicographically against each comparator
and separately require absolute improvement over O1C-0048; O1C-0048 itself is
not retroactively reclassified.
