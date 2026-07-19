# Active Goal — O1-256 Living Inverse

Recover and independently verify a uniformly random 256-bit key from a standard
20-round ChaCha20 public relation using only counter, nonce and output at attack
time. `SOTA` remains the target: a reproducible reduction of the best known
full-round 256-bit attack frontier and ultimately an exact verified key.

SOTA is a frontier, not a Boolean label reserved for the final key. Exact
256-bit recovery is the uncompromised north star, but a stable held-out bit or
joint-relation advantage, entropy reduction, true-key rank gain, smaller
effective residual domain or lower time-to-hit is real progress when it
transfers to unseen uniform keys under equal attacker work. A sub-256 result may
itself be a frontier result if it improves the strongest comparable full-round
attack; it is not renamed full recovery. Synthetic mechanism passes and
BUILD-only gains remain useful engineering evidence but are labelled as such.

## Attack architecture

Keep the already-working public ChaCha evaluator and exact verifiers frozen. Use
O1 as a bounded streaming evidence state and pursue two complementary decoders:

1. **Factorized completion:** eight public ChaCha blocks enter O1; holographic
   coordinate queries emit logits for key bits `52..255`; an exact top-K
   completion frontier feeds the unchanged A525/A526/A528 W52 engine.
2. **Relational completion:** O1 emits soft unary and joint scores; an exact
   ChaCha/SAT or factor-graph adapter combines them with attacker-valid algebraic
   relations and searches joint key configurations directly. This path may
   reduce the residual domain without first predicting 204 independent bits.

O1's output contract is deliberately broader than 256 independent binary
posteriors. The bounded state may expose unary confidence, sparse signed joint
factors, proof-ancestry identity and live search-control state. Coordinate logits
are one reader of that state, not the definition of the inverse architecture.

A526 is a retained terminal engine, not the definition of the entire problem.
Its native contract remains coordinates `0..51` residual and `52..255` fixed,
but a useful joint decoder may target another residual geometry or hand a
smaller constrained domain to a general exact verifier. Requiring A526's 204
fixed bits before acknowledging progress would force the upstream model to solve
almost four fifths of the key exactly before the backend contributes; that
contract is never the sole promotion gate again.

A513's zero-sum bases and A518B's K4,4 frame are exact equivalent compilations of
the same public relation, not dozens of independent information bits. Their
value is solver conditioning, proof-trajectory diversity and joint addressing.
They may guide a relational decoder, but their rows must never be counted as new
entropy removal merely because the equation is written in several bases.

## Progress ladder

Every real run uses standard full-round ChaCha20 with all 256 key bits unknown at
deployment and reports the strongest level it actually reaches:

1. held-out cross-entropy below the 256-bit random baseline or stable transferable
   coordinate/parity advantage;
2. higher probability or lower rank for the true joint configuration under an
   attacker-computable constrained decoder;
3. measured domain reduction, effective residual width or time-to-hit advantage
   against equal-work search;
4. the exact key enters a tractable beam or residual engine;
5. exact key recovery followed by independent public ChaCha verification.

Results below level five are not called full recovery, but they are not discarded
when they provide a reproducible frontier gain. Conversely, `180/204` correct
bits is not automatically useful: it counts only if confidence/joint structure
turns it into less real search work than the baseline.

Every rung may earn the next iteration. A result qualifies as a cryptanalytic
frontier advance when it beats the strongest comparable attacker-valid baseline
on one of the declared metrics under equal work; exact recovery is the highest
rung, not a prerequisite for measuring the lower ones. Representation transfer
that has not yet improved rank or search work remains a useful mechanism result
and breadcrumb, not a fake SOTA claim and not a worthless null.

## Execution priority

1. Build the smallest relational-completion test that consumes a frozen public
   O1 field plus one exact ChaCha representation and measures true-key joint
   rank, proven domain reduction or equal-work time-to-hit. Reuse A513/A518B as
   compiler geometry; do not claim they supply independent constraints.
2. Do not repeat A500's fixed parity-marginal decoder or A503's target-aligned
   Jacobian remainder model: both already failed exact held-out transfer. The new
   test must couple the soft field to target-specific exact solver search or
   proof-derived joint factors, not merely rescore a static parity catalogue.
3. Keep factorized completion available for a genuinely new positive evidence
   source, but do not scale O1C-0036's raw-output reader. Promote whichever path
   first produces transferable attacker-valid reduction.
   Hybridize only after one component has a measured effect.
4. Do not rebuild a working residual evaluator, verifier or ChaCha generator.
   Change upstream evidence or the completion geometry only.

## Iteration rule

- A positive consumed result at any progress-ladder level earns one unchanged
  consumed repeat. A repeated positive earns one fresh sealed uniform target.
- A failed repeat closes that exact mechanism. Record one terse do-not-repeat
  entry and pivot; a negative result is not a milestone or a reason for ceremony.
- Do not use exact `204/204` as the only promotion gate. Also promote a stable
  entropy, joint-rank, residual-width or time-to-hit gain that survives the same
  equal-work boundary.
- Before a positive effect, retain only four hard gates: all target key bits are
  unknown, target labels never enter deployment, scored work is matched, and all
  sibling projects remain strictly read-only.
- Broad controls, independent replication and publication hardening follow a
  real effect. They do not precede every exploratory run.
- Bookkeeping is proportional: one machine-readable result and one resume line
  per paid run. Tests and adapters support the run but never count as the result.

## Current boundary

O1C-0035 completed the literal native bridge. On the old O1C-0022 posterior,
`0/20` top-65,536 complement beams contain the exact 204-bit complement; MAP
reaches at most `118/204` and the post-reveal oracle beam at most `123/204`.
That closes the old unary field, not factorized completion in general and not
joint completion.

A296, A448, A465 and A469 full256 projections are closed at their tested
representations. O1C-0036 also closes raw eight-block output-only O1 at
`102.5/204`, `-0.393341` bit and `0/128` exact top-65,536 complements. A513/A518B
remain available as exact solver-compilation and joint-geometry mechanisms.
O1C-0037 now supplies the direct exact Full-256 bridge and closes key-phase-only
guidance on the frozen unary field: real O1 is no better than its coordinate-
shuffled control, and one wrong hint is unresolved through 32,768 conflicts.
O1C-0038 measures the corrected decoder ceiling: with 248 oracle-correct,
O1-ordered prefix bits, the unchanged relation recovers the remaining eight bits
and independently verifies the full key in 135,441 us; nine residual bits remain
unresolved through 32,768 conflicts. This is post-reveal mechanism capacity, not
attacker-valid recovery.

O1C-0039 supplies the first attacker-valid relational transfer. A BUILD-frozen
H16 signed clause-contrast field reaches `55.09%` and `56.99%` key-to-internal
relation accuracy on two unseen DEVELOPMENT keys (`397/711`, `55.84%` pooled),
above key-rotated `52.88%` and factor-rotated `49.51%`. The bounded fields occupy
3,512 and 2,288 bytes. This advances the first progress rung, but the present
first-encounter factor decisions recover no Full-256 key and do not extend the
post-reveal residual ceiling beyond eight bits.

O1C-0040 then evaluates the complete candidate-level consequence. Across 4,096
attacker-generated decoys per target, raw primary truth ranks are `1905/4097` and
`2292/4097`; one frozen structural-surprise correction reaches `1078/4097` and
`1461/4097` but loses decisively to key rotation (`107/4097`, `423/4097`). The
transferred occurrence edges therefore describe mostly universal ChaCha geometry,
not a usable target-key objective.

O1C-0041 moves one causal level deeper and retains branch-exclusive proof-chain
identity before signed original-leaf collapse. A BUILD-only rank-product selects
global orientation `-1`; on the two consumed DEVELOPMENT keys the unchanged
complete-candidate objective ranks truth `80/4097` and `998/4097`, geometric
`6.90%`, versus `27.02%` key rotation and `16.26%` factor rotation. This is the
first target-key joint-rank breadcrumb beyond terminal occurrence. It is
retrospective, so the active frontier is exactly one unchanged fresh Full-256
replication before any live solver integration.

O1C-0042 executes that one fresh replication. Primary rank is `1371/4097`
(`33.46%`), narrowly ahead of key rotation `1399/4097` and far ahead of factor
rotation `3385/4097`, but outside the frozen best-quarter gate. The unique-leaf
sum reader is closed without a retry. The next causal level preserves ordered
direct-parent role and candidate-relative clause criticality before leaf collapse;
it must earn consumed-panel joint rank before another fresh target.

O1C-0043 now earns that next rung. A 15-channel BUILD-fitted reader over ordered
RUP parent role and original functional-clause criticality ranks the two consumed
DEVELOPMENT truths `5/4097` and `91/4097` (geometric `0.52%`) versus `38.52%`
for the best endpoint control. Unchanged on the consumed O1C-0042 key it ranks
truth `141/4097` (`3.44%`) versus `3623/4097` key rotation and `3475/4097`
clause rotation. This is a strong consumed joint-rank result, not recovery. The
only authorized efficacy step is one sealed fresh target with the exact field,
reader weights, panel and rotations unchanged.

O1C-0044 confirms that prospective step. With the O1C-0043 reader loaded
byte-for-byte, a sealed fresh Full-256 truth ranks `54/4097` (`1.318%`, z
`+2.325`) versus key rotation `3567/4097` and clause rotation `2972/4097`.
The key opens only after every score hash freezes and independently verifies the
public output. This advances the joint-rank rung, not exact recovery: full
candidate executions were still scored. The active task is now to reuse the same
criticality field inside the existing exact solver and demonstrate less matched
search work or a smaller effective residual domain.

O1C-0045 executes that conversion without refitting. Exact local truth tables
reproduce all 4,097 frozen scores within `1.25e-14` and preserve primary rank
`54/4097`. At 512 conflicts Full-256 remains unresolved. Under an explicit
post-reveal prefix, internal search closes residual width 8 but not 9; primary
closes width 9 in 281 conflicts. Key and clause rotations also close width 9 in
69/129 conflicts, so the local potential family improves completion geometry but
the all-variable greedy scheduler does not preserve the primary reader's
target-specific margin. The active task changes only scheduling: observe every
factor variable, externally decide key variables only, and rerun the identical
consumed boundary before any fresh key or reader change.

O1C-0046 completes that scheduling test. Restricting external decisions to 126
key coordinates cuts primary residual-8/9 work from 152/281 to 43/87 conflicts,
while retaining every internal assignment for conditioning. The matched clause
rotation still wins at 22/46, Full-256 remains unresolved and the exact frontier
stays at nine residual bits. Greedy local marginals are therefore closed in both
all-variable and key-only forms. The active relational task preserves the frozen
global O1C-0044 score and changes only its search unit to bounded key prefixes or
score-aware factor groups before any new reader, budget or fresh target.

O1C-0047 confirms the complete-state side of that hypothesis. On exhaustive
nested post-reveal cubes, truth ranks `1/256`, `5/4096` and `50/65536`; the W16
rotations rank `60592/65536` and `43059/65536`, and only the primary top-256 beam
contains the independently verified key. This is `10.356` bits of local search
compression with 240 truth bits fixed, not attacker-valid Full-256 recovery. The
first soft reversible pairwise key-group/max-envelope conversion is now complete
as O1C-0048. Full-256 remains unresolved, and the frozen global all-arm gate
fails because internal search stops at width 8 while primary and both rotations
reach width 9. Nevertheless primary is fastest at both measured widths: 75
conflicts at W8 versus 217/195/89 and 155 at W9 versus internal UNKNOWN/331/167.
This is a consumed specificity breadcrumb, not a promoted recovery result. Close
the exact disjoint-pair adapter rather than tuning it.

The isolated bias-free Apple track independently tested a public Full-256
fixed-point/output-fitness view on 32 deterministic targets. Its AUC `0.50572`,
`-0.484` gained key bits and zero recoveries close that local-fitness direction;
it does not alter the positive complete-state criticality path. Its second,
genuinely different carry-quotient view also closes cleanly: independently free
non-LSB carries span all 512 output equations and leave exact key rank zero on
8/8 Full-256 targets. Future carry work must restore the real carry recurrence
globally by depth; it must not repeat independent-carry elimination.

The active conversion now uses O1/O1-O where it is architecturally justified:
learn bounded group credit online from attacker-visible propagation, conflict and
backtrack outcomes while retaining O1C-0048's static arms as frozen baselines.
The next mechanism must preserve the primary-over-rotation specificity seen at
W8/W9 and improve absolute work or frontier. Its pairwise comparator gate is
frozen prospectively; O1C-0048 is not retroactively promoted.

All writes stay inside this repository. Sibling projects remain read-only and no
competing heavy job starts without a resource check.
