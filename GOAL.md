# Active Goal — O1-256 Living Inverse

Recover and independently verify a uniformly random 256-bit key from a standard
20-round ChaCha20 public relation using only counter, nonce and output at attack
time. `SOTA` remains the target: a reproducible reduction of the best known
full-round 256-bit attack frontier and ultimately an exact verified key.

An exact key is the terminal result, not the only result worth keeping. A stable
held-out bit advantage, joint-relation advantage, entropy reduction, true-key
rank gain, smaller residual domain or lower time-to-hit is real progress when it
transfers to unseen uniform keys under equal attacker work. Synthetic mechanism
passes and BUILD-only gains remain useful engineering evidence but are labelled
as such.

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

A526 is a retained terminal engine, not the definition of the entire problem.
Its native contract remains coordinates `0..51` residual and `52..255` fixed,
but a useful joint decoder may target another residual geometry or hand a
smaller constrained domain to a general exact verifier.

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

The active frontier is therefore conversion rather than rediscovery: use the
frozen target-specific relation field as an attacker-computable forward-candidate
objective, then as context-reversible live guidance inside the exact adapter.
A500 already closes fixed joint-parity marginals and A503 closes its tested
target-aligned Jacobian factor model, so the successor must measure true-key joint
rank, effective residual width or real search work without requiring 248
independently perfect unary predictions.

All writes stay inside this repository. Sibling projects remain read-only and no
competing heavy job starts without a resource check.
