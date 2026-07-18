# Active Goal — O1-256 Living Inverse

Recover and independently verify a uniformly random 256-bit key from a standard
20-round ChaCha20 public relation using only counter, nonce and output at attack
time. `SOTA` here means a real reduction of the unknown-key search frontier and
ultimately an exact verified key—not infrastructure, a reduced-width proxy or a
synthetic mechanism pass.

## Execution priority

1. Reuse the strongest exact recovery mechanisms already demonstrated in the
   read-only sibling project. Preserve their feature, ordering, state and verifier
   semantics before inventing replacements.
2. Connect them directly:
   `public target -> sibling evidence -> O1 posterior/completion beam -> sibling residual recovery -> ChaCha verification`.
3. Run the real all-256 public relation immediately. Theory, adapters, tests and
   capsules support a run; they never count as the result.
4. Score progress by recovered key entropy, byte/block/full-key rank, verified
   candidate count, time-to-hit and exact key recovery.

## Iteration rule

- A positive consumed result earns exactly one unchanged consumed repeat.
- A repeated positive earns exactly one fresh blinded target.
- A failed repeat closes that exact reader immediately: record one do-not-repeat
  line, spend no fresh target and perform no rescue sweep.
- Do not celebrate negative results or optimize for balanced reporting. Their
  only value is preventing the same paid mistake from recurring.
- Do not rebuild A325/W46 or A526/W52. They are working terminal residual engines;
  invoke them only when an upstream completion or tractable beam satisfies their
  exact 210/210 or 204/204 complement contract.

## Scope and bookkeeping

All writes stay inside this repository. Every real iteration receives a monotone
O1C ID, wall-clock time, resource figures, frozen source/config hashes, raw result,
decision and direct next action. Keep `STATUS.md`, `RESULTS_INDEX.md`,
`research/ATTEMPT_LOG.md`, `research/HYPOTHESES.md` and
`research/NEXT_ACTIONS.md` current, but spend hardening effort only in proportion
to an observed recovery effect.

Current state: A296 (`118/61/9/230`) and A448 (`47/239`) exact all256 byte
transfers are closed. The next action is the strongest remaining sibling channel
whose deployment contract genuinely begins with all 256 key bits unknown.
