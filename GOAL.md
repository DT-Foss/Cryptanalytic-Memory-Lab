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
5. Classify every imported mechanism by its true input contract before spending
   compute. The sibling residual recoveries begin with 204--236 correct key bits;
   preserve them as terminal backends, not as evidence that those bits were found.

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
- Before a positive recovery effect, retain only four hard gates: all 256 target
  bits really unknown, no target-label/key leakage, equal scored work and strict
  sibling isolation. Replication, broad controls and publication hardening follow
  an effect; they do not precede every exploratory run.

## Scope and bookkeeping

All writes stay inside this repository. Every real iteration receives a monotone
O1C ID, wall-clock time, resource figures, frozen source/config hashes, raw result,
decision and direct next action. Keep `STATUS.md`, `RESULTS_INDEX.md`,
`research/ATTEMPT_LOG.md`, `research/HYPOTHESES.md` and
`research/NEXT_ACTIONS.md` current, but spend hardening effort only in proportion
to an observed recovery effect.

Current state: A296 (`118/61/9/230`), A448/A465 (`47/239`) and A469 (`56/239`)
exact all256 byte transfers are closed. Read-only audit finds no demonstrated
sibling recovery whose real deployment begins with all 256 bits unknown: the
reliable W20--W52 recoveries assume 236--204 correct complement bits. The sole
frontier task is therefore the missing all256-to-complement/beam bridge; once it
meets the exact gate, reuse A325/A526 and verification unchanged.

The real O1C-0019 and O1C-0022 all256 chain has now also run and is closed:
learned live compression is `-0.271090` bit, the learned raw reader loses its
untrained twin by `0.058470` bit, and the 352-byte vault falls to `-1.181837`
bits at K256. No precommitted arm exceeds `120/210` A325 or `118/204` A526
complement bits. Do not run the derivative O1C-0023/25/29 composer, frontier or
hot-readout stack on this null field. The next real experiment must introduce a
new all256-unknown evidence source and score its complement/beam effect directly.
