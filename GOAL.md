# Active Goal — O1-256 Living Inverse

Recover and independently verify a uniformly random 256-bit key from a standard
20-round ChaCha20 public relation using only counter, nonce and output at attack
time. `SOTA` here means a real reduction of the unknown-key search frontier and
ultimately an exact verified key—not infrastructure, a reduced-width proxy or a
synthetic mechanism pass.

## Execution priority

1. Freeze the already-working cheap full-round public path. Do not redesign its
   evaluator, verifier, state format or scheduler unless a measured bottleneck
   blocks an attack run.
2. Reuse the strongest exact recovery path already demonstrated in the read-only
   sibling project at its native interface. For A526 this means exactly key
   coordinates `0..51` residual and coordinates `52..255` fixed; do not replace
   it with an invented flexible-mask backend before this literal bridge is spent.
3. Connect the two existing halves directly:
   `8 public ChaCha blocks -> O1 logits for fixed bits 52..255 -> exact top-K
   complement beam -> unchanged A525/A526/A528 W52 search -> public ChaCha
   verification`.
4. Every substantive iteration must execute or score that end-to-end attack
   contract on already-consumed BUILD data. Theory, adapters, tests, capsules and
   synthetic retention never count as progress by themselves.
5. Score only complement Hamming error, exact-complement beam rank, induced W52
   work, time-to-hit and exact verified key recovery. General NLL or mechanism
   elegance is secondary unless it improves one of those quantities.
6. Only after the native transfer path has consumed the available O1 posterior
   should a new sensor be invented. New evidence must enter upstream of the same
   frozen complement beam and W52 backend, so an improvement is immediately an
   attack improvement rather than another disconnected model result.

## Iteration rule

- A positive consumed result earns exactly one unchanged consumed repeat.
- A repeated positive earns exactly one fresh blinded target.
- A failed repeat closes that exact reader immediately: record one do-not-repeat
  line, spend no fresh target and perform no rescue sweep.
- Do not celebrate negative results or optimize for balanced reporting. Their
  only value is preventing the same paid mistake from recurring. A null is one
  terse cache entry, not a milestone, report package or reason to build controls.
- Do not rebuild A325/W46 or A526/W52. They are working terminal residual engines;
  invoke them only when an upstream completion or tractable beam satisfies their
  exact 210/210 or 204/204 complement contract.
- Before a positive recovery effect, retain only four hard gates: all 256 target
  bits really unknown, no target-label/key leakage, equal scored work and strict
  sibling isolation. Replication, broad controls and publication hardening follow
  an effect; they do not precede every exploratory run.
- Bookkeeping is automatic and proportional: one timestamped machine-readable
  result plus one resume line per paid run. Extra prose, independent replay,
  broad ablations and reviewer-oriented hardening begin only after a positive
  recovery effect.

## Scope and bookkeeping

All writes stay inside this repository. Every real iteration receives a monotone
O1C ID, wall-clock time, resource figures, frozen source/config hashes, raw result,
decision and direct next action. Keep `STATUS.md`, `RESULTS_INDEX.md`,
`research/ATTEMPT_LOG.md`, `research/HYPOTHESES.md` and
`research/NEXT_ACTIONS.md` current, but spend hardening effort only in proportion
to an observed recovery effect.

Current state: A296 (`118/61/9/230`), A448/A465 (`47/239`) and A469 (`56/239`)
all256 projection attempts are closed at those exact projections. They do not
reject the native W52 pipeline; they show that projecting isolated ranking
operators onto byte classes was the wrong interface. The reliable W20--W52
recoveries assume 236--204 correct complement bits. The sole frontier task is
the upstream A526-native complement reader. O1C-0035 has already made the bridge
literal: it ranks complete assignments of bits `52..255` and hands them to
A525/A526/A528 without changing their semantics.

The real O1C-0019 and O1C-0022 all256 chain has now also run and is closed:
learned live compression is `-0.271090` bit, the learned raw reader loses its
untrained twin by `0.058470` bit, and the 352-byte vault falls to `-1.181837`
bits at K256. No precommitted arm exceeds `120/210` A325 or `118/204` A526
complement bits. Do not run the derivative O1C-0023/25/29 composer, frontier or
hot-readout stack on this null field. The next real experiment must introduce a
new all256-unknown evidence source and score its complement/beam effect directly.

Direct effect-first combinations with the sibling solver are also closed only at
their exact tested surfaces: a signed-pair proof proxy, single-bit terminal
assumptions, failed cores, inverse fixed points, one-bit neighbors and W8 cells.
Do not rescue-sweep them. They are not a license to invent another architecture
layer. O1C-0035 has exposed the real A526 cost of the current O1 logits: no
top-65,536 beam contains the exact complement. Change only the upstream
eight-block evidence source while keeping that attack loop frozen.
