# Scientific Boundaries

These boundaries protect the combined architecture from ambiguous successes. They
are design constraints, not judgments about whether the originating side projects
were “finished.”

## Memory claims

- Exact Stage-0 MQAR-256 recall proves storage after an ideal closed relevance gate.
  It does not demonstrate that O1 learned to distinguish bindings from distractors.
- A direct `position -> bit` vault is a fixed register bank, not holographic
  compression and not a dictionary-free general associative memory.
- Equal scalar-cell count does not equal equal bit precision or serialized storage;
  both are reported.
- “Arbitrarily long” means a mechanism whose state transition is exactly closed for
  irrelevant tokens plus empirical out-of-distribution length sweeps. It is not an
  empirical proof over infinite streams.
- An external index is a separate memory tier. Its entries and bytes never disappear
  into the bounded-state number.

## Cryptanalytic claims

- Synthetic 55% evidence is an oracle instrument. It proves the accumulator works
  if a signal exists; it does not show that a cipher exposes that signal.
- Raw full-round output distance is assumed uninformative until a prospective,
  controlled experiment shows otherwise.
- A teacher may use internal states on training keys to discover hypotheses. The
  frozen evaluation reader must use only public or attacker-recomputable inputs.
- A lower target rank is not recovery. Exact full-output confirmation remains the
  terminal gate.
- Every offline training and operator-search cost is included in an end-to-end work
  comparison.

## Information-flow boundary

Provenance labels are monotone. The following labels are terminal with respect to a
target-blind order:

- `TARGET_SECRET`
- `INTERNAL_TARGET`
- `POST_REVEAL`

They may appear in audit and analysis reports, but never in discovery state,
Failure-Memory, adaptive action selection or a frozen test order. No conversion or
operator can remove them.

## Split boundary

- Training keys: internal supervision allowed.
- Validation keys: operator selection and calibration allowed.
- Test keys: exactly one frozen evaluation; no learned response feeds back.
- Post-test audit: arbitrary diagnosis allowed, but stored in a physically separate
  ledger scope and never reused as discovery evidence.

The default ledger base `runs/failures.jsonl` resolves to the two append-only files
`runs/failures.discovery.jsonl` and `runs/failures.post-test-audit.jsonl`. Training
feedback cannot update the validation-best or validation-staleness fields.

## Control boundary

Every signal experiment needs at least:

- multiple independent seeds and unseen keys;
- a no-signal or shuffled-label control;
- a correlated-error control when repeated evidence is accumulated;
- a matched factual/control work budget;
- a full-context hard-attention or exact-address ceiling for storage qualification;
- an under-capacity baseline that should fail for the expected reason.

## O1-O outcome boundary

The real O1-O run is valuable because it demonstrates the control topology and
provides a replayable adaptive trace. For learning, four outcomes remain distinct:

1. generation/compilation;
2. process execution;
3. capability evidence;
4. mission progress.

The replay adapter records the first two directly, adds only aggregate adaptive-loop
counts, and leaves the latter two unknown until a domain-specific semantic evaluator
supplies structured evidence. Neutral replay events enter the bounded TargetModel as
observations, not rewards or failures. This makes the historical run suitable
training substrate without letting an exit code become an accidental scientific
reward or inventing retry ancestry absent from the stored schema.
