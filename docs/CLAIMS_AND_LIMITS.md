# Claims and limits

This document is the short public claim boundary for the Cryptanalytic Memory
Lab (`cryptO1`) defensive publication. The artifact-level sources of truth are
the immutable result JSON files, run-capsule manifests and interpretations
linked from `RESULTS_INDEX.md`.

## Established mechanisms

- Exact `256/256` addressed-bit retention after up to `2^20` distractors in a
  `352`-byte live state on the synthetic bounded-state benchmark.
- Fresh, public-input, full-round ChaCha20 complete-candidate rank transfer in
  O1C-0044 and O1C-0057 under their frozen candidate-panel contracts.
- Exact score-threshold Full-256 branch pruning and immutable no-good streams,
  including O1C-0068's `190` and O1C-0073's `311` globally novel exclusions.
- A complete `550`-clause causal attic with a bounded `K=256` live projection.
- Central decision-instance ownership over prefix, rank and frontier readers;
  O1C-0079 records `549/549/549` proposals, level bindings and releases with
  zero live or omitted tokens.

## Not established

- No exact attacker-valid recovery of an unknown 256-bit ChaCha20 key.
- No practical break, reduced security claim, global key-space exhaustion or
  generic distinguisher for ChaCha20.
- No evidence that runtime reduction, decision-count change, trace change,
  lower propagation count or successful instrumentation alone reduces key
  entropy.
- No conversion of post-reveal ceilings, fixed true-bit complements or target
  secrets into attacker-valid evidence.

## O1C-0079 correction

The checksum-sealed O1C-0079 runner result is preserved byte-for-byte. Its
post-call classifier searched all serialized telemetry for `returned-ever` and
therefore matched the safe, required rule description
`never-returned-ever-plus-variable-sign`. A zero-call re-evaluation against the
exact native runtime identity and complete lifecycle replay corrects
operational ownership and qualified prefix activation from `false` to `true`.
The scientific axis remains `false`: zero prune, zero clause, zero model and no
key. The erratum supersedes only the interpretation, never the raw evidence.

## Terminal recovery gate

A recovery claim requires a key generated without truth/reveal input and an
independent byte-exact verification against the public standard twenty-round
ChaCha20 relation. Until that gate passes, all results are reported as
retention, rank, pruning, exclusion, mechanism-only or negative evidence.
