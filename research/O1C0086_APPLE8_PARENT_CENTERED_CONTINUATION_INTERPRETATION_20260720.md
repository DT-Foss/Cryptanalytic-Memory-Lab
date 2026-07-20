# O1C-0086 — Page-11 parent-centered continuation

Recorded 2026-07-20 18:12:54 CEST. O1C-0086 consumed fresh Page 11 / local
episode 0 / lineage 24 exactly once and is terminal
`PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN`.

## Result

- Requested/actual/billed conflicts are `128/131/131`; CaDiCaL overshot the
  requested conflict limit by three before returning normally.
- The live O(256) continuation made `255` failure-first actions and `100,038`
  exact probes. It fully emitted `202` trail-upper-bound no-goods containing
  `546,864` literals.
- All 202 emitted clause identities are distinct, classified `new`, absent from
  the active Page-11 input, and absent from the complete sealed causal-attic
  baseline of 830 unique clauses. An independent sorted SHA-256 set comparison
  gives `baseline_unique=830`, `emitted_unique=202`, `intersection=0`.
- Witness upper bounds range from `8.269907850393242` through
  `14.604191886555723`; every value is strictly below
  `tau=14.606178797892962`. The closest strict margin is
  `0.00198691133723905`.
- A direct successor vault remains available at `456` clauses / `1,265,745`
  literals / `5,064,995` bytes, SHA-256
  `bdac04a286b508d18219367143bd1f2cfc420e13315582ce04dd4ef855115209`.
  Capacity did not stop the call.
- The 24,576-byte continuation bank evolves from `2c0c4ccb...` to SHA-256
  `658fd2856b83d1a0ff8d28e92a604c99b3843a49a589811bf9b61845959ec31f`.
- Native execution used 1.566374 s wall, 2.329425 s CPU and 399,785,984 bytes
  peak RSS. The sealed runner took 38.477707 s end to end, including the
  build-once and archival path.

## Claim boundary

This is exact-clause compounding on the public full-round relation. It is a
science gain because the newly proved exclusions are globally novel and
durably serializable. It is not a recovered key, complete model, certified
closure, key-bit posterior, or attacker-valid entropy/domain reduction.

`threshold_prunes=202` is the safe trail-upper-bound path that generated the
clauses. The different action-specific field remains
`actual_certified_prunes=0`: none of the 255 selected one-bit actions itself
crossed the certification threshold. The two counters must not be conflated.

No target bytes, truth-key bytes, reveal, refit, MPS or GPU were used. Page 11
and lineage 24 are burned and must never be retried or replayed.

## Provenance and continuation

The authoritative result SHA-256 is
`535b8fa095013d4b87cadfc5e54e62698a21ab285d92becfbba88dc9c6f0ee6e`.
The sealed capsule is
`runs/20260720_181212_319263_O1C-0086_apple8-parent-centered-continuation-v1`;
its artifact-manifest SHA-256 is
`d4ff926b1c2183ca2c70b499acd9e3aa00e9c6575aee43479dc6238e690953fb`.
All 29 manifest rows pass `shasum -a 256 -c`, and the capsule result is
byte-identical to the authoritative result.

The next state transition is zero-call ingestion of all 202 clauses into the
immutable causal attic, binding the evolved `658fd285...` bank, and deriving a
fresh bounded Page-12 / lineage-25 projection. Only after that projection and
its exact source/build/launch seals pass may one fresh continuation call be
authorized. There is no Page-11 replay and no blind cap or RAM increase.
