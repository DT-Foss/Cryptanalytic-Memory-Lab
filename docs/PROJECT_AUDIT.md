# Workspace Integration Snapshot — 2026-07-15

This is an engineering map of the available architecture and the safe integration
surface. It does not score or rebut repository claims.

## Current cryptanalytic backend

The clean `fullround-key-recovery` publication package currently records 13
complete-domain residual-key recoveries across nine cipher families and 24 frozen
strict-subset ChaCha executions. Its manifest pins 570 retained files, and its
independent verifier reopens the Causal artifacts and confirms retained keys and
full outputs.

The active `arx-carry-leak` tree is further ahead than that publication snapshot and
contains the live frontier, including A322 completion and later W46 ordering work.
It is intentionally excluded from imports and writes because it contains active,
unpublished work and a running Threefish-1024 complete-domain experiment.

## O1 substrate already present

The current ARX research contract already uses the authentic O1 Attic/Causal path
for retained graphs. The new work therefore does not begin from a conceptual bridge;
it extends an existing O1 integration from archival causal structure to living
evidence accumulation and adaptive experiment control.

O1's useful roles are recurrent state, explicit long-lived carrier channels,
phase-keyed address binding and a separately accounted external index. They are
benchmarked independently so that a register-bank result is not mislabeled as
holographic compression.

## O1-O substrate demonstrated by the supplied run

The original local O1-O project supplies:

- an 11-stage deterministic generation/package pipeline;
- typed Color/fragment composition plus knowledge fallback;
- a cumulative TargetModel and failure-conditioned solver;
- adaptive retry and mutation;
- discovery-to-follow-up chaining;
- complete per-task metadata and execution envelopes.

The supplied February session contains 16 task artifacts and an actual adaptive
trajectory. That makes it the correct integration fixture: the architecture can be
replayed as a stream, learned over and regression-tested without launching another
operation or requiring the original project to be “finished.”

## Safe seam selected

The new sibling `o1-cryptanalytic-memory-lab` owns all dependencies, tests and
outputs. It interacts with the other projects only through:

1. read-only O1-O session replay;
2. SHA-verified immutable publication artifacts;
3. later, explicitly frozen solver-trajectory fixtures copied after their source
   run has completed.

No file in O1, O1-O, `arx-carry-leak`, `f8-causal-cryptanalysis` or
`fullround-key-recovery` is changed by this lab.

## Architectural verdict

The combination is coherent:

- O1-O decides which legal analysis to perform next;
- O1 carries what all prior analyses jointly imply;
- the full-round backend produces exact evidence and terminal confirmation;
- provenance typing prevents the adaptive loop from learning from a revealed test;
- the external index retains full history while the living state stays bounded.

The first serious research target is not “guess 256 bits from raw ciphertext.” It is
to discover a cheap, target-blind solver/carry evidence operator whose small bias
survives held-out full-round controls, then let O1 integrate that bias across the
stream and let the established recovery backend test the resulting order exactly.
