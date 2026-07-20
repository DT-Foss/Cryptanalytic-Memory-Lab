# Defensive publication: Cryptanalytic Memory Lab (`cryptO1`)

## Publication identity

- **Author:** David Tom Foss
- **Initial public release:** 2026-07-20 (`Europe/Berlin`)
- **Canonical repository:**
  `https://github.com/DT-Foss/Cryptanalytic-Memory-Lab`
- **Initial disclosure tag:** `v0.1.0-prior-art`
- **License:** Apache-2.0, with the third-party notice in `NOTICE`

This repository is intentionally disclosed as enabling prior art. The tagged
source tree, complete experiment capsules, result files, configuration files,
tests and artifact manifests are the disclosure. Later work may extend the
research line, but it does not alter the contents or date of this release.

## Problem disclosed

The research asks whether a bounded live state can consume a long stream of
public, solver-native observations from a standard twenty-round ChaCha20
relation and turn them into reusable constraints or a 256-bit key posterior.
The attacker-valid target keeps all 256 key bits unknown; only the standard
public inputs and cipher output are available to the inference mechanism.

The architecture is a composition of:

1. a constant-in-stream-length selective state;
2. exact addressed binary registers for qualified retention tasks;
3. coordinate-, feature- and reader-conditioned holographic/polyphase binding;
4. a bounded live projection over an immutable causal exclusion attic;
5. a typed operator compiler and experiment-memory layer that preserve failed
   mechanisms as machine-readable constraints on later compositions; and
6. an exact SAT/constraint boundary whose final recovery gate is byte-exact
   verification against the public ChaCha20 relation.

It does not store or enumerate `2^256` candidate keys. The principal stream
elements are paired key-bit assumptions, propagation and conflict events,
proof antecedents, carry/round-local features, exact score bounds, no-goods and
reader lifecycle events. The live state is bounded independently of stream
length; persistent evidence is admitted into the external attic as compact
causal artifacts with explicit byte and work accounting.

## Implemented mechanisms and disclosed results

### Exact bounded retention

[O1C-0020](../runs/20260717_211433_O1C-0020_selective-mqar-256-learned-gate-v1/RUN.md)
trains a public-token routing gate and recovers all `256/256` explicit binary
bindings on 12 unseen benchmark cells after `0`, `2^16` and `2^20`
distractors. The complete live state is 352 bytes and byte-identical across
nested stream lengths. This is a storage/routing result, not a cipher result.

### Fresh full-round rank transfer

[O1C-0044](../research/O1C0044_FRESH_PARENT_CRITICALITY_RANK_RESULT_20260718.md)
and
[O1C-0057](../research/O1C0057_MULTIBLOCK_PARENT_CRITICALITY_RANK_RESULT_20260719.md)
demonstrate fresh complete-candidate rank transfer using only their frozen
public-input contracts. These results rank finite candidate panels; they do not
recover an unrestricted unknown 256-bit key.

### Exact Full-256 safe exclusions

[O1C-0068](../research/O1C0068_APPLE8_COMPLEMENTARY_PHASE_INTERPRETATION_20260719.md)
emits 190 globally novel score-threshold exclusions in one complementary
reader call. [O1C-0073](../research/O1C0073_APPLE8_VAULT_RELEASE_CONTRAST_RESULT_20260719.json)
emits 311 additional globally novel exclusions. Each exclusion is derived from
an admissible upper bound `U` and a frozen incumbent threshold `tau`; a branch
is prunable only under the strict relation `U < tau`. Equality remains live.

### Bounded causal exclusion memory

[O1C-0074](../research/O1C0074_APPLE8_CAUSAL_ATTIC_STREAM_INTERPRETATION_20260719.md)
preserves a 550-clause immutable attic with a bounded `K=256` active
projection, occurrence accounting, duplicate/subsumption relations and
deterministic page selection. Subsequent paging experiments establish which
changes alter operational traces and which are scientifically inert.

### Central decision ownership

[O1C-0079](../research/O1C0079_APPLE8_DECISION_OWNERSHIP_INTERPRETATION_20260720.md)
composes prefix, rank and frontier readers through one level-bound ownership
lifecycle. It records 549 proposals, 549 bindings and 549 releases with zero
live or omitted tokens. The qualified prefix activates, but the call emits no
prune, new clause, model or key. The immutable raw classification contains a
validator false negative caused by matching the safe phrase
`never-returned-ever`; the additive
[zero-call erratum](../research/O1C0079_APPLE8_DECISION_OWNERSHIP_ZERO_CALL_ERRATUM_20260720.json)
corrects only the operational axes and leaves the scientific result negative.

## Reproduction and integrity

Every substantive attempt has a monotone O1C identifier. Complete capsules
include the frozen configuration, source and executable identities, timestamps,
resource ledgers, raw evidence, result interpretation and SHA-256 manifest.
Consumed target/page ordinals are never replayed for new science. Parser and
zero-call correction checks may operate on the archived bytes without invoking
the solver.

Use [REPRODUCIBILITY.md](../REPRODUCIBILITY.md) for the current verification
commands. `RESULTS_INDEX.md` maps the result lineage, while `STATUS.md` and the
append-only research ledgers preserve the exact resume point and negative
breadcrumbs.

Absolute build paths and machine metadata present in historical capsules are
intentionally retained because changing them would invalidate the sealed raw
record. They are provenance strings, not runtime dependencies. No credential,
private key or API token is part of the publication.

## Explicit limits

As of this release, the project has not recovered an unrestricted unknown
256-bit ChaCha20 key, established a practical ChaCha20 break, proved global
key-space exhaustion or demonstrated a generic full-round distinguisher. The
strongest claims are bounded retention, finite-panel ranking, exact safe branch
exclusion, causal exclusion memory and deterministic solver-reader composition.
The complete boundary is maintained in
[CLAIMS_AND_LIMITS.md](CLAIMS_AND_LIMITS.md).

Any future exact recovery claim must output a key without truth/reveal input and
pass an independent byte-exact standard ChaCha20 verification.
