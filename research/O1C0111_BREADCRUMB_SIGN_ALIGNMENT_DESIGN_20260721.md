# O1C-0111 — Frozen local-prunable sign-alignment design

- **Frozen before truth read:** 2026-07-21 (`Europe/Berlin`).
- **Parent result:** O1C-0109, SHA-256
  `22ec1c6a2f67c0ec89c85347865c4fc248c43ad2dacc8955fd76a72940a52c28`.
- **Breadcrumb sidecar:** 46,063 bytes, SHA-256
  `da472d3a8d60deb95227e36cb7264734169db4da369fa9006835930dee401014`.
- **Canonical 100-row digest:**
  `74e34b57d61162c443119d65f4434540b455746bccb98e5090729d8e07fd80f5`.
- **Calls:** no solver, native, target generation, refit, MPS or GPU call.
  The sole permitted truth access is the already sealed historical O1C-0057
  reveal, and only after source, tests and config are hash-frozen.

## Pre-truth census

The O1C-0109 sidecar is complete: 100/100 rows retained, zero overflow, all
rows observed after their coordinate had already been consumed and zero rows
were crossing-eligible. There are 37 `ONE_PRUNABLE` and 63 `BOTH_PRUNABLE`
rows, but only two distinct key coordinates:

- coordinate 193 / variable 194: 57 rows, of which 8 are one-prunable;
- coordinate 196 / variable 197: 43 rows, of which 29 are one-prunable.

All 37 one-prunable rows have `upper_one < upper_zero` and losing literal
`+variable`. This census used no key truth.

## Frozen primary reader

1. Authenticate the exact O1C-0109 result, capsule and complete sidecar.
2. Retain only rows with `consumed_before=true`,
   `crossing_eligible=false`, and `classification=ONE_PRUNABLE`.
3. For each row compute `d = upper_one - upper_zero` in binary64.
4. Aggregate each coordinate in canonical probe order with `math.fsum`:
   `S_v = fsum(d)`.
5. Predict key bit 1 if `S_v > 0`, bit 0 if `S_v < 0`, and abstain only on
   exact zero. No post-reveal sign inversion is allowed.

`BOTH_PRUNABLE` rows are a separately reported secondary relative-bound arm;
they cannot change the primary prediction or rescue it after reveal.

Key bits use the project's existing RFC little-bit-within-byte coordinate
mapping from `living_inverse.key_bits`. The historical truth must be parsed and
verified through the existing sealed broker/reveal API.

## Measurements and controls

Report unique/repeated coordinates, abstentions, predicted bits, correct bits,
the exact one-sided fair-coin binomial tail, per-coordinate sums, and weighted
alignment `M0 = sum(truth_spin_v * S_v)`. Evaluate the frozen reader against all
255 nonidentity cyclic truth-coordinate rotations plus identity, with
conservative tie accounting, and against a global sign-flip arm.

The broad-posterior promotion gate remains predeclared at at least 32 unique
nonzero coordinates, one-sided binomial tail at most 0.05, primary cyclic-rank
fraction at most 0.25, and strict positive sign-flip margin. The known two-
coordinate coverage therefore cannot pass this gate, regardless of accuracy.

The two coordinates are nevertheless evaluated because results below 256 bits
are not discarded. If both frozen directions are correct, classify only
`RETROSPECTIVE_TWO_COORDINATE_DIRECTIONAL_BREADCRUMB`; otherwise classify
`RETROSPECTIVE_TWO_COORDINATE_MIXED_OR_WRONG`. Even 2/2 has fair-coin tail 0.25
and is neither a posterior, entropy reduction, independent recovery, nor a
fresh attacker-valid claim. It authorizes only exact unchanged replication on
fresh targets. A miss cannot be repaired by flipping the sign on this target.

The result must freeze canonical input, aggregate, control, truth-source and
result hashes and explicitly record that O1C-0109 itself read zero truth bytes.
