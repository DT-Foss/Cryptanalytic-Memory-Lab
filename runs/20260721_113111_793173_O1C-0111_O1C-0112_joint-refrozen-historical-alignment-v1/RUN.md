# O1C-0111 + O1C-0112 — joint refrozen historical alignment

Created: 2026-07-21 11:31:11 CEST  
Commit: `f2477af261ffc4f14371d61a9bae9764c326abb0`

Both truth-blind readers were authenticated, serialized, fsynced, and jointly sealed before the historical reveal. One physical reveal-file read and one broker verification then produced one in-memory truth object shared by both finalizers. The raw key was not persisted.

## Results

- O1C-0111: `RETROSPECTIVE_TWO_COORDINATE_MIXED_OR_WRONG`; primary `0/2`, secondary `0/2`.
- O1C-0112: `RETROSPECTIVE_FULL_BANK_NO_DIRECTIONAL_ALIGNMENT`; primary `130/255`, binomial tail `0.401134`, cyclic rank `198/256`; all byte and 16-bit exact counts zero.
- Best secondary correct count: `138/255`, but binomial tail `0.105161`, cyclic rank `166/256`, and negative identity-over-sign-flip margin.
- No solver, native, fresh-target, target-generation, GPU, MPS, or refit call.
- Timing: 63.876903 s freeze/authentication, 0.002936 s reveal verification, 0.038333 s evaluation.

## Contract history

The immediately preceding terminal capsule made one validation-only physical file read and rejected noncanonical JSON before broker verification or truth extraction. This successful capsule uses the corrected sealed-file-plus-broker contract, then refreezes the unchanged scores before its own reveal read. Cumulative physical reads are two; only this capsule made a broker call or materialized the 32-byte historical key.

## Claim boundary

This is retrospective diagnostic evidence only. It provides no attacker-valid bit, entropy, posterior, beam, exact key, or SOTA recovery claim. It closes raw sign orientation for the consumed two-coordinate sidecar and all seven frozen marginal bank formulas.
