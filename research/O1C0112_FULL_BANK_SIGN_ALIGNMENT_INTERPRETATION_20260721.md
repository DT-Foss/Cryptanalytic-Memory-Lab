# O1C-0112 — frozen full-bank sign alignment

Date: 2026-07-21  
Classification: `RETROSPECTIVE_FULL_BANK_NO_DIRECTIONAL_ALIGNMENT`

## Result

The frozen primary reader `S_v = -final.robust_z_mean` predicts 255/256 coordinates and scores `130/255` correct (`50.98%`). Its exact one-sided binomial tail is `0.401134`, conservative cyclic rank is `198/256` (`77.34%`), and the identity alignment loses to its global sign flip by `43.1644`. It recovers `0/31` fully predicted bytes and `0/15` fully predicted 16-bit words.

None of the six predeclared secondary diagnostics rescues the result. The largest raw correct count is the increment raw-mean arm at `138/255` (`54.12%`), but its one-sided tail is `0.105161`, cyclic rank is `166/256` (`64.84%`), and its identity alignment also loses to sign flip. The only secondary arm with a positive sign-flip margin is final centered signed consistency at `133/255`; its tail is `0.265625` and cyclic rank is `100/256`. All seven arms recover zero exact bytes and zero exact 16-bit words.

## Meaning

The 24,576-byte bank is a genuine bounded, coordinate-addressable memory of 449,663 accumulated probes, and O1C-0109 changed 255 records with 33,569 new observations. This result shows that the bank's unconditional marginal signs are not a Full-Round key posterior. The state is useful as a causal/query-priority carrier, but key orientation requires conditioned relations or a learned cross-target operator.

No attacker-valid entropy reduction, posterior, beam hit, key bit, or recovery follows. Do not sweep signs, normalizations, scales, offsets, or the seven consumed formulas on this historical key.

## Reveal contract correction

The first joint capsule stopped after one physical reveal-file read because O1C-0112 incorrectly required byte-canonical JSON in addition to the already frozen file hash and broker semantic verification. It made zero broker calls and read zero key bytes. Commit `f2477af` removes only that extra formatting assumption and adds a regression test; all score formulas and gates remain unchanged. The reader was then refrozen under score-freeze SHA-256 `c4691fe4d8c8c91463bdadb63c96b3047d6b93922e4180a4ee374a286bfad466` before the successful historical reveal.

## Provenance

- result identity SHA-256: `477fc736a7a0d7105639e9917e38fed46310a010f4a29190a53aaca5b2987387`
- serialized result file SHA-256: `222e6b7157cbb7c20382b76dc29c5d3aa4a36edf09d2176f286a077aa232da12`
- terminal pre-truth contract capsule: `runs/20260721_112152_890375_O1C-0111_O1C-0112_joint-frozen-historical-alignment-v1`
- successful capsule: `runs/20260721_113111_793173_O1C-0111_O1C-0112_joint-refrozen-historical-alignment-v1`
- successful resources: 63.8769 s freeze/authentication, 0.002936 s reveal verification, 0.038333 s evaluation; zero solver/native/fresh-target/refit calls

## Next action

Retain the full bank as an O(256) causal carrier, but replace unconditional sign reading with a prelearned, output-conditioned relational operator on fresh targets. Page continuation remains useful for growing the causal attic; it is not by itself a key posterior.
