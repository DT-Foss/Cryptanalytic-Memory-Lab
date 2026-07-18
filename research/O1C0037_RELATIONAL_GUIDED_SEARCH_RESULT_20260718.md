# O1C-0037 — Exact relational guidance result

`O1C-0037` is the first direct coupling of a frozen O1 full-256 score field to
the unchanged exact public ChaCha20-R20 relation. O1 scores are not converted to
key units: their signs and confidence order enter CaDiCaL as reversible,
first-encounter key decisions. Every SAT model is independently checked against
the public counter, nonce and output block.

The consumed `build-0000` target gives a clean mechanism split. Exact post-reveal
guidance recovers and verifies all 256 key bits in `5,065 us` with zero conflicts.
One wrong key-only hint is not repaired through `32,768` conflicts and
`8,908,928 us`. The attacker-valid frozen O1 field has `117/256` correct MAP
signs, produces no exact recovery, takes `2.123064x` the matched internal wall
time at K256 and has effectively identical K256 telemetry to its coordinate-
shuffled control (`1.004823x`). Key-phase-only guidance over this field is
therefore closed; the exact adapter remains useful as a residual-width and
relation-factor instrument.

One declared ceiling row needs an explicit correction. The
`oracle_one_residual_guided_k255` row received the one-error score vector. Because
the quantized field contains tied minimum magnitudes, its selected K255 prefix
contains `254` correct hints plus one wrong hint, with one additional bit
unguided. It is not evidence about the intended `255 correct + 1 unguided`
condition. The immutable capsule is retained exactly as produced, and O1C-0038
measures the corrected all-correct residual prefix under a new ID.

- Source commit: `ae0bcd339f4cfef42bda10c7d345bc34b4750753`
- Elapsed: `14.513263 s`
- Peak RSS: `139,853,824 B`
- Native solver calls: `12`
- Requested conflict ledger: `47,616`
- Capsule manifest: `1f3532e68fa15c4b1ced1e6456409f69b7f791c8f1def45f048b76049af0343a`
- [Immutable capsule](../runs/20260718_211056_O1C-0037_relational-guided-search-v1/RUN.md)
- [Machine-readable result](O1C0037_RELATIONAL_GUIDED_SEARCH_RESULT_20260718.json)

