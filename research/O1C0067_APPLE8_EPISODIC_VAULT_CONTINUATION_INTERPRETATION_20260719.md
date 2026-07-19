# O1C-0067 — APPLE8 episodic-vault continuation interpretation

- **Recorded:** 2026-07-19T15:26:04+02:00 (`Europe/Berlin`).
- **Classification:** `EPISODIC_VAULT_SATURATED_NO_GAIN`.
- **Source:** `865634458ef3f5b01a5881208eb028404b96f135`.
- **Capsule:**
  [`runs/20260719_152601_O1C-0067_apple8-vault-continuation-v1`](../runs/20260719_152601_O1C-0067_apple8-vault-continuation-v1/RUN.md).
- **Seals:** authoritative result SHA-256
  `c01ffe69198e997c6d3798e0b9f3190065bd7b58ec3ab1ba67a66a7ccd799f1f`;
  capsule manifest SHA-256
  `2562db062186fb5168e66c69943af83ba19a151bdc17489111a15dbb114f9341`.

## Result

The single authorized continuation used local ordinal `0` and lineage ordinal
`3`. It requested `512` conflicts and observed/billed `514` (`+2`). The input
and output vaults are byte-identical at `12` clauses, `35,061` literals and
`140,483 B`. Native code fully emitted one `2,951`-literal clause with SHA-256
`b5da89ef9791d65487e214da71e4f36b0600ceea033cc1917c4ba9f392f89c84`;
it is an input duplicate matching vault index `7` (zero-based; the eighth stored
clause), so no
novel clause or literal survived.

The carried vault still reduces work relative to O1C-0066's last completed
episode: decisions are `4,517` (`-149`) and propagations are `1,192,529`
(`-38,039`). Minimum upper bound is `9.111031965569408`, however, versus
`7.973483108047071` in the parent (`+1.1375488575223374`), so this is not a
new bound frontier. Runner elapsed time is `4.553662 s`; native wall/CPU are
`0.333463/0.921060 s`, with `392,609,792 B` native peak RSS.

## Interpretation and boundary

This is a fixed point for the exact reader, seed and soft horizon tested, not a
claim that every vault reader or schedule is exhausted. The archive demonstrably
reduces matched search work, but the unchanged vault, duplicate emission and
higher minimum upper bound provide no further novelty or recovery gain. No key,
truth byte, reveal, fresh target, entropy call, refit, MPS or GPU was used.

Do not replay this call or blind-scale the same horizon. The next bounded test
must change the reader operator explicitly: prefer the complementary phase
reader with `forcephase=true` and `phase=false`, or precommit another distinct
reader operator while preserving the sealed vault and exact accounting.

The authoritative machine result is
[`O1C0067_APPLE8_EPISODIC_VAULT_CONTINUATION_RESULT_20260719.json`](O1C0067_APPLE8_EPISODIC_VAULT_CONTINUATION_RESULT_20260719.json).
