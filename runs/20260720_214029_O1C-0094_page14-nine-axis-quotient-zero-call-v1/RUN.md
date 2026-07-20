# O1C-0094 — Page-14 nine-axis quotient zero-call receipt

- Classification: `LOSSLESS_NINE_AXIS_COMPRESSION_QUOTIENT`
- Input: sealed O1C-0092 Page-14 vault, `5,265,088 B`, SHA-256 `8cb5123d0867923a778ef08d64f73b71f51f8c41003b913da183f21e91dbd61b`
- Reconstructed: `261` clauses / `756,414` literals / aggregate `dad3883312e769efb4a650557a8cd0fdf0e53e0ca6ecbc840fb335c76730fce0`
- Per-row canonical clause and witness identities: exact for all `261`
- Shape: `2,709`-literal shared core; five prefix rows; `256 x 2,898` equal-support tail
- Decoder: axes `(15, 18, 23, 28, 100, 118, 181, 216, 238)`, `118` copy/complement variables, `256` unique nine-bit codewords
- Map: `1,574 B`, SHA-256 `c3103ef67f4edf1cb93f7443e1c3f7866bdb30af53c7866ca9376be396618185`
- Eight-axis multiplicities: `253 x 1`, `2 x 2`, `1 x 4`
- Proper subsumption: exactly one, clause `3 -> 2`; both rows retained for lossless reconstruction
- Conservative literal-entry accounting: `756,414 -> 47,514`, `93.7185192236%` reduction, `15.9198131077x`
- Packed streaming-decoder bound: `18,034 B` retained + `11,732 B` one-row scratch = `29,766 B`
- Native solver / preflight / science / public verification / target / truth / reveal / refit / MPS / GPU calls: `0`
- Focused verification: `10` tests passed; Ruff format/check clean; Pyright `0` errors / `0` warnings
- Focused-test runtime: `3.97 s` real / `3.87 s` user / `0.06 s` system
- Focused-test maximum resident set: `278,953,984 B`
- Result: `37,617 B`, SHA-256 `0bc68cb220386239b5dd046a8578777825dca88b6c7a2dfa8bd70be822fdc9a2`
- Interpretation: `3,115 B`, SHA-256 `5fa21befd75c34a53e179d46782d600fa253c2e51e52d58d196f9b41c94dff51`

This capsule records a compression result only. The observed copy/complement
map is not a CNF equivalence proof and authorizes no logical substitution,
key-bit claim, entropy gain, model, closure, or attacker-valid domain reduction.
Both persisted outputs are reproduced byte-for-byte by the commands sealed in
`config.json`.
