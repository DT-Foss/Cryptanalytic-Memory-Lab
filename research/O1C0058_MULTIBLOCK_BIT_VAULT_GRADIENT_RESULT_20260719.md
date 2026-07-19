# O1C-0058 — Multi-block bit-vault gradient

- **Started:** 2026-07-19T07:06:54+02:00 (`Europe/Berlin`)
- **Recorded:** 2026-07-19T07:08:33+02:00
- **Classification:** `MULTIBLOCK_BIT_VAULT_NO_DIRECTIONAL_TRANSFER`
- **Science source:** `09cc48b9d61b4cccbeaa7cf038404ac4f2a3b15a`
- **Terminal recovery source:** `d9d1a851f873ecd0afc33236adac52b8866ccb1f`
- **Authoritative JSON SHA-256:**
  `1ff36f9479b397f50c9421a7c0ba406df308ab8c9989d2e039e0874a1acbcb64`
- **Capsule manifest SHA-256:**
  `9367abdae4b8514eec3c9518c8cfc54f9b8a34ce45ec4ebc5c009280507b3b06`

## Result

One fresh uniform Full-256 target supplied eight contiguous public ChaCha20
blocks from the same key and nonce. The unchanged O1C-0057 primary scorer chose
the best of 4,096 public decoys after all eight blocks. From that same attended
base, O1C-0058 scored all 256 one-bit neighbors per block and streamed their
signed score deltas into one 256-cell `float64` vault per arm. All vaults,
confidence orders, synthesized keys and public verifications were frozen before
the one-shot reveal.

| Prefix-8 candidate | Correct bits | Gain over base | Longest correct confidence prefix | Exact public match |
|---|---:|---:|---:|---:|
| Attended base | 127 / 256 | — | — | no |
| Primary vault | 127 / 256 | 0 | 0 | no |
| Key-rotated control | 127 / 256 | 0 | 1 | no |
| Clause-rotated control | 128 / 256 | +1 | 0 | no |

The primary prefix-8 vault flipped only two base bits and gained zero correct
bits. Its top-eight confidence bits were not all correct, its longest fully
correct confidence prefix was zero and neither the primary guidance gate nor
either partial-recovery gate passed. No exact-recovery gate passed. The attended
base and all 12 synthesized arm/prefix candidates matched `0/8` public blocks;
none was an exact key.

## Mechanism boundary

Close the exact rule tested here: select the highest-scoring complete decoy from
the supplied panel, measure positive one-bit finite differences around it and
interpret the accumulated signs as key-bit direction. O1C-0057's complete-key
multi-block scorer remains a positive rank/order result. The supplied-panel
optimum had two locally score-improving primary directions, but those flips did
not improve truth alignment: scalar complete-key rank did not factor into useful
coordinate-wise direction on this fresh target.

This result does not reject O1 memory, multi-block compounding, partial-
assignment scoring, exact joint search or complete-decoy crowd/elite consensus
as a family. It closes only this attended-best-decoy plus positive one-bit-delta
vault. A separate cheap crowd-consensus scratch was control-negative, but it was
not part of the formal O1C-0058 run and carries no O1C-0058 closure claim.

## Highest-ROI continuation

O1C-0059 should preserve the eight-block score as an exact joint potential over
live CNF partial assignments instead of differentiating complete keys one bit at
a time. APPLE8 is its matched exact feed-forward-cancelled Cross-Block-CNF
augmentation: retain the public P20 units and add
`P_b = P_0 + (Z_b - Z_0)` on the key lanes, with O1C-0059's potential,
threshold and budget unchanged. These are logically redundant consequences of
the existing eight-block shared-key CNF, not new public information or a changed
solution set. The comparison must earn a strict propagation or pruning gain;
telemetry volume alone does not pass.

## Cost and bounded state

- 99.07695375000185 s elapsed; 211,124,224 B peak RSS.
- 34,824 candidate forward evaluations; 112 direct ChaCha block evaluations.
- 2,048 B primary live state; 6,144 B for all three simultaneous arms.
- One fresh target, one scientific entropy call and one reveal.
- Zero solver, sibling, MPS or GPU work.
- Original parent and child CPU seconds are unavailable and remain `null`; they
  were not reconstructed or estimated.

## Terminal serialization recovery

The science run completed and wrote every frozen scientific artifact, then
failed only while serializing a NumPy `int64` into terminal JSON. Commit
`d9d1a851f873ecd0afc33236adac52b8866ccb1f` reconstructed the terminal result
strictly from those artifacts with zero added entropy, reveal, scoring, native
probe or scientific trial. The original `RUN.md` and science command remained
byte-identical.

- [`RUN.md`](../runs/20260719_070833_O1C-0058_multiblock-bit-vault-gradient-v1/RUN.md),
  SHA-256 `05eadbcaef8db7003be3bd5a7144969a659cc2be52ffbc1c32e90d7dc1ed97f0`
- [`RECOVERY.md`](../runs/20260719_070833_O1C-0058_multiblock-bit-vault-gradient-v1/RECOVERY.md),
  SHA-256 `3da16a6017fc58a174d7d45e1c31f5052abce9f10ada8d7815741b512d7b7199`
- [Authoritative machine result](O1C0058_MULTIBLOCK_BIT_VAULT_GRADIENT_RESULT_20260719.json),
  byte-identical to the capsule `result.json`

The capsule contains 178 manifest entries plus the manifest itself, for 179
files total. All 178 entries pass `shasum -a 256 -c artifacts.sha256` from the
capsule root.
