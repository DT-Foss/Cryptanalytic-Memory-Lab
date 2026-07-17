# O1C-0014 Post-Reveal Forensics

- **Recorded:** 2026-07-17T09:03:05+02:00 (`Europe/Berlin`)
- **Scope:** read-only analysis of finalized O1C-0013/O1C-0014 artifacts
- **Claim boundary:** mechanism selection for O1C-0015 only; no O1C-0014 result
  is upgraded by this document
- **O1C-0014 manifest:**
  `741718cbc6b63de24f4d9c89cd2aedc8e9779a0ebb38adc4d40666e97ce24bcf`
- **O1C-0014 evaluation commitment:**
  `69a3142f56b08f60890b4849ab9d71d4a68aecb4ad5db3a0f24b304cf041b6ef`

## Frozen result

The exact O1C-0013 h96 bytes obtain `+0.233784143` bit/key, `1053/2048`
correct bits and conditional-uniform `z=1.819365` on eight new keys. Only `4/8`
targets are positive; paired primary-minus-shuffled `z=0.838026`; wrong-nonce and
byte-rotation controls are positive. The predeclared class remains
`NOT_REPLICATED`.

Target compressions in sealed order:

```text
-0.182409  +0.502634  +0.827483  -0.145782
+0.237792  -0.173504  -0.307404  +1.111464
```

All four positive targets have better million-decoy ranks than all four negative
targets. Positive-target ranks are `119,732`, `22,221`, `260,286`, `10,875`;
negative-target ranks are `574,513`, `556,972`, `591,464`, `644,297`.

## Pre-existing reader-arm reconstruction

The 36 O1C-0013 BUILD candidates (six arms times six ridge values) were
reconstructed from O1C-0013's persisted BUILD features/labels. All 36 candidate
SHA-256 values match the commitments recorded before O1C-0014. For each arm, the
temperature and logit scale are the already-recorded O1C-0013 CAL optimum; no
O1C-0014 label is used for fit or hyperparameter selection.

| Pre-existing arm | O1C-0013 CAL bit/key | O1C-0014 post-reveal bit/key | Correct bits | Positive targets |
|---|---:|---:|---:|---:|
| h64 | +0.346122 | +0.139097 | 1055/2048 | 5/8 |
| h96 | +0.571530 | +0.233784 | 1053/2048 | 4/8 |
| h65 | +0.440950 | +0.188340 | 1052/2048 | 6/8 |
| U3 | +0.457572 | +0.169106 | 1059/2048 | 5/8 |
| U3+ARX24 | +0.569105 | -0.374410 | 1057/2048 | 3/8 |
| U3+ARX24+M12 | +0.348758 | -0.355199 | 1045/2048 | 2/8 |

The richer coarse ARX/motif arms reverse while every unary wavelength remains
aggregate-positive. This is the strongest architecture discriminator in the
panel. It does not make any reconstructed arm a blind O1C-0014 result because only
h96 had a binary and predictions frozen before target entropy.

## Coordinate and structural audit

- Coordinates correct on at least 7/8 targets: `13` (uniform expectation `9`;
  approximate tail `0.12`).
- Coordinates correct on at least 6/8: `36` (uniform expectation `37`).
- Coordinates correct on 8/8: `0`.
- O1C-0013 versus O1C-0014 top-16 coordinate overlap: `0`.
- Cross-panel coordinate-compression correlation: `-0.024` (permutation
  `p≈0.704`).
- First 128 key bits contribute `-0.052` bit/key; second 128 contribute `+0.286`.
- Largest exploratory word/lane/bit-position views are key word 6
  (`+0.140`), ChaCha key lane 2 (`+0.147`) and within-word positions 24/13/6
  (`+0.0896/+0.0688/+0.0600`).

These are multiple post-reveal views and do not reproduce as a stable coordinate
map. They cannot justify a mask, lane filter or partial-key claim.

## O1C-0015 mechanism freeze

The only new primary mechanism is the exact equal-logit two-wavelength operator

```text
logit(q_ensemble) = 0.5 * logit(q_h96) + 0.5 * logit(q_h65)
```

h96 remains an exact-byte primary baseline. h65 is reconstructed exclusively from
O1C-0013 BUILD/CAL, serialized and frozen before new entropy. The matched shuffled
ensemble uses the identical operator.

On O1C-0014 this formula is only a post-reveal design diagnostic:

- compression `+0.229` bit/key;
- `1066/2048` correct bits (`52.05%`);
- `6/8` positive targets;
- conditional-uniform `z=2.107`;
- matched-shuffled paired `z=2.066`.

O1C-0015 attacks 32 entirely new sealed full-256 keys, persists h96, h65, ensemble
and matched-control predictions before any reveal, and makes no use of O1C-0014
features or labels during fit or inference. Failure pivots to the separately
designed h96 query-rooted carry/proof cone rather than weight or coordinate search.
