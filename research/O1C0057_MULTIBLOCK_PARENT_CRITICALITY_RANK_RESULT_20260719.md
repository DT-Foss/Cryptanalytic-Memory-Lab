# O1C-0057 — Multi-block parent-criticality rank transfer

- **Recorded:** 2026-07-19T06:29:32+02:00 (`Europe/Berlin`)
- **Classification:** `MULTIBLOCK_PARENT_CRITICALITY_COMPOUNDING_TRANSFER`
- **Source freeze:** `ba44cbd064499b68e665aade71d15dca0c672b71`
- **Authoritative JSON SHA-256:**
  `bae7899503ec0d349dd7da51ebaca3cef2982c4e53d1ca560adcffe7bff47971`
- **Capsule manifest SHA-256:**
  `008b985868b18160711be70cc9fa2a7697d5888c5515702caef72228ea2a742e`

## Result

The unchanged O1C-0043 parent-criticality reader compounds across additional
public ChaCha20 blocks and transfers complete-key candidate rank on one fresh,
uniform Full-256 target. The same 4,096 decoys plus the hidden truth were scored
after 1, 2, 4 and 8 contiguous public blocks produced by one key and nonce.
Reader state, decoy calibration and every score used for ranking were frozen
before the single reveal.

| Public-block prefix | Primary truth rank | Key-rotated rank | Clause-rotated rank | Primary rank gain |
|---:|---:|---:|---:|---:|
| 1 | 8 / 4,097 | 2,079 / 4,097 | 3,156 / 4,097 | 9.000352 bits |
| 2 | 7 / 4,097 | 2,355 / 4,097 | 2,706 / 4,097 | 9.192997 bits |
| 4 | **1 / 4,097** | 3,678 / 4,097 | 3,297 / 4,097 | **12.000352 bits** |
| 8 | **1 / 4,097** | 3,581 / 4,097 | 4,037 / 4,097 | **12.000352 bits** |

The frozen prediction passes: prefix 8 strictly improves on prefix 1, clears
the predeclared threshold and has a strict margin over both rotations. The
prefix-8 aggregate truth z-score is `+5.57888245`. Mean primary decoy
cross-block correlation is only `0.11818565` (key-rotated `0.08765081`,
clause-rotated `0.10412927`), so the added blocks are not merely copies of one
calibration surface.

The revealed key independently reproduces all eight outputs. There was one
scientific entropy call, one fresh target and one reveal; no reader refit,
reweighting or sign selection occurred after ingestion.

## What this establishes

O1C-0057 is the strongest prospective complete-key rank result in this branch.
It shows that the transferred parent-criticality field is a reusable
multi-block scoring/order primitive: additional attacker-visible blocks can
compound its target-specific joint signal instead of diluting it.

The rank-1 result is approximately 12 bits of discrimination **inside the
supplied 4,097-candidate panel**. It is not exact key recovery, free candidate
generation, a search over the full `2^256` domain or evidence that the truth can
yet be placed in such a panel without privileged information. Candidate keys
were supplied before scoring; the mechanism chose their order.

## Highest-ROI continuation

Do not spend the next experiment merely enlarging another supplied decoy panel.
Freeze the prefix-8 scorer and make it order attacker-generated partial
assignments or bounded exact-search branches. The next pass condition must be a
predeclared reduction in matched search work, effective residual width, or
verified exact-key beam rank. This directly tests whether the transferred
complete-candidate rank can become a live Full-256 search advantage.

## Cost and provenance

- 95.8946 s elapsed; 193,544,192 B peak RSS.
- 32,776 candidate forward evaluations and 4,096 native probe branches.
- 4,096 decoys plus truth; eight public blocks; one sensor build.
- Zero solver calls, sibling reads/writes, MPS or GPU work.
- Capsule: [`runs/20260719_062932_O1C-0057_multiblock-parent-criticality-rank-v1`](../runs/20260719_062932_O1C-0057_multiblock-parent-criticality-rank-v1/RUN.md)
- Authoritative machine result:
  [`O1C0057_MULTIBLOCK_PARENT_CRITICALITY_RANK_RESULT_20260719.json`](O1C0057_MULTIBLOCK_PARENT_CRITICALITY_RANK_RESULT_20260719.json)

The capsule contains 80 manifest entries plus the manifest itself. All 80
entries pass `shasum -a 256 -c artifacts.sha256` from the capsule root.
