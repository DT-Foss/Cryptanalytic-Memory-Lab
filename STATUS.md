# O1 Cryptanalytic Memory Lab — Current Status

- **Last updated:** 2026-07-15T13:56:31+02:00 (`Europe/Berlin`)
- **O1C-0005 implementation commit:** `a1ebe8a01bcfc1369b413e53c2e15ab4be043cb5`
- **Research phase:** Stage 5 — O1/O1-O bounded-memory validation; fresh-target gate next
- **Strongest internal result:** `VALIDATION / BOUNDED MEMORY TRANSFER` — O1-O
  selected a 4-bit, 16-slot spectral Bit-Vault from A348 alone; its 6,668-byte
  online state retained the A349 score order at rank-Spearman `0.990198`
- **Strongest external frontier anchors:** confirmed Threefish-1024 W39 complete
  domain and ChaCha20 A325 W46 strict-subset recovery; both remain read-only inputs
- **Active runs:** none
- **Last completed attempt:** `O1C-0005` — receipt-bound bounded-memory tournament
- **Primary uncertainty:** whether the frozen 16-scale template transfers to a
  genuinely untouched target and creates exact-recovery advantage rather than only
  high score-field fidelity
- **Blockers:** none

## Headline

`O1C-0005` compared 72 bounded mechanisms on A348 and transferred every frozen arm
to A349 only after O1-O had persisted its future choice. O1-O chose the 4-bit
Bit-Vault at 6,668 online bytes and zero clips; A348 calibration fidelity was
Spearman `0.990466`, Kendall `0.912033`, top-32 `0.75`. The same frozen 16 scales
gave A349 Spearman `0.990198` and top-32 overlap `0.71875`. All 86 A349 orders
(including declared ceilings) were receipt-bound and persisted before the separate
A348 truth call; A349 target/outcome/progress and labels remained unread.

The mechanism result is directional: dense low-precision registers transfer better
than sparse calibration-selected modes. At matched K=2,048, A272-distributed slots
reached `0.871477`, versus low-degree `0.494256`, best deterministic random
`0.716923`, and single-A348 sparse support `0.797225`. A349 field fidelity had been
inspected during mechanism development, so this is a mechanistic validation—not a
fresh architecture or recovery claim. The next run must use a new untouched field.

## Active process table

| Attempt | PID | Started | Command | Progress | ETA |
|---|---:|---|---|---|---|
| None | — | — | — | — | — |

## Highest-ROI next actions

1. `O1C-0006`: precommit a new lab-owned Direct12 field that has never entered
   architecture development; bind the already frozen 4-bit/16-scale template.
2. Persist its complete target-blind order with the same receipt protocol, then run
   equal-work exact recovery without any refit or A349 feedback.
3. Independently confirm any recovered candidate with the public full-round cipher;
   retain an exact negative result as the next observability breadcrumb if it fails.

## Recent attempts

| Attempt | Time | Hypothesis | Result | Claim level | Cost | Main breadcrumb | Artifact |
|---|---|---|---|---|---|---|---|
| `O1C-0005` | 2026-07-15 | Distributed slots and dense low-precision state transfer better than sparse single-field support; O1-O can freeze the smallest gated bank | Gate passed; O1-O chose 4-bit/H1.25, 6,668 B, zero clips; A349 Spearman 0.990198; 86/86 orders persisted; zero A349 labels | `VALIDATION` | 38.521 s; 72+72 arms; 311,689,216 update accumulations; zero solver/GPU work | Precision allocation beats coefficient pruning; carry the 16-scale template unchanged to a fresh field | [Run capsule](runs/20260715_135434_O1C-0005_bounded-spectral-memory-tournament/RUN.md) |
| `O1C-0004` | 2026-07-15 | The lab can independently reproduce the complete 532-feature Direct12 reader and frozen A348/A349 commitments | Gate passed; 52/52 shards, 13,312 cells, model/features/scores/orders exact; A348 rank 298 after freeze; zero A349 labels | `VALIDATION` | 5.986 s; 53,248 reused stages; zero new solver/GPU work | The real A349 field is now a legal target-blind input to bounded O1 memory | [Run capsule](runs/20260715_130047_O1C-0004_direct12-532-reproduction/RUN.md) |
| `O1C-0003` | 2026-07-15 | The dirty-source Direct12 dependency set can be pinned without reading progress/outcome | Gate passed; 71/71 members, 9,882,690 bytes, denied reads 0 | `SMOKE` | 0.069 s; zero solver/GPU work | Provenance is now lab-owned without misattributing it to the clean Fullround manifest | [Run capsule](runs/20260715_123734_O1C-0003_direct12-source-snapshot/RUN.md) |
| `O1C-0002` | 2026-07-15 | A 57-feature reader selected on A296 validation transfers to disjoint A296/W32 targets | Gate failed; validation 3.348 bits, A296 holdout 0.801, W32 1.104; familywise `p=0.664` | `RETROSPECTIVE` | 119 readers; 65,536 exact null label pairs; zero solver/GPU work | Replace single-channel selection with independently fixed joint temporal/XOR geometry | [Run capsule](runs/20260715_123236_O1C-0002_retrospective-reader-tournament/RUN.md) |
| `O1C-0001` | 2026-07-15 | A296/A297 can be normalized without post-reveal access | 12 episodes, 3,072 cells, 12,288 stages, 57 features; 24/24 members verified; zero labels read | `SMOKE` | 0.360 s; zero solver/GPU work | The real observability experiment can run entirely offline | [Run capsule](runs/20260715_122529_O1C-0001_stage3-a296-a297-ingest/RUN.md) |
| `O1C-0000` | 2026-07-15 | The three architectures can share a typed, bounded and reproducible control seam | Harness complete; no cipher signal tested | `INSTRUMENT` | 42 tests; five synthetic seeds | Stage 3 is the first unresolved scientific gate | [First results](docs/FIRST_RESULTS.md) |

## Reproducibility anchors

| Artifact | SHA-256 |
|---|---|
| `runs/quick.json` | `755e0ebee06337ac576a19d8408e4f5d9ae5d29b0c87063b021210b5b29e39da` |
| `runs/o1o-2026-02-18-replay.json` | `2f106c488c7eab15aee1cbed80114f6de2c33a9a2858152b1e2dc373d2b8dac1` |
| `runs/fullround-source-verification.json` | `8920811c6424a9d81be36ae658bcbbc3f09f5c826f04c768e493ea33a5d8458b` |
| `O1C-0001` capsule manifest | `376e3b27f107d132421e29c2669f468a57c8417924928ce41badadf14d3dd05f` |
| `O1C-0002` capsule manifest | `b4a242708ae30481deed5346df519bb5123c7601fa6c58b6c06bd514be314ff9` |
| `O1C-0003` capsule manifest | `d7dcb2b2c3f39d866c7820dbc7423ce55b4d5c9df6634d5a00126a954a0a065d` |
| `O1C-0004` capsule manifest | `ac3333606e0aaf47dc519553c0e9407fc8ab67dba5319ed340eac579cb25c7bf` |
| `O1C-0005` capsule manifest | `de67260cf44556a3fa48ef2b6daa1b738cf40b392739c6a05d835cbcdb1ab103` |
| `O1C-0005` deterministic report | `cf930a4f206423bbbd6072b90343c5955c56110d9640a36b12c7f639ad1723b8` |
| O1-O frozen selection | `5aaf243457850fbc1435cad8ff257da4eaf6a9b3ec983042f46dde690c1a5983` |
| Frozen 4-bit future template | `245ecb1c1ae8ec90c9feca6466ba007034635b1e737d607979f3ba237682b9d7` |
| A349 4-bit frozen order | `879d31ef67ae955951dba84fd27d7e8d9cfa9a08e51c8a518d3ff44c0b5e5e7e` |
| Stage-3 dataset | `ccd1c4e236cba798362745b0430beecf294599e1ac4332fd5d8ad4f8625161c1` |
| Frozen reader plan | `ae2bda0e6a337b5396cbbab2e72108c38f67543b137f2e266a4f3943d7d7a587` |
| Direct12 role-separated dataset | `6d645aa7e06fbc7e746a4e6bfe410cbc1b845357c54740bb6fd00c2bbd6a32ff` |
| A349 frozen order | `441c6af3d9a2a32e1a61f0d50804a1ecbf2363517a7b570c408a09a15fd1bbaa` |

## Resume here

Read [Next actions](research/NEXT_ACTIONS.md), then the top active hypothesis in
[Hypotheses](research/HYPOTHESES.md). Do not restart the repository audit.
