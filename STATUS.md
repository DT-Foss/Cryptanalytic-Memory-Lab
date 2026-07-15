# O1 Cryptanalytic Memory Lab — Current Status

- **Last updated:** 2026-07-15T15:50:05+02:00 (`Europe/Berlin`)
- **Implementation commits:** `e8ecbf7` (corrected bridge), `f3e6274` (order hardening)
- **Research phase:** Stage 5 — compact causal/bit-memory successor before fresh test
- **Strongest internal result:** exact A355/A356 corrected-codec reproduction plus a
  6-bit adaptive full-basis ceiling at worst-field Spearman `0.999224`
- **Strongest external frontier anchors:** confirmed Threefish-1024 W39 complete
  domain and ChaCha20 A325 W46 strict-subset recovery; both remain read-only inputs
- **Active runs:** none
- **Last completed attempt:** `O1C-0006` — corrected-codec adaptive-DC bridge
- **Primary uncertainty:** whether upstream carry/solver evidence can be retained in
  a genuine compact O1 state that beats the matched 3,918-byte direct-table baseline
- **Blocker before a fresh challenge:** no eligible compact successor yet

## Headline

`O1C-0006` corrected the W46 Direct12 codec to
`cell = (assignment >> 20) & 0xfff`, reproduced both historical 4,096-cell score
fields and orders exactly, and ran nine frozen adaptive-DC arms after the attempt
was irrevocably reserved. The selected `adaptive-dc-6bit-h1` arm uses 7,716 online
bytes and at most 8,014 bytes of serialized logical mechanism state. It achieved:

- A355 Spearman `0.9996473`, Kendall `0.9836352`, top-32 `0.96875`;
- A356 Spearman `0.9992244`, Kendall `0.9764259`, top-32 `0.96875`;
- top-8 `1.0` on both fields, worst-field top-128 `0.9453125`, zero clips.

The audit also establishes the decisive boundary: the 16×256 Walsh bank has 4,096
degrees of freedom and is information-equivalent to a direct candidate table. Its
8,014-byte maximum logical state is `2.045431×` the matched 3,918-byte 6-bit table,
with identical quantized orders on both fields. This is a valid reconstruction
ceiling and codec/streaming validation, not compression, fresh generalization,
recovery or SOTA. A compact successor must beat the direct table before any fresh
challenge is generated.

## Active process table

| Attempt | PID | Started | Command | Progress | ETA |
|---|---:|---|---|---|---|
| None | — | — | — | — | — |

## Highest-ROI next actions

1. `O1C-0007`: capsule the compact-support negative ladder and establish the
   3,918-byte direct table as a mandatory quantitative gate, not merely a control.
2. Move upstream from the dense final scalar field to streamed bit-, carry-, round-
   and solver-conflict evidence; retain no 4,096-row candidate representation.
3. Build a bounded bit/interaction memory under 3,918 bytes and require disjoint
   transfer, exact state accounting and a material fidelity/recovery advantage.
4. Only after that gate passes, bind an OS-random W46 challenge, persist every order
   before recovery and independently confirm any full-round candidate.

## Recent attempts

| Attempt | Time | Hypothesis | Result | Claim level | Cost | Main breadcrumb | Artifact |
|---|---|---|---|---|---|---|---|
| `O1C-0006` | 2026-07-15 | Corrected codec plus adaptive DC-complete registers can form a high-fidelity bounded ceiling | Gate passed; exact A355/A356; 8,014 B, worst Spearman 0.999224; 24/24 orders | `VALIDATION` | 7.347 s; 9 arms; zero solver/GPU work | Full-basis state is table-equivalent and 2.045× larger; move upstream to compact causal/bit evidence | [Run capsule](runs/20260715_154553_O1C-0006_corrected-codec-adaptive-dc-bridge/RUN.md) |
| `O1C-0005` | 2026-07-15 | Distributed slots and dense low-precision state transfer better than sparse single-field support | Gate passed; 4-bit/H1.25, 6,668 B; A349 Spearman 0.990198 | `VALIDATION` | 38.521 s; 72+72 arms; zero solver/GPU work | Precision allocation beats coefficient pruning, but the bank remains full rank | [Run capsule](runs/20260715_135434_O1C-0005_bounded-spectral-memory-tournament/RUN.md) |
| `O1C-0004` | 2026-07-15 | Independently reproduce the complete Direct12 reader and commitments | 52/52 shards, 13,312 cells, all score/order hashes exact | `VALIDATION` | 5.986 s; zero solver/GPU work | Verified input primitive for bounded memory | [Run capsule](runs/20260715_130047_O1C-0004_direct12-532-reproduction/RUN.md) |
| `O1C-0003` | 2026-07-15 | Pin the dirty-source Direct12 dependency set honestly | 71/71 members, 9,882,690 bytes | `SMOKE` | 0.069 s | Lab-owned provenance without sibling mutation | [Run capsule](runs/20260715_123734_O1C-0003_direct12-source-snapshot/RUN.md) |
| `O1C-0002` | 2026-07-15 | Validation-selected raw reader transfers | Failed; familywise `p=0.664` | `RETROSPECTIVE` | 119 readers | Replace scalar selection with structured evidence | [Run capsule](runs/20260715_123236_O1C-0002_retrospective-reader-tournament/RUN.md) |
| `O1C-0001` | 2026-07-15 | Normalize A296/A297 without post-reveal access | 24/24 members; zero labels read | `SMOKE` | 0.360 s | Offline observability path established | [Run capsule](runs/20260715_122529_O1C-0001_stage3-a296-a297-ingest/RUN.md) |

## Reproducibility anchors

| Artifact | SHA-256 |
|---|---|
| `O1C-0006` capsule manifest | `720bc88834e5ae2959ac960d4f5fe2ca1c8845283b0d32273c6ca2cfea34fdc6` |
| `O1C-0006` deterministic report | `64ace20f8798da49e6108352ea0c95459afb2a955439148cea8f357d643b870b` |
| `O1C-0006` complete order set | `964dd87ddf6cf506d9399ff6f1fb16245617bcec8f3ab66484031d79f9cd41e8` |
| `O1C-0006` source snapshot | `ef3da5d473a5a108ef3d212a1be88ac806c794a2a9c926c3fcc7330ddf8f30f3` |
| `O1C-0005` capsule manifest | `de67260cf44556a3fa48ef2b6daa1b738cf40b392739c6a05d835cbcdb1ab103` |
| `O1C-0004` capsule manifest | `ac3333606e0aaf47dc519553c0e9407fc8ab67dba5319ed340eac579cb25c7bf` |
| `O1C-0003` capsule manifest | `d7dcb2b2c3f39d866c7820dbc7423ce55b4d5c9df6634d5a00126a954a0a065d` |
| `O1C-0002` capsule manifest | `b4a242708ae30481deed5346df519bb5123c7601fa6c58b6c06bd514be314ff9` |
| `O1C-0001` capsule manifest | `376e3b27f107d132421e29c2669f468a57c8417924928ce41badadf14d3dd05f` |

## Resume here

Start from `O1C-0007`: formalize the compact-state failure ladder, then implement
the first bit/carry/solver-evidence memory that is structurally non-dictionary and
strictly smaller than 3,918 bytes. Do not generate a fresh challenge first.
