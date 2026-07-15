# O1 Cryptanalytic Memory Lab — Current Status

- **Last updated:** 2026-07-15T17:55:31+02:00 (`Europe/Berlin`)
- **Implementation commit:** `cf7ef298caf80006ae3470240d509c661221b150`
- **Research phase:** Stage 6 — preparing the frozen compact solver-evidence memory
  for its first genuinely fresh paired-assumption test
- **Strongest internal mechanism:** a 12-register unary solver-evidence memory with
  266-byte conservative logical-state bound and 162-byte frozen binary state
- **Strongest external frontier anchors:** confirmed Threefish-1024 W39 complete
  domain and ChaCha20 A325 W46 strict-subset recovery; both remain read-only inputs
- **Active runs:** none
- **Last completed attempt:** `O1C-0007` — upstream solver-evidence Bit-Vault freeze
- **Primary uncertainty:** whether the frozen unary evidence decoder transfers to
  unseen OS-random paired-assumption trajectories and improves search/recovery
- **SOTA status:** no lab SOTA result yet; O1C-0007 passed its protocol and compact-
  state gates but failed scientific efficacy at exact conditional `p=0.593505859375`
- **SOTA target:** the smallest genuine O(1)-in-stream solver-event memory with
  reproducible fresh unseen-key search-space reduction

## Headline

`O1C-0007` moved upstream of the dense final score table. It persisted all 672
complete target-blind A355 orders before opening the single A355 truth, applied a
target-blind tie gate to the 448 streamable views, and enumerated all 4,096 possible
labels through the exact resulting 152-view selection procedure. The selected
decoder is:

- `search_propagations__h1__signed-log1p__degree1__negative`;
- 12 implicit unary Walsh registers, zero candidate rows, evidence rows or KV
  entries;
- 266-byte conservative maximum logical mechanism state; 162-byte frozen binary;
- A355 rank `73`, raw rank gain `5.8101754411` bits;
- exact conditional random-label tail `2431/4096 = 0.593505859375`.

That probability is negative evidence after the declared selection family: the raw
5.81-bit rank is not demonstrated utility. The exact null also does not adjust for
pre-panel exploration or establish label exchangeability. The 266-byte figure is
only below O1C-0006's 3,918-byte prior table budget; the two states encode different
fields and fidelity targets, so this is not matched-information compression
dominance.

The compact accumulator was exercised eventwise over a materialized canonical
4,096-address field. Its accumulator contents and serialization are real, but
end-to-end source-event streaming is not yet demonstrated; that remains part of
O1C-0008 rather than a property inferred from this retrospective run.

After the template and A355 state were persisted, the same decoder emitted the
complete A356 order with SHA-256
`0a6e32430a97c968c3a831ef23c58eaacaaf411fcc9f44e59661f62efa764159`
without any A356 target or outcome read. A356 is a transductive target-/outcome-
blind freeze, not a source-unseen holdout. This gives O1C-0008 one clean question:
does the frozen 12-register mechanism produce reproducible gain on newly generated,
precommitted paired-assumption solver trajectories?

## Active process table

| Attempt | PID | Started | Command | Progress | ETA |
|---|---:|---|---|---|---|
| None | — | — | — | — | — |

## Highest-ROI next actions

1. `O1C-0008`: generate OS-random paired-assumption solver trajectories under a
   fully precommitted protocol; pass every tested key bit as an explicit assumption.
2. Apply the exact frozen O1C-0007 decoder eventwise, persist all output orders and
   compact states before any reveal, and compare matched numeric/hash/null controls.
3. Require reproducible gain across multiple unseen targets or a downstream
   time-to-hit/search-space advantage; one favorable rank is insufficient.
4. If the unary decoder fails, preserve the failure and localize new evidence by
   carry, round, conflict and assumption-pair provenance before expanding the state.
5. Attempt full-round recovery only after a compact mechanism passes the fresh,
   multi-target scientific-efficacy gate.

## Recent attempts

| Attempt | Time | Hypothesis | Result | Claim level | Cost | Main breadcrumb | Artifact |
|---|---|---|---|---|---|---|---|
| `O1C-0007` | 2026-07-15 | Low-degree upstream solver evidence can populate a genuine compact O1 memory | Protocol passed; 12 registers, 266 B; A355 rank 73 but exact conditional `p=0.593506`; target-blind A356 order frozen | `RETROSPECTIVE` | 10.799 s; 672 views; zero solver/GPU work | Compact mechanism exists, efficacy does not yet; run the exact decoder once on fresh paired-assumption trajectories | [Run capsule](runs/20260715_174537_O1C-0007_upstream-solver-evidence-bit-vault-freeze/RUN.md) |
| `O1C-0006` | 2026-07-15 | Corrected codec plus adaptive DC-complete registers can form a high-fidelity bounded ceiling | Gate passed; exact A355/A356; 8,014 B, worst Spearman 0.999224; 24/24 orders | `VALIDATION` | 7.347 s; 9 arms; zero solver/GPU work | Full-basis state is table-equivalent and 2.045× larger; move upstream to compact causal/bit evidence | [Run capsule](runs/20260715_154553_O1C-0006_corrected-codec-adaptive-dc-bridge/RUN.md) |
| `O1C-0005` | 2026-07-15 | Distributed slots and dense low-precision state transfer better than sparse single-field support | Gate passed; 4-bit/H1.25, 6,668 B; A349 Spearman 0.990198 | `VALIDATION` | 38.521 s; 72+72 arms; zero solver/GPU work | Precision allocation beats coefficient pruning, but the bank remains full rank | [Run capsule](runs/20260715_135434_O1C-0005_bounded-spectral-memory-tournament/RUN.md) |
| `O1C-0004` | 2026-07-15 | Independently reproduce the complete Direct12 reader and commitments | 52/52 shards, 13,312 cells, all score/order hashes exact | `VALIDATION` | 5.986 s; zero solver/GPU work | Verified input primitive for bounded memory | [Run capsule](runs/20260715_130047_O1C-0004_direct12-532-reproduction/RUN.md) |
| `O1C-0003` | 2026-07-15 | Pin the dirty-source Direct12 dependency set honestly | 71/71 members, 9,882,690 bytes | `SMOKE` | 0.069 s | Lab-owned provenance without sibling mutation | [Run capsule](runs/20260715_123734_O1C-0003_direct12-source-snapshot/RUN.md) |
| `O1C-0002` | 2026-07-15 | Validation-selected raw reader transfers | Failed; familywise `p=0.664` | `RETROSPECTIVE` | 119 readers | Replace scalar selection with structured evidence | [Run capsule](runs/20260715_123236_O1C-0002_retrospective-reader-tournament/RUN.md) |
| `O1C-0001` | 2026-07-15 | Normalize A296/A297 without post-reveal access | 24/24 members; zero labels read | `SMOKE` | 0.360 s | Offline observability path established | [Run capsule](runs/20260715_122529_O1C-0001_stage3-a296-a297-ingest/RUN.md) |

## Reproducibility anchors

| Artifact | SHA-256 |
|---|---|
| `O1C-0007` capsule manifest | `2900adafb938ba470ae595b21895a0035a77621a667e04abacf1fd8d5654f3c1` |
| `O1C-0007` deterministic report artifact | `868f339b22e6b1bddbde944dffcebd22ad8f94287b829cd65d85670d4de2dec5` |
| `O1C-0007` internal deterministic report commitment | `c371ce0b100684b518c1e9094547f2acdb869c3a9aac660408058acc48ccdfe7` |
| `O1C-0007` 672-order blob | `2ed242ba8582798cd23618be18a230cecabe27c9aed2546f5a88814117f86949` |
| `O1C-0007` frozen future template artifact | `836d6f0b01a7b86d50b0b5f81eaaaef1df235dfa45804b2a5ccc2a18d24775fd` |
| `O1C-0007` internal future-template commitment | `39cd8db1f10e6366cc26cbc896a8f8a7418d0fa8804277e5b373df08436d73cf` |
| `O1C-0007` A355 selected order | `fdf7c3618f7c2b5d9fbb1c47a0826fb1293932016fe5602a346e9c247e188852` |
| `O1C-0007` A356 target-blind order | `0a6e32430a97c968c3a831ef23c58eaacaaf411fcc9f44e59661f62efa764159` |
| `O1C-0007` source receipts | `decffd6bd44ada221ea7ef91446983ff9823241c0274303ba84655ceb582e52f` |
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

Start from `O1C-0008`: use frozen template
`39cd8db1f10e6366cc26cbc896a8f8a7418d0fa8804277e5b373df08436d73cf`
on newly generated OS-random paired-assumption trajectories. Persist the complete
target-blind output before reveal, use multiple unseen targets and matched controls,
and treat O1C-0007's `p=0.593505859375` as the negative calibration breadcrumb it is.
