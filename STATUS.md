# O1 Cryptanalytic Memory Lab — Current Status

- **Last updated:** 2026-07-17T03:11:14+02:00 (`Europe/Berlin`)
- **Implementation commit:** `826149ded68f0c9afbdd7a1c4f9ea90235f1ef56`
- **Worktree:** clean after the O1C-0008 implementation commit
- **Research phase:** O1-256 Living Inverse — first trained full-width readers
- **Strongest internal mechanism:** O1C-0007's 12-register/266-byte unary state is
  retained as a negative-calibrated primitive; the active design adds proof
  interactions, switching wavelengths and a 20,492-byte full-256 living state
- **Strongest read-only mechanism intake:** A447-A449 proof ancestry, A465 cubic
  Product-of-Experts and A469 positive bucket-local correction
- **Active runs:** none
- **Last completed attempt:** `O1C-0008` — full-256 Living Inverse foundation
- **Next attempt:** `O1C-0009` — matched output-only, candidate-relative and
  teacher-distilled full-256 readers
- **Primary uncertainty:** whether any attacker-valid full-round public-output
  contrast channel removes stable entropy from uniform unseen 256-bit keys
- **SOTA status:** no inverse signal yet; O1C-0008 is a successful `SMOKE` result,
  not evidence that public full-round output predicts a random key
- **SOTA target:** a stream-length-bounded living inverse that reduces the 256-bit
  key code length on sealed uniform targets and ultimately emits an exactly verified
  full ChaCha20 key

## Headline

`O1C-0008` makes the target contract executable: every attacked key has 256 unknown bits from the
first experiment.  The deployment path sees only public counter/nonce/output plus
self-generated candidate keys, their outputs and their internally computable
traces.  Target round states, carry paths and proof objects are training labels
only.  Reduced-width residual recovery is not an intermediate target claim.

The 2026-07-17 read-only W52 intake supplied mechanism, not target data.  A447/A448
show that exact proof ancestry transfers where flattened clause provenance does
not.  A460/A462/A463 expose complementary switching wavelengths `64/96/65`; A465
combines them with a cubic Product-of-Experts; A469 shows that interaction evidence
must be positive, bucket-local and identity-preserving.  These become the sensor,
timescale, backbone and correction layers of the Living Inverse.

The immutable foundation contains four build and two development targets, 72
deployment contrasts across six proposal families, 2,576 attacker-valid features
per one-block contrast, exact RFC-compatible round/carry traces, one-bit output and
wrong-nonce controls, a million-decoy rank path and a sealed full-256 broker.  The
random posterior measures exactly `256.0` bits; the metric oracle reaches `3.71189`
bits, exact mode, rank one and the exact verification beam.  No target trace field,
fresh target, sibling read/write, MPS or GPU call occurred.  Capsule manifest:
`50cd1dcd83034d69aafd2e7890d62b9f2c25b6e65c5a929d3119027a71105449`.

O1C-0007 remains a useful boundary: a pure unary state is structurally compact but
its selected result has exact conditional `p=0.593505859375`.  The new architecture
therefore includes pair/causal interaction from its first trained arm rather than
repeating the unary decoder on another narrow target.

The full design and exact attacker boundary are in
[`docs/O1_256_LIVING_INVERSE.md`](docs/O1_256_LIVING_INVERSE.md); the measured W52
transfer map is in
[`research/W52_TRANSFER_20260717.md`](research/W52_TRANSFER_20260717.md).

## Active process table

| Attempt | PID | Started | Command | Progress | ETA |
|---|---:|---|---|---|---|
| None | — | — | — | — | — |

## Highest-ROI next actions

1. `O1C-0009`: train output-only, candidate-relative and teacher-distilled 256-bit
   readers on a much larger generated build corpus, CPU-only.
2. Measure uniform development-key NLL and stable bits against shuffled-key,
   output-flip and wrong-nonce controls; retain round/orbit breadcrumbs if null.
3. Add a reusable streamed dataset interface so corpus size grows without retaining
   target/candidate traces in RAM.
4. `O1C-0010`: stream the best reader evidence through the O1 vault, holographic banks,
   A465 backbone and A469 local correction; attack a sealed uniform 256-bit target.
5. Iterate at full width on round/carry/proof observability and O1-O scheduling;
   short MPS windows require an explicit resource check and must not overlap W52.

## Recent attempts

| Attempt | Time | Hypothesis | Result | Claim level | Cost | Main breadcrumb | Artifact |
|---|---|---|---|---|---|---|---|
| `O1C-0008` | 2026-07-17 | A strict full-256 public-output attacker/teacher foundation can execute without sibling or accelerator use | Gate passed; 256 unknown bits, 72 contrasts, 2,576 features, 1M decoys, random NLL 256.0, zero target-trace fields | `SMOKE` | 0.996 s; 78 logical blocks; zero sibling/GPU work | The moonshot is now measurable; train the first full-width reader and demand uniform held-out entropy gain | [Run capsule](runs/20260717_031113_O1C-0008_full256-living-inverse-foundation/RUN.md) |
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
| `O1C-0008` capsule manifest | `50cd1dcd83034d69aafd2e7890d62b9f2c25b6e65c5a929d3119027a71105449` |
| `O1C-0008` deterministic foundation result | `14bfa1dd9e4593cac223a779562ff8b591bf88c485486814be62e6f73baa79a2` |
| `O1C-0008` deployment contrast set | `ab28ca614b27c20e71acc7815a9daff33c8ec20c4d331496dad45fb1fa6e7496` |
| `O1C-0008` teacher-label set | `b1f467e44cbaca82ff1e6aa031148cab2268ba7565bf897095d381000a05fb8e` |
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

Start from `O1C-0009`: use the frozen O1C-0008 deployment schema to train three
matched full-256 readers—raw public output, candidate-relative residual/trace and
teacher-distilled deployment student.  The evaluation corpus remains uniform and
disjoint; target traces are auxiliary labels only.  Persist complete development
posteriors and controls before considering a sealed target.  Keep the sibling W52
queue read-only and resource-prioritized.
