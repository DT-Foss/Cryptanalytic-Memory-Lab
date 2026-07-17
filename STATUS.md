# O1 Cryptanalytic Memory Lab — Current Status

- **Last updated:** 2026-07-17T08:03:43+02:00 (`Europe/Berlin`)
- **Reader implementation commit:** `a99206baabeb4ae21cf07f909186db9f25354d6e`
- **Worktree:** O1C-0013 capsule finalized and verified 63/63; O1C-0014 frozen-
  reader independent replication next; O1C-0009 through O1C-0013 immutable
- **Research phase:** O1-256 Living Inverse — paired-assumption solver events into
  coordinate-bound unary-plus-interaction O1 state
- **Strongest internal mechanism:** O1C-0013 turns each complete 512-branch public
  proof field into a 58,368-byte live causal-feature/logit state, while a frozen
  target-independent reader emits all 256 key-bit probabilities
- **Strongest read-only mechanism intake:** A447-A449 proof ancestry, A465 cubic
  Product-of-Experts and A469 positive bucket-local correction
- **Active runs:** none
- **Last completed attempt:** `O1C-0013` — frozen multi-key causal-orientation reader
  attacked two fresh sealed full-round output-only keys; all lifecycle/resource
  gates passed and aggregate compression was positive but tiny
- **Next attempt:** `O1C-0014` — reload the exact O1C-0013 reader bytes without
  fitting or selection and attack eight new independently sealed 256-bit keys
- **Primary uncertainty:** whether O1C-0013's `+0.088922` bit/key survives an
  independent multi-key panel, rather than reflecting its two-key CAL/test scale
- **SOTA status:** first prospective positive full-256 causal-reader breadcrumb,
  not yet a SOTA claim: 259/512 bits, `+0.088922` bit/key and a `+3.306254`-bit/key
  margin over the shuffled-key reader on only two sealed keys
- **SOTA target:** a stream-length-bounded living inverse that reduces the 256-bit
  key code length on sealed uniform targets and ultimately emits an exactly verified
  full ChaCha20 key

## Headline

`O1C-0013` is the first complete learned full-256 causal-reader experiment.  Four
deterministic BUILD keys and two disjoint CAL keys each generated the unchanged
O1C-0012 paired public-CNF field.  Labels were unavailable until each public state
was frozen.  BUILD fitted only shared signed orientation; CAL selected one of the
predeclared wavelengths and scale choices.  The selected `horizon_1` reader
(`h96`, ridge `0.001`, temperature `0.5`, logit scale `1.0`) was serialized and
reloaded before exactly two OS-random target entropy calls.

On those two fresh sealed standard-ChaCha20 targets the frozen reader obtains
`259/512` bits and mean NLL `255.911078` bits, or `+0.0889215` bit of effective
compression per key.  Its frozen shuffled-key counterpart obtains `239/512` and
`-3.217332` bit/key, a primary margin of `+3.306254` bit/key.  The two individual
compressions are `-0.186702` and `+0.364545` bit, so the aggregate is not yet a
stable effect.  Full-key million-decoy ranks are `580,519` and `194,708`; exact
keys recovered are zero.  Across 64 factorized bytes the best truth rank is `2`
and five are top-16; no byte or 16-bit block is exactly mode-correct.

All three preregistered target controls are directionally negative against the
anchor key: output-bit flip `-0.272987`, wrong nonce `-0.167376`, and output-byte
rotation `-0.040618` bit.  Every lifecycle, public-recompute, swap, containment,
memory and work gate passes.  Live target state is exactly `58,368` bytes
(`17,408` causal state + `39,936` bounded feature bank + `1,024` logits), with no
candidate keys or transcripts.  The static primary reader is `281,764` bytes.

The capsule verifies 63/63 members.  It used `392.187980` billed CPU seconds,
`314.384032` wall seconds, `5,632` billed native branches and a conservative
process-group peak of `321.90625` MiB; persistent artifacts are `2,479,016` bytes.
Sibling reads/writes, MPS and GPU calls are zero.  Capsule manifest:
`a0d4df5c01f7de3c65a429f9589e46d784f802bc1f8e0aa90dffb011be46922c`;
internal result:
`a70610d3d589e97048c6045747c0821e5669c5dc89e420df79b0fca43476d4cd`.

`O1C-0011` compiled the complete standard twenty-round ChaCha20 block relation
directly at full key width.  Variables `1..256` are the unknown key, `257..384`
the public counter/nonce and `385..896` the public 512-bit output; internal wires
begin at `897`.  The immutable template contains `32,128` variables, `187,370`
clauses and `656` semantically named add/XOR operators.  Every operator carries
32 exact LSB-first bit ranges with explicit sum, carry or XOR variables and
one-based inclusive clause ancestry.

The public attacker instance adds exactly `640` counter/nonce/output units and
zero key units (`188,010` clauses).  Two persisted bit-173 probes share the exact
public relation and differ only in the final opposite key literal.  Byte-identical
double compilation passed; the RFC fixed-key instance is SAT, its one-bit output
flip is UNSAT, and an independent second 256-bit vector is SAT.  This validates
the inversion substrate and causal address map; it does not yet claim an unknown-
key solve or inverse signal.

The capsule verifies 18/18 members.  CPU work was `8.692029` s, peak through
artifact persistence `163.59375` MiB, maximum temporary workspace `25,414,624`
bytes and persistent CNF artifacts `21,069,379` bytes.  Sibling reads/writes,
MPS/GPU calls and fresh random targets were all zero.  Capsule manifest:
`b7a07e6461805946897adbfb90da9e9f55ff1074e9aa1343f602eecb0645b7b4`;
internal result:
`6c4fd7becd5307d60b30e16ea1fae8d3f4739b06c888204d638950c94b53adfe`.

`O1C-0010` prospectively copied the exact O1C-0009 direct and shuffled model bytes,
froze the post-reveal signed scales and every gate before target entropy, then
attacked 2,048 new broker-secret uniform keys with all 256 bits unknown.  The six
`2048 x 256` posterior/control matrices (`25,165,824` bytes) were persisted before
the first reveal.  Direct mean NLL was `256.0190884625`, i.e. compression
`-0.0190884625` bit, conditional reference `z=-0.94608`, and target-level 3-SE
lower bound `-0.032620` bit.  It lost to the signed shuffled control by
`0.0175411` bit and beat output permutation by only `0.0009622` bit (`z=0.1902`).
Only the algebraic reverse-polarity checksum passed; every efficacy criterion
failed.  The O1C-0009 `+0.023159`-bit observation was finite-panel selection noise,
not a transferable orientation.

The O1C-0010 capsule verifies 23/23 members.  All 2,048 commitments open, all keys
recompute their standard twenty-round outputs and every receipt binds prediction
blob `4643e0e849178014ede98e355037829158ca2eadc9b404671a8f64d6904e2dee`.
CPU work was `2.424391` s; peak through outcome persistence `201.96875` MiB and
end-to-end process peak `245.390625` MiB, with zero sibling, MPS or GPU work.
Capsule manifest:
`a87b7a9fb799d667e9d2e670f759ca4f389aac2be9cb932c3f308ab669f4ab7c`.

`O1C-0009` attacked 128 broker-secret uniform keys with all 256 bits unknown.  The
four frozen readers and every factual/control posterior were persisted before the
one-shot reveal.  Calibration selected scale zero for direct, relative, distilled
and shuffled-key arms, so all declared DEV posteriors remained exactly uniform:
mean NLL `256.0`, effective compression `0.0`, zero familywise transferable bits.
This closes the first linear full-round end-output reader, not the moonshot.

The immutable capsule verifies 25/25 members.  Its 128 publications are unique,
all 128 revealed keys exactly reproduce their public ChaCha20 outputs, and every
reveal receipt binds prediction blob
`8431b3c19a697ce0d48e66d29b199ec6d199670870d40231564c9516e3c34ad2`.
Peak RSS was `182.90625` MiB, CPU work `6.923216` s, with zero sibling, MPS or GPU
work.  Capsule manifest:
`f31d7672921dc0c2ec684cf8c5247a3ff2386fbea316c2eab98072cd22fb29d2`.

One post-reveal diagnostic was retained rather than discarded: allowing a signed
global scale chosen from CAL only gives the frozen direct reader scale
`-0.03860970720667151`, CAL NLL `255.984754` and O1C-0009 DEV NLL `255.976841`
(`+0.023159` bit).  This was not preregistered and is not a result claim.  Its
target-level standard deviation is `0.199937` bit. O1C-0010 has now closed it on a
16-times larger prospective panel. The sealed broker remains public-view-only in
memory and retains no privileged round traces.

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

1. `O1C-0014`: copy and hash-pin O1C-0013's exact primary and shuffled reader
   binaries before any new entropy; prohibit fitting, arm selection and rescaling.
2. Generate eight new sealed uniform full-256 keys, run the unchanged public-only
   h96 probe field sequentially, and persist every prediction before any reveal.
3. Replicate the three anchor transforms under the same reader, then compare total
   NLL, target sign count, shuffled margin, per-coordinate transfer and decoy ranks.
4. If the fixed reader fails, use the eight-key residual map to choose one new
   proof-motif/ARX sensor family; if it holds, scale the same bytes to a larger
   blind panel before adding Attic compounding or a verification beam.

## Recent attempts

| Attempt | Time | Hypothesis | Result | Claim level | Cost | Main breadcrumb | Artifact |
|---|---|---|---|---|---|---|---|
| `O1C-0013` | 2026-07-17 | BUILD/CAL full-256 paired-proof fields can learn a target-independent causal orientation that lowers sealed output-only key NLL | First positive blind breadcrumb: 259/512 bits, +0.088922 bit/key, +3.306254 bit/key over shuffled; controls all negative; 0 exact keys | `TEST` prospective signal; replication required | 392.188 CPU s; 314.384 wall s; 321.906 MiB conservative peak; zero sibling/GPU work | Two targets split -0.186702/+0.364545; freeze the exact reader and replicate on eight new keys without refit | [Run capsule](runs/20260717_075537_O1C-0013_full256-multikey-causal-calibration-v1/RUN.md) |
| `O1C-0012` | 2026-07-17 | All 512 opposite assumptions can emit complete closed proof prefixes into a bounded full-256 O1 causal state | Mechanism passed: 256 bits, 1,536 frontiers, 17,408 B state; known-key diagnostic negative at 119/256 and -86.780 bit compression | `TEST` mechanism; no inverse claim | 58.032 CPU s; 49.199 wall s; 317.281 MiB conservative group peak; zero sibling/GPU work | The W52 `(7,1,4)` orientation is not portable; horizon 96 alone gives 139/256 on one key and must be tested cross-key | [Run capsule](runs/20260717_065248_O1C-0012_full256-paired-causal-sensor-v1/RUN.md) |
| `O1C-0011` | 2026-07-17 | A complete target-independent full-256 ChaCha20 CNF can expose exact coordinate-bound paired-assumption relations under bounded resources | Passed: 32,128 vars, 187,370 template clauses, 656 operators x 32 bit ranges; public instance has 640 public/0 key units; SAT/UNSAT/SAT self-tests | `VALIDATION` infrastructure | 8.692 CPU s; 163.594 MiB outcome peak; 25.415 MB workspace; zero sibling/GPU work | Full-width causal substrate is valid; stream paired solver deltas into O1C-0012 | [Run capsule](runs/20260717_054138_O1C-0011_full256-public-cnf-foundation-v1/RUN.md) |
| `O1C-0010` | 2026-07-17 | O1C-0009's signed direct orientation transfers without refit | Refuted on 2,048 sealed keys: compression -0.019088 bit, z -0.946; loses to shuffled, output-permutation delta only +0.000962 | `VALIDATION` negative | 2.424 CPU s; 201.969 MiB outcome peak, 245.391 MiB end-to-end; zero sibling/GPU work | Raw end-output regression is closed; move to public-CNF assumption/proof events | [Run capsule](runs/20260717_045214_O1C-0010_full256-signed-direct-replication-v1/RUN.md) |
| `O1C-0009` | 2026-07-17 | Direct, candidate-relative or teacher-distilled full-width readers remove reproducible entropy from unseen public-output targets | Declared gate failed; all CAL scales 0, DEV NLL 256.0, compression 0, transferable bits 0; sealed lifecycle passed | `VALIDATION` negative | 6.923 CPU s; 182.906 MiB peak; 128 fresh keys; zero sibling/GPU work | Post-reveal CAL-only signed direct scale gives exploratory DEV +0.023159 bit; replicate once on a larger new panel, then move upstream | [Run capsule](runs/20260717_040741_O1C-0009_full256-output-only-reader-v1/RUN.md) |
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
| `O1C-0013` capsule manifest | `a0d4df5c01f7de3c65a429f9589e46d784f802bc1f8e0aa90dffb011be46922c` |
| `O1C-0013` internal result commitment | `a70610d3d589e97048c6045747c0821e5669c5dc89e420df79b0fca43476d4cd` |
| `O1C-0013` sealed evaluation | `11d3cdfffb6cb078f7d8a54e56ff827d3c9a4237df32632274c2176e7e5efa38` |
| `O1C-0013` primary frozen reader | `796e79ec932b990a59ecbc34216c4878b9279bae3bb136fe0832e580bcb2e9f8` |
| `O1C-0013` reader freeze receipt | `2d96c4582076818d1d101a10527535de8ed5be1f2e928658a14427043645a5e5` |
| `O1C-0012` capsule manifest | `a28acc299d2ed42b7f4eba14e653cd8d0c3f09347658fcb65d49936e0a255556` |
| `O1C-0012` internal result commitment | `33184e9245f4e31e56f16c9f8cfaa21e18849279058b278959cdb2c8acc54bd7` |
| `O1C-0012` bounded state | `aea9d4c0bd88d2c8480fb51b98d5524bc8c6fc319dd612c9dc345aa03035b664` |
| `O1C-0012` paired event stream | `b52bf4cce10f69672077f4b6b0d8496cfe0c633aac5ae0ce43502d2e9d5b26b1` |
| `O1C-0012` public baseline | `3061939c1ea041b73d82ada74b71c3265cb2a90b4cb1904030f178807844eaaf` |
| `O1C-0012` bit-173 sentinel pair | `3631a4e16ea5a7fde6dc3c096db89ab595494cf44e4e6fea0ae315cc8a60817c` |
| `O1C-0012` known-key diagnostic artifact | `35bbcc55dd1151a9cec1d7980a6126cd8c4b9f1f60a22acfa83cc7380257af73` |
| `O1C-0011` capsule manifest | `b7a07e6461805946897adbfb90da9e9f55ff1074e9aa1343f602eecb0645b7b4` |
| `O1C-0011` internal result commitment | `6c4fd7becd5307d60b30e16ea1fae8d3f4739b06c888204d638950c94b53adfe` |
| `O1C-0011` exact CNF template | `c293d36cab270b28ab2e89c073227fd50b75a6b357b9994d27c3acf7c01a0d52` |
| `O1C-0011` causal map commitment | `13c0dd32b1c0eec0b9b95e9c7c0f2a8390b8be6f98bd59e3b7d021c23762bfaf` |
| `O1C-0011` public attacker instance | `dde6a2791726e148c99064ec71f746fb8803e5d0f6b1996dd8b238c9c9b0a2a0` |
| `O1C-0011` bit-173 assumption-0 instance | `758c463982ce6222bf6dab9d130fc1c18a34fb2bf48d1f004d851ca46c9de003` |
| `O1C-0011` bit-173 assumption-1 instance | `10717d9dadd4aa60d04ea4e38ffb95d34be0867c2424a501e01c224a1b930e5d` |
| `O1C-0010` capsule manifest | `a87b7a9fb799d667e9d2e670f759ca4f389aac2be9cb932c3f308ab669f4ab7c` |
| `O1C-0010` internal result commitment | `76069cf7e25e194feee027d4e4a1e2cca0fed47ae4ec84fbaa9ff966845e3bc9` |
| `O1C-0010` pre-reveal prediction blob | `4643e0e849178014ede98e355037829158ca2eadc9b404671a8f64d6904e2dee` |
| `O1C-0010` prediction index | `2224ab10e3b3362ab374c4d5d90b7f19a697c9aca4cbfe094864e90d5a5313ca` |
| `O1C-0010` frozen protocol | `75d90a63501ca4c6671170b7b9ffb039f2c6e713279b63a2073f26d15d20e419` |
| `O1C-0010` publication root | `cb9868cce5fb79b2b7690e90e7047681b765a28c9f3507255dd419efb9b97b63` |
| `O1C-0010` reveal root | `203804994ae7dcae7eac6459a762911d9b7a550829762098b560de0057183fac` |
| `O1C-0009` capsule manifest | `f31d7672921dc0c2ec684cf8c5247a3ff2386fbea316c2eab98072cd22fb29d2` |
| `O1C-0009` internal result commitment | `40276d71516d4d150b02cc8235c08d00fb8ceb28daf64d1316826b38fd094bf9` |
| `O1C-0009` report artifact | `e007dd7964269036c427be53e9563a4bc450955cafecbd0b8ae2f6a9db064332` |
| `O1C-0009` pre-reveal prediction blob | `8431b3c19a697ce0d48e66d29b199ec6d199670870d40231564c9516e3c34ad2` |
| `O1C-0009` frozen calibration selection | `8e938893dcda020cadb5aa3d3cde0efc43cfe9cd6d34879ca00eb4538dd4d24d` |
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

Start from `O1C-0014`: treat O1C-0013 reader SHA-256
`796e79ec932b990a59ecbc34216c4878b9279bae3bb136fe0832e580bcb2e9f8`
and its shuffled binary as immutable external model inputs.  Freeze their source
capsule and the eight-target replication protocol before the first entropy call.
No BUILD/CAL replay, hyperparameter selection, sign change or temperature change
is allowed.  Attack eight fresh output-only targets, persist all posteriors, reveal
once, and decide transfer from aggregate NLL plus the frozen shuffled margin. Keep
the sibling recovery queue read-only and prioritized.
