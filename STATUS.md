# O1 Cryptanalytic Memory Lab — Current Status

- **Last updated:** 2026-07-17T17:29:19+02:00 (`Europe/Berlin`)
- **Prior published baseline:** `dbbe63a` (`O1C-0017` mechanism result)
- **Latest execution commit:** `f40e71aa8ed80b4653acf44d98e14eabec18a955`
  (`O1C-0018` clean full-round real-gate freeze)
- **Latest implementation freeze:** `dc249add99aa0673fc611fab8b2e75b8ba1434a0`
  (`O1C-0019` artifact-only four-fold BUILD-LOO gate; no scientific run yet)
- **Publication:** the O1C-0018 outcome and deterministic post-reveal forensics are
  recorded below; immutable capsules and sibling repositories remain untouched
- **Research phase:** O1-256 Living Inverse — paired-assumption solver events into
  coordinate-bound unary-plus-interaction O1 state
- **Strongest internal mechanism:** O1C-0017 autonomously discovers one oriented
  channel among 330 anonymous raw channels and preserves 256 addressed readings in
  a 21,472-byte exact fast state, reaching 80.225% held-out bit accuracy
- **Strongest read-only mechanism intake:** A447-A449 proof ancestry, A465 cubic
  Product-of-Experts and A469 positive bucket-local correction
- **Active lab runs:** none. The sibling W52 production launcher is active, so the
  O1C-0019 heavy CPU gate is resource-interlocked and has not started. O1C-0018
  BUILD/DEVELOPMENT pools and O1C-0017 formal seeds remain consumed and may not be
  replayed as fresh evidence
- **Strongest completed mechanism attempt:** `O1C-0017` — independently verified
  `MECHANISM_PASS` on 16/16 untouched synthetic full-256 episodes
- **Strongest completed full-round online attempt:** `O1C-0018` — public-only
  paired-proof reader/picker on two disjoint DEVELOPMENT keys, classified
  `NO_RAW_SIGNAL_PICKER_UNINTERPRETABLE`
- **Last operational attempt:** `O1C-0018` — 3,072 native branches, 545.024 CPU s,
  510.875 wall s and 315,703,296 B peak RSS; every structural/resource gate passed
- **Next attempt:** execute the frozen `O1C-0019` four-fold BUILD-LOO config after
  the W52 interlock clears. The runner has packetized incremental evidence,
  reader-SHA-bound stationary credit, all-address preview, finite starvation,
  learned ACTION/STOP, an exact no-STOP twin, shifted/static/hash controls and an
  isolated learned-versus-untrained reader gate
- **Primary uncertainty:** whether common-mode-rejected proof/carry innovations can
  acquire portable key orientation when O1 learns its representation and O1-O
  learns its sensing policy rather than receiving a fixed scalar reader
- **SOTA status:** no cryptanalytic SOTA claim and no recovery. O1C-0018's raw
  learned field is `-1.284644` mean bits on two consumed full-round targets; its
  W1 true picker is positive on both but is not yet an autonomous gate pass
- **SOTA target:** a stream-length-bounded living inverse that reduces the 256-bit
  key code length on sealed uniform targets and ultimately emits an exactly verified
  full ChaCha20 key

## Headline

`O1C-0019` is implementation-frozen at `dc249ad` but deliberately unexecuted while
the sibling W52 production run remains active. The committed artifact-only runner
imports exactly four immutable O1C-0018 BUILD pools (`8,336,169` source bytes;
corpus SHA `d137a931782b19e2cd8fdd44f38a9109d239ba332605c3a512078ca314c1be64`),
generates no solver work and materializes no held-out key during discovery. It
trains three reveal-delayed episodes per fold, refits the critic only against the
final frozen reader, then freezes all five policy trajectories and both exhaustive
reader trajectories before deriving the held-out label.

The three nested physical-work caps are `16,384/32,768/49,152`; the last is the
complete H64/H65/H96 packet field. Controls are true ACTION/STOP, the identical
true picker with STOP disabled, shifted-label stationary credit, fold-local static
packet reward, pool-blind uniform hash, and learned versus deterministic untrained
reader on the same exhaustive order. The STOP route is required to be an exact
prefix of its no-STOP twin. The current targeted regression is `29 passed` plus
`5` subtests; pycompile, Ruff, real manifest/index discovery and the exact run-config
loader pass. A non-scientific one-fold/three-action real-artifact smoke traversed
both freeze callbacks and scoring with every structural gate green in `2.559` CPU s,
`2.803` wall s and `315,359,232` B peak RSS; its deliberately undertrained outcome
is not efficacy evidence. No O1C-0019 efficacy number exists yet.

`O1C-0018` completed from clean execution commit `f40e71a`. It is the first full
256-bit, standard twenty-round ChaCha20 run of the continuous O1 reader and learned
picker: four reveal-delayed BUILD keys, then two disjoint DEVELOPMENT keys, all 256
bits unknown at probe time and only public counter/nonce/output passed to the
deterministic paired-proof sensor. Its frozen classification is
`NO_RAW_SIGNAL_PICKER_UNINTERPRETABLE`.

The exhaustive learned Bit-Vault is negative on both targets at
`-1.400387/-1.168901` bits (mean `-1.284644`). Training still improves the
untrained mean by `+0.724371` bits, but the coordinate-rotation control reaches
`+0.203963` mean and the direct final O1 field is `-0.093388`; raw transferable
orientation is therefore not established.

The early learned picker preserves a real breadcrumb. At W1, true reward is the
best arm on both targets at `+0.326847/+0.160175` bits. It beats the shifted-reward
critic in all six target-by-checkpoint cells, with positive IAUC margins on both
targets. Yet the score replay shows why this cannot be promoted: the first
decision has coverage contribution `0.5` versus learned reward about `0.00195`,
and only `0.169%` mean W1 score mass comes from learned reward. The hard
minimum-coverage gate and hash-32 shortlist make true/shifted and cross-target
routes nearly identical; forced later spending then destroys target-0 compression.

Post-reveal forensics also finds a training/deployment mismatch: a cumulative O1
query is repeatedly added as though it were incremental evidence. The direct
field avoids `1.191256` mean bits of the exhaustive path's damage. BUILD per-action
reward transfer is near zero (`0.013824` pairwise, `0.023765` leave-one-out), so
the critic is additionally trained on a nonstationary reader. These observations
define O1C-0019: packetize same-coordinate horizons, train an incremental/gated
readout, refit credits against the exact frozen reader, let every affordable
address be scored, replace compulsory breadth with soft no-starvation attention,
and learn HOLD/STOP/DECAY. Full forensics are in
[`research/O1C0018_POST_REVEAL_FORENSICS_20260717.md`](research/O1C0018_POST_REVEAL_FORENSICS_20260717.md).

The capsule verifies 51/51 members. Manifest
`fcbf43c99994c0debe5b39bb3e734ea1d1e23ba58e89b10ff2bb7e23886493fb`;
internal result
`db92bd86849ff93e0f9b935a72f64f1b4bd46b134747c913ee82e5d772ac11c9`.

`O1C-0017` completed from clean freeze commit `22ea4dd` and is independently
verified `MECHANISM_PASS`. After eight reveal-delayed BUILD episodes, the unchanged
reader attacked 16 disjoint full-256 synthetic episodes and obtained `3286/4096`
bits (`80.224609%`), mean NLL `213.691258` and mean compression
`+42.308742` bits. Every target is positive; the weakest target still has 195/256
correct bits. All predictions were persisted before label scoring.

The controls isolate the mechanism. Hidden-channel ablation gives `-4.392651`
bits, shifted-label learning `-0.456155`, the untrained reader `-7.336737`, and the
same learned reader's raw end-of-stream O1 field `-4.922579`. Primary margins are
therefore `+46.701393`, `+42.764897`, and `+47.231321` bits respectively. Exact
polarity-swap antisymmetry, common-only zero orientation, complete coordinate
coverage and fixed fast-state bytes all pass. Capsule manifest
`59f1f59b4e24545391cb06cd2bee395285d4385c893af36d18def28bcb3858fd`
verifies 18/18 members; internal result
`609014695bc3013bb971d7d05b682d18797af5c9d9cd31561cdc41de120ff28c`.

This is the wanted autonomous-learning proof at the architecture level: the model
was not told which of 330 channels carried orientation, learned only after prior
episodes were frozen, and retained the useful addressed readings where the raw
holographic end field lost them to crosstalk. It is deliberately not evidence that
ChaCha20 exposes such a channel, not a stateless-baseline comparison, not proof
that O1 memory is necessary, and not a learned-picker result. O1C-0018 has now
tested that transition and localizes the next limits to reader accumulation,
critic stationarity and picker agency.

`O1C-0016` is complete and independently verified. The frozen equal-logit h96+h65
ensemble obtains `4093/8192` bits and `-0.078249097` bit/key compression on 32
entirely new full-256 targets. Exact h96 obtains `-0.175000`, h65 `-0.033913`, and
the matched shuffled ensemble `+0.001976` bit/key. Only 11/32 targets are positive;
the primary loses to shuffled by `-0.080225` bit/key (`z=-0.555358`). The ensemble
improves h96 but loses to h65, and its promotion z is only `1.004470`. The frozen
classifications are therefore `NOT_REPLICATED` and `DO_NOT_PROMOTE`; exact keys are
zero.

The result is null-like at useful resolutions: byte top-1/top-4/top-16 counts are
`4/16/61` against uniform expectations `4/16/64`, zero 16-bit groups are top-16,
and the best million-decoy rank 45,147 is unexceptional across 32 tries. Six
coordinates reach 22/32 correct against 6.41 expected; the best 24/32 coordinate
has familywise null probability about 0.592. O1C-0014-to-0016 coordinate transfer
is approximately zero.

The O1C-0016 common-mode diagnosis still determines the real-cipher transition:
per-target h65 primary and matched-shuffled compression correlate `0.999905`.
O1C-0017 shows that the replacement machinery can autonomously discover a hidden
orientation and retain it. O1C-0018 finds a positive early true-versus-shifted
picker margin but no raw full-round gate pass; O1C-0019 must give that learned
utility actual control over target-conditioned packet selection and stopping.

The O1C-0016 capsule verifies 680/680 members. All commitments open and every
output independently recomputes. It used `1972.624545` billed CPU seconds,
`1620.537008` wall seconds, `17,920` native branches, `414.8125` MiB conservative
peak RSS, `67,584` bytes of live target state and `6,768,561` persistent bytes.
Manifest:
`fd0469885ee436414f94d708006cc40d86fc730d25b618167c7d664b3fe195ea`;
internal result:
`6146dbfe10e1add60fe5d16f133c5b1acdced42bcf2249561926d26ee0e11652`.
Detailed forensics are in
[`research/O1C0016_POST_REVEAL_FORENSICS_20260717.md`](research/O1C0016_POST_REVEAL_FORENSICS_20260717.md).

`O1C-0015` remains an immutable operational resource failure, not a scientific
inverse result. It froze all 32 factual predictions and three controls, then
revealed all 32 targets once in process memory before the old late resource gate
fired. No reveal receipt, evaluation or final scientific report was persisted, so
no key metric may be reconstructed or claimed. All 32 targets are burned and may
never be replayed.

The failed capsule
`runs/20260717_103252_O1C-0015_full256-polyphase-blind-replication-v1/`
verifies `579/579`; manifest
`326bc30a1499f6479d306df43b17ec390c020832bb5d1816fa8ab9f7f9660314`
and prediction-set commitment
`f2958da162a2dca74f2c5dd62ccb45f3d764be7c8f71200ee3afba8409a62116`
are immutable. The run exceeded all three old soft ceilings: CPU `>1600 s`, peak
RSS `>384 MiB`, and wall `>1400 s`; the exact values were discarded by the old
exception path and are unavailable.

`O1C-0014` reloaded O1C-0013's exact primary reader
`796e79ec932b990a59ecbc34216c4878b9279bae3bb136fe0832e580bcb2e9f8`
and shuffled reader without fitting, reselection, sign, temperature or scale
changes. The protocol and reader bytes were persisted before exactly eight fresh
OS-random key calls; all eight factual predictions and three controls were
persisted before any reveal. Every target was standard twenty-round ChaCha20 with
all 256 key bits unknown and only public counter, nonce and output at inference.

The primary reader obtained `1053/2048` bits and NLL `255.766215857` bit/key,
equivalent to `+0.233784143` bit/key compression. The exact conditional-uniform
reference gives `z=1.819365` (`p≈0.034428`), every leave-one-target-out mean remains
positive, and the primary beats the shuffled reader by `+1.524765187` bit/key.
However only `4/8` targets are individually positive, the paired reader-control
comparison is only `z=0.838026`, and wrong-nonce/byte-rotate controls are positive.
The predeclared classification is therefore `NOT_REPLICATED`, not a stable signal
or SOTA result. There are zero exact keys; the best million-decoy rank is `10,875`.

Post-reveal mechanism diagnostics do not alter that verdict. All three already-
existing unary horizons are aggregate-positive (`h64 +0.139097`, `h96 +0.233784`,
`h65 +0.188340` bit/key), while the richer ARX24 and ARX24+Motif12 arms are
negative (`-0.374410` and `-0.355199`). This localizes the current breadcrumb to
  paired proof difficulty across wavelengths and rejects the present coarse ARX/
  motif aggregation as the next blind primary. A fixed h96+h65 equal-logit
  ensemble gives an exploratory `+0.229` bit/key, `1066/2048` bits, `6/8` positive
  targets and conditional `z=2.107`; O1C-0015 must test it only on fresh targets.

The O1C-0014 capsule verifies 124/124 members. It used `306.194798` billed CPU
seconds, `245.756482` wall seconds, `5,632` native branches, `302.578125` MiB peak
RSS and `2,947,408` persistent bytes. Sibling reads/writes, MPS and GPU calls are
zero. Capsule manifest:
`741718cbc6b63de24f4d9c89cd2aedc8e9779a0ebb38adc4d40666e97ce24bcf`;
internal result:
`ecc06b011a95f6ceeec08641b68e1105511cf714cc250f9fe3b62e66c2af4c4a`.

`O1C-0013` was the first complete learned full-256 causal-reader experiment. Four
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
[`research/W52_TRANSFER_20260717.md`](research/W52_TRANSFER_20260717.md), and the
latest result audit is in
[`research/O1C0016_POST_REVEAL_FORENSICS_20260717.md`](research/O1C0016_POST_REVEAL_FORENSICS_20260717.md).
The implemented continuous fast/slow learner, its frozen controls and the
O1C-0017 result boundary are documented in
[`docs/O1_ONLINE_MOBIUS_CONTROLLER.md`](docs/O1_ONLINE_MOBIUS_CONTROLLER.md).

## Active process table

| Attempt | PID | Started | Command | Progress | ETA |
|---|---:|---|---|---|---|
| Sibling W52 (external, read-only) | 8 launchers | 2026-07-17 14:35 | A528 W52 protocol-bound workers | active at 17:24; O1C-0019 interlock engaged | unknown |
| O1C-0019 | — | — | frozen config only | implementation/test/micro-smoke complete; scientific run not started | after W52 clears |

## Highest-ROI next actions

1. Keep commit `dc249ad` and the O1C-0019 config byte-exact; monitor the sibling
   W52 resource interlock without touching its files or processes.
2. When W52 clears, execute the committed four-fold artifact-only capsule at
   W1/W2/W3 and change no reader, critic, control or threshold mid-run.
3. Use raw learned-vs-untrained transfer, true-vs-shifted/static/hash IAUC and the
   exact STOP/no-STOP twin to localize reader, credit, routing or abstention.
4. Allocate a disjoint target only if the frozen BUILD-LOO authorization gate
   passes; otherwise change only the failed mechanism and retain all breadcrumbs.

## Recent attempts

| Attempt | Time | Hypothesis | Result | Claim level | Cost | Main breadcrumb | Artifact |
|---|---|---|---|---|---|---|---|
| `O1C-0019` pre-run | 2026-07-17 | Incremental packet learning plus reader-bound stationary credit lets O1 discover and autonomously route public full-256 evidence | Implementation frozen; 29 tests + 5 subtests and real one-fold micro-smoke pass; no efficacy execution while W52 is active | `INSTRUMENT` only | smoke 2.559 CPU s; 2.803 wall s; 315,359,232 B peak; 0 solver branches | Exact no-STOP twin separates routing from abstention; key-lazy discovery closes a lifecycle leak | [Config](configs/full256_multiresolution_build_loo_v1.json) |
| `O1C-0018` | 2026-07-17 | A reveal-delayed O1 reader can learn attacker-valid full-round paired-proof orientation and a true reward critic can select more information per work | `NO_RAW_SIGNAL_PICKER_UNINTERPRETABLE`: raw learned mean -1.284644 bits; W1 true +0.326847/+0.160175 and true beats shifted in all 6 cells, but static wins mean IAUC and hard coverage/hash dominate selection | `TEST` negative full-round gate with autonomous-picker breadcrumb | 545.024 CPU s; 510.875 wall s; 315,703,296 B peak; 3,072 native branches | Remove cumulative-query double integration; packetize horizons; stationary reader-bound credit; all-address preview; soft no-starvation plus STOP | [Run capsule](runs/20260717_152827_O1C-0018_full256-online-real-gate-dev-v1/RUN.md) |
| `O1C-0017` | 2026-07-17 | A bounded O1 reader can autonomously discover one oriented channel among 330 anonymous channels and retain all 256 addressed readings without target-time updates | `MECHANISM_PASS`: 3286/4096 bits, +42.308742 bits mean compression, 80.225% accuracy, 16/16 positive; +46.701 over ablation, +42.765 over shuffled, +47.231 over raw end state | `VALIDATION` synthetic mechanism; no crypto/picker claim | 78.089 CPU s; 79.853 wall s; 286.438 MiB peak; 29,184 action observations | Anonymous signal discovery works; raw holographic end state is crosstalk-limited while the exact Bit-Vault retains the learned readings | [Run capsule](runs/20260717_140953_O1C-0017_full256-online-self-discovery-v1/RUN.md) |
| `O1C-0016` | 2026-07-17 | Frozen h96 and equal-logit h96+h65 remove transferable code length on 32 new full-256 output-only keys | `NOT_REPLICATED / DO_NOT_PROMOTE`: 4093/8192 bits, -0.078249 bit/key, 11/32 positive, paired z -0.555, null-like byte/block ranks, 0 exact keys | `VALIDATION` negative; lifecycle/integrity pass | 1972.625 CPU s; 1620.537 wall s; 414.813 MiB peak; 17,920 branches | h65 primary/shuffled target compression corr 0.999905 exposes common-mode difficulty; learn nuisance rejection and residual orientation online | [Run capsule](runs/20260717_115325_O1C-0016_full256-polyphase-blind-replication-v2/RUN.md) |
| `O1C-0015` | 2026-07-17 | The fixed h96+h65 polyphase reader transfers to 32 new full-256 output-only keys | Operational resource failure after all 32 reveals occurred in memory; no evaluation or reveal receipt persisted, so no scientific metric or classification exists | `OPERATIONAL_FAILURE`; no scientific result | CPU >1600 s; wall >1400 s; RSS >384 MiB; exact values unavailable; 17,920 branches | Burn all 32 targets; rerun the identical science as O1C-0016 with truthful pre-reveal accounting and corrected soft ceilings | [Failed capsule](runs/20260717_103252_O1C-0015_full256-polyphase-blind-replication-v1/RUN.md) |
| `O1C-0014` | 2026-07-17 | O1C-0013's exact h96 bytes remove code length on eight new full-256 output-only keys without refit | `NOT_REPLICATED`: 1053/2048 bits, +0.233784 bit/key, conditional z 1.819, +1.524765 over shuffled, but 4/8 positive, paired z 0.838, controls mixed, 0 exact keys | `VALIDATION` negative with positive aggregate breadcrumb | 306.195 CPU s; 245.756 wall s; 302.578 MiB peak; zero sibling/GPU work | Unary h64/h96/h65 remain positive, coarse ARX/Motif arms turn negative; freeze h96+h65 once on 32 new keys | [Run capsule](runs/20260717_084847_O1C-0014_full256-frozen-reader-blind-replication-v1/RUN.md) |
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
| `O1C-0018` capsule manifest | `fcbf43c99994c0debe5b39bb3e734ea1d1e23ba58e89b10ff2bb7e23886493fb` |
| `O1C-0018` internal result commitment | `db92bd86849ff93e0f9b935a72f64f1b4bd46b134747c913ee82e5d772ac11c9` |
| `O1C-0018` result artifact | `a8e5940edc5887e404725c98631df89e1f91963abd47d1fa51263fc681e9df4d` |
| `O1C-0018` canonical config | `fd539d2a2461f879ebdbcad2c29f3c6de7c514385fece2ef1bf8ddb06707056a` |
| `O1C-0018` prediction freeze | `529356d380baec494ddfe0710e8b9cf0f85308c50b2913600e4c39b9a041c30e` |
| `O1C-0018` learning freeze | `09043f7dec8eb916baff3879706111add83f1c4337f321e01842bc351fc2564a` |
| `O1C-0018` primary slow state | `de7030eab45e7e88770d4789183e0ca604ecf943302d6c3e8b792f0a316c035c` |
| `O1C-0018` shifted slow state | `bc71d80b9f98feaf9c5f1ffe9244384f8fdd8775359b27fe62bc60076098f8b7` |
| `O1C-0017` capsule manifest | `59f1f59b4e24545391cb06cd2bee395285d4385c893af36d18def28bcb3858fd` |
| `O1C-0017` internal result commitment | `609014695bc3013bb971d7d05b682d18797af5c9d9cd31561cdc41de120ff28c` |
| `O1C-0017` prediction freeze | `a2f5a8ba939bdedf9fdce4bb1e0dabac9fc3ac850a3b9e249b9b2f1d3abafba7` |
| `O1C-0017` primary slow state | `481f8177a1d4cca0efc7a96daf09dbfa9615fcbeca5106845b976985c353c477` |
| `O1C-0017` representative fast state | `51c99f3a8a273863329f524b36909c24cdc1237ec17b8dc361ab6c54533f35bb` |
| `O1C-0017` canonical config | `6bab5437954da6b26e4db0ac3b0a5a613b0a3180c4a406500264615ff908971b` |
| `O1C-0016` capsule manifest | `fd0469885ee436414f94d708006cc40d86fc730d25b618167c7d664b3fe195ea` |
| `O1C-0016` internal result commitment | `6146dbfe10e1add60fe5d16f133c5b1acdced42bcf2249561926d26ee0e11652` |
| `O1C-0016` canonical config | `054e8b05c7824cf4c47f509d6a4977e3feac7e5df5ce006f55948b93554daaa6` |
| `O1C-0015` failed capsule manifest | `326bc30a1499f6479d306df43b17ec390c020832bb5d1816fa8ab9f7f9660314` |
| `O1C-0015` prediction set | `f2958da162a2dca74f2c5dd62ccb45f3d764be7c8f71200ee3afba8409a62116` |
| `O1C-0014` capsule manifest | `741718cbc6b63de24f4d9c89cd2aedc8e9779a0ebb38adc4d40666e97ce24bcf` |
| `O1C-0014` internal result commitment | `ecc06b011a95f6ceeec08641b68e1105511cf714cc250f9fe3b62e66c2af4c4a` |
| `O1C-0014` evaluation commitment | `69a3142f56b08f60890b4849ab9d71d4a68aecb4ad5db3a0f24b304cf041b6ef` |
| `O1C-0014` protocol freeze | `3664e586a30daa758f719bb918e64938690cf5aa47daaf6aa3a027720ca9c2b9` |
| `O1C-0014` prediction set | `5b5912420948fef68b4be4a4fb171c5927286e0c9e6acfb9d1c0f48d3302a683` |
| `O1C-0014` coordinate stability | `6fc66caf0ff3e26938e25f4e6cde15b2a58943c10dbd1cb482f32b06223d3364` |
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

The O1C-0019 implementation is complete and frozen at `dc249ad`; the real-artifact
micro-smoke is recorded at `305542c`. Do not rebuild or tune it. Recheck the eight
sibling W52 launchers and memory pressure. While they remain active, perform only light
tests/microbenchmarks. After they exit, launch the exact committed config from a
clean tree and preserve the timestamped capsule. DEVELOPMENT stays outside this
BUILD-LOO decision. Never reuse O1C-0015/16 targets, O1C-0017 formal seeds or
O1C-0018 DEVELOPMENT targets as fresh evidence. Keep the sibling recovery queue
read-only, CPU-only and prioritized.
