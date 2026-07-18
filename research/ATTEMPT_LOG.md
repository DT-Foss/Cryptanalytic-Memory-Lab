# Append-Only Attempt Log

Never rewrite historical attempt entries. Corrections are appended as new notes.

## O1C-0000 — Integration-instrument baseline

- **Recorded:** 2026-07-15T12:05:14+02:00
- **Source commit:** `5bb39913bec2712ce1348bc5b9667b6d5798326b`
- **Claim level:** `INSTRUMENT`
- **Hypothesis:** O1 bounded memory, O1-O typed adaptive control and the exact
  recovery backend can share a deterministic, provenance-safe integration seam.
- **Outcome:** Supported at harness level. The lab has deterministic memory and
  evidence baselines, a legal typed chain, a bounded TargetModel, a real O1-O replay
  and a 570-member verified publication source.
- **Controls:** under-capacity CountSketch, full-context ceiling, no-signal stream,
  perfectly correlated stream, post-reveal flow rejection.
- **Cost:** five synthetic seeds; 42 unit tests; no external GPU or active-run work.
- **Limitation:** no real cipher-derived bit evidence has entered the O1 state.
- **Breadcrumb:** Stage 3 is the first unresolved gate; use manifest-pinned
  pre-result artifacts and attacker-computable features before building more memory
  mechanisms.
- **Artifacts:** `runs/quick.json`, `runs/o1o-2026-02-18-replay.json`,
  `runs/fullround-source-verification.json`.
- **Next action:** `O1C-0001` Stage-3 dataset selection and ingestion.

## O1C-0001 — Manifest-pinned Stage-3 ingestion

- **Recorded:** 2026-07-15T12:25:29+02:00
- **Source commit:** `d897c531a7b065117eeefadfb95b067f38f5370a`
- **Claim level:** `SMOKE`
- **Hypothesis:** the A296/A297 publication artifacts can form a complete
  target-blind solver-trajectory dataset without reading result labels.
- **Outcome:** supported. Twelve episodes yielded 3,072 cells, 12,288 model-free
  UNKNOWN stages and 57 deterministic features per cell. All 24 selected members
  matched the source manifest; the adapter read zero post-reveal members.
- **Controls:** bounded zstd decode; compressed/raw bytes and hashes; exact cell and
  horizon coverage; clear watchdogs; empty model bits; hard progress/result denylist.
- **Cost:** 0.360 wall seconds, zero solver calls, zero GPU seconds.
- **Artifact:** `runs/20260715_122529_O1C-0001_stage3-a296-a297-ingest/`;
  capsule manifest `376e3b27f107d132421e29c2669f468a57c8417924928ce41badadf14d3dd05f`.
- **Next action:** fit and freeze real target-blind readers with physically separate
  label access.

## O1C-0002 — Frozen retrospective reader tournament

- **Recorded:** 2026-07-15T12:32:36+02:00
- **Source commit:** `5f456c616b50458cba97a0201d636b5fdb743d32`
- **Claim level:** `RETROSPECTIVE`
- **Hypothesis:** one of 119 TRAIN-only readers will retain its validation advantage
  on the disjoint A296 holdout and W32 transfer panel.
- **Frozen plan:** `feature.rank.047.+1`, the positive midrank of
  `h8.search_propagations`; plan SHA-256
  `ae2bda0e6a337b5396cbbab2e72108c38f67543b137f2e266a4f3943d7d7a587`.
- **Outcome:** gate failed. Validation mean gain was 3.348 bits; A296 holdout was
  0.801 bits and W32 transfer 1.104 bits. The reader lost to numeric and published
  controls on A296 and to numeric/public-hash on W32.
- **Multiplicity control:** exact enumeration of all 65,536 two-label pairs across
  the complete 119-reader selection procedure gave familywise `p=0.664139`.
- **Leakage boundary:** complete holdout and baseline orders were persisted before
  any holdout broker call; `holdout_labels_read_before_freeze=0`.
- **Cost:** 4.573 wall seconds, zero solver calls, zero GPU seconds.
- **Breadcrumb:** the end-horizon propagation channel is a component, not a stable
  reader. Move to independently fixed temporal profiles, XOR-neighbor geometry and
  Laplacian/spectral binding; do not resweep this single channel.
- **Artifact:** `runs/20260715_123236_O1C-0002_retrospective-reader-tournament/`;
  capsule manifest `b4a242708ae30481deed5346df519bb5123c7601fa6c58b6c06bd514be314ff9`.
- **Next action:** `O1C-0003` curate and pin the Direct12 dependency snapshot, then
  reproduce the 532-feature and frozen-pair hashes before new selection.

## O1C-0003 — Immutable Direct12 source snapshot

- **Recorded:** 2026-07-15T12:37:34+02:00
- **Source commit:** `be3e8c5`
- **Claim level:** `SMOKE`
- **Hypothesis:** the minimal A272/A342/A348/A349 dependency set can be copied into
  a lab-owned immutable source without reading recovery progress or outcomes.
- **Outcome:** supported. All 71 ledger members and 9,882,690 bytes verified and
  copied; every member is bound by both the source ledger and capsule manifest.
- **Provenance correction:** these members came from dirty `arx-carry-leak` HEAD
  `97fa868b…`; the clean Fullround manifest is explicitly not claimed.
- **Boundary:** zero denied members read; zero sibling writes/imports/execution.
- **Cost:** 0.069 wall seconds; zero solver calls and zero GPU seconds.
- **Artifact:** `runs/20260715_123734_O1C-0003_direct12-source-snapshot/`; capsule
  manifest `d7dcb2b2c3f39d866c7820dbc7423ce55b4d5c9df6634d5a00126a954a0a065d`.
- **Next action:** independently reconstruct the feature geometry and commitments.

## O1C-0004 — Independent Direct12 532-reader reproduction

- **Recorded:** 2026-07-15T13:00:47+02:00
- **Source commit:** `bfd5d9b2514375943ed955fee21f25662f5dbb07`
- **Claim level:** `VALIDATION`
- **Hypothesis:** a lab-owned implementation can exactly reproduce the 133→532
  temporal/XOR transform, A342 pair score and frozen A348/A349 orders from O1C-0003.
- **Outcome:** supported. The model (`b096c086…`), both feature-name hashes, A348
  raw/slice-z score and order hashes, A349 score/order and contextual commitment all
  match exactly. Dataset hash: `6d645aa7…`; reader contract: `a972842a…`.
- **Lifecycle:** both full orders were persisted with zero labels read; only then was
  A348 calibration truth opened (rank 298, 3.780831 bits). A349 truth is unavailable.
- **Cost:** 5.986 wall seconds; 52 shards, 13,312 cells and 53,248 precomputed solver
  stages; zero new solver calls and zero GPU seconds.
- **Artifact:** `runs/20260715_130047_O1C-0004_direct12-532-reproduction/`; capsule
  manifest `ac3333606e0aaf47dc519553c0e9407fc8ab67dba5319ed340eac579cb25c7bf`.
- **Next action:** `O1C-0005` bounded spectral/multi-slot/Bit-Vault state tournament.

## O1C-0005 — Receipt-bound bounded spectral memory tournament

- **Recorded:** 2026-07-15T13:54:34+02:00
- **Source commit:** `a1ebe8a01bcfc1369b413e53c2e15ab4be043cb5`
- **Claim level:** `VALIDATION`
- **Hypothesis:** distributed multi-target spectral support and dense low-precision
  O1 registers preserve the verified Direct12 order more transferably than sparse
  modes learned from one calibration field; O1-O can freeze the smallest arm that
  crosses predeclared A348 fidelity, state, work and clip gates.
- **Frozen O1-O choice:** `quantized-bit-vault-4bit-h1.25`; selection SHA-256
  `5aaf243457850fbc1435cad8ff257da4eaf6a9b3ec983042f46dde690c1a5983`;
  future-template SHA-256
  `245ecb1c1ae8ec90c9feca6466ba007034635b1e737d607979f3ba237682b9d7`.
- **Calibration evidence:** A348 Spearman `0.9904664476`, Kendall `0.9120328239`,
  top-32 overlap `0.75`, top-128 `0.796875`, zero clips, 6,668 serialized online
  bytes and 128 static scale bytes. The template retains 16 scales, not the 4,096
  A348 scores.
- **Target-blind transfer:** A349 Spearman `0.9901983485`, top-32 overlap `0.71875`;
  frozen order SHA-256
  `879d31ef67ae955951dba84fd27d7e8d9cfa9a08e51c8a518d3ff44c0b5e5e7e`.
- **Mechanism comparison:** at total K=2,048, A272-distributed multi-slot support
  reached `0.8714770054`, low-degree `0.4942562890`, best of three deterministic
  candidate-ID random controls `0.7169227600`, and global single-A348 energy support
  `0.7972250917`.
- **Lifecycle:** the O1-O future template received a hash-bound persistence receipt
  before the A349 score member entered the experiment reader. All 86 complete A349
  orders then received an exact artifact-map receipt before the A348 truth API was
  opened. A272 truths read: 0; A348 truth labels: 1 post-freeze; A349 labels: 0.
- **Cost:** 38.521 wall seconds; 72 calibration and 72 deployment arms; 14 explicit
  dictionary controls; 311,689,216 declared stream-update accumulations; 2,723,840
  A272 feature values; 2,801,664 reconstruction FWHT butterflies; zero new solver
  calls and zero GPU seconds.
- **Controls:** global low-degree and deterministic random masks, full float banks,
  invalid direct dictionaries, exact hash-bound stream coverage, monotone
  `INTERNAL_TRAIN`/`CONTROL` provenance, staged score-member access and receipt-only
  persistence gates.
- **Limitation:** A349 target/outcome/progress remained unavailable, but A349
  target-blind field fidelity had been inspected during mechanism development. This
  is mechanistic validation, not a fresh architecture-generalization or exact
  recovery claim. The 4,080-register dense bank is full rank, not sublinear capacity.
- **Breadcrumb:** sparse coefficient selection is the wrong compression axis here;
  preserve the distributed basis and compress its precision. Carry the exact
  16-scale template unchanged to a new, untouched field.
- **Artifact:** `runs/20260715_135434_O1C-0005_bounded-spectral-memory-tournament/`;
  capsule manifest `de67260cf44556a3fa48ef2b6daa1b738cf40b392739c6a05d835cbcdb1ab103`;
  deterministic report `cf930a4f206423bbbd6072b90343c5955c56110d9640a36b12c7f639ad1723b8`.
- **Next action:** `O1C-0006` precommit a fresh lab-owned Direct12 field, apply this
  frozen template without refitting, persist the complete order and run equal-work
  exact recovery plus independent full-round confirmation.

## O1C-0006 — Corrected-codec adaptive-DC validation ceiling

- **Recorded:** 2026-07-15T15:45:53+02:00
- **Source commit:** `f3e627490bd046618ce1e550cb7cbce9d02bf140`
- **Claim level:** `VALIDATION`
- **Hypothesis:** the corrected W46 Direct12 codec can reproduce A355/A356 exactly,
  and a frozen DC-complete bounded register bank can emit high-fidelity complete
  orders under an 8,192-byte maximum serialized-logical-state budget.
- **Lifecycle:** O1C-0006 was reserved before its only outcome-bearing replay. A
  crash would have consumed the attempt and finalized it as stopped; no optional
  retry was available. Fresh challenges generated: 0.
- **Exact reproduction:** A355 field `de420a7e…`, order `516e32fd…`; A356 field
  `ac29c51b…`, order `436082dc…`. Both stored orders independently decode to exact
  permutations of cells 0–4095.
- **Selected arm:** `adaptive-dc-6bit-h1`; 7,716 online bytes, 8,014 maximum
  serialized logical mechanism bytes, zero clips. A355/A356 worst metrics:
  Spearman `0.9992243507`, Kendall `0.9764258528`, top-8 `1.0`, top-32 `0.96875`,
  top-128 `0.9453125`.
- **Matched baseline:** a conservative direct 6-bit table uses 3,918 maximum
  serialized logical bytes and produces the identical quantized order on both
  fields. The spectral ceiling is therefore `2.045431×` larger.
- **Claim boundary:** 4,096 spectral degrees of freedom over a 4,096-cell domain
  make the transform information-equivalent to the direct table. No compression,
  domain-independent capacity, fresh generalization, recovery or SOTA claim.
- **Artifacts:** 24/24 complete orders; 61 pinned sibling members plus three local
  immutable anchors; 141/141 manifest entries independently verified; zero sibling
  writes and zero active progress/outcome reads.
- **Cost:** 7.347 wall seconds; nine adaptive arms, 147,456 field reads, zero new
  solver calls and zero GPU seconds.
- **Artifact:** `runs/20260715_154553_O1C-0006_corrected-codec-adaptive-dc-bridge/`;
  capsule manifest `720bc88834e5ae2959ac960d4f5fe2ca1c8845283b0d32273c6ca2cfea34fdc6`;
  report `64ace20f8798da49e6108352ea0c95459afb2a955439148cea8f357d643b870b`;
  order set `964dd87ddf6cf506d9399ff6f1fb16245617bcec8f3ab66484031d79f9cd41e8`.
- **Breadcrumb:** stop compressing the dense final scalar field with full-rank
  transforms. Move upstream to bit/carry/round/solver evidence and require a genuine
  non-dictionary successor below 3,918 bytes before generating a fresh challenge.

## O1C-0007 — Upstream solver-evidence Bit-Vault freeze

- **Recorded:** 2026-07-15T17:45:37+02:00
- **Source commit:** `cf7ef298caf80006ae3470240d509c661221b150`
- **Claim level:** `RETROSPECTIVE`
- **Hypothesis:** low-degree projections of upstream solver-event evidence can
  populate a genuine compact O1 state and yield a useful complete candidate order
  without retaining candidate rows, evidence rows or a KV store.
- **Lifecycle:** all 672 A355 orders were persisted before the single A355 target
  read. The exact 152-view target-blind selection procedure was then replayed for
  every possible label. The selected decoder and A356 state/order were persisted
  before any A356 target or outcome read. The finalized attempt cannot be replayed.
- **Selected decoder:**
  `search_propagations__h1__signed-log1p__degree1__negative`; selected-spec SHA-256
  `4c78e10edf21504085e6bf3efc21ef03e50fe6abfb0993556b8fb6f0531d6694`.
- **Compact state:** 12 implicit unary Walsh registers; 266-byte conservative
  maximum logical mechanism state; 162-byte frozen A355/A356 binaries; zero
  candidate/evidence rows and zero external index growth.
- **Retrospective efficacy:** A355 rank `73`, raw gain `5.810175441119982` bits;
  exact favorable-label count `2431/4096`, hence conditional
  `p=0.593505859375`. The efficacy gate failed and no statistical SOTA is claimed.
- **Prospective artifact:** target-/outcome-blind transductive A356 order SHA-256
  `0a6e32430a97c968c3a831ef23c58eaacaaf411fcc9f44e59661f62efa764159`.
  A356 is not source-unseen and therefore is not the fresh test.
- **Controls:** 14 channels, four horizons, three transforms, two supports and two
  orientations; 448/672 views structurally streamable, 152/448 eligible after the
  target-blind tie gate. Best nonstreamable post-hoc rank was 23; best tied
  streamable control rank was 26 with 3,328 collision excess. Neither is promoted.
- **Boundary:** the 266-byte state and O1C-0006's 3,918-byte table encode different
  fields and fidelity targets, so their sizes do not prove matched-information
  compression dominance. The accumulator consumed a materialized canonical field;
  source-event-to-state streaming remains unproven.
- **Source and cost:** 34 allowed members opened and copied from immutable O1C-0006
  source capsule `720bc888…`, totaling 2,942,292 bytes; zero sibling reads/writes,
  zero active progress or outcome reads, zero fresh challenges, zero new solver/GPU
  work; elapsed `10.798910` seconds.
- **Artifact:**
  `runs/20260715_174537_O1C-0007_upstream-solver-evidence-bit-vault-freeze/`;
  capsule manifest `2900adafb938ba470ae595b21895a0035a77621a667e04abacf1fd8d5654f3c1`;
  report artifact `868f339b22e6b1bddbde944dffcebd22ad8f94287b829cd65d85670d4de2dec5`;
  internal report commitment `c371ce0b100684b518c1e9094547f2acdb869c3a9aac660408058acc48ccdfe7`;
  panel blob `2ed242ba8582798cd23618be18a230cecabe27c9aed2546f5a88814117f86949`;
  future-template artifact `836d6f0b01a7b86d50b0b5f81eaaaef1df235dfa45804b2a5ccc2a18d24775fd`.
- **Breadcrumb:** preserve the compact mechanism and the negative calibration;
  never resweep A355. The originally proposed narrow W46 O1C-0008 is superseded by
  the full-256 Living Inverse; the decoder remains a matched unary arm.

## 2026-07-17 — W52 read-only intake and full-256 target pivot (non-attempt)

- **Recorded:** 2026-07-17T02:44:45+02:00
- **Mutation boundary:** `arx-carry-leak` was inspected read-only; no project script
  executed and no sibling file changed.  This entry records architecture intake,
  not an outcome-bearing O1C experiment.
- **Resource state:** 16 GiB physical RAM, 47% system-wide free memory, zero
  throttled pages; observed active solver engines used roughly 13 MiB RSS each.
  Local work remains light while that queue is active.
- **New evidence:** A447/A448 proof ancestry transfers across all eight held blocks;
  A449 transfers the operator target-label-blind to W52.  Wavelengths 64/96/65 are
  complementary; A465's cubic PoE and A469's positive bucket-local correction form
  the strongest reusable composition.
- **Target decision:** all 256 ChaCha20 key bits are unknown from experiment one.
  Attack inputs are public counter/nonce/output plus self-generated candidate
  traces.  Target internal traces are teacher-only.
- **Superseded action:** do not generate a fresh W46 target merely to exercise the
  frozen O1C-0007 decoder and do not scale a residual-width ladder through W52.
- **New O1C-0008:** implement the full-256 attacker/teacher type boundary, traced
  relation generator, structured-to-uniform contrast stream and complete progress
  metrics before training the first Living Inverse reader.
- **Artifacts:** `docs/O1_256_LIVING_INVERSE.md` and
  `research/W52_TRANSFER_20260717.md`.

## O1C-0008 — Full-256 Living Inverse foundation

- **Recorded:** 2026-07-17T03:11:14+02:00
- **Source commit:** `826149ded68f0c9afbdd7a1c4f9ea90235f1ef56`
- **Claim level:** `SMOKE`
- **Hypothesis:** the full-256 public-output attacker type, physically separate
  teacher labels, exact traced ChaCha20 contrasts and non-recovery progress vector
  can be made executable without sibling or accelerator use.
- **Result:** all gates passed.  Six proposal families generated 72 deployment
  contrasts over four build and two development targets.  Every target has 256
  unknown key bits and one standard full-round block.  The attacker feature vector
  has 2,576 values and contains candidate round/carry summaries but zero target
  trace fields.
- **Metric harness:** uniform posterior NLL exactly `256.0` bits; one-million-decoy
  rank path completed; `0.99` truth oracle NLL `3.7118898419494637` bits, exact mode,
  block ranks one, full-key decoy rank one and exact key in the 65,536 beam.
- **Controls:** public output flip Hamming one; wrong nonce Hamming one while output
  bytes remain fixed; shuffled-key control registered for the trained reader.
- **Boundary:** this is an executable attacker/data/measurement result, not evidence
  of inversion.  No learned posterior, entropy gain or SOTA claim exists yet.
- **Resources:** `0.996414` wall seconds; 78 logical unique ChaCha blocks; CPU only;
  zero MPS/GPU, sibling reads/writes and fresh target generation/reveal.
- **Artifact:**
  `runs/20260717_031113_O1C-0008_full256-living-inverse-foundation/`;
  capsule manifest
  `50cd1dcd83034d69aafd2e7890d62b9f2c25b6e65c5a929d3119027a71105449`;
  deterministic result
  `14bfa1dd9e4593cac223a779562ff8b591bf88c485486814be62e6f73baa79a2`.
- **Next action:** O1C-0009 trains matched output-only, candidate-relative and
  teacher-distilled full-256 readers and measures uniform development-key NLL plus
  all controls before any sealed target is generated.

## O1C-0009 — Sealed full-256 output-only readers

- **Recorded:** 2026-07-17T04:16:16+02:00
- **Source commit:** `f718e78cf63ee457298288cc80e192b9bc110228`
- **Claim level:** `VALIDATION` negative
- **Lifecycle:** 512 known TRAIN and 64 known CAL keys were created first. Four
  models, scales, primary arm, proposal policy and familywise bit selections were
  persisted while DEV entropy and labels were absent. Only then were 128 unique
  broker-random targets published. All factual/control `128 x 256` posteriors were
  stored in prediction blob
  `8431b3c19a697ce0d48e66d29b199ec6d199670870d40231564c9516e3c34ad2`
  before any reveal; all reveal receipts bind that blob.
- **Declared result:** CAL selected `direct`, but scale zero for direct, relative,
  distilled and shuffled-key control. DEV mean NLL `256.0`, compression `0.0`, zero
  CAL-selected/familywise transferable bits and no exact beam key. Scientific gate
  failed; no inverse or SOTA claim is made.
- **Integrity:** capsule verification 25/25; 128/128 commitments open; every key
  exactly recomputes its standard twenty-round public block; target trace fields in
  deployment `0`; live accumulator bound `2,056` bytes.
- **Resources:** `6.923216` CPU seconds, `182.90625` MiB peak RSS, CPU only, zero
  MPS/GPU and zero sibling reads/writes.
- **Post-reveal breadcrumb, not claim:** continuous signed scale fit on CAL alone
  selects direct scale `-0.03860970720667151`, CAL NLL `255.98475392461603` and
  revealed DEV NLL `255.97684081564623`, i.e. `0.02315918435379` bit compression.
  Across 128 targets SD is `0.19993730517725` bit; the CAL-selected top-16
  coordinates do not transfer (`49.7559%` oriented DEV accuracy), and relative/
  distilled signed scales worsen DEV. This isolates a global sign breadcrumb, not
  stable bits.
- **Artifact:**
  `runs/20260717_040741_O1C-0009_full256-output-only-reader-v1/`; manifest
  `f31d7672921dc0c2ec684cf8c5247a3ff2386fbea316c2eab98072cd22fb29d2`;
  internal result
  `40276d71516d4d150b02cc8235c08d00fb8ceb28daf64d1316826b38fd094bf9`.
- **Next action:** freeze the exact direct model/negative scale for a larger new
  sealed replication, then replace end-output regression with paired public-CNF
  solver/proof evidence regardless of outcome.

## O1C-0010 — Prospective signed-direct full-256 replication

- **Recorded:** 2026-07-17T04:52:16+02:00
- **Source commit:** `1d061c2661a3d93c9fe82c8df828b328b04cd23a`
- **Claim level:** `VALIDATION` negative
- **Hypothesis:** the post-reveal O1C-0009 direct-reader orientation at signed
  scale `-0.03860970720667151` transfers without any refit to new uniform
  full-width keys.
- **Lifecycle:** exact O1C-0009 direct/shuffled model bytes, both scales, six arm
  names and every gate were copied, hash-bound and persisted before target
  entropy. Only then were 2,048 unique OS-random targets published. All six
  `2048 x 256` float64 posterior matrices (`25,165,824` bytes) were persisted in
  blob `4643e0e849178014ede98e355037829158ca2eadc9b404671a8f64d6904e2dee`
  before the first reveal. The run cannot be replayed.
- **Declared result:** direct mean NLL `256.01908846250825`, compression
  `-0.019088462508241047` bit, target SE `0.004510444449122523`, conditional
  uniform/Rademacher reference `z=-0.9460815985078296`. The three-SE target lower
  bound was `-0.03261979585560862` bit.
- **Matched controls:** direct-minus-shuffled compression `-0.017541123410184392`
  bit (`z=-0.909288`); direct-minus-output-permutation `+0.0009622424228086879`
  bit (`z=0.190158`); output-flip delta `-0.00037314`; wrong-nonce delta
  `+0.00017779`. Only the algebraically expected reverse-polarity-negative
  checksum passed; every efficacy gate failed.
- **Bit boundary:** mean mode accuracy `49.9599457%`, mean correct bits
  `127.89746`; the strongest post-reveal coordinate gains are about `0.00055`
  bit each and are unselected diagnostics. O1C-0009 exploratory bits 82/218/240
  give `+0.000184`, `+0.0000395`, and `-0.0000891` bit respectively, so there is
  no stable coordinate breadcrumb.
- **Integrity:** capsule verification 23/23; 2,048/2,048 commitments open; every
  key exactly recomputes the standard twenty-round block; target trace fields `0`,
  model refits `0`, sibling/MPS/GPU calls `0`.
- **Resources:** `2.424391` CPU seconds, `201.96875` MiB peak through outcome
  persistence, `245.390625` MiB end-to-end process peak under the 256 MiB limit.
- **Artifact:**
  `runs/20260717_045214_O1C-0010_full256-signed-direct-replication-v1/`; manifest
  `a87b7a9fb799d667e9d2e670f759ca4f389aac2be9cb932c3f308ab669f4ab7c`;
  internal result
  `76069cf7e25e194feee027d4e4a1e2cca0fed47ae4ec84fbaa9ff966845e3bc9`;
  protocol `75d90a63501ca4c6671170b7b9ffb039f2c6e713279b63a2073f26d15d20e419`.
- **Conclusion:** the O1C-0009 `+0.023159`-bit signed observation was finite-panel
  selection noise. Close raw full-round end-output regression, preserve the exact
  negative as a sentinel, and move O1C-0011 upstream to paired public-CNF
  conflict/propagation/proof events.

## O1C-0011 — Full-256 public CNF and causal bit map

- **Recorded:** 2026-07-17T05:41:38+02:00
- **Source commit:** `b9f514a33386066706d1b023cc97487595ed63c4`
- **Claim level:** `VALIDATION` infrastructure
- **Hypothesis:** the complete RFC 8439 twenty-round ChaCha20 block relation can be
  compiled at full 256-bit key width with only public counter/nonce/output units,
  symmetric assumption polarity and stable bit-level carry/clause ancestry for a
  later O1 evidence stream.
- **Exact relation:** key variables `1..256`, counter `257..288`, nonce `289..384`,
  output `385..896`, internal variables from `897`; `32,128` total variables and
  `187,370` template clauses.  The map contains `656` round/feed-forward operators
  and 32 exact LSB-first bit ranges per operator with explicit sum, carry or XOR
  variables and one-based inclusive clause ranges.
- **Attacker instance:** exactly `640` public unit clauses and zero key units,
  producing `188,010` clauses.  Persisted bit-173 assumption-0 and assumption-1
  instances reuse identical public evidence and differ only in the final opposite
  key literal.
- **Self-tests:** independent double compile is byte-identical; RFC fixed-key
  instance SAT; the same key with one output bit flipped UNSAT; a second unrelated
  deterministic 256-bit key/counter/nonce vector SAT.  Semantic-map reconstruction,
  exact instance-body hashing and every report/unit digest verify.
- **Boundary:** no unknown-key inversion, entropy reduction or cryptanalytic SOTA
  signal is claimed.  O1C-0011 validates the upstream relation and address space on
  which O1C-0012 can measure paired solver-event orientation.
- **Resources:** `8.692029` CPU seconds; `163.59375` MiB outcome peak and
  `204.046875` MiB end-to-end process peak; `25,414,624` peak temporary bytes;
  `21,069,379` persistent CNF bytes; three bounded CPU solver calls; zero fresh
  random targets, sibling reads/writes, MPS or GPU calls.
- **Artifact:**
  `runs/20260717_054138_O1C-0011_full256-public-cnf-foundation-v1/`; manifest
  `b7a07e6461805946897adbfb90da9e9f55ff1074e9aa1343f602eecb0645b7b4`;
  internal result
  `6c4fd7becd5307d60b30e16ea1fae8d3f4739b06c888204d638950c94b53adfe`;
  template `c293d36cab270b28ab2e89c073227fd50b75a6b357b9994d27c3acf7c01a0d52`;
  causal map `13c0dd32b1c0eec0b9b95e9c7c0f2a8390b8be6f98bd59e3b7d021c23762bfaf`.
- **Next action:** O1C-0012 uses the immutable relation through an incremental
  paired-assumption sensor and streams equal-work propagation, conflict, decision
  and proof-ancestry deltas into the bounded coordinate-bound O1 state.

## O1C-0012 — Full-256 paired causal sensor and bounded O1 state

- **Recorded:** 2026-07-17T06:53:37+02:00
- **Source commit:** `08535f94ae3c1de17f3622aa032b945233b0ee92`
- **Claim level:** `TEST` mechanism; no inverse-signal claim
- **Hypothesis:** one immutable public-only full-round relation can support both
  assumptions for every one of 256 unknown key coordinates, expose complete
  proof-ancestry prefixes at three short conflict horizons, and stream them into a
  nonzero unary-plus-ARX-interaction-plus-holographic state below 18,000 bytes.
- **Sensor:** CaDiCaL 3.0.0 loads the 32,128-variable/188,010-clause public instance
  once, records 667 public baseline proof events, then runs 512 fresh POSIX-fork COW
  branches.  All 256 bits and both polarities are covered.  The three horizons
  `64/96/65` yield 1,536 complete closed proof prefixes; 1,472 end exactly at the
  cutoff event.  The remaining explicit event gap has maximum 4 and mean
  0.1080729167; final conflict overshoot is billed and excluded.
- **Living state:** 768 unary cells, 256 evidence masses, 2,048 directed ARX-local
  interaction cells, four by 128 complex holographic channels, 256 probe counters
  and 64 family statistics serialize to exactly 17,408 bytes.  The state retains
  zero transcripts and zero candidate keys.  Every signed component negates under
  assumption swap while unsigned mass/counts remain invariant.
- **Mechanism result:** all sensor, provenance, determinism, state, resource and
  attacker-boundary gates pass.  State commitment
  `aea9d4c0bd88d2c8480fb51b98d5524bc8c6fc319dd612c9dc345aa03035b664`;
  stream commitment
  `b52bf4cce10f69672077f4b6b0d8496cfe0c633aac5ae0ce43502d2e9d5b26b1`.
- **Known-key diagnostic:** after state freeze only, the configured RFC key exactly
  recomputes the public output.  The imported A465 `(7,1,4)` mixture plus local
  correction predicts 119/256 bits, Hamming distance 137, NLL 342.7799900847,
  compression -86.7799900847 bits, 0 correct bytes/16-bit blocks and rank 999,898
  among one million decoys.  Raw horizon counts are 119/139/112 for 64/96/65.
  This is a negative single-key breadcrumb, not cross-key evidence.
- **Resources:** 58.031723 CPU seconds, 49.199165 wall seconds, 514 native branches,
  317.28125 MiB conservative process-group peak, 554,653 persistent bytes; zero
  fresh targets, sibling reads/writes, MPS or GPU calls.
- **Verification:** capsule 16/16; repeat invocation returns
  `already-finalized-no-replay`; full CPU suite 257 passed/8 skipped and targeted
  Ruff passes.
- **Artifact:**
  `runs/20260717_065248_O1C-0012_full256-paired-causal-sensor-v1/`; manifest
  `a28acc299d2ed42b7f4eba14e653cd8d0c3f09347658fcb65d49936e0a255556`;
  internal result
  `33184e9245f4e31e56f16c9f8cfaa21e18849279058b278959cdb2c8acc54bd7`.
- **Conclusion:** preserve the full causal stream and discard the uncalibrated W52
  readout, not the mechanism.  O1C-0013 must learn orientation/horizon mixing on
  multiple known full-256 keys, freeze it, then attack a new sealed output-only
  target without inspecting O1C-0012's opened key again.

## O1C-0013 — Multi-key causal calibration and sealed full-256 attack

- **Recorded:** 2026-07-17T07:55:37+02:00
- **Source commit:** `a99206baabeb4ae21cf07f909186db9f25354d6e`
- **Claim level:** `TEST` prospective signal; independent replication required
- **Hypothesis:** shared signed orientation learned only from multiple known
  full-256 paired-proof fields can turn the O1C-0012 causal state into a portable
  output-only key posterior with lower sealed NLL than uniform and a frozen
  shuffled-key reader.
- **Lifecycle:** four BUILD states and two disjoint CAL states were persisted before
  their labels were opened. CAL selected `horizon_1`, ridge `0.001`, temperature
  `0.5` and logit scale `1.0`. Primary and shuffled readers, all control transforms
  and split receipts were frozen before exactly two `os.urandom` target calls.
  The persisted primary reader was deserialized for inference; every factual and
  control posterior was persisted before either target reveal.
- **Known splits:** BUILD gives 520/1,024 bits and `+0.094509` bit/key. CAL gives
  269/512 and `+0.571530`; shuffled CAL gives 253/512 and `-2.982440` bit/key.
- **Sealed result:** 259/512 bits, mean NLL `255.9110784812`, compression
  `+0.0889215188` bit/key. Individual targets give 133/256 with `-0.1867018020`
  bit and 126/256 with `+0.3645448397` bit. The frozen shuffled reader gives
  239/512 and `-3.2173322436` bit/key, so the aggregate factual margin is
  `+3.3062537624` bit/key.
- **Ranks and recovery:** million-decoy ranks `580,519` and `194,708`; zero exact
  keys, zero correctly predicted bytes and zero correctly predicted 16-bit blocks.
  Factorized value ranks over 64 bytes have best `2`, mean `130.5`, five top-16;
  over 32 words best `99`, mean `33,307.28125`.
- **Controls:** on the sealed anchor key, output-bit flip compression
  `-0.2729867102`, wrong nonce `-0.1673760755`, and output-byte rotation
  `-0.0406180758`. Exact assumption-swap complement, public recomputation, reader
  reload, pre-reveal persistence and all containment gates pass.
- **State and resources:** `58,368` live target bytes (`17,408` causal + `39,936`
  bounded feature bank + `1,024` logits); `281,764` static primary reader bytes;
  zero retained candidate keys/transcripts. `392.187980` billed CPU seconds,
  `314.384032` wall seconds, `5,632` billed native branches, `321.90625` MiB
  conservative group peak and `2,479,016` persistent bytes; zero sibling reads/
  writes, MPS or GPU calls.
- **Verification:** capsule 63/63; result
  `a70610d3d589e97048c6045747c0821e5669c5dc89e420df79b0fca43476d4cd`;
  sealed evaluation
  `11d3cdfffb6cb078f7d8a54e56ff827d3c9a4237df32632274c2176e7e5efa38`;
  primary reader
  `796e79ec932b990a59ecbc34216c4878b9279bae3bb136fe0832e580bcb2e9f8`.
- **Conclusion:** this is the first positive prospective causal-reader breadcrumb,
  but two targets cannot distinguish portable entropy removal from panel variance.
  O1C-0014 must reload the exact primary and shuffled reader bytes, prohibit all
  refitting/selection, and attack eight new sealed keys under the same public-only
  relation before changing the sensor.
- **Artifact:**
  `runs/20260717_075537_O1C-0013_full256-multikey-causal-calibration-v1/`; manifest
  `a0d4df5c01f7de3c65a429f9589e46d784f802bc1f8e0aa90dffb011be46922c`.

## O1C-0014 — Exact frozen-reader blind replication

- **Recorded:** 2026-07-17T08:48:47+02:00
- **Source commit:** `527d5c273403f07e03241243a38e0b5375c4d745`
- **Claim level:** `VALIDATION` negative; positive aggregate breadcrumb retained
- **Hypothesis:** the exact O1C-0013 h96 reader removes reproducible code length
  from eight independent standard twenty-round ChaCha20 keys with all 256 bits
  unknown and only public counter, nonce and output visible.
- **Lifecycle:** source capsule and both reader binaries were hash-pinned; primary
  and shuffled readers reserialized byte-identically. Protocol artifacts were
  persisted before exactly eight `os.urandom` key calls. All eight factual and all
  three control predictions were persisted before the first reveal. Reader fits,
  selections and hyperparameter changes were zero.
- **Sealed result:** primary `1053/2048` bits, NLL `255.7662158570` bit/key and
  compression `+0.2337841430` bit/key. Conditional-uniform reference `z=1.819365`
  (`p≈0.034428`). Shuffled compression `-1.2909810442`; primary margin
  `+1.5247651872` bit/key, paired `z=0.838026`.
- **Robustness:** target compressions are `-0.182409`, `+0.502634`, `+0.827483`,
  `-0.145782`, `+0.237792`, `-0.173504`, `-0.307404`, `+1.111464`; only `4/8`
  are positive. Every leave-one-out aggregate remains positive, minimum
  `+0.108401`, but the preregistered 5/8 directional and 7/8 strong gates fail.
- **Controls and recovery:** output-bit-flip `-0.212425`, wrong nonce `+0.045371`,
  byte rotation `+0.010570`; specificity fails. Zero exact keys, one exact byte of
  256, zero exact 16-bit blocks; million-decoy ranks span `10,875..644,297`.
- **Decision:** `NOT_REPLICATED`. Aggregate-positive and primary-over-shuffled
  gates pass; target sign, paired-z and control-specificity gates do not. No stable
  keybit, recovery or SOTA claim is made.
- **Post-reveal breadcrumb:** every O1C-0013 BUILD-fitted candidate was reconstructed
  without using O1C-0014 for fit. h64/h96/h65 remain positive at `+0.139097`,
  `+0.233784`, `+0.188340` bit/key, while ARX24 and ARX24+Motif12 are `-0.374410`
  and `-0.355199`. A fixed equal-logit h96+h65 diagnostic gives `+0.229` bit/key,
  `1066/2048`, `6/8` positive and `z=2.107`; this selects only the O1C-0015
  architecture and is not an O1C-0014 claim.
- **Resources:** `306.194798` billed CPU seconds, `245.756482` wall seconds,
  `5,632` native branches, `302.578125` MiB peak RSS and `2,947,408` persistent
  bytes; zero sibling reads/writes, MPS or GPU calls.
- **Verification:** capsule 124/124; result
  `ecc06b011a95f6ceeec08641b68e1105511cf714cc250f9fe3b62e66c2af4c4a`;
  evaluation
  `69a3142f56b08f60890b4849ab9d71d4a68aecb4ad5db3a0f24b304cf041b6ef`;
  prediction set
  `5b5912420948fef68b4be4a4fb171c5927286e0c9e6acfb9d1c0f48d3302a683`.
- **Next action:** O1C-0015 freezes exact h96 plus one fixed equal-logit h96+h65
  ensemble and attacks 32 new sealed keys. O1C-0014 may choose that successor but
  never enters its fit or result. Query-rooted carry cones remain the mechanism
  fallback if the unary channel fails.
- **Artifact:**
  `runs/20260717_084847_O1C-0014_full256-frozen-reader-blind-replication-v1/`;
  manifest
  `741718cbc6b63de24f4d9c89cd2aedc8e9779a0ebb38adc4d40666e97ce24bcf`.

## O1C-0015 — Polyphase blind replication (pre-run freeze)

- **Recorded:** 2026-07-17T09:46:03+02:00
- **Implementation commit:** `26709cde97df26dc8bfebf99eb108dc0d58f4281`;
  canonical execution must use the subsequent clean preregistration commit
- **Claim level:** `VALIDATION` pending; no result claim and zero fresh O1C-0015
  target entropy calls at freeze time
- **Hypothesis:** a fixed equal-logit ensemble of exact O1C-0013 h96 and a
  deterministic h65 reader reconstructed only from O1C-0013 BUILD/CAL removes
  reproducible code length from 32 fresh standard twenty-round ChaCha20 keys with
  all 256 bits unknown and only public counter, nonce and output visible.
- **Frozen readers:** exact h96
  `796e79ec932b990a59ecbc34216c4878b9279bae3bb136fe0832e580bcb2e9f8`;
  reconstructed h65
  `b7dd365753bf2ca131c2c263f3c04e5e644d9d438feaf17a5a313790dcf8409d`;
  arm-matched shuffled h96
  `6dd8b6c09c4593228cfafe545bdff4c6e6b9953ba013fff35f97ac87c8ab3cb1`;
  shuffled h65
  `d9077567e1ffd6b73d673fdca22626495fb213057c0a203a0cd1c264d15b00d6`.
- **Composition:** persist h96, h65, `0.5*h96+0.5*h65` logit ensemble and the
  identically composed shuffled control for every target. One unchanged 512-
  assumption public sweep feeds all views; 32 targets plus three controls equal
  exactly 17,920 conservatively billed native branches and 67,584 bytes maximum
  live target state.
- **Lifecycle:** freeze protocol before 32 OS-random keys; persist all factual and
  control posteriors before any reveal; exact assumption-swap complements; no
  target key/internal state, O1C-0014 feature/label/fit, sibling read/write, MPS or
  GPU path.
- **Decision:** directional requires positive ensemble compression, positive exact
  h96 compression, at least 18/32 positive targets and positive ensemble-over-
  matched-control margin. Strong additionally requires conditional and paired
  `z>=1.6448536269514722`, at least 22/32 positive and positive minimum leave-one-
  out compression. Polyphase promotion is separate and requires positive mean
  ensemble-minus-h96 compression with paired conditional
  `z>=1.6448536269514722`.
- **Budgets:** 1,600 CPU s, 1,400 wall s, 384 MiB peak RSS, 24,000,000 persistent
  bytes, 17,920 native branches, 32 fresh keys and zero sibling/MPS/GPU calls.
- **Verification before entropy:** canonical `tests/` suite `317 passed, 9 skipped,
  51 subtests`; targeted O1C-0015/CLI `33 passed, 12 subtests`; changed-file Ruff,
  format, compileall and diff checks pass. Independent reconstruction reproduced
  the reader hashes and full-grid output equality.
- **Next action:** wait for the sibling resource gate, launch exactly once from a
  clean source commit, verify the immutable capsule, then publish the frozen
  classification without target-time tuning.

## O1C-0015 — Polyphase blind replication (post-run operational outcome)

- **Recorded:** 2026-07-17T11:46:03+02:00
- **Execution commit:** `2f53cc775d316c719482c4cb64fa2e5d108f7647`
- **Claim level:** `OPERATIONAL_FAILURE`; no scientific inverse result or efficacy
  classification is available.
- **Lifecycle truth:** 32 targets were generated, all 32 predictions plus three
  controls were frozen, and all 32 targets were then revealed once in process
  memory. The late resource gate fired before any reveal receipt, evaluation or
  final scientific report was persisted. The sequence-3 durable checkpoint says
  zero reveals only because it records the last persisted pre-reveal phase; exact
  code-path audit establishes `32 generated / 32 revealed in memory / 0 persisted
  reveals`.
- **Decision:** all 32 targets are burned and may never be replayed. No bit count,
  NLL, compression, rank, exact-key count or replication decision can be claimed.
  O1C-0014 remains the strongest completed scientific result.
- **Resources:** the run exceeded CPU `1600 s`, wall `1400 s`, and peak RSS
  `384 MiB`. The old exception path discarded the exact values, so only those
  strict lower bounds are available. The planned 17,920 native branches completed.
- **Verification:** immutable capsule 579/579; manifest
  `326bc30a1499f6479d306df43b17ec390c020832bb5d1816fa8ab9f7f9660314`;
  prediction set
  `f2958da162a2dca74f2c5dd62ccb45f3d764be7c8f71200ee3afba8409a62116`.
- **Artifact:**
  `runs/20260717_103252_O1C-0015_full256-polyphase-blind-replication-v1/`.
- **Next action:** use a new attempt ID and entirely new keys; preserve the
  scientific mechanism while moving resource enforcement before reveal and
  persisting terminal truth before any post-reveal failure decision.

## O1C-0016 — Budget-corrected polyphase replication (pre-run freeze)

- **Recorded:** 2026-07-17T11:46:03+02:00
- **Implementation commit:** `4f4c5280ecf876083222138db4cb55dae9e2dfca`;
  canonical execution must use its clean preregistration descendant.
- **Claim level:** `VALIDATION` pending; zero O1C-0016 target entropy calls at
  freeze time and no result claim.
- **Scientific identity:** exact O1C-0015 readers, h96+h65 equal-logit composition,
  matched shuffled controls, public-only attacker boundary, decision gates,
  67,584-byte live-state bound, 17,920 native branches and 32-target panel are
  unchanged. All 32 keys are entirely new; no O1C-0015 public view, prediction,
  reveal or target is read or reused.
- **Operational delta only:** soft ceilings are 3,000 CPU-s, 3,000 wall-s and
  768 MiB peak RSS. A complete resource snapshot and gate now occur before reveal;
  after reveal, complete truth/evaluation artifacts are persisted before a
  terminal resource classification.
- **Frozen config:** `configs/full256_polyphase_replication_v2.json`; SHA-256
  `054e8b05c7824cf4c47f509d6a4977e3feac7e5df5ce006f55948b93554daaa6`.
- **Next action:** launch once from the clean preregistration commit and classify
  only by the frozen gates. O1C-0017's adaptive h65-all/top32-h96 live-causal
  fidelity probe follows only after O1C-0016; its deterministic work model predicts
  `19.79%` requested conflict-work saving.

## O1C-0016 — Budget-corrected polyphase replication (completed outcome)

- **Recorded:** 2026-07-17T12:20:25+02:00
- **Execution commit:** `30dfd1dfe29afd2ad89c8508e5c4a75da065a5e3`
- **Claim level:** `VALIDATION` negative; lifecycle and resource mechanism passed
- **Classification:** `NOT_REPLICATED`; polyphase architecture `DO_NOT_PROMOTE`.
- **Sealed result:** ensemble `4093/8192`, accuracy `0.4996337891`, compression
  `-0.0782490971` bit/key and conditional `z=-0.4165615`. Only `11/32` targets
  are positive. Exact h96 gives `4052/8192` and `-0.1749999959`; h65 gives
  `4100/8192` and `-0.0339132617`; the matched shuffled ensemble gives
  `4100/8192` and `+0.0019763046` bit/key.
- **Frozen decisions:** the primary loses to shuffled by `-0.0802254017` bit/key
  with paired `z=-0.5553579`. The ensemble improves h96 by `+0.0967508988`, but
  loses to h65 by `-0.0443358354`; promotion z `1.0044702` is below the frozen
  threshold.
- **Ranks and recovery:** byte top-1/top-4/top-16 counts `4/16/61` against uniform
  expectations `4/16/64`; zero 16-bit top-16 groups; best million-decoy rank
  `45,147` has 32-try null probability approximately `0.772`; zero exact keys.
- **Coordinate robustness:** six coordinates reach at least `22/32` versus `6.41`
  expected under fair bits; maximum `24/32` has familywise null probability about
  `0.592`; none reach `32/32`. O1C-0014-to-O1C-0016 coordinate compression
  correlation is approximately zero.
- **Controls:** output-bit flip `+0.253971`, wrong nonce `-0.078066`, byte rotation
  `+0.515872` bit/key; specificity fails.
- **Mechanistic breadcrumb:** target-level h65 primary and shuffled compression
  correlate `0.999905`. Shuffled-h96 logits are zero and shuffled-h65 is, to
  residual below `4e-9`, `0.38857049` times primary-h65. The frozen reader family
  tracks common-mode public-instance difficulty/amplitude without portable hidden-
  key orientation.
- **Resources:** `1972.624545` billed CPU seconds, `1620.537008` wall seconds,
  `414.8125` MiB conservative peak RSS, `17,920` native branches, `67,584` live
  target bytes and `6,768,561` persistent bytes; every frozen gate passes.
- **Independent verification:** 680/680 manifest members; all 32 commitments and
  independently recomputed ChaCha20 outputs match. Manifest
  `fd0469885ee436414f94d708006cc40d86fc730d25b618167c7d664b3fe195ea`;
  result
  `6146dbfe10e1add60fe5d16f133c5b1acdced42bcf2249561926d26ee0e11652`.
- **Conclusion:** close exact global h96, direct h65 and their fixed equal-logit
  ensemble as inverse readers. Preserve the causal event substrate. O1C-0017 uses
  no fresh entropy: cross-fit bounded nuisance rejection, residual event encoding
  and adaptive sensing on self-generated known-key folds. Advance to O1C-0018 only
  after repeated held-out NLL lift over a norm/spectrum-matched coordinate-
  destroying null.
- **Artifact:**
  `runs/20260717_115325_O1C-0016_full256-polyphase-blind-replication-v2/`;
  forensics `research/O1C0016_POST_REVEAL_FORENSICS_20260717.md`.

## O1C-0017 — Online anonymous-channel self-discovery gate

- **Recorded:** 2026-07-17T14:12:09+02:00
- **Execution commit:** `22ea4dd0bfedd3134f82624ea434c9b339f35a73`
- **Claim level:** `VALIDATION` synthetic mechanism; no cryptanalytic, learned-
  picker, stateless-baseline or O1-memory-necessity claim.
- **Classification:** `MECHANISM_PASS`; every predeclared scientific, lifecycle,
  structural and resource gate passed.
- **Frozen experiment:** eight deterministic reveal-delayed BUILD episodes followed
  by five prediction arms on 16 disjoint synthetic full-256 evaluation episodes.
  The controller receives 330 anonymous raw channels but never the hidden channel
  index. Complete coordinate coverage is fixed, so action selection is not scored.
- **Primary result:** `3286/4096` bits, accuracy `0.80224609375`, mean NLL
  `213.6912579064` and mean compression `+42.3087420936` bits. All `16/16`
  targets are positive; target correct-bit range is `195..213`.
- **Controls:** hidden-channel ablation `-4.3926511273` bits, shifted-label learner
  `-0.4561548402`, untrained reader `-7.3367374797`, and the primary learned raw
  end-of-stream O1 field `-4.9225787896`. Primary margins are `+46.7013932209`,
  `+42.7648969338`, and `+47.2313208832` bits respectively.
- **Structural result:** exact polarity-swap antisymmetry, common-only zero
  orientation, complete 256-coordinate coverage and constant `21,472`-byte fast
  state all pass. Predictions were persisted before any evaluation label scoring.
- **Resources:** 29,184 action observations, `78.088885` CPU s, `79.852657` wall
  s, `286.4375` MiB peak RSS, 285,581 persistent bytes and zero fresh entropy,
  native solver, sibling read/write, MPS or GPU calls.
- **Verification:** 18/18 capsule members; manifest
  `59f1f59b4e24545391cb06cd2bee395285d4385c893af36d18def28bcb3858fd`;
  result
  `609014695bc3013bb971d7d05b682d18797af5c9d9cd31561cdc41de120ff28c`;
  prediction freeze
  `a2f5a8ba939bdedf9fdce4bb1e0dabac9fc3ac850a3b9e249b9b2f1d3abafba7`.
- **Conclusion:** the fast/slow architecture can learn a useful oriented feature
  without being handed a scalar signal and can retain 256 addressed readings after
  the raw holographic end field loses them to crosstalk. The untested question is
  whether attacker-valid full-round proof/carry streams contain such a feature.
- **Next action:** preserve the controller and all five arms; replace only the
  synthetic generator with deterministic known-key standard twenty-round ChaCha20
  paired-proof pools, multiple horizons and a sub-exhaustive learned-picker budget.
- **Artifact:**
  `runs/20260717_140953_O1C-0017_full256-online-self-discovery-v1/`.

## O1C-0018 — Full-round online real gate

- **Recorded:** 2026-07-17T15:59:32+02:00
- **Execution commit:** `f40e71aa8ed80b4653acf44d98e14eabec18a955`
- **Claim level:** `TEST` full-round reader/picker gate; no recovery, sealed-target
  or cryptanalytic SOTA claim.
- **Classification:** `NO_RAW_SIGNAL_PICKER_UNINTERPRETABLE`; every structural,
  lifecycle and resource gate passed.
- **Frozen experiment:** four deterministic reveal-delayed BUILD keys, then two
  disjoint DEVELOPMENT keys under standard twenty-round ChaCha20. The public probe
  receives counter/nonce/output and generates H64/H96/H65 paired-proof pools while
  all 256 key bits and target traces remain unavailable. Predictions, both slow
  states and all trajectories are frozen before DEVELOPMENT labels.
- **Raw reader:** learned Bit-Vault `-1.400387/-1.168901` bits, mean `-1.284644`;
  untrained mean `-2.009015`; learned-minus-untrained `+0.724371`. Coordinate
  rotation is `+0.203963` mean and direct final O1 is `-0.093388`, so the raw gate
  fails.
- **Policy result:** true reward W1/W2/W3 means
  `+0.243511/-0.124100/-0.507493`, IAUC `-0.085264`. Shifted IAUC is `-0.306661`,
  static `+0.177296`, shortest `-0.156428`, hash `+0.035494`. True is best W1 on
  both targets and beats shifted reward in all six target-by-checkpoint cells, but
  does not beat all controls on both targets.
- **Agency forensics:** the first true decision contains coverage contribution
  `0.5`, exploration `0.013378` and learned reward `0.001955`; mean learned W1
  score share is about `0.17%`. True/shifted common-action rank correlations are
  `0.970..0.996` through W2, and cross-target true correlation is
  `0.986/0.995`. The hash shortlist and hard minimum-coverage gate dominate.
- **Accumulation forensics:** the reader trains a cumulative addressed query while
  deployment repeatedly adds that query. Direct final O1 is `1.191256` mean bits
  better than the exhaustive re-integrated vault. BUILD reward correlation is
  `0.013824` pairwise and `0.023765` leave-one-out because credits are mixed across
  changing readers. H65-only is post-reveal positive on both consumed targets at
  `+0.124720/+0.083065`; it is not promoted.
- **Structural result:** exact polarity antisymmetry, common-only zero, nested
  checkpoint paths, bounded state, prediction-before-label freeze and unchanged
  slow states all pass. Six pools contain exactly 3,072 native branches.
- **Resources:** `545.024331` CPU s, `510.875` elapsed wall s, peak RSS
  `315,703,296 B`, persistent artifacts `13,139,765 B`; zero fresh entropy,
  sibling reads/writes, MPS or GPU work.
- **Verification:** 51/51 capsule members; manifest
  `fcbf43c99994c0debe5b39bb3e734ea1d1e23ba58e89b10ff2bb7e23886493fb`;
  internal result
  `db92bd86849ff93e0f9b935a72f64f1b4bd46b134747c913ee82e5d772ac11c9`;
  prediction freeze
  `529356d380baec494ddfe0710e8b9cf0f85308c50b2913600e4c39b9a041c30e`.
- **Conclusion:** preserve the public proof sensor and the true-versus-shifted
  breadcrumb, but replace double integration, nonstationary credit, hash-only
  observability, compulsory breadth and forced spending. O1C-0019 uses local
  multiresolution packets, learned incremental/gated evidence, reader-bound credit,
  all-address preview, soft no-starvation attention and HOLD/STOP/DECAY.
- **Artifact:**
  `runs/20260717_152827_O1C-0018_full256-online-real-gate-dev-v1/`;
  forensics `research/O1C0018_POST_REVEAL_FORENSICS_20260717.md`.

## O1C-0019 — Artifact-only BUILD-LOO gate (implementation freeze)

- **Recorded:** 2026-07-17T17:29:19+02:00
- **Implementation commit:** `27cd5b1f1e3172218c9c993846f1dcc950bb909a`
  (base runner `dc249ad`; deterministic commitment hardening `27cd5b1`).
- **State:** runner/config frozen and tested; no run capsule or efficacy result yet.
- **Source:** four immutable BUILD `.fap` files from O1C-0018, verified through
  manifest `fcbf43c99994c0debe5b39bb3e734ea1d1e23ba58e89b10ff2bb7e23886493fb`
  and artifact index. Discovery reads `8,336,169` bytes and never invokes the
  deterministic key oracle.
- **Protocol:** four symmetric leave-one-BUILD-out folds. Each fresh fold reader
  learns on the other three packet-local H64->H65->H96 streams with four frozen
  replay passes per episode; the episode-equal critic is then refit from zero and
  bound to the final reader SHA.
- **Frozen arms:** learned stationary ACTION/STOP; identical learned picker with
  STOP disabled; shifted-label stationary critic with byte-identical reader and
  contexts; fold-local static packet reward; pool-blind uniform hash; fixed-order
  exhaustive learned reader and deterministic untrained reader.
- **Work:** nested caps `16,384/32,768/49,152`; complete field `49,152` paired
  physical conflicts; zero pool generation and zero native solver branches.
- **Lifecycle:** every fold's slow states, paths, predictions and ledgers are
  persisted before its held-out label is reconstructed. STOP must be an exact
  route prefix of the no-STOP twin. DEVELOPMENT pools remain untouched by O1C-0019.
- **Verification:** targeted runner/controller/critic suite `29 passed` plus `5`
  subtests in `6.50 s`; pycompile, Ruff, real four-pool discovery and exact config
  loading pass. A one-fold, three-training-action real-artifact micro-smoke persisted
  one learning freeze and one prediction freeze, produced policy shape
  `1x5x3x256` and raw shape `1x2x256`, and passed every structural gate with zero
  solver/pool generation. It used `2.558903` CPU s, `2.803259` wall s and
  `315,359,232` B peak RSS. The original full-report SHA included volatile
  timing/RSS and was therefore retired before execution. Two new Python processes
  now reproduce scientific result SHA
  `79648ab86896b3ea5ee1b7acb74983057ff32b9901da18905a46ae073c8f36a8`,
  learning freeze `1fbddd26a41fbb31d49538bd71b13a93ccc6507171a63eb581596e42cc850a0e`,
  prediction freeze `5d711b317c9c2315f0046727e3848aa598bf7e260d51905c9a7b99e702ff04e5`
  and both global slot-ledger hashes byte-exact. Runtime metadata has a separate
  execution-report SHA.
  Its `BUILD_LOO_NO_TRANSFER` label is a deliberately undertrained wiring-smoke
  outcome, not scientific evidence and not an O1C-0019 execution.
- **Resource interlock:** sibling W52 is active, with two additional one-core
  CaDiCaL processes observed. The heavy four-fold gate is intentionally deferred;
  only light validation ran. System memory-pressure query reported 30% free.
- **Resume:** recheck W52/process/RAM state. When clear, run
  `PYTHONPATH=src python -m o1_crypto_lab.full256_multiresolution_build_loo_run --config configs/full256_multiresolution_build_loo_v1.json`
  from the clean implementation commit; do not alter config or consume DEVELOPMENT.

## 2026-07-17 — O1C-0019 deferred execution armed (non-attempt)

- **Recorded:** 2026-07-17T18:40:03+02:00
- **Operational commits:** `0158a92`, `e23cd77`, `4511a06`; scientific freeze
  remains `27cd5b1f1e3172218c9c993846f1dcc950bb909a` and was not changed.
- **Discovery:** the eight sibling launcher PID files contain stale PIDs. A dynamic
  read-only process scan finds 24 live identities: eight production shell/
  `caffeinate` companions, eight A528 Python launchers and eight native A526 workers.
- **Interlock:** PID `67247` owns an inherited `flock`, polls every 60 s, and was
  acknowledged only after `setsid`, durable-log redirection and a real host
  preflight. Release requires all eight progress envelopes terminal for three
  identical polls, no related process, at least 25% free memory, load/core at most
  `0.75`, a clean descendant tree, and exact config/runtime hashes including
  `pyproject.toml`. The eventual run gets its own PID-bound `caffeinate` companion.
- **Verification:** 17 watcher tests cover stale/restarted PIDs, read-only sibling
  access, terminal geometry/bindings, final-snapshot races, duplicate exclusion,
  real detach ACK/failure, and fork/exec lock survival. Real preflight saw
  `58,078/16,777,216` cells (`0.3462%`), all eight workers running, 37% free memory,
  clean tree and exact scientific hashes. Lock file and live daemon both report
  PID `67247`; log is `runs/.o1c0019-w52-interlock.log`.
- **Scientific state:** no O1C-0019 capsule, target reveal or efficacy number was
  produced. The watcher is operational infrastructure, not cryptanalytic evidence.
- **Resume:** do not manually start O1C-0019. Inspect the ignored log if needed;
  the watcher will exec the exact frozen command only after every release gate is
  green and will retain the same lock throughout the scientific process.

## O1C-0020 — Learned-mask MQAR-256 exact retention

- **Recorded:** 2026-07-17T21:14:43+02:00
- **Execution commit:** `3aefaf7a88aaf425bd52bc1c56614348a024ba1c`
- **Claim level:** `VALIDATION` synthetic routing/retention mechanism; terminal
  subcondition (a), no cipher inversion, causal-evidence or recovery claim.
- **Classification:** `EXACT_256_LEARNED_GATE_RETENTION`; every scientific,
  lifecycle, state and resource gate passed.
- **Frozen experiment:** 32 BUILD seeds train only `input_gate.weight` of the O1
  core with a paired logistic route-margin objective. Eight disjoint CAL seeds
  freeze threshold `2.6524462699890137`. Four never-used EVALUATION seeds each
  receive the same 256 binding tokens embedded in stable public streams with
  `H=0/65,536/1,048,576` distractors. Address, value and token features are public;
  no family ID, truth mask or route label enters the deployment API.
- **Primary result:** every one of 12 EVALUATION cells accepts exactly 256 tokens,
  with `TP=256`, `FP=0`, `FN=0`, `256/256` randomized-query recall and complete O1
  replay. For each seed the full live-state SHA is byte-identical at all three
  lengths. The primary slow state is unchanged throughout evaluation.
- **State:** exactly `352` live bytes: `288` O1 fast-state bytes plus a `64`-byte
  packed value/validity vault. Model external index, retained transcript and
  stream-length-dependent state are all zero. The 2,216 fp32 slow parameters
  (`8,864` raw bytes; `9,767` canonical bytes) are billed separately. Evaluator
  masks and freeze receipts are explicitly excluded and separately accounted.
- **Learning gate:** zero errors on 8,192 CAL tokens, sampled signed margin
  `+0.468234777`; analytic worst-case margin `+0.454628304` over every legal
  family/payload/address/nuisance token. Shuffled-label training has 4,096 false
  negatives and a negative certificate. A 4,096-token literal replay containing
  all 256 bindings and 3,840 rejections is byte-identical to sparse compaction.
- **Controls:** shuffled-label, untrained, cue-rotated, cue-ablated and all-open
  arms fail every longest-stream cell and are strictly below primary. Matched
  64-slot CountSketch and 64-channel holographic stores obtain `68.1641%` and
  `77.6367%` mean accuracy with zero exact cells. A `2^20` no-binding stream has
  zero accepts/updates and holds the initial state byte-exact. The actual oracle
  ceiling is reconstructed and replayed only after the public prediction freeze.
- **Lifecycle:** gate slow states freeze before any EVALUATION stream is generated;
  all public masks, recalls, state bytes and storage controls freeze before one
  truth reveal. A second runner invocation returns `already-finalized-no-replay`.
  All 21 capsule members independently pass SHA-256 verification. Independent
  audit also checks every binary offset and vault/recall correspondence. One P2
  carry-forward remains: revealed truth bitplanes are deterministically
  reconstructible and commitment-bound but were not persisted as standalone raw
  artifacts; O1C-0021 will persist them post-reveal without replaying O1C-0020.
- **Resources:** `9.55336` CPU s, `9.914966` elapsed s, peak RSS `438,747,136 B`,
  persistent artifacts `945,387 B`; 23,366,656 gate-token evaluations and
  10,485,760 training exposures; zero solver branches, entropy, sibling reads/
  writes, MPS or GPU calls.
- **Commitments:** manifest
  `8380a3a1bbf826e62fbaa99f25e0ea1ba41f7020c101238b867ac99201077c59`;
  scientific result
  `6c12a0fcb9e0b58a86b8bea340ea475294b530372c9a9a28ddaa62724cab8cb5`;
  gate freeze
  `0b027d4f0cd078fd775e8e20b8793b92231ad014205fb3ae644bbb24208ccfd0`;
  prediction freeze
  `f898ef2fdff2180f1d7d66d53bf295d439761b0d13c7ba2f8072a3251d1d1523`.
- **Conclusion:** terminal subcondition (a) is achieved. Freeze this state API.
  O1C-0021 must replace explicit one-shot values with weak, contradictory,
  reliability-varying coordinate evidence and require learned posterior
  accumulation against equal-work controls before mapping the API to real paired
  solver/carry/proof events.
- **Artifact:**
  `runs/20260717_211433_O1C-0020_selective-mqar-256-learned-gate-v1/`.

## 2026-07-17 — O1C-0021 causal-evidence source freeze (non-attempt)

- **Recorded:** 2026-07-17T23:46:49+02:00
- **Source freeze:** `4ba1cc61c3b786139749c3e57137e3ba7ae6cf74`; five new
  O1C-0021 files, clean worktree, no formal capsule or EVAL entropy consumed.
- **Mechanism:** a 352-byte O1 live state receives only public marker/evidence/
  nuisance events and signed weak votes. BUILD outcomes train temporal reliability;
  EVAL truth never enters execution. An independent O1-O-targetable FSM owns its
  256-byte evidence vault, one-byte delayed marker and two uint64 counters for an
  exact 273-byte live state plus a frozen 64-byte slow table.
- **Scratch breadcrumb:** the pre-hardening 480-step broad DEV run recovered
  256/256 on both non-formal seeds in `134.522567` wall seconds on one CPU thread;
  O1 compression was `255.999999725 / 255.999960508` bits and independent-
  replacement gains were `98.7501 / 115.1371` bits. This is development evidence,
  not the formal result and not ChaCha20 inversion.
- **Hardening:** FSM route/state is independent of O1; complete state bytes and
  prefix hashes are duplicate-gated; complement, opaque-ID and coordinate
  equivariance are mandatory. FSM work is exact at `262,144` BUILD outcome
  lookups, `524,288` CAL table lookups and `1,835,008` EVAL table lookups. Missing
  or precedence-masked integrity gates now fail the runner.
- **Verification:** Ruff, pycompile and 31 focused mechanism/runner tests pass.
  Three independent read-only audits report no remaining P0/P1 blocker. Literal
  O1-O graph compilation is not claimed until a graph is emitted and replayed.
- **Resource decision:** sibling W52/A539 work is still active. Per the lab
  resource contract, the post-hardening broad recheck and one-shot four-seed
  formal EVAL were not started.
- **Resume:** when sibling compute clears, rerun the committed two-seed broad DEV
  check. If unchanged, execute
  `PYTHONPATH=src python3 -m o1_crypto_lab.causal_evidence_stream_run --config configs/causal_evidence_stream_256_v1.json`
  exactly once from a clean commit, then publish the capsule and update terminal
  condition (b).

## 2026-07-18 — O1C-0022 real-packet causal-vault source freeze (non-attempt)

- **Recorded:** 2026-07-18T00:52:15+02:00
- **Source freeze:** `ce56ba44ef9fe8583c0603ab145afa6133849954`; nine new
  config/design/result/code/test files, no O1C-0022 reservation, capsule, label
  score, fresh entropy or scientific efficacy result.
- **Mechanism:** each future finalized O1C-0019 fold restores its exact frozen
  reader and replays immutable O1C-0018 BUILD pools. Native incremental
  `q_after-q_before` values at H64/H65/H96 stream into raw/normalized float arms
  and the exact 352-byte O1C-0021 int8 vault. One label-free nonzero-median scale
  per horizon is fit from public training deltas; posterior scales are constrained
  to a nonnegative 401-point grid so calibration cannot reverse orientation.
- **Full-width intervention:** nested public coordinate sets K=12/52/128/256 keep
  all 256 target bits unknown. The exact frozen budget is 32 reader replays,
  17,664 packet slots, 1,130,496 public work units and 7,391,232 calibration value
  evaluations; upstream reader state is billed separately from the 352-byte
  accumulator. No new pool or native solver branch is allowed.
- **Controls and lifecycle:** raw float, normalized float, int8 vault, last-only,
  unit-sign, coordinate-shuffled and zero-prior arms freeze fold-locally before
  that fold's held-out label is used. A pass requires every K256 fold positive,
  +1 mean bit, strict K-growth, 90% float preservation and positive K256 margins
  over shuffled, unit-sign and last-only. Actual swapped-pool antisymmetry,
  duplicate byte invariance, coordinate commutation, finite state and exact work
  override efficacy.
- **O1-O integration:** the bridge emits literal
  `CAUSAL || uint16_be(1) || zlib(msgpack(graph))`, lets the real local O1-O
  KnowledgeEngine select the exact triplet, assembles its standard fragment and
  byte-replays a 64-byte table into the independent 273-byte FSM. Native and
  internal dependency-free MessagePack are byte-identical. The external O1-O tree
  is left without files or caches from the test. This is composition parity, not
  cryptanalytic evidence or a formal O1C-0021 table export.
- **Negative breadcrumb:** an exact 1.5-second exploratory replay of 4 regimes x
  8 handcrafted family masses failed at every K and smoothing alpha. The least
  negative K256 member was 519/1,024 correct but `-213.404152` code bits. Preserve
  the learned 330D O1C-0019 reader; do not resweep scalar family sums.
- **Verification:** 17 focused core/runner tests, 10 native O1-O tests plus four
  subtests, and 34 direct O1C-0019/O1C-0021 regression tests plus 575 subtests pass.
  Ruff, format, pycompile, JSON, source pins and three independent P0/P1 audits are
  clear. O1C-0021's state-defining source bytes are bound to commit `4ba1cc6`.
- **Preflight:** live CLI exits 2 with `prerequisite-pending`, verifies the O1C-0018
  corpus and O1C-0021 state, reports no finalized/recoverable O1C-0022 and creates
  no reservation. The actual future O1C-0019 capsule remains intentionally
  unexercised until the watcher finalizes it.
- **Resource decision:** W52 remains active with eight workers; only light tests
  ran. O1C-0019, O1C-0022 and O1C-0021 formal execution remain unstarted.
- **Resume:** after watcher-finalized O1C-0019 exists, run
  `PYTHONPATH=src python3 -m o1_crypto_lab.o1c19_causal_vault_bridge_run --config configs/o1c19_causal_vault_bridge_v1.json`
  exactly once from `ce56ba4`. Promote a fresh DEVELOPMENT target only if the
  frozen real-packet gate passes; otherwise change only the stage named by its
  width/control classification.

## 2026-07-18 — O1C-0022 real-artifact ABI hardening (non-attempt)

- **Recorded:** 2026-07-18T01:14:34+02:00
- **Source hardening:**
  `ac5691c5a563e43c8dc1788cf22e183f4295e6ab`; the scientific O1C-0022 config
  and source freeze `ce56ba4` are unchanged. No attempt, reservation, label score,
  target, entropy or solver branch was created.
- **Gap closed:** the earlier tests exercised real O1C-0018 corpus discovery but
  mocked packet extraction. The new optional regression loads the immutable real
  `.fap`, instantiates a genuine untrained `MultiResolutionCausalController`,
  restores it through production `_fresh_extraction`, fits the real label-free
  median-absolute quantizer and executes the exact 352-byte bridge.
- **Exact smoke ledger:** K12, H64/H65/H96, 36 packet slots and 2,304 public work
  units per replay. Base, exact repeat and actual polarity swap total 6,912 reader
  work units. All 12 groups and 36 slots are accepted by the primary bridge.
- **Integrity:** the label oracle is patched to raise before config/corpus loading;
  it is never called. Extraction bytes repeat exactly; authentic q-deltas are
  finite and nonzero; actual swap delta and logit residuals are at most `1e-6`;
  duplicate application leaves primary and control bytes unchanged; the output is
  finite `7x256`, and primary state is exactly 352 bytes.
- **Verification:** Ruff, format and pycompile pass. All 18 bridge/runner tests
  pass. With the 10 native O1-O tests the focused surface totals 28 tests plus four
  subtests; the native path passes separately with `O1O_FORGE_ROOT` supplied. The
  real-artifact test itself passes in 1.39 seconds under the local pytest timing.
- **Boundary:** the reader is intentionally untrained and the K12 quantizer is fit
  on the same public replay. This proves production transport and invariants, not
  trained O1C-0019 compatibility, formal cross-pool K256 calibration or efficacy.
  Add the trained-fold version only after O1C-0019 finalizes.

## 2026-07-18 — A539/A541 read-only clause transfer (non-attempt)

- **Recorded:** 2026-07-18T01:14:34+02:00
- **Scope:** four stable sibling RACF-DES artifacts were SHA-256 verified and both
  `.causal` files reopened with native integrity checks. No sibling write, copy,
  local science run or O1C attempt occurred.
- **Direct result:** A539's training-frozen raw clause reader beat both declared
  controls on its first 12-target panel with zero recovery. On A541's fresh
  12-target panel, all five learned readers lost to both controls and zero of 108
  executed frozen top candidates matched.
- **Replication boundary:** unchanged A539 raw and centered anchors combine across
  24 prospective targets to `0.9848642579531143` and `0.9911105120337214` of the
  exact discrete-uniform geometric-rank expectation. The first-panel concentration
  is therefore not a portable additive single-position reader.
- **Transfer:** preserve projected clause identity, proof ancestry, prospective
  selection and immutable baselines. Do not add another single-position marginal
  or manual family sum. If and only if frozen O1C-0022 returns an all-float
  sensor/reader null, use consumed BUILD folds to test interaction-bearing signed-
  variable pairs, proof antecedents or exact candidate contradictions at matched
  work. O1C-0022 itself remains unchanged.
- **Artifact:**
  `research/A539_A541_TRANSFER_20260718.md` records exact hashes, direct metrics,
  derived 24-target arithmetic and the materialized-inference boundary.

## 2026-07-18 — O1C-0022 real-FAP payload sensitivity (non-attempt)

- **Recorded:** 2026-07-18T01:25:31+02:00
- **Source hardening:**
  `2d8bf69957fe689b75e61fea5cab8e9a693192ed`; frozen O1C-0022 science remains
  `ce56ba4`. No label, score, reservation, entropy, solver branch or target was
  consumed.
- **Discriminator:** a fourth K12 replay preserves the real source-stream hash,
  reader state, coordinate set, pair identities and final resource counters but
  zeros only the `float32[H,256,2,330]` branch-feature tensor. Its q-delta vector
  must differ from the authentic real-FAP vector.
- **Result:** the payload-ablated and authentic q-deltas differ. All four replays
  retain the exact 36-slot/2,304-work ledger, for 9,216 total reader work units;
  the label oracle remains unopened. The focused test passes in 1.18 seconds after
  formatting and lint checks.
- **Conclusion:** the real-artifact smoke now proves data-path sensitivity, not
  merely hash/address transport or a metadata-generated polarity. It remains an
  untrained K12 transport result and makes no claim about O1C-0019 efficacy or
  O1C-0022 cross-pool K256 calibration.

## 2026-07-18 — O1C-0023 deterministic native composer source freeze (non-attempt)

- **Recorded:** 2026-07-18T03:05:32+02:00
- **Source freeze:**
  `aa17eed6740edfdba18aaad487c93be8afaf5935`; composer SHA
  `ba241c00f1a3a501f426d89e514c2145d4d397559f52ff684704d803fd90939c`,
  runner SHA
  `79a37541e77dccfa7097cdbcdc56551eab96ce11d28b048fd3fd0fe50608727f`
  and policy SHA
  `96f49e703fce24d9e8675596caf202a22618ef7886be411b915fa8c943d2f9c8`.
  No O1C-0023 attempt, target, solver branch, entropy call or accelerator work
  occurred.
- **Authoritative input:** the runner accepts only the canonical manager-reserved
  finalized O1C-0022 publication. It verifies source ancestry, exact config and 38
  source hashes; all 384 indexed artifacts; four 36-artifact calibration and
  58-artifact held-out phases; eight scored artifacts; every freeze commitment;
  four K256 ledgers, executions and 352-byte states; and recomputed result,
  classification, gates, resources and operational status before reservation.
- **Composer:** the full result plus exact K256 quantization facts selects one
  canonical operator over operational/integrity replay, dilution, scale,
  quantization, true residual capacity, all-float sensor null, matched-control
  failures, robustness or prospective pass. Immutable failure memory closes only
  an exact scientific no-lift context; operational failure remains replayable and
  exhausted contexts require a novel policy extension. Fresh-target authorization
  is always false inside O1C-0023.
- **Native O1-O:** two Python `-I -B -S` children receive one opaque route, one
  data-only fragment and disposable byte-exact copies of eight pinned core files.
  Seven imported runtime files are origin/hash-attested. The original O1-O path is
  not disclosed; both sources must be byte-identical and are syntax-parsed but
  never compiled or executed. An inherited exclusive lease plus a 35-second child
  alarm prevents false concurrent recovery.
- **Accounting/recovery:** CPU and wall baselines start immediately after lease
  acquisition, before strict config, 384-artifact preflight, Git/source checks and
  assembly. Parent plus child CPU and parent/child/native RSS are enforced on
  success and retained on operational failure. Zero sibling writes is emitted
  only after an exact audit; otherwise the value is null with a separate observed
  lower bound. Prepared completed/failed/stopped capsules recover without replay
  or a surviving source config.
- **Verification:** 32 focused tests pass with one optional environment-driven
  integration skip. They include the exact synthetic 384-artifact capsule,
  canonical-authority negatives, unused-artifact and freeze corruption, exact AST
  tamper cases, real native double assembly, active-lease rejection and complete
  recovery truth cases. Ruff, Mypy, JSON validation and two final read-only
  semantic/adversarial audits clear.
- **Live state:** the real preflight verifies all local O1-O pins, returns
  `prerequisite-pending` because O1C-0022 is not finalized and creates no
  O1C-0023 reservation.
- **Boundary/next:** this is autonomous result-to-next-operator infrastructure,
  not efficacy or key recovery. After O1C-0019 and O1C-0022 finalize in order,
  execute O1C-0023 once from this freeze. Execute its selected mechanism only
  under a new source-frozen attempt ID.

## 2026-07-18 — O1C-0024 exact global posterior frontier

- **Recorded:** 2026-07-18T04:01:34+02:00
- **Source freeze:** `36133bc6e75349c2cd3999f60eee08f2cbeb903a`;
  decoder SHA `f57f20ae32311f1c5291953e9619a0bd32c31fa04ab969c8bf3a787dfd800fb8`,
  runner SHA `11d9a9a340dbc6a17ea32255c7a3a73fd989444f3d18b3930cb8827edc778652`
  and config SHA `d0b393ea14fc3594907b2ed1abf63f2ef7a5cbdecf6dc1bf29701a6c4889f84d`.
- **Capsule:**
  `runs/20260718_035947_O1C-0024_exact-factorized-posterior-frontier-v1`,
  manifest `44d2f75b53c7f0d0f08a431a12ee6bc90d24b860ef6d7de9218b34b535250c3f`;
  28/28 members independently verify with zero missing, mismatched or unexpected.
- **Hypothesis:** the old least-uncertain-coordinate cube is not a global
  factorized posterior beam. Exact all-coordinate subset-sum decoding should emit
  high-probability keys excluded by that cube and give honest rank/Hamming values
  at configured K.
- **Mechanism:** binary64 flip penalties are represented in common exact
  power-of-two integer units. Lazy add/replace children give deterministic
  `O(K log K)` global top-K over all 256 coordinates. Candidate generation accepts
  posterior plus K only; truth and exact 20-round public verification are separate
  post-freeze consumers.
- **Proof/control result:** exhaustive widths 3/6/10 match exactly. The synthetic
  full-round truth is global rank four while the matched two-coordinate cube cannot
  contain it. Factual verification hits rank four; identical wrong-nonce and
  one-bit-output controls have zero matches.
- **Burned result:** O1C-0016 target-0000 yields 65,536 unique score-ordered keys,
  no exact key, and no match in the first 4,096 exact public verifications. MAP is
  Hamming 117; the best global candidate is Hamming 110 at rank 15,405. The legacy
  complete 16-bit cube has oracle floor 108 but cannot contain the exact key. The
  global top-K score interval is only `-251.968003323662` to
  `-251.9751244505961`, confirming a nearly flat recovery frontier rather than
  useful key concentration.
- **Reveal boundary:** one pinned 680-entry manifest is parsed without scanning its
  member tree. Exactly publication, posterior and original freeze are read before
  the new frontier freeze; exactly one selected reveal and one selected evaluation
  are read afterward. START/COMPLETE phases are durable, all five selected member
  hashes bind the pinned manifest, no-follow traversal rejects links, and reveal,
  publication and evaluation identities cross-bind.
- **Work/resources:** 65,544 global candidates, 2,192 proof evaluations, 65,540
  legacy assignments, 20 synthetic plus 4,096 burned public verifications, zero
  solver branches/entropy/sibling/MPS/GPU. Runtime was 2.438174 CPU s and
  2.4539935 wall s; peak RSS 115,261,440 B (109.922 MiB); persistent artifacts
  2,890,445 B. Every resource gate passed.
- **Classification:** `EXACT_GLOBAL_FRONTIER_VALIDATED_BURNED_NULL` at
  `RETROSPECTIVE`; `terminal_c_achieved=false` and
  `cryptanalytic_signal_claimed=false`.
- **Breadcrumb/next:** global beam geometry is now solved and fixed. Do not enlarge
  K or tune the decoder on this opened target. Improve portable evidence
  orientation through O1C-0019/O1C-0022, then stream any frozen positive posterior
  through the unchanged O1C-0024 decoder and exact public verifier.

## 2026-07-18 — O1C-0025 logit-native frontier source freeze (non-attempt)

- **Recorded:** 2026-07-18T04:15:00+02:00
- **Status:** `INSTRUMENT` source freeze only. No O1C-0025 scientific attempt,
  target, result, reveal, solver work, entropy, sibling access or accelerator work
  was reserved or consumed. Source freeze:
  `b008e219bfcfb16d72383f236f96db25700c9f57`.
- **Mechanism:** the exact global 256-bit frontier ranks flip subsets in common-
  power-of-two integer units of the absolute binary64 natural logits. Rounded
  sigmoid probabilities and rounded division by `ln(2)` never determine rank;
  `/ln(2)` is display-only.
- **Fixed source slice:** the complete O1C-0022 prediction artifact is exactly
  57,344 bytes with shape `float64[4,7,256]`. The handoff selects only K256 arm
  `quantized_int8_vault`, an exact 2,048-byte `float64[256]` logit vector, and fixes
  the candidate limit at 65,536.
- **Lifecycle/provenance:** the supplied capsule manifest binds the artifact index,
  which binds the O1C-0022 held-out prediction freeze, its upstream O1C-0019
  prediction freeze and the public target. Foreign fold, target, action pool,
  vector, arm, width, byte count or hash fails closed before certificate freeze.
  This proves internal consistency; the future formal caller must resolve the
  authoritative finalized O1C-0022 capsule through `RunCapsuleManager`.
- **Verification:** 14 focused plus 18 neighboring tests pass, totaling 32 tests
  and 80 subtests. A non-formal CPU smoke emitted 65,536 candidates in `0.937653`
  wall seconds with `44,384,256` B peak RSS.
- **Boundary/next:** this fixes only the lossless deployment handoff and makes no
  signal or efficacy claim. Wait for the authoritative O1C-0022 outcome. Positive
  frozen K256 logits enter this unchanged frontier; an all-float null goes to the
  exact O1C-0023-selected operator. Never tune the decoder to create evidence.
- **Artifact:**
  [`O1C0025_LOGIT_FRONTIER_HANDOFF_DESIGN_20260718.md`](O1C0025_LOGIT_FRONTIER_HANDOFF_DESIGN_20260718.md).

## 2026-07-18 — O1C-0026 initial conditional design (non-attempt)

- **Recorded:** 2026-07-18T04:18:00+02:00
- **Status at record time:** `CONDITIONAL DESIGN` only; superseded by the proxy v2
  source freeze below. No O1C-0026 attempt, target, scientific run or result is
  reserved.
- **Activation:** O1C-0026 may proceed if and only if the authoritative finalized
  O1C-0023 decision and operator graph both select
  `proof_ancestry_pair_residual_v1` against the authoritative finalized O1C-0022
  all-real-primary-null result. Any other selection or incomplete provenance exits
  without reservation.
- **Question:** on the four already-consumed BUILD FAPs, test whether projected
  assumption-coordinate x ancestry-touch-coordinate interactions preserve
  orientation that O1C-0022's unary scalar reader collapsed. No fresh target,
  DEVELOPMENT FAP, solver branch, entropy, MPS or GPU work is authorized.
- **Boundary/next:** this design does not alter O1C-0024/O1C-0025 and cannot be
  launched manually to manufacture evidence. Preserve the active W52/O1C-0019
  interlock and execute the O1C-0019 → O1C-0022 → O1C-0023 chain first.
- **Artifact:**
  [`O1C0026_PROOF_ANCESTRY_PAIR_RESIDUAL_DESIGN_20260718.md`](O1C0026_PROOF_ANCESTRY_PAIR_RESIDUAL_DESIGN_20260718.md).

## 2026-07-18 — O1C-0026 proxy v2 source freeze and BUILD structural probe (non-attempt)

- **Recorded:** 2026-07-18T05:31:51+02:00
- **Source freeze:**
  `0af57fbeb6beaf69be66e64c3f0981227f829fd7`; policy SHA
  `2e2c1e56d4a9db94a575337a74e6523fe300f05bc5a2b21228ecfd151f808a7f`.
  No attempt or run capsule was reserved, and no label, target, solver branch,
  entropy, sibling write, MPS or GPU call occurred.
- **Mechanism:** v2 retains self-touch in dedicated bucket zero and hashes all
  off-diagonal touches into buckets 1..15. The complete touch sketch is divided
  by `sqrt(256)` before the two polarity-odd touch/context outer products. A
  fixed-point-free 256-cycle breaks pair identity while preserving primitive
  values; additive polarity-odd and even common-mode controls are energy matched.
- **Bounded state:** the offset ridge standardizes by
  `sqrt(sum(X*X)/768)`, uses unit regularization and folds nonnegative alpha into
  one effective `float64[768]` vector. Effective weights plus 256 posterior logits
  are exactly `6,144 + 2,048 = 8,192` bytes, with no retained FAP, feature matrix
  or transcript. Accounted simultaneous NumPy payload is `12,672` bytes; the
  warmed all-coordinate `tracemalloc` maximum is `14,529` bytes under the frozen
  `16,384`-byte process-local ceiling.
- **Label-free real replay:** all four hash-pinned BUILD FAPs produced primary and
  shuffled `1024x768` matrices in `1.609594` wall seconds at `105,955,328` B
  process peak RSS. RMS is `1.0497150e-5 / 1.0405888e-5` (ratio `1.008770`),
  cosine is `0.027591`, and only the same 85 genuinely branch-empty rows are
  identical.
- **Breadcrumb:** raw psi-odd self-touch is nonzero in `1610/3072 = 52.408854%`
  with RMS `0.005490716`; one off-diagonal cell is nonzero in
  `84273/783360 = 10.757889%` with RMS `0.000622317`. Self is `4.87x` denser and
  `8.82x` stronger, but global normalization prevents a diagonal-only proxy.
- **Verification:** 13 focused plus 42 neighboring tests pass (55 total, one
  optional native O1-O integration skip). Ruff, Mypy, JSON, pycompile and
  `git diff --check` pass; three read-only mechanism/API/math audits were folded
  into v2 before freeze.
- **Boundary:** this is `RETROSPECTIVE_STRUCTURAL_ONLY`, not a learned compression
  or key-recovery result. Formal O1C-0026 remains gated on authoritative O1C-0023
  selection. A null closes only `fap_ancestry_touch_bilinear_proxy_v2`; parent
  R07 and other 330D interactions remain open.
- **Artifacts:**
  [`structural report`](O1C0026_BUILD_ONLY_STRUCTURAL_PROBE_V2_20260718.md),
  [`exact JSON`](O1C0026_BUILD_ONLY_STRUCTURAL_PROBE_V2_20260718.json), and
  [`design`](O1C0026_PROOF_ANCESTRY_PAIR_RESIDUAL_DESIGN_20260718.md).

## 2026-07-18 — O1C-0026 conditional formal runner source freeze (non-attempt)

- **Recorded:** 2026-07-18T07:47:03+02:00
- **Source freeze:** formal runner commit
  `7855492ac754f156d5de9bbea65fd2b6cf1910f9` over proxy-v2 mechanism
  `0af57fbeb6beaf69be66e64c3f0981227f829fd7`; config SHA-256
  `17df7a8a1cc3100c13ef86d4d355783b97382700b6d68fcf045362183131efb4`
  and runner SHA-256
  `0e3ae438b9df8189a2042dc1a78db1a734350ebab64de2764e2ec4c773ff1ddf`.
- **Live preflight:** exits 2 with `prerequisite-pending` because authoritative
  O1C-0023 is not finalized. It creates no O1C-0026 reservation and performs no
  scientific work.
- **Truth-safe lifecycle:** the runner persists and reloads 16 inner-OOF freezes.
  The full label vector is parsed only after every projection freezes, then each
  held-out label is excluded from its own fold fit. Every outer and aggregate
  prediction freezes before that already-loaded own-fold label is scored.
- **Exact conditional work:** if and only if O1C-0023 selects
  `proof_ancestry_pair_residual_v1`, the runner opens exactly 4 BUILD and 0
  DEVELOPMENT FAPs, performs 64 ridge fits, 4,927,488 alpha-bit evaluations and
  4,096 diagnostic-bit evaluations.
- **Living state:** four persisted/reloaded 6,144-B primary weight vectors each
  create one transient `ProjectedResidualState`, covering 1,024 coordinates in
  total. Its weights plus mutable posterior are exactly 8,192 live bytes. Each
  resulting 2,048-B logit vector is persisted and reloaded for scoring, with a
  hard process-local scratch gate of at most 16,384 B.
- **Artifact graph:** 120 semantic artifacts are indexed; the complete prepared
  directory has 121 files including `artifact_index.json`. The verifier
  rehydrates provenance, predictions, labels, score classification, work and
  every resource envelope from persisted bytes.
- **Authority/recovery:** result JSON is candidate-only. Only completed
  operational metrics after semantic verification, the final source recheck and
  every budget gate may authorize closure of this exact proxy instance. An
  operational, stopped or publication failure closes neither the proxy nor R07.
  Recovery from a prepared-publication fault retries immutable publication and
  never reruns the scientific computation.
- **Verification:** 15 core plus 8 runner tests pass (23 focused total); scoped
  Ruff, Mypy, pycompile and `git diff --check` are clean, and the adjacent
  composer/frontier/capsule groups remain green.
- **Boundary:** this is an `INSTRUMENT` source freeze and synthetic lifecycle
  verification only; an activated capsule declares `RETROSPECTIVE`. No O1C-0026
  attempt, scientific run, result or signal exists.
- **Artifacts:**
  [`config`](../configs/proof_ancestry_pair_residual_run_v1.json),
  [`runner`](../src/o1_crypto_lab/proof_ancestry_pair_residual_run.py), and
  [`design`](O1C0026_PROOF_ANCESTRY_PAIR_RESIDUAL_DESIGN_20260718.md).

## 2026-07-18 — O1C-0027 full-256 polyphase sufficient state

- **Recorded:** 2026-07-18T09:08:36+02:00
- **Source/run identity:** source commit
  `f47a6dacd54a7d9c93bc41c0ee08902bf855e85d`; finalized capsule
  `runs/20260718_090248_O1C-0027_polyphase-sufficient-state-full256-v1`;
  manifest SHA-256
  `1361823ceb8711090b4773fd8409ced7123e490b71c30a2a9e41c5ec205c2023`;
  result SHA-256
  `6041fbb157cb96c98a988da60b0a88f958507b3c5d0e1b5cd8ebe2733280a568`.
- **Hypothesis:** a fixed bank of stable polyphase resonators is a
  stream-length-independent sufficient statistic of a once-consumed, full-256
  evidence stream for late-bound slot weights and temperature. Encoder, kernel
  and phase basis changes are not hot parameters and must require replay.
- **Input/control:** one deterministic, target-free
  `float32[384,3,256]` source with a regime switch before group 193. Primary,
  rechunk, exact polarity-swap and prefix arms are matched by explicit work;
  a collapsed-slot negative control distinguishes genuine reader geometry from
  scalar rescaling. There are zero target, label, entropy, outcome, solver,
  sibling, network, GPU, MPS, gradient or optimizer accesses.
- **Result:** `POLYPHASE_SUFFICIENT_STATE_PASS`; all 12 frozen gates pass.
  Primary and rechunk states are byte identical, polarity swap negates all complex
  slots and readouts exactly, serialization roundtrips exactly, coverage/clock
  accounting is exact, and an independent chronological complex128 recurrence
  stays inside the derived float32 error envelope.
- **Hot-reader result:** four readers query one immutable final state with zero
  stream reingestion and zero state writes. Their minimum pairwise RMS after
  normalization is `0.08166284453308809`; the collapsed-bank maximum is
  `1.2395688701142996e-16` and correctly fails the distinctness gate. Encoder
  order, one kernel timescale and one phase wavelength each raise
  `ReplayRequiredError` before computation.
- **Bounded state/work:** one state is exactly 25,096 bytes at T=0/193/384;
  four deployment arms are 100,384 bytes. The run bills 294,912 generated
  evidence values, 4,131,840 production resonator-cell updates, 12 successful
  readouts and 3 replay-required probes.
- **Resources:** 0.081856 CPU seconds, 0.094719 measured wall seconds and
  0.122845 complete-capsule seconds at 41,304,064 B peak RSS; persistent artifacts
  occupy 164,132 B. Programmatic verification checks 22 members with no missing,
  mismatched or unexpected paths.
- **Interpretation:** this answers the continuous-machine question narrowly and
  usefully. O1 may keep streaming while reader weights/temperature switch after
  ingestion; changing the evidence encoder, recurrence or phase binding still
  needs replay. This is synthetic mechanism validation, not a cryptanalytic
  signal or full-round key-recovery result.
- **Next action:** adapt immutable O1C-0022 `PacketDeltaGroup` packets to sparse
  three-horizon full-256 groups and bind O1-O operator choices to immutable hot
  readout specs. Validate the adapter with no target/reveal and no W52 access;
  only finalized O1C-0019/O1C-0022 may later supply efficacy-bearing packets.
- **Artifact:**
  [`capsule`](../runs/20260718_090248_O1C-0027_polyphase-sufficient-state-full256-v1/RUN.md).

## 2026-07-18 — O1C-0028 horizon-major V2 hot routing

- **Claim level:** `VALIDATION`, synthetic mechanism only.
- **Source freeze:** `17c02dfdbf56de6a81ae34700b258815bf0b7f88`.
- **Hypothesis:** a byte-exact O1C-0022-compatible full-256 packet ledger can be
  transposed into a bounded, allocation-invariant polyphase state once, after
  which O1-O may bind immutable horizon readers without replaying evidence.
- **Construction:** a pure-standard-library codec reconstructs the pinned
  O1C-0019 packet wire ABI and both normalized/int8 transports. Canonical
  horizon-major H64/H65/H96 groups enter a self-describing V2 state; two hot
  bindings and thirteen cold-operator probes exercise the routing boundary.
- **Result:** `HORIZON_MAJOR_HOT_ROUTING_PASS`; all 14 frozen gates pass. The
  primary V2 state SHA is `02837fe6...`, result commitment `ed3517f2...`, and
  eight fresh processes reproduce the same result SHA. A second formal call
  returns the verified finalized capsule without mechanism replay.
- **Bounded state/work:** 25,128-byte persistent state, 9,216-byte dense stream
  per encoding, one primary consume, zero primary reingested groups, 75 total
  consumes, 731 group updates and 2,245,632 resonator-cell updates.
- **Resources:** 0.112165 CPU seconds, 0.123936 measured mechanism wall,
  0.143779 complete-capsule seconds and 44,892,160 B / 42.8125 MiB peak RSS;
  persistent artifacts occupy 378,809 B and every resource budget passes.
- **Breadcrumb:** coordinate-major sparse replay creates artificial decay from
  ledger row order, so complete K256 ledgers must be transposed horizon-major.
  O1C-0027 V1 stays immutable; V2 freezes explicit float32 rounding and embeds
  the basis digest because this runtime exposed two allocation-dependent one-ULP
  V1 variants. Legacy and foreign state bytes require cold replay.
- **Boundary:** this contains no ChaCha20 evidence, target key, solver result or
  key signal. The real successor must use nested cross-fitting so held-out fold A
  never receives a hot reader fit from states whose upstream reader trained with
  A labels, and it must verify the authoritative O1C-0023 decision graph.
- **Artifacts:**
  [`result note`](O1C0028_HORIZON_MAJOR_HOT_ROUTING_RESULT_20260718.md),
  [`capsule`](../runs/20260718_103518_O1C-0028_horizon-major-hot-routing-full256-v1/RUN.md).

## 2026-07-18 — O1C-0029 conditional stacked-hot calibration source freeze (non-attempt)

- **Recorded:** 2026-07-18T12:56:28+02:00
- **Source freeze:** `22d417ca73c73af59c8043c456c5475ed57f66a3`.
  This is a source-only `INSTRUMENT`, conditional on the manager-authoritative
  finalized O1C-0022 publication. No O1C-0029 attempt or capsule is reserved,
  and no scientific run, result, null, key-recovery claim or signal exists.
- **Live preflight:** reports `prerequisite-pending` while O1C-0022 is absent.
  The formal call performs zero state construction, target/label science, solver
  work, entropy, sibling access, MPS or GPU work and creates no reservation.
- **Truth-safe authority:** one isolated trusted process performs the sole full
  manager verification. The parent receives only a factory-minted, path- and
  label-byte-free authority receipt plus a nonce-bound label-free packet corpus.
  Arbitrary self-hashed wire bytes cannot mint either authority. Manager-pass
  reads and the two later scientific label openings are separately committed
  and accounted.
- **Frozen lifecycle:** after readiness, 12 calibration and 4 held-out O1C-0022
  packet ledgers construct and persist all 16 owner/episode states before any
  scientific label opening. The first exact artifact-index plus `labels.bitpack`
  opening authorizes four owner-safe fits. All 4 fits and 8 held-out logit vectors
  persist before the second exact index-plus-label opening authorizes scoring.
- **Dependency boundary:** O1C-0023 is not looked up, read or used for selection;
  optional metadata stays unavailable/unknown and `consumed: false`. The full
  application/runtime closure, Python/NumPy ABI and every transitive source byte
  are pinned and freshly verified before reservation.
- **Hot/cold boundary:** O1C-0022 evidence and its 16 state constructions are
  cold. Once a state is persisted, reader weights and positive temperatures are
  hot and may change without packet replay or state mutation.
- **Verification:** 44 focused tests plus 25 subtests pass; 45 neighboring tests
  plus 12 subtests pass. Ruff, Mypy, runtime/source-closure checks, pycompile and
  `git diff --check` are clean.
- **Boundary/next:** preserve this conditional source freeze unchanged until the
  authoritative O1C-0022 capsule exists. A future activation must use the exact
  two-opening lifecycle; this source freeze itself contributes no evidence.
- **Artifacts:**
  [`design`](O1C0029_STACKED_HOT_CALIBRATION_DESIGN_20260718.md),
  [`config`](../configs/o1c29_stacked_hot_calibration_v1.json), and
  [`runner`](../src/o1_crypto_lab/o1c29_stacked_hot_calibration_run.py).

## 2026-07-18 — O1C-0030 incremental-diagonal frontier

- **Source/run identity:** source freeze
  `e7c1bf551f2abf3c00a82c46d48b021452dfd417`; finalized capsule
  `runs/20260718_134406_O1C-0030_incremental-diagonal-frontier-v1`; manifest
  SHA-256 `ed6ef945e0e05ebf3199b3526c71d70da8402cc07bd8d7c4ec6c66bed483b04e`.
- **Question:** can the cheapest label-free local lamp over the four already
  consumed O1C-0018 BUILD pools expose a transferable incremental self-ancestry
  diagonal before the authoritative packet-delta path becomes available?
- **Result:** `RETROSPECTIVE_BREADCRUMB_NO_STRONG_GATE`. Mean compression is
  `-0.680620` bit for primary, `-0.097788` for cumulative replacement,
  `+0.035626` for legacy reintegration, `+0.779642` for the deranged-confidence
  control and `-0.262728` for even common mode. Primary beats cumulative on
  `0/4` folds, and no exact key appears in any primary exact top-65,536
  frontier.
- **Post-result diagnostic boundary:** a label-opened active-row inspection
  finds `312/574` active rows and one fold reverses orientation. This was
  computed only after the formal result and is a breadcrumb, not a frozen
  pre-result selector or evidence that rescues the failed gate.
- **Interpretation:** close only this local incremental-diagonal lamp. The
  deranged control win and fold reversal argue against promoting the local
  coordinate diagonal as causal orientation; they do not close packet-level,
  temporal or ancestry-pair mechanisms.
- **Resources/lifecycle:** 7.455637 s wall, 65,748,992 B peak RSS and 168,648 B
  persistent artifacts. The run generated no pool and used zero solver branches,
  scientific entropy, sibling reads/writes, MPS or GPU calls. The finalized
  attempt is replay protected.
- **Next action:** once authoritative packet deltas exist, compare an O1-O live
  scout-to-focus re-ranker against an identical frozen one-shot policy at matched
  work. If packet features are null, move to raw antecedent/signed-pair evidence
  rather than resweeping this diagonal.
- **Artifacts:**
  [`capsule`](../runs/20260718_134406_O1C-0030_incremental-diagonal-frontier-v1/RUN.md),
  [`result note`](O1C0030_INCREMENTAL_DIAGONAL_FRONTIER_RESULT_20260718.md), and
  [`post-result diagnostic`](O1C0030_POSTRESULT_DIAGNOSTIC_20260718.json).

## 2026-07-18 — Effect-first recovery-transfer correction (non-attempt)

- **Recorded:** 2026-07-18T14:24:04+02:00.
- **Correction:** the preceding cycle put too much work into state, lifecycle and
  routing machinery before establishing a useful cipher score. Negative results
  are now treated as failed hypotheses with one do-not-repeat sentence, not as
  milestones. O1C-0030 closes its exact local-diagonal lamp; no additional value
  is assigned to the null.
- **Read-only sibling evidence:** A291/A296's fixed eight-channel causal reader
  achieved eight of eight exact strict-subset W24/W28 recoveries with `3.0821x`
  geometric domain reduction and zero control hits. A317/A321/A325's frozen
  nearest-prototype L-infinity rank operator recovered a fresh W46 residual at
  rank `77/4096`, `5.733213459` gain bits and `53.194805x` domain reduction.
  The sibling tree was not modified.
- **A291/A296 boundary:** the literal eight-channel reader cannot be reconstructed
  from cached FAPs. It requires accepted-learned-clause/conflict stage deltas at
  H1/2/4/8 and one 256-cell XOR cube; FAPs retain H64/65/96 over 256 independent
  bit x polarity actions. The only honest cached proxy, H96 derived-clause
  pressure, is negative/unstable: BUILD-LOO `-1.939277` mean bits and consumed
  DEVELOPMENT `[+1.802489,-0.794993]`. Close the proxy, not exact A296.
- **A317/A321/A325 transpose:** exact nearest-L-infinity distance and six-field
  A317 tie semantics were applied to three complete 512-action rank views with
  BUILD-only prototypes and nested BUILD-only scale fitting. BUILD-LOO is positive
  in 4/4 (`+1.113828` bits total), but consumed DEVELOPMENT is
  `[+0.147004,-1.530953]`, `-1.383949` total and 255/512 correct. Opposite sign is
  also null (`-0.057103` total). The transpose does not transfer; close it.
- **Cost:** both write-nothing cached screens use zero fresh solver branches,
  target entropy, sibling writes, MPS or GPU work. The A291 boundary/proxy screen
  takes about `0.05` seconds and reads `12,424,733` bytes.
- **Interpretation:** these are negative results. They are recorded once so the
  exact proxy/transposition is not repeated; no full key or stable bit signal was
  recovered.
- **Next:** acquire the missing A291 H1/2/4/8 raw channels directly for one fixed
  256-value byte-intervention cube while all 256 target bits remain unknown. Apply
  the sibling's frozen eight-feature scorer unchanged. Only a positive consumed-
  target screen that repeats may spend one fresh sealed all-256 target.
