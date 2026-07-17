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
- **Implementation commit:** `dc249add99aa0673fc611fab8b2e75b8ba1434a0`
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
  loading pass.
- **Resource interlock:** sibling W52 is active, with two additional one-core
  CaDiCaL processes observed. The heavy four-fold gate is intentionally deferred;
  only light validation ran. System memory-pressure query reported 30% free.
- **Resume:** recheck W52/process/RAM state. When clear, run
  `PYTHONPATH=src python -m o1_crypto_lab.full256_multiresolution_build_loo_run --config configs/full256_multiresolution_build_loo_v1.json`
  from the clean implementation commit; do not alter config or consume DEVELOPMENT.
