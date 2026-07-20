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

## 2026-07-18 — Exact A296 full256 byte-2 transfer

- **Mechanism:** the literal sibling `IdentityLearner`, cumulative H1/2/4/8
  stages, complete 256-cell XOR cube and unchanged A268/A272/A291 selected-eight
  coefficients. Key bits 16..23 form the candidate byte; all other 248 key bits
  remain free in the standard 20-round public CNF.
- **Runtime:** four complete cubes finished in `55.505`, `46.006`, `45.671` and
  `54.063` seconds. Every one of the 4,096 stages remained UNKNOWN; no target key
  or trace entered measurement.
- **Result:** consumed RFC/DEVELOPMENT ranks were `118/61/9`. With no parameter
  change, the precommitted fresh EVALUATION target ranked `230/256`.
- **Decision:** `CLOSED_NULL_DOES_NOT_GENERALIZE`. Four-target geometric rank is
  `62.129`, but exact uniform lower-tail rank-product `p=0.1766`; the fresh result
  is negative. No byte, sign, coefficient or target resweep.
- **Artifact:**
  [`A296_FULL256_BYTE2_TRANSFER_20260718.json`](A296_FULL256_BYTE2_TRANSFER_20260718.json).

## 2026-07-18 — Exact residual-backend entry boundary

- **Direct reuse finding:** A325/W46 and A526/W52 are retained exact terminal
  search engines. A325 assumes bits 46..255 are already correct; A526 assumes
  bits 52..255 are already correct. Their sibling recoveries do not produce those
  210/204 bits.
- **Current real gate:** the strongest O1C-0018 completion has `115/210` correct
  A325 complement bits and `110/204` correct A526 complement bits. It fixes 95/94
  bits incorrectly, so the true key is absent from either residual domain.
- **Action:** freeze the exact bit codec, completion hashes and public verifier;
  do not spend a W46/W52 search until the complement is exact or a tractably small
  beam contains an exact completion.
- **Artifact:**
  [`RESIDUAL_BACKEND_ENTRY_GATE_20260718.json`](RESIDUAL_BACKEND_ENTRY_GATE_20260718.json).

## O1C-0031 / O1C-0032 — Exact A448 full256 byte-3 transfer

- **Mechanism:** exact hash-frozen sibling A448 proof-antecedent top4 reader,
  A442 Borda tie backbone and frozen equal hybrid over one H1/H2/H4/H8 pass.
  Key bits 24..31 form the 256 candidates; all other 248 key bits remain free.
- **O1C-0031:** consumed RFC8439 truth `0x03` ranked `47/256` in `55.290270`
  measured seconds. This authorized exactly one unchanged consumed repeat.
- **O1C-0032:** disjoint consumed DEVELOPMENT-0000 truth `0x0f` ranked
  `239/256` in `48.297538` seconds. Its A442 baseline, proof-only reader and
  final hybrid ranked the truth `242/236/239`.
- **Decision:** `CLOSED_NOT_REPLICATED`. No fresh target, rescue fit, byte,
  coefficient, sign, horizon or operator sweep. The two-target descriptive
  ranking delta is `-0.149617` bit versus exact uniform mean log-rank.
- **Artifacts:**
  [`A448_FULL256_BYTE3_TRANSFER_20260718.json`](A448_FULL256_BYTE3_TRANSFER_20260718.json),
  [O1C-0031 capsule](../runs/20260718_174416_O1C-0031_a448-proof-byte3-full256-transfer-v1/RUN.md),
  [O1C-0032 capsule](../runs/20260718_175112_O1C-0032_a448-proof-byte3-development-repeat-v1/RUN.md).
- **Next:** transfer the next exact sibling mechanism that accepts all 256 bits
  unknown; do not rebuild A325/A526, and do not invoke them before their exact
  complement gate is satisfied.

## O1C-0033 / O1C-0034 — Exact retained A465/A469 all256 transfer

- **Mechanism:** reconstruct A460/A462/A463 switching-wavelength ranks, the
  frozen A465 cubic `(7,1,4)` Product-of-Experts and the selected A469 positive
  bucket-local correction exactly from the already-retained A448 public
  telemetry. No solver stage or target was added.
- **Result:** A465 leaves RFC/DEVELOPMENT truth ranks at `47/239`; A469 changes
  them to `56/239` in `1.068837` and `0.002521` scientific-path seconds.
- **Decision:** `CLOSED_NOT_REPLICATED`. This is negative. Do not resweep the
  A448--A469 family when the known complement is absent.
- **Artifacts:**
  [`summary`](A465_A469_FULL256_TRANSFER_20260718.md),
  [O1C-0033 capsule](../runs/20260718_180604_O1C-0033_a465-retained-two-target-full256-transfer-v1/RUN.md),
  [O1C-0034 capsule](../runs/20260718_181054_O1C-0034_a469-retained-two-target-full256-transfer-v1/RUN.md).
- **Next:** preserve A325/A526 unchanged as terminal backends. Work only on an
  attacker-valid all256 source that can satisfy their exact complement/beam gate.

## O1C-0035 — Literal A526-native completion frontier

- Exact 204-bit complement decoder added at A526's real interface: coordinates
  `52..255` are ranked; `0..51` remain the unchanged W52 residual domain.
- Four consumed O1C-0022 BUILD folds x five frozen arms x 65,536 complements ran
  in `0.832396` seconds at `45,989,888` B peak. MAP max is `118/204`; even the
  post-reveal best beam member is only `123/204`; exact complement count is `0/20`.
- **Decision:** do not launch W52 on this posterior. Retain the bridge and change
  only upstream eight-block public-stream evidence.
- **Artifact:**
  [`O1C0035_A526_NATIVE_COMPLETION_FRONTIER_RESULT_20260718.json`](O1C0035_A526_NATIVE_COMPLETION_FRONTIER_RESULT_20260718.json).

## O1C-0019 / O1C-0022 — Real full256 unary bridge execution

- **Recorded:** 2026-07-18T19:09:38+02:00.
- **O1C-0019:** the exact four-fold artifact-only BUILD-LOO reader/picker ran on
  the existing public full-round pools with all 256 held-out bits unknown. It
  completed in `2467.325471` elapsed seconds at `362528768` B peak RSS and
  finalized under manifest `d636d935...`. Classification:
  `BUILD_LOO_NO_TRANSFER`. Learned live compression is `-0.271089809` bit. The
  raw learned reader is `+0.312763538`, but its untrained twin is better at
  `+0.371233059`; learned-minus-untrained is `-0.058469521` bit.
- **O1C-0022:** the four frozen readers streamed their exact K12/K52/K128/K256
  packet deltas into the 352-byte addressed vault. It completed in `70.217948`
  elapsed seconds at `297910272` B peak RSS and finalized under manifest
  `d5ae33be...`. Classification: `CROSS_COORDINATE_DILUTION`. The int8 curve is
  `[-0.006772,-0.021457,-0.580458,-1.181837]` bits; every K256 float/sign arm is
  also negative.
- **Residual gate:** across all precommitted raw arms and all post-reveal folds,
  the maximum diagnostic complement is `120/210` for A325 and `118/204` for
  A526. Neither terminal backend can contain the true key.
- **Decision:** negative. Close the entire unary O1C-0019 packet/O1C-0022 vault
  field. Do not run O1C-0023, O1C-0025 or O1C-0029 on it and do not sweep scale,
  quantization, horizon weights or frontier size. The next paid run must add a
  genuinely new all256 evidence source and score complement/beam effect directly.
- **Artifacts:**
  [`result`](O1C0019_O1C0022_FULL256_BRIDGE_RESULT_20260718.md),
  [O1C-0019 capsule](../runs/20260718_181855_O1C-0019_full256-multiresolution-build-loo-v1/RUN.md),
  [O1C-0022 capsule](../runs/20260718_190629_O1C-0022_o1c19-causal-vault-build-loo-v1/RUN.md).

## 2026-07-18 — Effect-first direct recovery combinations (non-attempt)

- **Question:** can the retained sibling solver convert an existing O1 all256
  candidate directly into error-bit evidence before the A325/A526 residual gate?
- **Executed:** exact signed-pair proxy; deeper single-bit assumptions; full and
  one-output failed cores; inverse-round fixed-point and one-bit landscapes;
  complete-candidate contradiction neighbors; deterministic W8 relaxation cells.
- **Result:** no repeated error-bit effect. Cores are `255..256` bits, the wrong
  bit remains UNKNOWN at `262,144` conflicts, inverse rankings are chance-like,
  the frozen inverse rule loses `14` DEVELOPMENT bits, the frozen neighbor rule
  splits `-4/+6`, and W8 correlation collapses from `-0.158165` to `-0.014003`.
- **Decision:** close only these exact surfaces. Do not scale, reverse, regroup or
  wrap them in more O1/O1-O infrastructure. Keep A325/A526 unchanged and require
  a new attacker-valid error-bit source before invoking either backend.
- **Artifact:**
  [`ALL256_EFFECT_FIRST_TRANSFER_SCREENS_20260718.md`](ALL256_EFFECT_FIRST_TRANSFER_SCREENS_20260718.md).

## O1C-0036 — Eight-block public O1 at the native A526 frontier

- **Input:** 1,024 generated uniform 256-bit training keys and 128 disjoint
  read-only A448 BUILD targets. Deployment received only counter, nonce and eight
  full-round outputs; the sibling's published 210-bit complement stayed teacher-
  only.
- **Result:** `102.5/204` mean MAP, `50.2451%` aggregate accuracy,
  `-0.393341` bit mean held-out compression and `0/128` exact complements in the
  exact top-65,536 frontier. Runtime `36.541987` s; peak RSS `339,542,016` B.
- **Decision:** close this raw-output reader without width/data/epoch scaling.
  Retain O1C-0035 and move to joint relational completion, where any held-out
  entropy/rank/residual-width gain counts even before exact 256-bit recovery.
- **Artifact:**
  [`O1C0036_EIGHT_BLOCK_A526_READER_RESULT_20260718.json`](O1C0036_EIGHT_BLOCK_A526_READER_RESULT_20260718.json).

## O1C-0037 — Frozen O1 scores inside exact Full-256 CDCL

- **Hypothesis:** reversible confidence-ordered O1 key decisions reduce work in
  the unchanged exact public ChaCha20-R20 relation.
- **Result:** exact post-reveal guidance recovers and verifies the key in
  `5,065 us` with zero conflicts. The attacker-valid O1 K256 field has `117/256`
  correct signs, produces zero recovery, takes `2.123064x` internal wall time and
  matches the coordinate-shuffled K256 telemetry. One wrong hint remains UNKNOWN
  through `32,768` conflicts / `8,908,928 us`.
- **Correction:** the declared K255 residual row contains 254 correct guided bits,
  one wrong guided bit and one unguided bit because of tied minimum confidence.
  It is retained unchanged and does not answer the intended 255+1 ceiling.
- **Decision:** close key-phase-only guidance over this frozen field. Keep the
  exact adapter and move O1 decisions onto target-specific proof/relation factors.
- **Resources:** `14.513263` elapsed s; `139,853,824` B peak; 12 native calls;
  47,616 requested conflicts; zero sibling/MPS/GPU work.
- **Artifacts:**
  [`result`](O1C0037_RELATIONAL_GUIDED_SEARCH_RESULT_20260718.md) and
  [`capsule`](../runs/20260718_211056_O1C-0037_relational-guided-search-v1/RUN.md).

## O1C-0038 — Corrected exact residual completion frontier

- **Hypothesis:** the unchanged exact relation can close a nonzero O1-ordered
  residual once every supplied prefix decision is correct.
- **Result:** at 512 conflicts the complete key is recovered and publicly
  verified for residual widths `0/1/2/4/8`. Width eight takes `89` conflicts and
  `135,441 us`. Width nine remains UNKNOWN at `512/2,048/8,192/32,768`
  conflicts; width 16 is UNKNOWN at 512.
- **Boundary:** every supplied prefix sign is built from post-reveal truth. This
  is an exact decoder ceiling and contributes zero attacker-valid recovered bits.
- **Decision:** retain the eight-bit completion zone as a concrete target. The
  next run must reduce joint/effective width with attacker-computable signed
  proof/relation factors, not another unary confidence or conflict-budget sweep.
- **Resources:** `11.494730` elapsed s; `139,575,296` B peak; 10 native calls;
  46,592 requested conflicts; zero sibling/MPS/GPU work.
- **Artifacts:**
  [`result`](O1C0038_EXACT_RESIDUAL_COMPLETION_RESULT_20260718.md) and
  [`capsule`](../runs/20260718_212009_O1C-0038_exact-residual-completion-v1/RUN.md).

## O1C-0039 — Attacker-valid proof-clause relation transfer

- **Recorded:** 2026-07-18T22:02:17+02:00.
- **Hypothesis:** the BUILD-selected H16 signed clause-occurrence contrast retains
  target-specific key-to-internal relation orientation on unseen full-round keys.
- **Result:** supported at relation level on both DEVELOPMENT targets: `238/432`
  (`55.0926%`) and `159/279` (`56.9892%`), pooled `397/711` (`55.8368%`).
  Pooled key-rotated and factor-rotated controls are `52.8833%` and `49.5077%`.
- **Boundary:** fields, controls, residual coordinates and Full-256 search outputs
  froze before labels. The current factor injector recovered `0` Full-256 keys;
  the explicit post-reveal residual-9 arms also recovered `0`. Classification:
  `RELATION_TRANSFER_ONLY`, not entropy removal or a ChaCha break.
- **Resources:** `12.202150` elapsed s; `142,262,272` B peak; 1,024 paired
  branches; 18 exact-solver calls; zero sibling/MPS/GPU work.
- **Decision:** preserve H16/`|J|=0.5` unchanged. Test whether the aggregate field
  ranks true forward executions above decoys, then make it live/reversible only
  on a positive rank result; otherwise move to signed antecedent-chain factors.
- **Artifacts:**
  [`result`](O1C0039_PROOF_CLAUSE_RELATION_TRANSFER_RESULT_20260718.md) and
  [`capsule`](../runs/20260718_220217_O1C-0039_proof-clause-relation-v1/RUN.md).

## O1C-0040 — Complete-candidate relation rank diagnostic

- **Recorded:** 2026-07-18T22:22:55+02:00.
- **Hypothesis:** O1C-0039's transferred occurrence edges jointly rank the true
  forward execution, raw or after one fixed structural-surprise correction.
- **Result:** refuted. Raw primary ranks are `1905/4097` and `2292/4097`;
  surprise ranks are `1078/4097` and `1461/4097`. Primary geometric surprise
  rank fraction is `30.6315%`, versus `5.1927%` for key rotation.
- **Boundary:** consumed post-reveal targets; all 8,192 decoys, forward wires,
  weights and score vectors froze before the runner reread truth. Zero recovered
  bits, entropy reduction or recovery claim.
- **Resources:** `3.981557` elapsed s; `101,466,112` B peak; 8,194 candidate
  forward evaluations; zero solver/sibling/MPS/GPU work.
- **Decision:** close H16 clause-occurrence scoring and its single surprise arm.
  Move to branch-exclusive signed antecedent-chain factors without a sweep.
- **Artifacts:**
  [`result`](O1C0040_RELATION_CANDIDATE_RANK_RESULT_20260718.md) and
  [`capsule`](../runs/20260718_222255_O1C-0040_relation-candidate-rank-v1/RUN.md).

## O1C-0041 — Branch-exclusive antecedent-chain candidate rank

- **Recorded:** 2026-07-18T22:55:50+02:00.
- **Hypothesis:** exact branch-exclusive proof-chain identity preserves
  target-specific joint information erased by terminal clause occurrence.
- **Result:** strict BUILD unanimity selects nothing (`[-1,-1,-1,+1]`), while
  the separately frozen BUILD rank-product selects global orientation `-1`.
  DEVELOPMENT truth ranks are `80/4097` and `998/4097`; geometric primary is
  `6.8967%`, versus key rotation `27.0187%` and factor rotation `16.2556%`.
- **Boundary:** all six keys were already consumed; DEVELOPMENT scores and the
  BUILD-selected orientation froze before the label artifact reread. This is a
  retrospective joint-rank signal, not fresh transfer or recovery.
- **Resources:** `31.551941` elapsed s; `131,629,056` B peak; 3,072 native H16
  branches; 24,582 complete forward evaluations; zero sibling/MPS/GPU work.
- **Decision:** freeze extractor, unit weights, `-1` orientation and controls;
  run exactly one fresh O1C-0042 target before live-CDCL integration.
- **Artifacts:**
  [`result`](O1C0041_ANTECEDENT_CHAIN_RANK_RESULT_20260718.md) and
  [`capsule`](../runs/20260718_225550_O1C-0041_antecedent-chain-rank-v1/RUN.md).

## O1C-0042 — One-shot fresh antecedent-chain rank replication

- **Recorded:** 2026-07-18T23:04:37+02:00.
- **Hypothesis:** O1C-0041's exact H16 unique-leaf reader and global `-1`
  orientation transfer to one newly sealed Full-256 key.
- **Result:** not replicated. Primary ranks `1371/4097` (`33.46%`), narrowly
  ahead of key rotation `1399/4097` and factor rotation `3385/4097`, but outside
  the frozen best-quarter gate.
- **Boundary:** exactly one `os.urandom` call; public relation and commitment only
  until all candidate/score hashes froze and a reveal receipt opened the key.
- **Resources:** `7.435433` elapsed s; `131,579,904` B peak; 512 H16 branches;
  4,097 forward evaluations; zero sibling/MPS/GPU work.
- **Decision:** no retry or tune. Close unique-leaf summation and retain ordered
  direct-parent role plus candidate-relative clause criticality next.
- **Artifacts:**
  [`result`](O1C0042_FRESH_ANTECEDENT_CHAIN_RANK_RESULT_20260718.md) and
  [`capsule`](../runs/20260718_230437_O1C-0042_fresh-antecedent-chain-rank-v1/RUN.md).

## O1C-0043 — Ordered parent-role criticality joint rank

- **Recorded:** 2026-07-18T23:34:58+02:00.
- **Hypothesis:** exact RUP parent role and original functional-clause criticality
  retain the causal candidate information erased by unordered leaf union.
- **Result:** passed on consumed keys. DEVELOPMENT ranks are `5/4097` and
  `91/4097`, geometric `0.52%` versus best control `38.52%`. The conditional
  unchanged O1C-0042 repeat ranks `141/4097` versus controls `3623/3475`.
- **Boundary:** 15 weights fit only from four BUILD truths; all Development and
  repeat scores freeze before label parsing; public units excluded; zero fresh
  targets and no exact recovery claim.
- **Resources:** `63.609326` s; `183,795,712` B peak; 3,584 H16 branches; 28,679
  forward evaluations; 571,189-byte capsule.
- **Decision:** freeze exactly one fresh replication. No channel, horizon, sign,
  weight, panel or rotation adjustment.
- **Artifacts:**
  [`result`](O1C0043_PARENT_CRITICALITY_RANK_RESULT_20260718.md) and
  [`capsule`](../runs/20260718_233458_O1C-0043_parent-criticality-rank-v1/RUN.md).

## O1C-0044 — One-shot fresh parent-criticality transfer

- **Recorded:** 2026-07-18T23:42:33+02:00.
- **Hypothesis:** the exact O1C-0043 causal reader transfers joint rank to one
  newly sealed uniform Full-256 key.
- **Result:** passed. Primary `54/4097` (`1.318%`, z `+2.325`) versus key rotation
  `3567/4097` and clause rotation `2972/4097`.
- **Boundary:** reader weight hash `c4149a...` loaded without refit; exactly one
  entropy call; all candidate/score hashes freeze before reveal; key independently
  verifies; no exact recovery claim.
- **Resources:** `11.095178` s; `142,262,272` B peak; 512 H16 branches; 4,097
  forward evaluations; 284,774-byte capsule.
- **Decision:** no second rank panel. Inject the unchanged factors into existing
  exact search and measure matched work, time-to-hit and effective residual width.
- **Artifacts:**
  [`result`](O1C0044_FRESH_PARENT_CRITICALITY_RANK_RESULT_20260718.md) and
  [`capsule`](../runs/20260718_234233_O1C-0044_fresh-parent-criticality-rank-v1/RUN.md).

## O1C-0045 — Lossless parent-criticality live search

- **Recorded:** 2026-07-19T00:10:05+02:00.
- **Hypothesis:** the prospectively transferred rank-54 reader reduces exact
  search work when compiled into reversible local conditional decisions.
- **Result:** mixed. Full-256 has zero hits at 512 conflicts. Internal residual 9
  is UNKNOWN; primary verifies the exact key in 281 conflicts, but key/clause
  rotations also verify in 69/129. All arms recover residual 8.
- **Boundary:** exact score error at most `1.25e-14`; no refit; Full-256 search
  precedes reveal; residual prefixes are explicit post-reveal conditions; zero
  fresh targets.
- **Resources:** `17.290067` s; `130,269,184` B peak; 12 native calls; 6,144
  requested conflicts; 4,097 forward evaluations; zero sibling/MPS/GPU.
- **Decision:** preserve reader/factors. The all-variable greedy scheduler is
  closed; rerun the consumed boundary with internal variables observed but only
  key variables externally decided.
- **Artifacts:**
  [`result`](O1C0045_CRITICALITY_LIVE_SEARCH_RESULT_20260718.md) and
  [`capsule`](../runs/20260719_001005_O1C-0045_criticality-live-search-v1/RUN.md).

## O1C-0046 — Key-only parent-criticality search

- **Recorded:** 2026-07-19T00:24:50+02:00.
- **Hypothesis:** observing the complete factor trail while externally deciding
  only designated key coordinates preserves O1C-0044's primary orientation and
  removes generic internal-variable competition.
- **Result:** partial mechanism improvement without primary margin. Full-256 has
  zero hits at 512 conflicts. Primary verifies residual 8/9 in 43/87 conflicts,
  down from O1C-0045's 152/281, but the matched clause rotation verifies them in
  22/46. Internal remains UNKNOWN at width 9.
- **Boundary:** O1C-0045 potential bytes, target, residual sets, seed and work cap
  unchanged; all potential variables observed; exactly 126 key variables
  externally eligible; Full-256 rows precede reveal; residual rows are explicit
  post-reveal ceilings; zero fresh targets.
- **Resources:** `7.767220` s; `122,552,320` B peak; 12 native calls; 6,144
  requested conflicts; 35,478 persistent bytes; zero sibling/MPS/GPU.
- **Decision:** close greedy marginal branching in both all-variable and key-only
  forms. Preserve the global O1C-0044 score for bounded best-first key prefixes or
  score-aware factor activation; do not refit or raise the budget first.
- **Artifacts:**
  [`result`](O1C0046_KEY_ONLY_CRITICALITY_SEARCH_RESULT_20260719.md) and
  [`capsule`](../runs/20260719_002450_O1C-0046_key-only-criticality-search-v1/RUN.md).

## O1C-0047 — Global criticality residual beam

- **Recorded:** 2026-07-19T00:40:19+02:00.
- **Hypothesis:** the prospectively transferred criticality signal is global over
  coordinated complete assignments and survives exhaustive residual ranking even
  though one-variable search schedulers erase it.
- **Result:** passed as a post-reveal ceiling. Primary truth ranks W8 `1/256`,
  W12 `5/4096` and W16 `50/65536`; W16 rotations rank `60592/65536` and
  `43059/65536`. The primary top-256 contains exactly one public-output match,
  the independently verified consumed key at rank 50; rotated beams contain none.
- **Boundary:** 240 truth-key complement bits define the W16 cube. Every member is
  a complete 256-bit forward execution, but this is not attacker-valid Full-256
  recovery. Reader/potential bytes and support order are unchanged; zero fresh
  targets.
- **Resources:** `67.546893` s; `89,325,568` B peak; 65,536 forward evaluations;
  196,608 scores; 769 public verifications; zero sibling/MPS/GPU.
- **Decision:** preserve complete-state ordering and build only a soft reversible
  pairwise key-group/max-envelope scheduler. Do not hard-code a truth or decoy-
  maximum prefix; require matched Full-256/control work before promotion.
- **Artifacts:**
  [`result`](O1C0047_GLOBAL_CRITICALITY_RESIDUAL_BEAM_RESULT_20260719.md) and
  [`capsule`](../runs/20260719_004019_O1C-0047_global-criticality-residual-beam-v1/RUN.md).

## APPLE-VIEW-0001 — Public fixed-point and output-fitness descent

- **Recorded:** 2026-07-19, isolated parallel track.
- **Hypothesis:** treating ChaCha as 16 coupled 32-bit odometers exposes key
  direction through the public feed-forward fixed point or output-Hamming fitness.
- **Result:** negative. Across 32 deterministic Full-256 targets, holdout
  projection gains `-0.484` key bits, one-flip landscape AUC is `0.50572`,
  direction accuracy `0.49854`, and exact recoveries are zero.
- **Breadcrumb:** projection chains reduce output error by 23.906 bits and
  coordinate descent by 33.0 bits while key distance remains random. Public
  output improvement is therefore not a key-proximity surrogate.
- **Resources:** `10.478` s wall, `10.425` s CPU, `43.43 MB` peak; 21,108
  20-round core evaluations; zero MPS/GPU.
- **Decision:** close this fixed-point/local-output-fitness direction; do not
  scale target count, descent depth or restart count.
- **Artifact:** [`isolated result`](apple_view/apple_view_result.md), commit
  `dba4143c73aa84559e6b0466ca6cc232500c5fe9`.

## APPLE-VIEW-0002 — Independent-carry quotient

- **Recorded:** 2026-07-19, isolated parallel track.
- **Hypothesis:** lifting every modular addition into XOR plus nuisance carries
  and quotienting the carry columns leaves exact public linear key parities.
- **Result:** negative on eight deterministic Full-256 targets. Primary carry
  rank is `512`, exact key-information rank is `0`, and exact recoveries are
  `0/8`. Every individual double-round carry group already spans all 512 output
  dimensions; all `8,192/8,192` exact lifted equations validate.
- **Resources:** `5.851181` s wall, `5.788550` s CPU, `34,553,856` B peak RSS;
  zero network, sibling, MPS or GPU work.
- **Decision:** close independently free carries. If resumed, substitute the real
  majority recurrence globally by carry depth and measure exact domain pruning.
- **Artifact:** [`isolated result`](apple_view_2/apple_view_2_report.md), commit
  `b3c0400999c86d2ce078aa3c06e517e6ff536916`.

## O1C-0048 — Soft pair-envelope search

- **Recorded:** 2026-07-19T01:46:25+02:00.
- **Hypothesis:** coordinated global max-envelope decisions over frozen key pairs
  preserve O1C-0047's complete-state orientation better than greedy unary
  marginals.
- **Protocol:** primary plan compiled once before reveal; 63 disjoint pairs over
  126 key coordinates, with transformed matched controls. Four public Full-256
  calls precede attacker freeze and reveal; four arms then run on residual widths
  8 and 9. Fixed work is 12 calls and 6,144 requested conflicts.
- **Result:** `PAIR_ENVELOPE_NO_STRICT_PRIMARY_GAIN`. Full-256 is unresolved in
  all arms. Exact maxima internal/primary/key/clause are `8/9/9/9`. Conflicts are
  W8 `217/75/195/89` and W9 `UNKNOWN/155/331/167`. Every SAT row is the exact
  publicly verified truth key and honors its truth-fixed prefix.
- **Gate:** failed as frozen. The largest width recovered by every arm is 8, but
  the arm frontiers are untied, so the all-arm conflict tier cannot pass.
- **Breadcrumb:** primary nevertheless beats every comparator pairwise: internal
  by width, and both rotations by conflicts at W9. This is a post-result
  diagnostic, not a retroactive gate pass. Static pair envelopes restore
  specificity but cost more absolute work than O1C-0046's unary primary.
- **Resources:** `9.362067` s, `128,122,880` B peak, 12 calls, 6,144 requested
  conflicts, `50,256` persistent B; zero fresh/sibling/MPS/GPU.
- **Decision:** close this exact disjoint-pair adapter. Next use bounded live
  propagation/backtrack credit to select group operators, with O1C-0048 frozen as
  baseline and a prospectively defined per-comparator lexicographic gate.
- **Artifacts:**
  [`result`](O1C0048_PAIR_ENVELOPE_SEARCH_RESULT_20260719.md) and
  [`capsule`](../runs/20260719_014625_O1C-0048_pair-envelope-search-v1/RUN.md).

## APPLE-VIEW-0003 — Global carry-depth filter

- **Recorded:** 2026-07-19, isolated parallel track.
- **Hypothesis:** restoring the real carry-majority recurrence uniformly from
  low to high bit positions across every ChaCha addition exposes a cheap
  determined-output filter for complete wrong Full256 keys.
- **Result:** negative. Across 32 output-independent wrong keys, depths `0..30`
  determine zero final output bits and reject `0/32`; depth `31` determines all
  512 bits and rejects `32/32`, which is ordinary complete evaluation. Exact
  recovery and claimed entropy reduction are zero.
- **Boundary:** the strong three-valued evaluator is sound for rejection but
  deliberately discards correlations among unknown carries. The null closes
  forward-only bitwise carry-depth truncation, not carry structure in general.
- **Resources:** `13.291865` s wall, `13.232632` s CPU, `27,295,744` B peak;
  1,056 abstract blocks and 5,499,648 exact carry recurrences; zero sibling,
  network, MPS or GPU work.
- **Decision:** do not enlarge the probe panel or repeat the depth ladder. A new
  carry test must preserve correlations or propagate constraints from both the
  candidate input and public output.
- **Artifact:** [`isolated result`](apple_view_3/apple_view_3_report.md).

## APPLE-VIEW-0004 — Bidirectional partial-carry propagation

- **Recorded:** 2026-07-19T02:30:48+02:00, isolated parallel track.
- **Hypothesis:** exact generalized arc consistency from both a complete probe
  key and the public output rejects wrong keys before every carry recurrence is
  restored.
- **Result:** negative at the frozen gate. Depths 24/28/29/30 reject `0/4`
  probes; depth 31 rejects `4/4` and is the complete relation. At depth 30 the
  output nevertheless infers 3,720–3,850 variables beyond the 770 fixed inputs.
- **Boundary:** one unconstrained `c31` per each of 336 additions keeps every
  wrong probe locally consistent. Truth never conflicts and completes at d31.
- **Resources:** 18.124440 s wall, 18.020902 s CPU, 87,867,392 B peak; one CPU
  process, no solver branching, sibling, network, MPS or GPU work.
- **Decision:** close deeper local propagation. Test whether a sparse subset of
  the 336 missing carry identities forms a much smaller rejection certificate.
- **Artifact:** [`isolated result`](apple_view_4/apple_view_4_report.md), commit
  `6afbe22`.

## O1C-0049 — Bounded online pair-credit screen

- **Recorded:** 2026-07-19T02:37:28+02:00.
- **Hypothesis:** a 630-byte target-time state over O1C-0048's frozen 63 groups
  reduces absolute exact-search work using only assignment, propagation,
  conflict and backtrack events.
- **Result:** `ONLINE_PAIR_CREDIT_NO_ABSOLUTE_PRIMARY_GAIN`. Full-256 remains
  unresolved with the exact static telemetry `513` conflicts / `10,802`
  decisions. Online W8/W9 improve `75/155 → 65/128`, but W10 regresses
  `310 → 320`; both recover the exact key, so the registered gate fails.
- **Mechanism boundary:** all 3,301 Full-256 tickets close on `Advance`, before
  any of the solver's 590 later backtracks. Ticket conflict/backtrack deltas are
  zero and 62/63 group credits collapse to 424.
- **Resources:** 7.952809 s, 66,043,904 B peak, five calls, 2,560 requested
  conflicts; zero fresh/sibling/MPS/GPU.
- **Decision:** close this exact short-ticket equation. Change only the causal
  horizon: retain a bounded eligibility trace until later backtracks can credit
  the pair decisions they actually undo.
- **Artifacts:**
  [`result`](O1C0049_ONLINE_PAIR_CREDIT_SCREEN_RESULT_20260719.md) and
  [`capsule`](../runs/20260719_023728_O1C-0049_online-pair-credit-screen-v1/RUN.md).

## APPLE-VIEW-0005 — Sparse high-carry conflict certificates

- **Recorded:** 2026-07-19T02:55:37+02:00, isolated parallel track.
- **Hypothesis:** the 336 missing depth-30 `c31` majority identities are not all
  required simultaneously; a sparse joined subset can reject a complete wrong
  Full-256 candidate exactly.
- **Result:** positive on the fixed four-probe matrix. All 20 strategy×probe runs
  conflict exactly. Reason-DAG slices independently replay conflict with
  `250–265/336` identities; best is 250, omitting 86. Four slices use at most
  252. All five true-key controls complete consistently with all identities.
- **Boundary:** this filters supplied complete candidates; it generates no key,
  recovers zero bits and claims no global entropy reduction.
- **Resources:** 30.812515 s wall, 30.686913 s CPU, 56,573,952 B peak; no CDCL,
  branching, sibling, network, MPS or GPU work.
- **Decision:** immediate propagation gain is weak/tie-degenerate. Stream exact
  proof participation across BUILD targets into a bounded identity state and
  freeze its order before held-out evaluation.
- **Artifact:** [`isolated result`](apple_view_5/apple_view_5_report.md), commit
  `93d7fd7`.

## O1C-0050 — Delayed trail-owner pair credit

- **Recorded:** 2026-07-19T03:06:57+02:00.
- **Hypothesis:** keeping pair-member eligibility until the solver actually
  removes its decision level fixes O1C-0049's premature uniform credit.
- **Protocol:** one post-reveal exact W10 primary call at 512 conflicts against
  the frozen static value 310. Pass requires the exact key in fewer conflicts;
  telemetry and wall cannot pass.
- **Result:** `DELAYED_PAIR_CREDIT_STRICT_W10_GAIN`; exact key in 302 conflicts
  and 307 decisions versus static 310/315. The 1,134-byte state records 302
  conflict-owner undos, seven nonzero group credits and zero assignment or
  propagation reward.
- **Resources:** 4.558947 s, 64,356,352 B peak, one call/512 requested conflicts;
  zero fresh/sibling/MPS/GPU.
- **Decision:** run unchanged delayed primary once at W11. Exact completion earns
  matched W11 controls and Full-256; failure closes this scheduler.
- **Artifacts:**
  [`result`](O1C0050_DELAYED_PAIR_CREDIT_SCREEN_RESULT_20260719.md) and
  [`capsule`](../runs/20260719_030657_O1C-0050_delayed-pair-credit-screen-v1/RUN.md).

## O1C-0051 — Delayed pair-credit W11 promotion

- **Recorded:** 2026-07-19T03:32:57+02:00.
- **Hypothesis:** the unchanged O1C-0050 delayed owner rule expands exact
  completion from W10 to W11 at the same 512-conflict cap.
- **Protocol:** run delayed primary W11 first and require an exact publicly
  verified truth key honoring the 245-bit prefix. Only a pass authorizes static
  primary, both rotations and three Full256 calls.
- **Result:** `DELAYED_PAIR_CREDIT_NO_EXACT_W11_CLOSE`. The sole call is
  `UNKNOWN` at 512 conflicts, 513 decisions and 11,983,327 propagations. The
  gate fails; all six follow-ups are skipped.
- **Boundary:** consumed post-reveal ceiling, one call/512 requested conflicts;
  telemetry and wall cannot pass; zero fresh/sibling/MPS/GPU work.
- **Mechanism localization:** after bit 177 joins the residual, conflict-owner
  undos flip from `(143,144)` `227→1` and `(59,60)` `55→382`. Scalar unary
  group credit is context/action blind: all four pair masks share one credit and
  502/513 decisions repeat. This does not validate a replacement.
- **Resources:** 5.6889655 s wall, 128,335,872 B peak RSS.
- **Decision:** close delayed unary credit on these fixed pairs. Test only a
  bounded context/action-conditioned state at unchanged groups and cap, beginning
  with `4×63` per-pattern credits; do not sweep weights or assume static edges.
- **Artifacts:**
  [`result`](O1C0051_DELAYED_PAIR_CREDIT_PROMOTION_RESULT_20260719.md) and
  [`capsule`](../runs/20260719_033251_O1C-0051_delayed-pair-credit-promotion-v1/RUN.md).

## O1C-0052 — Exact pattern-action credit screen

- **Recorded:** 2026-07-19T04:02:47+02:00.
- **Hypothesis:** separating the four masks within each frozen pair repairs
  O1C-0051's action/polarity aliasing and closes W11 at the same cap.
- **Protocol:** one pattern-primary W11 call first, same 63 groups, seed 0 and
  512-conflict cap. Exact public/truth/prefix verification alone authorizes the
  six static/rotation/Full256 follow-ups.
- **Result:** `PATTERN_ACTION_CREDIT_NO_EXACT_W11_CLOSE`; `UNKNOWN` at 512
  conflicts, 513 decisions and 12,066,879 propagations. All six follow-ups are
  skipped. The state is exactly 2,646 bytes.
- **Mechanism localization:** 162/448 credit-modulated selections are reordered
  and 18 action cells across seven groups differentiate, but repeated decisions
  remain `502/513`. Every visited cell is penalized. `(59,60)` cycles masks
  `00/01/10/11` with 48/50/48/51 conflict-owner undos; six of eight active
  groups also penalize their true mask in the post-result diagnostic.
- **Resources:** 5.098155667 s wall, 128,303,104 B peak RSS, one call/512
  requested conflicts; zero fresh/sibling/MPS/GPU.
- **Decision:** close negative-only exact-mask credit without a rescue sweep.
  Reuse the state once with positive support only for the deepest action that
  survives a conflict backjump. Failure then moves to exact proof attribution.
- **Artifacts:**
  [`result`](O1C0052_PATTERN_CREDIT_SCREEN_RESULT_20260719.md) and
  [`capsule`](../runs/20260719_040242_O1C-0052_pattern-action-credit-screen-v1/RUN.md).

## O1C-0053 — Deepest-survivor support screen

- **Recorded:** 2026-07-19T04:38:53+02:00.
- **Hypothesis:** one positive `+32` update to the deepest externally owned
  `(group,mask)` action surviving each conflict backjump identifies the retained
  causal frontier and closes W11 at the unchanged cap.
- **Protocol:** one survivor-primary W11 call first, same 63 groups, seed 0,
  512-conflict cap and 2,646-byte action/owner layout. Exact public/truth/prefix
  verification alone authorizes the six static/rotation/Full256 follow-ups.
- **Result:** `SURVIVOR_SUPPORT_NO_EXACT_W11_CLOSE`; `UNKNOWN` at 512 conflicts,
  513 decisions and 12,068,568 propagations. The exact gate fails after one call,
  so all six follow-ups are skipped.
- **Mechanism localization:** every conflict backjump finds a survivor and emits
  exactly one support update: 512 updates / 16,384 units. The update reorders 111
  actions but differentiates only two groups; 502/513 decisions still repeat.
  The proxy is active but too coarse to expand the frontier.
- **Post-result truth diagnostic:** the true mask is supported/top in 4/8 active
  groups and receives 9,472/16,384 support units. This consumed-target view did
  not close W11 and is not fresh evidence; it points to exact antecedent credit,
  not a `+32` or group/cap tuning sweep.
- **Resources:** 5.326337459 s wall, 127,893,504 B peak RSS, one call/512
  requested conflicts; zero fresh/sibling/MPS/GPU.
- **Decision:** refute H-DEEPEST-SURVIVOR-SUPPORT-062 and close trail survival as
  a causal proxy. Next instrument exact learned-clause/first-UIP antecedent
  membership at the conflict boundary. The parallel global-prefix path is
  measured separately by O1C-0054 below.
- **Artifact:** [`result`](O1C0053_DEEPEST_SURVIVOR_SUPPORT_SCREEN_RESULT_20260719.md);
  authoritative JSON SHA-256
  `ab616087ec4aaf5862dbda0b0139146ea845b9a1cbe3cff0881e9a596e00f16a`, source
  freeze `0b89887f961f50fced087a987a6a2c4fb2122b18`.

## O1C-0054 — Global factor-bound screen

- **Recorded:** 2026-07-19T05:23:48+02:00.
- **Hypothesis:** an admissible sum of independent conditional factor maxima can
  retain O1C-0047's coordinated complete-state signal while a width-256 beam
  assigns all 128 key pairs from public data alone.
- **Protocol:** unconditional public-only Full256 first, before any reveal read;
  one consumed post-reveal W11 best-first diagnostic second. Frozen primary
  field, O1C-0048 pair order plus ascending completion pairs, no rotations,
  sweeps, tuning, native solver, fresh target, sibling, GPU or MPS work.
- **Result:** `GLOBAL_FACTOR_BOUND_NO_FULL256_W11_BOUND_FAILURE`. Full256 expands
  31,829 parents / 127,316 children, forward-scores and verifies 256 complete
  keys in 1.497645500 s and recovers none. After reveal, truth first leaves the
  beam at stage 5 on pair `(9,10)`; final top/minimum Hamming is `120/116`.
- **W11 localization:** the queue stops at 1,024 unscored pops, 2,020 child-bound
  evaluations and 14 forward evaluations with zero certified leaves. Exact W12
  truth rank 5 is therefore not preserved by the factorwise envelope.
- **State/resources:** 24,624 B logical mutable Full256 beam state; 1,026,688 B
  prefix history recorded separately as telemetry. Total 2.732336917 s wall,
  2.704926 s CPU, 88,031,232 B peak RSS and 270 forward/public verifications.
- **Decision:** refute the global separable factor-bound hypothesis. Independent
  local maxima are mutually incompatible and erase joint score geometry. Close
  without width, pair-order, cap or bound-scale tuning; exact learned-clause
  membership remains the active causal successor.
- **Artifacts:** [`result`](O1C0054_GLOBAL_FACTOR_BOUND_SCREEN_RESULT_20260719.md)
  and [`capsule`](../runs/20260719_052346_O1C-0054_global-factor-bound-screen-v1/RUN.md);
  authoritative JSON SHA-256
  `91aa42c2b036a5709f0f093e091c017c568aea459098dd238800cea87d9c32d5`, source
  freeze `2a63a749b5d0f92280a750ca79218ab841f2037a`.

## O1C-0055 — Exact learned-clause all-member credit screen

- **Recorded:** 2026-07-19T05:37:08+02:00.
- **Protocol:** one post-reveal primary W11 call at seed 0/512 conflicts. Exact
  minimized clause literals match only opposite-sign live decision owners;
  every distinct represented `(group,mask)` receives `-32`.
- **Result:** `UNKNOWN` at 512 conflicts, 513 decisions and 12,083,477
  propagations. All 512 clauses match; 43,483 literals yield 2,684 owner members,
  2,057 per-clause cell penalties and 65,824 units. Only 18 unique cells/seven
  groups differentiate, with 167 reorders and 502 repeated decisions.
- **Comparison:** O1C-0052 also touches 18 cells/seven groups, reorders 162 and
  uses 12,066,879 propagations. Exact membership is active, but all-member
  negative blame reproduces the diffuse prior boundary.
- **Consumed truth diagnostic:** true masks are penalized in 6/8 active groups,
  total `-17,568`, top/tied-top in 2/8 with ranks `1:2,2:1,3:2,4:3`. This is
  post-result localization, not fresh evidence.
- **Resources:** 4.951483084 s wall, 2.024342 s parent CPU, 2.654086 s child CPU,
  127,057,920 B peak and exactly 2,662 B state.
- **Decision:** refute all-member `-32` exact membership without tuning. Average
  fan-out is 5.24 owners/4.02 cells per conflict; select one deepest/current-
  level exact clause member next.
- **Artifacts:** [`result`](O1C0055_LEARNED_CLAUSE_CREDIT_SCREEN_RESULT_20260719.md)
  and [`capsule`](../runs/20260719_053703_O1C-0055_learned-clause-credit-screen-v1/RUN.md);
  authoritative JSON SHA-256
  `569b9770a690357b64dcfc44bce79b1a7eedb1f9688e5c03ad6f185b50adc9b8`, source
  freeze `8d7aa3d6053356ab7c5b95661df6548697505959`.

## APPLE-VIEW-0006 — Held-out streaming proof-credit transfer

- **Recorded:** 2026-07-19T03:11:06+02:00, isolated parallel track.
- **Hypothesis:** exact `c31` identities that repeatedly participate in BUILD
  conflict proofs transfer through a bounded target-independent addressed state
  into a better held-out candidate-filter order.
- **Protocol:** three BUILD targets × two wrong probes × three exact proof
  collectors emit 4,603 identity events into one 1,346-byte saturating
  frequency/recency state. State and order freeze before two disjoint held-out
  targets × two probes. Learned order is always scored first with zero held-out
  feedback; all truth controls run only after every wrong-candidate pass.
- **Result:** split. Raw scheduling loses: learned needs 317 switches on every
  probe, total `1,268`, versus final→early `1,031`. Exact reason-DAG certificates
  nevertheless transfer smaller on all four held-out cases:
  `248/248/251/250` versus best fixed structural `251/252/257/255`, aggregate
  `997` versus `1,015`; immediate-public aggregate is `1,013`. Every certificate
  replays exactly, all 24 strategy×probe runs reject and all truth controls
  complete.
- **Boundary:** this is held-out exact certificate compression, not an improved
  first-conflict scheduler, key generation, recovered key bit or entropy claim.
- **Resources:** 64.317798 s wall, 64.166830 s CPU, 62,226,432 B peak; one CPU
  process, no CDCL branching, sibling, network, MPS or GPU work.
- **Decision:** close unary frequency/recency scheduling. Preserve its proof-core
  transfer and test proof-edge/predecessor credit only if the next gate requires
  a raw held-out first-conflict win.
- **Artifact:** [`isolated result`](apple_view_6/apple_view_6_report.md), commit
  `6d12d6d`.

## APPLE-VIEW-0007 — Held-out proof-DAG predecessor transfer

- **Recorded:** 2026-07-19T03:37:23+02:00, isolated parallel track.
- **Hypothesis:** a bounded target-independent proof-DAG edge state plus one
  static strongest-predecessor reader preserves conflict-closing sequence that
  APPLE-VIEW-0006 unary membership discards.
- **Protocol:** the exact APPLE6 split, Full20 circuit, probes, collectors and
  fixed comparators are reused. Eighteen independently replayed BUILD proofs
  stream 4,189 canonical predecessor-edge events, 414 roots and 18 terminals
  into one 113,570-byte saturating state. State and order freeze before two
  disjoint EVAL targets × two probes; edge order is always scored first, with
  zero held-out updates or EVAL-visible design choice. The embedded APPLE6 unary
  order reproduces its exact hash and result.
- **Result:** hard raw gate fails: edge `1,340` > unary `1,268` > final→early
  `1,031` total first-conflict switches. Edge needs 335 switches on every probe.
  Its replayed certificate total `1,003` beats fixed `1,015` but loses unary
  `997`; certificate-only gain was prospectively forbidden from passing. All 28
  wrong strategy×probe passes reject exactly, every proof replays, every truth
  control completes and frozen state is unchanged.
- **Boundary:** refute H-APPLE-PROOF-EDGE-060 for this static/global
  strongest-predecessor reader. Identity 11 is a root in 12 BUILD proofs but has
  zero incident edge support and lands at position 335; a path without
  first-class start/context credit schedules its closing requirement last.
- **Resources:** 84.397724 s wall, 83.777569 s CPU, 68,321,280 B peak;
  113,570 B frozen state, one CPU process, no CDCL branching, sibling, network,
  MPS or GPU work.
- **Decision:** close without root-weight, threshold, traversal or EVAL rescue
  sweep. Preserve only the convergence with O1C-0051: static/global relations
  are context-blind, so the active successor is live action-conditioned credit
  H-CONTEXT-ACTION-CREDIT-061 rather than another Apple reader.
- **Artifact:** [`isolated result`](apple_view_7/apple_view_7_report.md), commit
  `87ead9e`.

## O1C-0056 — Exact learned-clause one-role credit screen

- **Recorded:** 2026-07-19T06:17:16+02:00.
- **Protocol:** one post-reveal primary W11 call at seed 0/512 conflicts. Each
  exact learned clause selects one opposite-sign live external-decision owner:
  greatest owner level, then group/member order. The selected action receives
  exactly one fixed `-32` update in the unchanged 2,662-byte state.
- **Result:** `CLAUSE_ROLE_CREDIT_MEMBERSHIP_NO_EXACT_W11_CLOSE`; `UNKNOWN` at
  512 conflicts/513 decisions/12,013,641 propagations. All 512 clauses have
  membership and select one current-level role. Of 2,662 matched members, 2,150
  are discarded; 508 clauses are multi-member, with zero below-current
  selections and zero deepest-level ties. The 512 updates total 16,384 units;
  18 persistent cells/seven groups differentiate, 142 actions reorder and
  502/513 decisions repeat.
- **Comparison:** versus O1C-0055 all-member credit, conflicts and decisions are
  unchanged, propagations fall by 69,836, reorderings by 25 and selected credit
  updates from 2,057 to 512. Native wall rises from 1.590827 s to 1.928103 s.
  Neither difference closes the exact gate.
- **Resources:** 5.687863334 s total wall, 1.928103 s native wall,
  127,057,920 B peak and exactly 2,662 B state; no tuning, promotion, rotation,
  sweep, fresh-target, sibling, MPS or GPU work.
- **Decision:** refute fixed negative deepest/current-owner `-32` only. Owner
  localization is exact and should not be revisited. A later causal successor
  must condition the retained role on outcome/utility because conflicts can be
  productive; immediate ROI moves to Apple joint-score and O1C-0057.
- **Artifacts:**
  [`result`](O1C0056_CLAUSE_ROLE_CREDIT_SCREEN_RESULT_20260719.md) and
  [`capsule`](../runs/20260719_061710_O1C-0056_clause-role-credit-screen-v1/RUN.md);
  authoritative JSON SHA-256
  `f2dda492e7c6af7d0cea12a9aeb33ae5da7b08d8e4e352c18b695f9683a48740`,
  manifest `ba7f92ebd96cc7879b2d3321be905ffb5b0ec52563fa0dcda08c821066f1dfac`,
  source freeze `9de519a973595b76f8a2ef512a5edc518499901a`.

## O1C-0057 — Multi-block parent-criticality rank transfer

- **Started:** 2026-07-19T06:27:56+02:00.
- **Recorded:** 2026-07-19T06:29:32+02:00.
- **Hypothesis:** the unchanged transferred O1C-0043 parent-criticality reader
  compounds rather than dilutes its complete-key signal when additional
  attacker-visible blocks from the same fresh key and nonce enter the stream.
- **Protocol:** one fresh uniform Full-256 target; eight contiguous public blocks;
  one shared panel of 4,096 decoys plus hidden truth; primary, key-rotated and
  clause-rotated scores at prefixes 1/2/4/8. Reader state, decoy calibration and
  all rank inputs freeze before one reveal; no refit, reweighting or sign choice.
- **Result:** `MULTIBLOCK_PARENT_CRITICALITY_COMPOUNDING_TRANSFER`. Primary truth
  ranks are `8/7/1/1` of 4,097. At prefix 8, key and clause rotations rank
  `3581/4037`; truth z is `+5.57888245`, and both the threshold and strict
  control-margin gates pass. Mean primary cross-block decoy correlation is
  `0.11818565`.
- **Boundary:** prefix-8 rank 1 is `12.000352` bits of discrimination inside the
  supplied panel. Candidate generation happened upstream. This is a transferred
  full-key scorer/orderer, not free key generation, `2^256` enumeration or exact
  recovery.
- **Resources:** 95.894570834 s elapsed, 193,544,192 B peak RSS, 32,776 candidate
  forward evaluations, 4,096 native probe branches, one fresh target/entropy/
  reveal; zero solver calls, sibling reads/writes, MPS or GPU work.
- **Decision:** support H-MULTIBLOCK-PARENT-CRITICALITY-067. Freeze the prefix-8
  scorer and integrate it into attacker-generated partial-assignment or bounded
  exact-search ordering. Do not treat a larger supplied decoy panel as the next
  scientific advance.
- **Artifacts:**
  [`result`](O1C0057_MULTIBLOCK_PARENT_CRITICALITY_RANK_RESULT_20260719.md) and
  [`capsule`](../runs/20260719_062932_O1C-0057_multiblock-parent-criticality-rank-v1/RUN.md);
  authoritative JSON SHA-256
  `bae7899503ec0d349dd7da51ebaca3cef2982c4e53d1ca560adcffe7bff47971`,
  manifest `008b985868b18160711be70cc9fa2a7697d5888c5515702caef72228ea2a742e`,
  source freeze `ba44cbd064499b68e665aade71d15dca0c672b71`.

## O1C-0058 — Multi-block bit-vault gradient

- **Started:** 2026-07-19T07:06:54+02:00.
- **Recorded:** 2026-07-19T07:08:33+02:00; terminal serialization recovered at
  2026-07-19T07:39:33+02:00 without added science.
- **Protocol:** one fresh uniform Full-256 target and eight contiguous public
  blocks. The unchanged primary scorer selects one attended base from 4,096
  decoys; the same base plus all 256 one-bit neighbors is scored per block in
  primary/key-rotated/clause-rotated arms. Signed finite differences stream into
  three 256-cell `float64` vaults; all prefix-1/2/4/8 outputs and 13 public
  candidate checks freeze before one reveal.
- **Result:** `MULTIBLOCK_BIT_VAULT_NO_DIRECTIONAL_TRANSFER`. The attended base
  and primary prefix-8 candidate both have `127/256` correct bits: improvement
  `0`, longest correct confidence prefix `0`. Prefix-8 controls have `127` and
  `128` correct bits. Every candidate matches `0/8` public blocks; all exact and
  partial gates fail.
- **Resources:** 99.07695375000185 s elapsed, 211,124,224 B peak, 34,824
  candidate forwards, 112 direct ChaCha block evaluations, 2,048 B primary and
  6,144 B all-arm live state. Original parent/child CPU seconds are unavailable
  and remain `null`.
- **Decision:** close attended-best-decoy plus positive one-bit delta vault.
  Preserve O1C-0057 as a complete-key scorer; move directly to O1C-0059 exact
  partial-assignment joint scoring. Test APPLE8 as the matched augmentation at
  identical potential/threshold/budget by making the logically redundant public
  P20 units plus `P_b = P_0 + (Z_b - Z_0)` key-lane consequences explicit.
  APPLE8 adds no information or solutions; it must improve propagation/pruning.
  Crowd/elite consensus was not part of O1C-0058; a separate cheap scratch was
  control-negative only.
- **Recovery:** terminal JSON serialization failed on a NumPy `int64` only.
  Recovery source `d9d1a851f873ecd0afc33236adac52b8866ccb1f` validated the
  already-frozen science from source `09cc48b9d61b4cccbeaa7cf038404ac4f2a3b15a`
  with zero added entropy, reveal or scoring.
- **Artifacts:**
  [`result`](O1C0058_MULTIBLOCK_BIT_VAULT_GRADIENT_RESULT_20260719.md) and
  [`capsule`](../runs/20260719_070833_O1C-0058_multiblock-bit-vault-gradient-v1/RUN.md);
  authoritative JSON SHA-256
  `1ff36f9479b397f50c9421a7c0ba406df308ab8c9989d2e039e0874a1acbcb64`,
  manifest `9367abdae4b8514eec3c9518c8cfc54f9b8a34ce45ec4ebc5c009280507b3b06`.

## O1C-0059 / O1C-0060 — Joint-sieve commissioning failures

- **Recorded:** 2026-07-19T08:36:17+02:00 and
  2026-07-19T09:03:30+02:00.
- **Result:** both attempts are operational failures and carry no science claim.
  O1C-0059 preserved a native result but failed its post-native resource-ledger
  validation after truth access; O1C-0060 then failed the repaired incremental
  conflict ledger before any truth read. Each consumed exactly one native call
  and neither was retried.
- **Decision:** keep the artifacts as immutable commissioning breadcrumbs only.
  O1C-0061 is the first validated joint-sieve science result.
- **Artifacts:**
  [`O1C-0059`](O1C0059_MULTIBLOCK_JOINT_SCORE_SIEVE_RESULT_20260719.json) and
  [`O1C-0060`](O1C0060_MULTIBLOCK_JOINT_SCORE_SIEVE_CONFLICT_LEDGER_RESULT_20260719.json).

## O1C-0061 / APPLE-VIEW-0008 — Exact Full-256 joint pruning

- **Recorded:** 2026-07-19T09:19:54+02:00 and
  2026-07-19T09:55:09+02:00.
- **Baseline:** O1C-0061 validates the exact eight-block shared-key joint bound.
  It drops the admissible bound materially before any complete model, but emits
  zero safe trail cuts at requested 512/billed 513 conflicts and returns no key.
- **Matched result:** APPLE-VIEW-0008 adds only logically redundant public P20
  and exact cross-block key-lane consequences at the same target, potential,
  threshold and work. Minimum upper bound falls
  `24.7944466611→13.1979307788`, below threshold `14.6061787979`; safe trail
  cuts rise `0→6`, decisions fall `9166→4471`, and propagations fall
  `1227877→1178185`.
- **Classification:**
  `APPLE_VIEW_0008_STRICT_INCREMENTAL_EFFECT_NO_RECOVERY`. This is certified
  Full-256 search-branch removal, not key recovery; no complete key was returned
  and the Apple arm did not read truth.
- **Artifacts:**
  [`baseline`](O1C0061_MULTIBLOCK_JOINT_SCORE_SIEVE_SOFT_STOP_RESULT_20260719.json)
  and [`matched result`](apple_view_8/apple_view_8_matched_result.json).

## O1C-0062 / O1C-0063 / O1C-0064 — Exact 4K scaling boundary

- **Recorded:** 2026-07-19T10:25:19+02:00 through
  2026-07-19T11:45:27+02:00.
- **Result:** no member of this chain produced a science result and none was
  retried. O1C-0062 exposed a callback/teardown defect. O1C-0063 repaired the
  lifecycle and stayed in the real path for `17.763142674 s`, but its old
  wrapper lost the terminating cause. O1C-0064 preserves that cause exactly:
  `watchdog_memory` after `29.804627625 s`, with `1,040,285,696 B` observed at
  the guarded `1,040,187,392 B` threshold.
- **Boundary:** one native call per attempt; O1C-0064 returns no native result or
  key and reads no truth. Pure resource enlargement is now closed as the next
  move.
- **Decision:** reduce or delay the measured memory growth using the distinct
  APPLE-VIEW-0009 grouped bound before paying for another promotion.
- **Artifacts:**
  [`O1C-0062`](O1C0062_APPLE8_CROSSBLOCK_SIEVE_4K_RESULT_20260719.json),
  [`O1C-0063 diagnosis`](O1C0063_RESOURCE_WATCHDOG_DIAGNOSIS_20260719.md), and
  [`O1C-0064`](O1C0064_APPLE8_CROSSBLOCK_SIEVE_4K_RESOURCE_FIX_RESULT_20260719.json).

## APPLE-VIEW-0009 — Exact score-aware width-6 grouping

- **Recorded:** 2026-07-19T11:23:00+02:00.
- **Result:** `PUBLIC_EXACT_GROUPED_BOUND_STRICTLY_DOMINATES_PAIR_RELAXATION_NO_SEARCH_CLAIM`.
  The deterministic width-6 partition lowers the safe public root upper bound
  `269.7472723039718→262.68644197084643`, while groups fall `3805→2885`, rows
  `265256→176912`, and estimated indexed state
  `2510008→1710776 B`.
- **Validation:** exhaustive synthetic partial/completion safety, 10,000
  deterministic exact outward-sum checks and all focused tests pass. The build
  uses zero solver, truth or fresh-target calls.
- **Boundary:** this is a positive exact bound mechanism, not yet measured
  pruning or recovery.
- **Decision:** compile frozen grouping hash
  `3da85bae132d829252a68f0e3fd99220ea7d1ef365042806af810ff02f75f636`
  into the native Full-256 sieve and test it once against the O1C-0064 boundary.
- **Artifact:** authoritative
  [`result`](APPLE_VIEW_0009_EXACT_GROUPED_BOUND_RESULT_20260719.json).

## O1C-0065 — Matched exact width-6 native efficacy

- **Started:** 2026-07-19T12:36:01+02:00.
- **Recorded:** 2026-07-19T12:36:04+02:00.
- **Source commit:** `8f231003161c17608c3daba63da2a6ccf4d567da`.
- **Protocol:** one frozen native call on the exact APPLE-VIEW-0008 Full-256
  target with unchanged CNF, potential, threshold, seed and requested
  512/billed 513 conflicts. The sole science change is grouping hash
  `3da85bae132d829252a68f0e3fd99220ea7d1ef365042806af810ff02f75f636`.
- **Result:** `O1C65_GROUPED_WIDTH6_EFFICACY_RETAINED`. Root UB improves
  `292.30611344510277→262.68644197084643`, minimum observed UB improves
  `13.197930778790159→12.934208247009447`, derived cache shrinks
  `60,456→23,080 B`, and bounded persistent logical state shrinks
  `99,227→61,851 B`. Emitted cuts remain `6→6`; decisions remain
  `4,471→4,471`; propagations remain `1,178,185→1,178,185`. Status is
  `UNKNOWN`; no key is returned and truth is not read.
- **Resources:** `3.327685084 s` elapsed, `1.985387 s` child CPU,
  `0.346329 s` native wall, `386,547,712 B` native peak RSS, one native call,
  zero fresh targets/reveals/refits/MPS/GPU. Time and RSS are contextual.
- **Decision:** standalone width-6 tightening is terminal at matched 512 work.
  Do not retry it or promote it directly to the known 4K memory wall. The next
  distinct mechanism is a fixed bounded episode stream that persists only
  canonical threshold-certified emitted clauses for the identically bound
  `CNF ∧ score_potential >= threshold` problem and destroys solver memory after
  every episode.
- **Artifact:** authoritative
  [`result`](O1C0065_APPLE8_WIDTH6_GROUPED_SIEVE_RESULT_20260719.json), SHA-256
  `04c2e0d32fff6e7a8f685880049579c90c4a399b14518ee3e650b15d01834bfb`;
  ignored sealed capsule
  `runs/20260719_123602_O1C-0065_apple8-width6-grouped-sieve-v1`, manifest
  `0450c64d60ed84f10e76248367318e363131194cebe93d079bef4b8679e407f4`.

## O1C-0066 — APPLE8 episodic score-threshold no-good vault

- **Supersession:** this completed attempt consumes the earlier O1C-0064,
  APPLE-VIEW-0009 and O1C-0065 forward decisions to build/run the episodic vault;
  their timestamped text remains immutable and is no longer the current action.
- **Started:** 2026-07-19T13:58:54+02:00.
- **Recorded:** 2026-07-19T13:59:02+02:00.
- **Source commit:** `881c461c79dc1fd9aa51aed89d3f2a8b298c2284`.
- **Protocol:** a fixed bounded stream of fresh native APPLE8 subprocesses on
  the unchanged Full-256 target, CNF, potential, width-6 grouping, threshold,
  seed and requested 512 conflicts per episode. Only canonical fully emitted
  clauses valid for `CNF ∧ score_potential >= threshold` persist; ordinary
  solver learning, assignments, trail and group cache do not. A written intent
  consumes its ordinal and no ordinal is retriable.
- **Positive bounded efficacy:** episode 0 completes and grows the vault
  `0→6` clauses, `17,804` literals and `71,431 B`. Episode 1 completes and grows
  it `6→12` clauses with `+6` novel clauses, `+17,257` novel literals and one
  duplicate, ending at `140,483 B`. At the same requested 512 conflicts, the
  carried vault changes decisions `4,471→4,666`, propagations
  `1,178,185→1,230,568`, and minimum UB
  `12.934208247009447→7.973483108047071`; peak RSS changes only
  `388,907,008→389,234,688 B`.
- **Terminal:** episode 2 consumes its intent/call and stops in
  `adapter_validation` on `joint-score-sieve-v5 soft conflict ledger differs`.
  Classification is `EPISODIC_VAULT_OPERATIONAL_TERMINAL`. This is an adapter
  contract stop after two positive bounded episodes, not a scientific negative,
  recovery or authorization to retry/replay. Truth key bytes remain unread and
  no key is returned. Native conflict identities are constructed exactly, so
  the generic v8/v5 failure can only mean episode-2 `solve_conflicts >= 514` and
  overshoot `>= 2`, beyond the arbitrary frozen `+1`/513 cap. The exact value is
  lost because the adapter failure path retained null stdout.
- **Resources:** three native call intents/calls, two completed episodes,
  requested `1,536` and billed `1,025` conflicts, `0.716103 s` native wall,
  `8.157195 s` elapsed and maximum episode peak RSS `389,234,688 B`; zero fresh
  targets, entropy/reveal calls, refits, sibling writes, MPS or GPU work.
- **Decision:** preserve the final 12-clause vault. Target-free fixtures must
  preserve raw native stdout and replace the unsupported `+1`/513 cap with an
  honest actual-observed soft-limit ledger plus hard process/time/RSS caps while retaining exact algebraic
  ledger consistency. Freeze those adapter gates before a distinct non-replay
  O1C-0067 continues; no consumed O1C-0066 ordinal is run again.
- **Artifacts:** authoritative
  [`result`](O1C0066_APPLE8_EPISODIC_VAULT_RESULT_20260719.json), SHA-256
  `b8b61d0f2feaa9c544c1fef30cba4c7cead90c390a577a444405d45ad85000e3`;
  sealed capsule
  [`runs/20260719_135856_O1C-0066_apple8-episodic-vault-v1`](../runs/20260719_135856_O1C-0066_apple8-episodic-vault-v1/RUN.md), manifest
  `b0022997a1c316e71131268b3e3e5524aee4de8167013463f845646c8982d562`.

## O1C-0067 — APPLE8 sealed-vault continuation

- **Supersession:** this completed attempt consumes O1C-0066's forward decision
  after the target-free adapter-v9 gates passed. It is a distinct lineage call,
  not a replay of O1C-0066's consumed ordinal 2.
- **Started:** 2026-07-19T15:25:59+02:00.
- **Recorded:** 2026-07-19T15:26:04+02:00.
- **Source commit:** `865634458ef3f5b01a5881208eb028404b96f135`.
- **Protocol:** exactly one fresh native subprocess from the sealed 12-clause
  vault, using local ordinal `0`, lineage ordinal `3`, the unchanged reader,
  seed and requested 512-conflict soft horizon. Actual solve conflicts are
  billed without a numeric overshoot ceiling; process/time/RSS limits remain
  hard.
- **Result:** `EPISODIC_VAULT_SATURATED_NO_GAIN`. The call observes and bills
  `514` conflicts (`+2`) and fully emits one `2,951`-literal clause, SHA-256
  `b5da89ef9791d65487e214da71e4f36b0600ceea033cc1917c4ba9f392f89c84`.
  It is an input duplicate matching vault index `7` (zero-based; the eighth
  stored clause). Novel
  clauses/literals are `0/0`; input and output remain `12` clauses, `35,061`
  literals and `140,483 B`.
- **Search and resources:** decisions `4,517` and propagations `1,192,529` are
  `-149/-38,039` versus O1C-0066's last completed episode. Minimum UB is
  `9.111031965569408`, `+1.1375488575223374` versus the parent. Runner elapsed
  time is `4.553662 s`; native wall/CPU are `0.333463/0.921060 s`, and native
  peak RSS is `392,609,792 B`. One native call; zero key/truth/reveal/fresh
  target/entropy/refit/MPS/GPU work.
- **Decision:** the exact reader/seed/horizon is at a clause-generation fixed
  point. The retained vault still lowers matched search work, but this call adds
  no novelty, bound frontier or recovery. Do not replay it or blind-scale the
  same horizon. Test a complementary phase reader (`forcephase=true`,
  `phase=false`) or another explicitly precommitted reader operator next.
- **Artifacts:** authoritative
  [`result`](O1C0067_APPLE8_EPISODIC_VAULT_CONTINUATION_RESULT_20260719.json),
  SHA-256
  `c01ffe69198e997c6d3798e0b9f3190065bd7b58ec3ab1ba67a66a7ccd799f1f`;
  concise [`interpretation`](O1C0067_APPLE8_EPISODIC_VAULT_CONTINUATION_INTERPRETATION_20260719.md);
  sealed
  [`capsule`](../runs/20260719_152601_O1C-0067_apple8-vault-continuation-v1/RUN.md),
  manifest SHA-256
  `2562db062186fb5168e66c69943af83ba19a151bdc17489111a15dbb114f9341`.

## O1C-0068 — APPLE8 complementary phase reader

- **Supersession:** this completed attempt consumes O1C-0067's forward decision
  after the target-free complementary-reader gates passed. It is a distinct
  lineage call, not a replay of lineage ordinal `3`.
- **Started:** 2026-07-19T16:18:37+02:00.
- **Recorded:** 2026-07-19T16:18:58+02:00.
- **Source commit:** `8446414d73e871de829c182ca4cd5b500e4d9d14`.
- **Protocol:** exactly one fresh native subprocess from the sealed 12-clause
  vault, using local ordinal `0`, lineage ordinal `4`, forced initial phase `0`
  (`forcephase=true`, `phase=false`), seed `0` and requested 512-conflict soft
  horizon. Target, Full-256 CNF, potential, width-6 grouping, threshold and
  accounting are otherwise unchanged. Actual solve conflicts are billed without
  a numeric overshoot ceiling; process/time/RSS limits remain hard.
- **Result:** `EPISODIC_VAULT_COMPLEMENTARY_PHASE_GAIN`. Requested, actual and
  billed conflicts are exactly `512/512/512`, with zero overshoot. The call fully
  emits `195` clauses / `579,526` literals: `190` clauses / `564,667` literals
  are novel, `5` clauses are duplicates and `0` clauses remain pending. The
  vault grows `12→202` clauses, `35,061→599,728` literals and
  `140,483→2,399,911 B`; its final SHA-256 is
  `cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858`.
- **Search and resources:** decisions are `1,330`, propagations `31,944,523`,
  minimum UB `12.8607806294803` and root UB `262.68644197084643`. Runner elapsed
  time is `21.9159 s`; native wall/CPU are `5.331635/5.925889 s`, and native
  peak RSS is `397,099,008 B`. Native status is `UNKNOWN`; one native call; no
  model or key, no truth read, and zero reveal/entropy/fresh-target/refit/MPS/GPU
  work.
- **Claim boundary:** the complementary reader unlocks a large distinct exact
  score-threshold exclusion population, which is a meaningful mechanism
  frontier. It is not key recovery, a SAT model, UNSAT, global threshold-region
  exhaustion or authorization to replay/sweep. The concise interpretation
  formally audits the frozen threshold and explains why O1C-0066 episode 1's
  minimum UB is a visited-partial-trail statistic, not a population score,
  global maximum or exhaustion certificate.
- **Decision:** preserve the sealed 202-clause vault. The precommitted successor
  was exactly one explicit O1C-0069 forced-phase-1 composition call from that
  vault at the same seed `0` and requested `512` conflicts, a distinct operator
  rather than replay or phase sweep. If the
  observed O1C-0068 195-clause/579,526-literal envelope repeats and every clause
  is novel, the vault would reach `397` clauses, `1,179,254` literals and
  `4,718,795 B`, below the frozen caps. This is a capacity-planning scenario,
  not a formal maximum for a 512-conflict call; the hard native capacity guard
  remains fail-closed. O1C-0069 later executes this sole decision and returns
  zero novelty with exact O1C-0067 phase-1 trace identity, closing passive
  composition and selecting a vault-conditioned active phase field next.
- **Artifacts:** authoritative
  [`result`](O1C0068_APPLE8_COMPLEMENTARY_PHASE_RESULT_20260719.json), SHA-256
  `d494887d2be96516211acf09ff8852a88a44576044723223b9057942fd7aea80`;
  concise
  [`interpretation`](O1C0068_APPLE8_COMPLEMENTARY_PHASE_INTERPRETATION_20260719.md);
  sealed
  [`capsule`](../runs/20260719_161838_O1C-0068_apple8-complementary-phase-v1/RUN.md),
  manifest SHA-256
  `dd0236774c1352238cce86458a8f01380aa32dc538dbe80a3c1744b0f126a745`.

## O1C-0069 — APPLE8 alternating-reader composition

- **Supersession:** this completed attempt consumes the sole O1C-0068 forward
  decision after all target-free reader, identity and capacity gates passed. It
  is a distinct lineage call, not a replay of lineage ordinal `4`.
- **Started:** 2026-07-19T17:08:24+02:00.
- **Recorded:** 2026-07-19T17:08:40+02:00.
- **Source commit:** `d6dfc06f3e7d6dfcc29d696829927b132bad23aa`.
- **Protocol:** exactly one fresh native subprocess imports the sealed
  202-clause O1C-0068 vault, uses local ordinal `0`, lineage ordinal `5`,
  explicit forced phase `1`, seed `0` and requested 512-conflict soft horizon.
  Target, Full-256 CNF, potential, width-6 grouping, threshold and actual-work
  accounting remain unchanged. No retry is authorized.
- **Result:** `EPISODIC_VAULT_ALTERNATING_READER_NO_GAIN`. Requested, actual
  and billed conflicts are `512/514/514`. The call fully emits one
  `2,951`-literal clause, SHA-256
  `b5da89ef9791d65487e214da71e4f36b0600ceea033cc1917c4ba9f392f89c84`;
  it is the input duplicate at zero-based vault index `7` (eighth clause), so
  novel clauses/literals are `0/0`. Input and
  output are byte-identical at `202` clauses / `599,728` literals /
  `2,399,911 B`, SHA-256
  `cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858`.
- **Exact fixed point:** conflicts, decisions (`4,517`), propagations
  (`1,192,529`), minimum/root upper bounds
  (`9.111031965569408/262.68644197084643`), emitted clause, terminal assignment
  hash and native trace SHA-256
  `676386a030ce3dcfea0fccdaea60d482a2da8de4992102669585fff3fb896a91`
  all exactly equal O1C-0067's phase-1 trajectory. The additional 190 phase-0
  clauses do not perturb this bounded passive-reader path.
- **Resources:** runner elapsed `16.869109082996147 s`; native wall/CPU
  `0.367456/1.080018 s`; native peak RSS `398,032,896 B`; runner peak RSS
  `323,895,296 B`; one native call and zero key/truth/reveal/fresh-target/
  entropy/refit/MPS/GPU work. Known completed lineage billing is `2,565`; exact
  total remains unavailable because O1C-0066 ordinal 2 is unbilled.
- **Decision:** refute only one-step passive alternating-reader composition at
  this exact reader/seed/horizon. Do not replay ordinal `5`, run a second
  alternation, sweep phase/horizon or scale RAM. Derive a target-free bounded
  vault-conditioned phase field and test whether stored evidence can actively
  steer decisions before authorizing any O1C-0070 Full-256 call.
- **Artifacts:** authoritative
  [`result`](O1C0069_APPLE8_ALTERNATING_READER_RESULT_20260719.json), SHA-256
  `43512370d7243d57bb3ffaed445ee9196315e350d3ee1169ee0c0d8ad94ba89b`;
  concise
  [`interpretation`](O1C0069_APPLE8_ALTERNATING_READER_INTERPRETATION_20260719.md);
  sealed
  [`capsule`](../runs/20260719_170824_O1C-0069_apple8-alternating-reader-v1/RUN.md),
  manifest SHA-256
  `2a78e568f0be7eafad4d117cd84aeadd0d495d19296d8ba85676496219377cb8`.

## O1C-0070 — APPLE8 vault-conditioned phase reader

- **Supersession:** this completed attempt consumes O1C-0069's sole forward
  decision after the target-free field, native, adapter, public consequence,
  source and capacity gates passed. It is a distinct lineage call, not a replay
  of ordinal `5`.
- **Started:** 2026-07-19T18:10:48+02:00.
- **Recorded:** 2026-07-19T18:11:03+02:00.
- **Source commit:** `c5ad5c40f0ac84f65d281cf2366d2ca6b6c49a52`.
- **Protocol:** exactly one fresh native subprocess imports the sealed 202-clause
  vault, uses local ordinal `0`, lineage ordinal `6`, seed `0` and the requested
  512-conflict soft horizon. The exact O1C-0068 190-clause suffix supplies a
  `139` positive / `116` negative / one fallback phase field; native applies
  `255` per-variable phase calls. Target, CNF, potential, grouping, threshold
  and actual-work billing are unchanged. The reader changes polarity only, not
  variable order or confidence magnitude. No retry is authorized.
- **Result:** `EPISODIC_VAULT_ACTIVE_PHASE_READER_NO_GAIN`. Requested, actual
  and billed conflicts are `512/514/514`. The call emits `0` eligible clauses:
  `0` novel, `0` duplicate and `0` pending. No model or key is returned. Input
  and output remain byte-identical at `202` clauses / `599,728` literals /
  `2,399,911 B`, SHA-256
  `cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858`.
- **Active-not-gainful comparison:** versus O1C-0069, decisions fall
  `4,517→2,297`, propagations `1,192,529→1,169,826`, and minimum UB rises
  `9.111031965569408→18.846601115977638`; root UB remains
  `262.68644197084643`. Native trace changes from `676386a030ce3dcf…` to
  `5c5fb773ac889d46bc26c2742dccfe4ca6559f7dd5f02d5dd0f83b1760aa712f`.
  This proves active steering into a higher-minimum-UB visited population, but
  the precommitted key-or-novel-clause gate fails exactly.
- **Threshold clarification:** `tau=14.606178797892962` and minimum UB use the
  same compiled metric/direction but different populations/statistics. The
  `7.973483108047071` comparison belongs to O1C-0066 episode 1, not O1C-0068;
  strict `U(a)<tau` is only a safe local prune for the visited trail `a`.
- **Resources and lineage:** runner elapsed `16.31510445800086 s`; native wall/
  CPU `0.316808/1.023602 s`; native peak RSS `406,568,960 B`; runner peak RSS
  `326,664,192 B`. Only ordinal `6` is consumed. Known completed lineage billing
  becomes `3,079`; the full actual total remains `null` because failed ordinal
  `2` is unbilled. One native call and zero key/truth/reveal/fresh-target/
  entropy/refit/MPS/GPU work.
- **Decision:** refute `H-VAULT-CONDITIONED-PHASE-074` specifically for
  phase-only gain while retaining the active-not-inert trace. Do not replay
  ordinal `6`, issue a second phase call, sweep phase/horizon or raise RAM.
  Separately precommit a confidence-ranked `cb_decide`/variable-order operator
  with a new target-free specification and attempt identity.
- **Artifacts:** authoritative
  [`result`](O1C0070_APPLE8_VAULT_PHASE_READER_RESULT_20260719.json), SHA-256
  `778d2b91935ff2ae663ea706e5b7b66c8cfed2f02007ba8359e8c1cb7ff45cd7`;
  concise
  [`interpretation`](O1C0070_APPLE8_VAULT_PHASE_READER_INTERPRETATION_20260719.md);
  sealed
  [`capsule`](../runs/20260719_181048_O1C-0070_apple8-vault-phase-reader-v1/RUN.md),
  manifest SHA-256
  `ca5e0dfc724dc541b5311e2fc1453fc017f4ccd562d510aad341a53188d194c2`.

## O1C-0071 — APPLE8 vault-ranked decision

- **Supersession:** this completed attempt consumes O1C-0070's sole forward
  decision after the target-free rank, callback, public consequence, source and
  capacity gates passed. It is a distinct lineage call, not a replay of ordinal
  `6` or another phase call.
- **Started:** 2026-07-19T19:27:38+02:00.
- **Recorded:** 2026-07-19T19:28:15+02:00.
- **Source commit:** `66400bc6cc76653fb0a4b2c5bd64af498f4a49d3`.
- **Protocol:** exactly one fresh native subprocess imports the sealed 202-clause
  vault, uses local ordinal `0`, lineage ordinal `7`, seed `0` and requested
  512-conflict soft horizon. The reader orders the 255 nonzero-delta key
  variables by descending absolute vault vote, descending singleton grouped-gap
  and ascending variable, with frozen vote sign. Variable `241` is omitted.
  Native uses `cb_decide`; phase calls and rank sweeps are both zero. No retry is
  authorized.
- **Result:** `EPISODIC_VAULT_ACTIVE_RANKED_DECISION_NO_GAIN`. Requested and
  observed/billed conflicts are `512/513`; native status is `0`. The call emits
  `0` eligible/novel/duplicate clauses and returns no model or key. Input/output
  remain byte-identical at `202` clauses / `599,728` literals / `2,399,911 B`,
  SHA-256
  `cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858`.
- **Active callback:** `763` `cb_decide` calls comprise `499` nonzero and `264`
  zero/delegate returns, `255` unique variables and `244` redecisions. First
  fallback is call `256`. Versus O1C-0070, decisions fall `2,297→763`
  (`-1,534`, `-66.78%`), propagations rise
  `1,169,826→91,260,183` (`+90,090,357`, `78.01x`), and minimum UB rises
  `18.846601115977638→19.297551436176224` (`+0.45095`). Root UB remains
  `262.68644197084643`.
- **Tail-cascade diagnosis:** ranks `1..248` form a callback-visible stable
  prefix and are never returned twice.
  Ranks `249..255` incur `1/3/7/15/31/62/125` extra returns, summing to the
  exact `244` redecisions. Static same-sign reassertion after backtrack builds a
  truncated binary counter and a propagation furnace instead of opening a new
  causal direction. Native wall rises `0.316808→14.818087 s` (`46.77x`) versus
  O1C-0070; lower decisions are not gain.
- **Threshold clarification:** `tau=14.606178797892962` and minimum UB use the
  same compiled metric/direction but different populations/statistics. The
  `7.973483108047071` comparison belongs to O1C-0066 episode 1, not O1C-0068;
  strict `U(a)<tau` is only a safe local prune for the visited trail `a`.
- **Resources and lineage:** runner elapsed `36.94019316699996 s`; native wall/
  CPU `14.818087/15.388436 s`; native peak RSS `405,553,152 B`; runner peak RSS
  `283,738,112 B`. Only ordinal `7` is consumed. Known completed lineage billing
  becomes `3,592`; the full actual total remains `null` because failed ordinal
  `2` is unbilled. One native call and zero key/truth/reveal/fresh-target/
  entropy/refit/MPS/GPU work.
- **Decision:** refute `H-CONFIDENCE-RANKED-DECIDE-075` for static same-sign
  reassertion while retaining the strong-order-control evidence. Do not rerun
  O1C-0071, replay ordinal `7`, sweep rank/phase/horizon or raise RAM. Next
  precommit a backtrack-release/one-shot causal reader that injects every ranked
  bit at most once and permanently delegates it after backtrack.
- **Artifacts:** authoritative
  [`result`](O1C0071_APPLE8_VAULT_RANKED_DECISION_RESULT_20260719.json), SHA-256
  `84ffbe35ae83266dd4993ad70b6dc988f4a13a8595861c23f36f0d610334cb41`;
  concise
  [`interpretation`](O1C0071_APPLE8_VAULT_RANKED_DECISION_INTERPRETATION_20260719.md);
  machine-readable
  [`tail analysis`](O1C0071_RANKED_DECISION_TAIL_CASCADE_ANALYSIS_20260719.json),
  SHA-256
  `8172db9a9d8265f61a1b1191682db06f879939d99271b0f5ba96108f7ccb8259`;
  sealed
  [`capsule`](../runs/20260719_192742_O1C-0071_apple8-vault-ranked-decision-v1/RUN.md),
  artifact-manifest SHA-256
  `c7bbbd9d7ad0d37b80b956a3ad8141254a460ddf763ae84109a067e0343294d9`.

## O1C-0072 — APPLE8 vault backtrack release

- **Supersession:** this completed attempt consumes O1C-0071's sole authorized
  successor after the monotone-cursor, consume-once, release, target-free
  sequence, source and capacity gates passed. It is a distinct mechanism and
  lineage call, not an O1C-0071 retry or ordinal-7 replay.
- **Started:** 2026-07-19T20:44:18+02:00.
- **Recorded:** 2026-07-19T20:44:41+02:00.
- **Source commit:** `bf1ffaad30ac276c2fcc3b332207c5933bf96443`.
- **Protocol:** exactly one fresh native subprocess imports the unchanged sealed
  202-clause vault and immutable 255-variable signed rank, uses local ordinal
  `0`, lineage ordinal `8`, seed `0` and requested 512-conflict soft horizon.
  The cursor consumes every rank row permanently before acting, returns each
  ranked literal at most once, consumes rows already assigned before their
  opportunity, never rewinds after backtrack and delegates with zero after rank
  exhaustion. Phase calls, rank sweeps and retries are zero.
- **Result:**
  `EPISODIC_VAULT_BACKTRACK_RELEASE_MECHANISM_WORK_GAIN_NO_RECOVERY`.
  Requested, observed and billed conflicts are `512/512/512`; native status is
  `0`. The call emits `0` eligible/novel/duplicate clauses and returns no model
  or key. Input/output remain byte-identical at `202` clauses / `599,728`
  literals / `2,399,911 B`, SHA-256
  `cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858`.
- **Validated release mechanism:** `1,155` `cb_decide` calls comprise `255`
  nonzero once-returns followed by `900` zero/delegate returns; first fallback is
  call `256`. All `255` guided literals are later observed released, every rank
  row is consumed, and redecisions/phase calls are exactly `0`. The bounded live
  guidance state is `2,140 B`.
- **Matched-work gain:** versus O1C-0071, propagations fall
  `91,260,183→5,763,035` (`-85,497,148`), an exact
  `15.835437924635196x` ratio or `93.685049919%` reduction. Decisions rise
  `763→1,155` (`+392`), and minimum UB rises
  `19.297551436176224→19.57599384995442` (`+0.278442413778194`); root UB
  remains `262.68644197084643`. The predeclared secondary mechanism/work gate
  passes because repeated-ranked-bit telemetry is zero and propagation work is
  below half the parent. This validates furnace removal, not key recovery,
  entropy reduction or threshold-region exhaustion.
- **Threshold boundary retained:** `tau=14.606178797892962` and minimum UB use
  the same compiled score metric and retained direction but different
  populations/statistics. O1C-0066 episode 1's `7.973483108047071` is not an
  O1C-0068 or O1C-0072 result. For a visited trail `a`, strict
  `U(a)<tau` safely excludes only its completions from the retained
  `S(k)>=tau` region; root UB remains above threshold, so no global prune or
  UNSAT follows.
- **Resources and lineage:** end-to-end elapsed `23.25862954198965 s`; native
  wall/CPU `1.193428/1.858495 s`; native peak RSS `395,214,848 B`; runner peak
  RSS `286,539,776 B`. Only ordinal `8` is consumed. Known completed lineage
  billing becomes `4,104`; the full actual total remains `null` because failed
  ordinal `2` is unbilled. One native call and zero key/truth/reveal/
  fresh-target/entropy/refit/MPS/GPU work.
- **Decision:** support `H-BACKTRACK-RELEASE-076` at its mechanism/work level.
  Preserve the one-shot release primitive, but do not relabel it as recovery or
  entropy. Do not rerun O1C-0072, replay ordinal `8`, or sweep rank/phase/
  horizon/RAM. Next derive the highest-ROI genuinely new O1C-0073 evidence or
  causal operator from this breadcrumb before freezing another call.
- **Artifacts:** authoritative
  [`result`](O1C0072_APPLE8_VAULT_BACKTRACK_RELEASE_RESULT_20260719.json),
  SHA-256
  `e441a32de808ee33e2245ea69af4e6ad6f246311e5a410b0cbab4a63dbd165d8`;
  sealed
  [`capsule`](../runs/20260719_204421_O1C-0072_apple8-vault-backtrack-release-v1/RUN.md),
  artifact-manifest SHA-256
  `83bbc2438fc33e3a61fdf5b23b589574c6a12cfaefd9fc2f0e7c4c4e84b521f8`.

## O1C-0073 — APPLE8 vault release contrast

- **Supersession:** this completed attempt consumes O1C-0072's sole forward
  decision after the original-first, release-gated hard-opposite reader, bounded
  queue/state, target-free consequence, source and capacity gates passed. It is
  a distinct mechanism and lineage call, not an O1C-0072 retry or ordinal-8
  replay.
- **Started:** 2026-07-19T21:56:14+02:00.
- **Recorded:** 2026-07-19T21:56:54+02:00.
- **Source commit:** `a1a447f47b4e7bec833f1148330573fefa8e3119`.
- **Protocol:** exactly one fresh native subprocess imports the unchanged sealed
  202-clause vault and immutable 255-variable signed rank, uses local ordinal
  `0`, lineage ordinal `9`, seed `0` and requested 512-conflict soft horizon.
  Native first preserves O1C-0072's monotone consume-once original reader. A
  genuine original-literal release enqueues that rank, and only after original
  rank exhaustion can the earliest released, currently unassigned hard opposite
  be returned once. Assigned contrasts are deferred and retained. Phase calls,
  retries, replays and sweeps are zero.
- **Result:** `EPISODIC_VAULT_CAPACITY_TERMINAL`. Native status is `0`; requested,
  actual and billed conflicts are `512/179/179`, leaving `333` requested
  conflicts unused. The process fully emits `313` eligible exact threshold
  no-goods / `803,144` literals: `311` independently certified novel clauses /
  `798,046` novel literals and two exact duplicates. It returns no model or key
  and does not prove threshold-region exhaustion. The fail-closed published
  output vault therefore remains the byte-identical input at `202` clauses /
  `599,728` literals / `2,399,911 B`, SHA-256
  `cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858`.
- **Capacity terminal:** retaining all 311 novel clauses would produce exactly
  `202+311=513` clauses, one above the clause cap `512`. Their combined
  `1,397,774` literals remain below the `1,600,000` literal cap and the computed
  `5,593,339 B` serialization remains below the `8,388,608 B` payload cap.
  Thus `capacity_clause_count`, and no other vault cap, terminates the episode;
  capacity is the blocker rather than absence of newly certified evidence.
- **Validated contrast mechanism:** all `255` originals are returned and later
  released/enqueued; all `255` hard opposites are returned and later released.
  The `6,250` callbacks comprise `510` nonzero and `5,740` zero/delegate
  returns, with `255` paired variables, `255` second decisions, zero same-sign
  redecisions, maximum/terminal queue `253/0`, and two unique deferred-assigned
  ranks. Guidance is bounded at `706 B` live and telemetry at `33,490 B`.
- **Search telemetry:** decisions are `6,250`, propagations `3,278,941`, minimum
  UB `13.16709627777236` and root UB `262.68644197084643`. Versus O1C-0072,
  decisions change by `+5,095`, propagations by `-2,484,094` and minimum UB by
  `-6.408897572182058`. These are diagnostic deltas, not a gain, recovery or
  entropy classification.
- **Formal threshold clarification:** `tau=14.606178797892962` and every
  reported UB use the same compiled score metric and retained direction
  `S(k)>=tau`; minimum UB is instead the minimum of an admissible upper-bound
  statistic over the visited partial trails. The value `7.973483108047071`
  belongs to O1C-0066 episode 1, not O1C-0068; O1C-0068's minimum UB is
  `12.8607806294803`. For any visited trail `a`, admissibility gives
  `S(k)<=U(a)` for every completion `k` of `a`, so strict `U(a)<tau` safely
  prunes exactly those descendants from the retained region. It does not prune
  other trails: root `U(root)=262.68644197084643>tau`, so neither a global prune,
  UNSAT nor threshold-region exhaustion follows.
- **Resources and lineage:** runner elapsed `40.378152000004775 s`; native wall/
  CPU `0.754070/1.479117 s`; native peak RSS `431,915,008 B`; runner peak RSS
  `352,075,776 B`; persistent artifacts `31,718,876 B`. Only ordinal `9` is
  consumed. Known completed lineage billing becomes `4,283`; the full actual
  total remains `null` because failed ordinal `2` is unbilled. One native call
  and zero key/truth/reveal/fresh-target/entropy/refit/MPS/GPU work.
- **Decision:** support `H-RELEASE-CONTRAST-077` at the exact-emission mechanism
  level, while retaining the formal capacity-terminal/no-recovery result. Do not
  retry O1C-0073, replay ordinal `9`, or sweep rank, phase or horizon. Preserve
  all 513 certified exact clauses in an external causal attic, derive a bounded
  target-free active subset with deliberate headroom, and freeze that new
  O1C-0074 mechanism before any further science call.
- **Artifacts:** authoritative
  [`result`](O1C0073_APPLE8_VAULT_RELEASE_CONTRAST_RESULT_20260719.json), SHA-256
  `43fb980b50fef20f9bc4bdcfd2ecd6e0f1f7df3bcee9297b0005bb55e4ea0cdc`;
  sealed
  [`capsule`](../runs/20260719_215617_O1C-0073_apple8-vault-release-contrast-v1/RUN.md),
  artifact-manifest SHA-256
  `ad2791ff4ae09e9426878be4ba2f3b55eb77c85f46308c7a506d0dc96111317d`;
  native-result SHA-256
  `bf5f0ce2f72b9d86b5bb6a7fa08e44f777a0980c0bbbd2e0ed9aaa1bca20410a`.

## O1C-0074 — APPLE8 causal-attic stream

- **Started:** 2026-07-19T23:18:23+02:00.
- **Recorded:** 2026-07-19T23:21:48+02:00.
- **Source/execution:** `a5f2ad130e2e13c39a5e888f927d86d5fdd68d78`.
- **Protocol:** retain the complete O1C-0073 corpus as immutable attic chunks and
  all duplicate witness occurrences as separate ledger events; keep the
  immutable 202-clause parent vault as the reader/rank source; project exactly
  256 target-free clauses into each fresh solver; run local ordinals `0..3` /
  lineage ordinals `10..13` for exactly 128 requested conflicts apiece; archive
  and reproject durably after every completed call. No K/rank/phase/horizon
  sweep, retry or replay is permitted.
- **Aggregate result:** `CAUSAL_ATTIC_STREAM_NOVEL_CLAUSE_GAIN`. All `4/4`
  calls complete with status `0`, exact aggregate `512/512` requested/billed
  conflicts and no operational failure. The complete attic grows
  `513→550` unique clauses, `1,397,774→1,488,224` literals and
  `515→558` occurrences; duplicate occurrences grow `2→8`. Exactly 37
  globally novel exact threshold-relative exclusions are retained. Live
  residency stays at 256 clauses and the final active state is
  `652,184` literals / `2,609,951 B`, SHA-256
  `78696f2b662beda4b371aa547350cc66b2105bc4dcaf0b982af2d1279e3012ed`.
- **Episode 0 / lineage 10:** `128/128`, 2,437 decisions, 2,956,417
  propagations, minimum/root UB
  `13.527469461337148/262.68644197084643`. Six safe threshold prunes emit six
  exact global duplicates at union indices `202..207`; unique clauses remain
  513 while occurrences grow `515→521` and duplicates `2→8`. Their recurrence
  promotes all six previously inactive clauses, changing active SHA
  `fb7528bf…→ccfad8b3…`.
- **Episode 1 / lineage 11:** `128/128`, 3,536 decisions, 2,954,223
  propagations, minimum/root UB
  `13.140486923093844/262.68644197084643`. All 37 safe-prune emissions are
  globally novel, becoming union indices `513..549`; attic occurrences and
  unique clauses both grow by 37. Reprojection changes active SHA
  `ccfad8b3…→78696f2b…`.
- **Episodes 2/3 / lineages 12/13:** each is exactly `128/128`, 2,288
  decisions, 2,890,144 propagations, minimum/root UB
  `14.67138759145431/262.68644197084643`, zero prunes and zero emissions.
  Active vault, reader evidence, sieve trace and vault telemetry are
  bit-identical. The static projection is therefore an exact fixed point at
  this reader/seed/horizon and must not be replayed.
- **Mechanistic result:** episode-0 recurrence changes bounded attention, and
  the changed live projection exposes 37 new exact clauses one episode later.
  The complete attic retains both repetition and novelty while the active state
  remains constant-size. Support `H-CAUSAL-ATTIC-078`; do not claim that the six
  promoted clauses are uniquely necessary under every possible policy.
- **Formal threshold clarification:** `tau=14.606178797892962` and UB use the
  same compiled score units and retained direction `S(x)>=tau`, but not the same
  population/statistic. For visited trail `a`, admissibility gives
  `S(x)<=U(a)` for every completion, hence strict `U(a)<tau` safely prunes only
  that trail's descendants. The historical `7.973483108047071` is O1C-0066
  episode 1, not O1C-0068; O1C-0068 is `12.8607806294803`. O1C-0074 episodes
  0/1 have below-threshold minima and `6/37` local prunes; episodes 2/3 have
  minimum `14.67138759145431>tau` and zero prunes. Root UB remains
  `262.68644197084643>tau`, so no global prune, UNSAT or exhaustion follows.
- **Resources and lineage:** elapsed `204.95784179099428 s`; runner peak RSS
  `504,233,984 B`; largest native episode peak `412,270,592 B`; persistent
  artifacts `30,567,197 B`. Ordinals `10..13` are consumed and known completed
  lineage billing becomes `4,795`; the full actual total remains `null` because
  failed ordinal `2` is unbilled. Zero key/truth/fresh-target/entropy/reveal/
  refit/MPS/GPU work.
- **Decision:** preserve the complete 550-clause/558-occurrence attic, separate
  rank source and final K256 projection. Do not replay O1C-0074 or sweep K,
  rank, phase, horizon, seed, threshold, RAM or caps. Before O1C-0075, perform
  zero-call analysis and freeze one nonrepeating bounded residency/attention
  rule; the exact rule remains pending that analysis.
- **Artifacts:** authoritative
  [`result`](O1C0074_APPLE8_CAUSAL_ATTIC_STREAM_RESULT_20260719.json), SHA-256
  `b6bc2895459e3256fa4c857b67bd786b36d80ab5018a9c73709a2096cd169127`;
  [`interpretation`](O1C0074_APPLE8_CAUSAL_ATTIC_STREAM_INTERPRETATION_20260719.md);
  sealed
  [`capsule`](../runs/20260719_231823_O1C-0074_apple8-causal-attic-stream-v1/RUN.md),
  artifact-manifest SHA-256
  `7a3f272268296005c5c6e532d377eb100244f38e941a102876abbfd732a8049b`.
  Capsule `result.json` is byte-identical to the published result and all
  `54/54` manifest entries validate. `publication_source.json` is only the
  pre-finalization source (`persistent_artifact_bytes=0` versus final
  `30,567,197`) and is not an authoritative result citation.

## O1C-0075 — APPLE8 causal-residency stream

- **Started:** 2026-07-20T00:27:24+02:00.
- **Recorded:** 2026-07-20T00:28:57+02:00.
- **Source/execution:** `1b30cc06b3ab28d94df773cc854a7814af9fb210`.
- **Protocol:** keep O1C-0074's 550-clause / 558-occurrence attic and immutable
  202-clause rank source; rotate two fresh target-free K256 pages at local
  ordinals `0..1` / lineage `14..15`, exactly 128 requested conflicts each;
  reject used page hashes, preserve every occurrence and stop after call two.
- **Result:** `CAUSAL_RESIDENCY_STREAM_NO_NOVEL_GAIN`. Both calls complete at
  exact `128/128` requested/billed work, aggregate `256/256`, with zero prunes,
  emitted occurrences, novel clauses or model. Input pages `82b1512a…` and
  `db3acd5e…` are byte-distinct, but both reproduce trace `f64441a2…`, 2,288
  decisions, 2,890,144 propagations, minimum/root UB
  `14.67138759145431/262.68644197084643` and O1C-0074 episodes 2/3 exactly.
- **Residency boundary:** inherited parent plus Page 1 and Page 2 cover all
  `545/545` undominated clauses and leave zero residency debt. A deterministic
  unused next page is produced at SHA `5b459ea4…`; the attic remains exactly
  550 clauses / 558 occurrences / eight duplicate occurrences. Paging succeeds
  operationally, while pure rotation is scientifically inert at this horizon.
- **Threshold boundary:** `tau=14.606178797892962` and UB share score units and
  retained direction but not statistic/population. Strict `U(a)<tau` safely
  prunes only descendants of visited trail `a`; both O1C-0075 minima exceed
  `tau`, so there are zero local prunes and no global-exhaustion implication.
  The historical `7.973483108047071` is O1C-0066 episode 1, not O1C-0068;
  O1C-0068 is `12.8607806294803` and remains untouched.
- **Resources:** elapsed `93.29592229200352 s`; runner peak RSS `482,541,568 B`;
  native peaks `411,435,008 B` / `408,993,792 B`; persistent artifacts
  `20,788,748 B`. Zero truth/reveal/fresh-target/refit/MPS/GPU/publication-
  recovery calls.
- **Decision:** do not replay lineages `14/15` or rotate another page. Preserve
  the exact coverage ledger. The next high-ROI mechanism is a target-free live
  reader for Page 3's unique nearest zero-true no-good: union index 526, clause
  SHA `c4a9c471…`, 2,409 false / 29 unassigned under the sealed public terminal
  assignment. Use one lineage-16/128-conflict falsify-then-release-contrast
  call. Preserve the ten exact pair resolvents as a later compiler breadcrumb;
  their direct terminal distance is much larger.
- **Artifacts:** authoritative
  [`result`](O1C0075_APPLE8_CAUSAL_RESIDENCY_STREAM_RESULT_20260720.json), SHA-256
  `1307be5e1c140f27ec76873a212785f7dae9b5dd986ca8f953e94809e31639c9`;
  [`interpretation`](O1C0075_APPLE8_CAUSAL_RESIDENCY_STREAM_INTERPRETATION_20260720.md);
  sealed
  [`capsule`](../runs/20260720_002724_O1C-0075_apple8-causal-residency-stream-v1/RUN.md),
  artifact-manifest SHA-256
  `3a421ee236af5afe46011314d74c25b726a2e7f35e9963ae8d4a862e070327f9`.
  Capsule `result.json` is byte-identical to the published result and all
  `41/41` manifest entries validate.

## O1C-0076 — APPLE8 live causal-frontier reader

- **Started:** 2026-07-20T01:36:32+02:00.
- **Recorded:** 2026-07-20T01:37:20+02:00.
- **Source/execution:** `f78424e92b1035a07a70350f0ad5666f2c9459e4`.
- **Protocol:** use fresh Page 3 `5b459ea4…`, the immutable 550-clause /
  558-occurrence attic and separate 202-clause rank source; bind union clause
  526's 29 public residuals; invoke the unchanged release-contrast parent first
  on every callback and replace only a parent zero with one falsifying residual,
  followed by its satisfying opposite only after genuine release. Consume local
  ordinal 0 / lineage 16 once at exactly 128 requested conflicts with no retry.
- **Result:** `CAUSAL_FRONTIER_NO_ACTIVATION_NO_GAIN`. The sole call requests
  and bills `128/128` conflicts, returns status `0`, makes 2,288 decisions and
  2,890,144 propagations, and records zero substitutions, trace change, safe
  prunes, emitted occurrences, globally novel clauses or model. Native trace
  remains `f64441a2…`; minimum/root UB is
  `14.67138759145431/262.68644197084643`.
- **Activation diagnosis:** the parent records 510 nonzero and 1,778 zero
  returns; its first zero is callback 256. At that callback all 29 residual rows
  are already assigned, so the frontier cursor consumes them all without a
  return: 18 are preassigned in the falsifying sign and 11 in the rescue sign.
  There are zero releases or contrasts. Only five residual variables occur in
  the parent's 255 ranked rows; propagation assigned the other 24 before first
  delegation. `prior_distance_reached=true`, but `unit_distance_reached=false`.
- **Threshold boundary:** `tau=14.606178797892962` and UB share score units and
  retained direction but not statistic/population. Minimum UB
  `14.67138759145431>tau` yields zero prunes. The historical
  `7.973483108047071` is O1C-0066 episode 1; O1C-0068 is
  `12.8607806294803` and remains untouched.
- **Resources:** runner elapsed `47.79094816700672 s`, runner peak RSS
  `408,141,824 B`; native wall `0.566478 s`, native CPU `1.346263 s`, native
  peak RSS `408,944,640 B`; persistent artifacts `15,055,265 B`. Zero
  publication-recovery calls, truth/reveal/fresh-target/refit/MPS/GPU work.
- **Decision:** close the parent-zero-only 29-row operator and never replay
  lineage 16. The highest-ROI immediate successor is O1C-0077 residual-
  polarity staging: preserve rank order, but change the two ranked rescue
  originals `+131/-130` to falsifying `-131/+130` before constructing the
  existing contrast reader, and use fresh Page 4
  `b57e3091df7eca20137f4c63e3bc125aa8978c2ff183a7396de3a2a4a79acf33`
  in one target-free call. The exact 11-row falsifying set is the next stronger
  preemptor only if staging cannot redirect propagation. No K/rank/phase/
  horizon/seed/threshold/RAM/cap sweep.
- **Artifacts:** authoritative
  [`result`](O1C0076_APPLE8_CAUSAL_FRONTIER_RESULT_20260720.json), SHA-256
  `9459f80444b2dc196251623dfc1f59f014e6593b3b5cd7d8bbaaa5c62f0b671e`;
  [`interpretation`](O1C0076_APPLE8_CAUSAL_FRONTIER_INTERPRETATION_20260720.md);
  sealed
  [`capsule`](../runs/20260720_013632_O1C-0076_apple8-causal-frontier-v1/RUN.md),
  artifact-manifest SHA-256
  `875655a95a30a4f0df01e130a074b0b6a82b98c683575818ad5110cc6a6f1366`.
  Capsule `result.json` is byte-identical to the published result and all
  `35/35` manifest entries validate.

## O1C-0077 — APPLE8 residual-polarity staging

- **Started:** 2026-07-20T02:55:50+02:00.
- **Recorded:** 2026-07-20T02:56:38+02:00.
- **Source freeze/execution:** `d4f9b3aa066b22a38ead63d83cbb76b4ead673de`
  / `8eba8614fc9d19ef893a0e7f093737ed6b23dc68`.
- **Protocol:** preserve the complete O1C-0076 causal attic, immutable 255-row
  rank and fresh Page 4 `b57e3091…`. Change only source rank rows 224/226 from
  `+131/-130` to effective `-131/+130` before constructing the inherited
  release-contrast reader. Consume local 0 / lineage 17 once at exactly 128
  conflicts, with no retry, sweep, truth, reveal, refit, MPS or GPU.
- **Result:** `RESIDUAL_POLARITY_STAGING_MECHANISM_ONLY`. Effective originals
  `-131/+130` return at callbacks 225/227 and source contrasts `+131/-130`
  at 574/576. Native activation is true and trace changes
  `f64441a2…→706ad4fa…`. The sole call bills `128/128` conflicts, makes 884
  decisions and 4,754,555 propagations, and records zero safe prunes, emitted
  occurrences, globally novel clauses or model.
- **Reference displacement:** versus O1C-0076, decisions fall
  `2,288→884` (-61.36%) while propagations rise
  `2,890,144→4,754,555` (+64.51%). Minimum UB moves
  `14.67138759145431→14.656823218163392`, reducing the positive margin above
  `tau=14.606178797892962` by 22.33%, but remains above threshold and yields
  zero prune. Page 3 advances to Page 4, so these whole-call deltas are not a
  same-input counterfactual. The reader streams match through callback 224 and
  first diverge exactly on the planned callback-225 overlay; at parent fallback
  callback 256 the residual split improves from 18/11 to 23/6
  falsifying/rescue. This is causal trajectory control, not yet search-space
  gain.
- **Threshold boundary:** `tau` and `U(a)` share the compiled score metric,
  units and retained direction `S(k)>=tau`, but threshold and minimum UB have
  different statistic roles/populations. Strict `U(a)<tau` safely prunes only
  completions of that visited trail. Historical `7.973483108047071` belongs
  to O1C-0066 episode 1 and accompanies seven actual local prune events; it is
  neither global exhaustion nor O1C-0068, whose minimum is
  `12.8607806294803` and whose artifacts remain untouched.
- **Resources:** runner elapsed `48.2352461249975 s`, runner peak RSS
  `402,210,816 B`; native wall `0.838922 s`, CPU `1.600825 s`, native
  peak RSS `423,968,768 B`; persistent artifacts `15,291,549 B`.
- **Decision:** close the two-row operator and never replay lineage 17. Advance
  once to the already sealed 11-row falsifying prefix
  `130,-131,31874,63746,190565,190566,190569,191212,191213,191216,191234`
  on fresh Page 5 `07c73013…`. Activation requires all 11 rows consumed before
  the parent, all 11 falsifying at handoff with zero rescue skips, at least one
  exact prefix once-return and a new trace. Requiring 11 returns would wrongly
  reject causal propagation assigning later rows. Science still requires a safe
  prune, globally novel exact clause, formal exhaustion or public model.
- **Artifacts:** authoritative
  [`result`](O1C0077_APPLE8_RESIDUAL_POLARITY_STAGING_RESULT_20260720.json),
  SHA-256
  `8b87d7cdc39f6380a887b2e45d4879544ff88cd7c53e22f44876e46c334cf103`;
  [`interpretation`](O1C0077_APPLE8_RESIDUAL_POLARITY_STAGING_INTERPRETATION_20260720.md);
  sealed
  [`capsule`](../runs/20260720_025550_O1C-0077_apple8-residual-polarity-staging-v1/RUN.md),
  artifact-manifest SHA-256
  `6b8526c5eaa2c318d4eef1e8c4dc87e744307c95f30699a90e4444021d2dbece`.
  Capsule `result.json` is byte-identical to the published result and all
  `39/39` manifest entries validate.

## O1C-0078 — APPLE8 rescue-prefix preemption

- **Started:** 2026-07-20T06:55:05+02:00.
- **Recorded:** 2026-07-20T06:55:37+02:00.
- **Source freeze/execution:** `ced7e5917194362b84d44625f7f9f6484bb555ad`
  / `2840824b2aa482f30dfbd39060c200994fc09957`.
- **Protocol:** preserve the immutable attic, separate 202-clause rank source,
  inherited O1C-0077 stack and exact prefix
  `130,-131,31874,63746,190565,190566,190569,191212,191213,191216,191234`
  (signed-i32le `b5debc5f…`). Consume fresh Page 5 once at local 0 / lineage 18,
  requested 128 conflicts, with no retry, truth, reveal, refit, sweep, MPS or GPU.
- **Result:** `RESCUE_PREFIX_PREEMPTION_OPERATIONAL_TERMINAL`. The native call
  exits before returning a result with exact stderr
  `cadical_o1_joint_score_sieve_v16: backtrack-release guided assignment sign differs`
  and empty stdout. Requested conflicts are 128; actual and billed conflicts are
  unknown / `null`. There is no activation, trace, bound, solver-status, clause
  or model payload.
- **Narrow reachability fact:** v11 can throw this only for a rank row already
  marked returned. That bit is set after inherited parent `cb_decide` returns a
  ranked literal; O1C-0078 calls the parent only after consuming all 11 prefix
  rows. Complete-prefix consumption and parent handoff are therefore proven.
  At least one prefix once-return, zero rescue skips, all-falsifying handoff and
  changed trace are not proven. This is not qualified activation.
- **Input identity:** the bound plan/capsule identifies Page 5 as the fresh input
  and it is now burned. Conservative failure finalization leaves
  `no_science_input_sha256_reused=false` because postvalidation did not run;
  that fallback is not positive evidence that an input identity was reused.
- **Strongest code-path inference:** the proven state is one returned-ever,
  unreleased proposal plus a currently disappearing opposite-sign assignment.
  Empty stdout does not establish which layer created that counter-assignment.
  Nested readers most likely conflate proposal history with current signed
  assignment ownership; another reader, propagation or a later decision are
  possible routes, not observed facts.
- **Threshold clarification:** `tau=14.606178797892962` and minimum UB use the
  same compiled score metric/units/maximization direction, but not the same
  statistic/population. O1C-0066 episode 1's
  `7.973483108047071` is a minimum over visited partial trails. For each
  particular trail, admissibility plus strict `U(a)<tau` safely excludes only
  its descendants; this is not root/global exhaustion. O1C-0077's
  `14.656823218163392>tau` gives zero prunes; O1C-0078 has no UB result.
  O1C-0068 remains untouched at `12.8607806294803`.
- **Resources:** one call; runner elapsed `31.211805499973707 s`; native-failure
  elapsed `29.31788737498573 s`; native/watchdog peak RSS `404,815,872 B`;
  runner peak RSS `381,730,816 B`; persistent artifacts `12,137,843 B`.
- **Decision:** do not retry lineage 18 or Page 5. First reproduce the ownership
  conflict as a synthetic zero-science trace, then implement one explicit signed
  decision-instance arbiter. Derive fresh Page 6 / lineage 19 by burning Page 5
  without importing nonexistent native output; test the unchanged scientific
  prefix once only after the ownership gate.
- **Artifacts:** authoritative
  [`result`](O1C0078_APPLE8_RESCUE_PREFIX_PREEMPTION_RESULT_20260720.json),
  SHA-256
  `f72821443ed7e7dd80698a39288ff31f9c8f52a120bb745e713e3b23b1822fed`;
  [`interpretation`](O1C0078_APPLE8_RESCUE_PREFIX_PREEMPTION_INTERPRETATION_20260720.md);
  sealed
  [`capsule`](../runs/20260720_065505_O1C-0078_apple8-rescue-prefix-preemption-v1/RUN.md),
  artifact-manifest SHA-256
  `5d358863162a64f27d215fc4b91258c73194d2458f89d9dd7495bb1e05e50a69`.
  Capsule `result.json` is byte-identical to the published result and all
  `33/33` manifest entries validate.

## O1C-0079 — APPLE8 central decision ownership

- **Started/recorded:** 2026-07-20T08:57:38+02:00 /
  2026-07-20T08:58:18+02:00.
- **Execution commit:** `8b058cbfe62d93d0263a275f4081982f382a4355`.
- **Protocol:** after zero-science ownership fixtures and fresh Page-6
  reprojection, compose prefix, staged rank and live frontier under one typed
  level-bound decision owner. Consume local 0 / lineage 19 once at 128 requested
  conflicts, with unchanged public inputs, scorer, threshold, K256, seed and
  prefix; no retry, truth, reveal, refit, sweep, MPS or GPU.
- **Corrected result:**
  `DECISION_OWNERSHIP_QUALIFIED_PREFIX_MECHANISM_ONLY`; stop
  `qualified-prefix-activation-without-science-gain`. Operational ownership and
  qualified prefix activation pass; science gain fails.
- **Ownership evidence:** `549` proposals = `549` level bindings = `549`
  releases; `547` are confirmed and two are level-bound unobserved releases.
  Tokens 75/110 retire `-108/-112`; later `+108/+112` observations are foreign
  token 0. There are `9,966` foreign assignments, zero opposite assignments,
  zero live tokens and zero omitted events. Rank original/contrast each account
  for `254` releases; frontier initial/contrast each account for `16`.
- **Prefix evidence:** all 11 rows are consumed before the first non-prefix
  decision; nine bind and release, two are preassigned falsifying, zero are
  skipped as rescue. The central reader makes `1,587` callbacks, `549` nonzero
  and `1,038` zero. The returned trace differs from O1C-0077.
- **Science boundary:** minimum UB `18.742222666780805` is
  `4.136043868887843` above `tau=14.606178797892962`. Safe prunes, novel
  clauses, complete models, keys and other sub-256 progress are all zero.
  Decisions move `884→1,587` and propagations `4,754,555→468,611` (`-90.14%`)
  versus O1C-0077, but successive pages make those whole-call differences
  mechanism telemetry rather than a same-input science effect. O1C-0068 is
  untouched.
- **Work/resources:** exact requested/actual/billed conflicts `128/128/128`;
  native `176,794 us` wall / `994,976 us` CPU / `390,922,240 B` peak; runner
  `40.11452975 s` / `330,285,056 B` peak; complete command including preflight
  `80.96 s`; zero swaps.
- **Decision:** never retry Page 6 or lineage 19 and stop the qualified-prefix
  path without a science gain. This breadcrumb was consumed by O1C-0080's exact
  same-parent `U0/U1` crossing test on fresh Page 7; see its terminal entry
  below.
- **Artifacts:** immutable raw
  [`result`](O1C0079_APPLE8_DECISION_OWNERSHIP_RESULT_20260720.json), SHA-256
  `ce68d10eed83d9a0d90518c579f4e1841cd8a6791e4cd975d0d27a64bcc6251e`;
  [`zero-call erratum`](O1C0079_APPLE8_DECISION_OWNERSHIP_ZERO_CALL_ERRATUM_20260720.json);
  [`interpretation`](O1C0079_APPLE8_DECISION_OWNERSHIP_INTERPRETATION_20260720.md);
  sealed
  [`capsule`](../runs/20260720_085738_O1C-0079_apple8-decision-ownership-v1/RUN.md),
  artifact-manifest SHA-256
  `f7cd0de5ba58a59de913db88ba3e9ce2ae1b486a4e922700f65dff3aa5d39475`.

## 2026-07-20 — O1C-0079 publication-classification correction (non-attempt)

- **Defect:** the archived validator searched all serialized native text for
  `returned-ever`. It matched the positive descriptor
  `origin-row-level-token;never-returned-ever-plus-variable-sign`, set
  `old_returned_ever_runtime_absent=false`, and emitted raw classification
  `DECISION_OWNERSHIP_NO_ACTIVATION_NO_GAIN` despite complete positive ownership
  evidence.
- **Fix:** corrected validator commit
  `665ea8260ae7127baabc83af2fe208080f6f58f9` checks native/central parent schema,
  eligibility rule and assignment-notification rule by exact identity. Applying
  that predicate to the archived canonical evidence yields axes
  operational=`true`, qualified-prefix=`true`, science=`false`.
- **Archive boundary:** no result, capsule, gzip or manifest byte is modified.
  Native gzip/uncompressed SHA-256 is `ec75d6c…` / `acda128d…`; ownership is
  `6403d8a6…` / `87e64764…`. The correction makes zero solver, truth, reveal,
  target, refit, MPS or GPU calls.
- **Authority:** additive erratum SHA-256
  `b5c2465a532486aaf68a6a622f2312de29ec8a52ea6cea70c9d9c36f19985fa9`.
  The immutable raw result remains the historical publication output; the
  erratum supplies its corrected classification and stop reason.

## O1C-0080 — APPLE8 exact one-bit bound crossing

- **Started/recorded:** 2026-07-20T12:45:16+02:00 /
  2026-07-20T12:46:05+02:00.
- **Source/execution freezes:**
  `0c18e064ae792ee719db34ff702f249994f4aab4` /
  `9469c988375673c901be453e199078ad61c42c1c`.
- **Protocol:** consume fresh Page 7 / lineage 20 exactly once at 128 requested
  conflicts. At each parent callback, evaluate exact same-parent child bounds
  `U0/U1` for every eligible unassigned key coordinate without mutating solver
  state. Intervene only on a strict asymmetric threshold crossing or validated
  two-child closure. Public inputs, scorer, threshold, K256, seed and conflict
  budget remain fixed; no retry, truth, reveal, refit, sweep, MPS or GPU.
- **Result:** `BOUND_PROBE_OPERATION_ONLY`; stop
  `exact-probes-operated-without-crossing-or-science`. Exact probe operation
  passes; crossing activation and science gain fail.
- **Probe evidence:** `1,587` parent scans, `285,725` probes and `571,450`
  exact child-bound evaluations over all `255` eligible candidates. Every probe
  is `NEITHER_PRUNABLE`; all crossing/closure classes are zero. The full trace
  contains `285,725` events / `16,286,325 B`, SHA-256 `c6f6c2a9…`. Only the
  first `16,384` objects are retained; `269,341` omitted events are digest-bound
  and must not be reconstructed or used as measured values.
- **Minimum witness:** callback `413`, parent level `330`, probe `37,567`,
  coordinate index `252`, variable `115`,
  `U0=19.10564473318062`, `U1=18.464862193097684`. The minimum is
  `3.8586833952047215` above `tau=14.606178797892962`; every pre/post state hash
  is identical.
- **Science boundary:** zero bound proposals/bindings/releases, interventions,
  realized or fully emitted prunes, both-child closures, globally novel clauses,
  public models, keys or attacker-valid sub-256 gain. O1C-0080's child minimum is
  numerically `0.277360473683121` below O1C-0079's visited-parent minimum, but
  those are different statistics/populations and establish no improvement.
- **Threshold clarification:** `tau` and `U(a)` share score metric, units and
  maximization direction but are different statistic/population objects. Strict
  admissibility makes `U(a)<tau` a safe prune only for descendants of that
  visited trail. O1C-0066 episode 1's historical `7.973483108047071` belongs to
  its population and accompanies seven separately realized prunes; it is not a
  global bound or an O1C-0080 result. O1C-0080 has no child below threshold.
- **Work/resources:** exact requested/actual/billed `128/128/128`; native
  `6,803,373 us` wall / `7,618,434 us` CPU / `467,042,304 B` peak; effective
  watchdog headroom `36,274,176 B`; total `48.718023834 s`, runner CPU
  `40.98647 s`, runner peak `582,172,672 B`, persistent `14,998,858 B`.
- **Decision:** never retry Page 7 or lineage 20. The `+3.858683...` margin is
  not a genuine near crossing, so depth 2 is closed. Reuse the retained prefix
  target-free in O1C-0081: remove per-parent common mode from `d=U0-U1`, stream
  bounded O(256) coordinate residual moments/sign stability/surprise, separate
  belief orientation from query priority, and compare deterministic controls
  before defining any fresh Page-8/lineage-21 operator.
- **Artifacts:** authoritative
  [`result`](O1C0080_APPLE8_BOUND_CROSSING_RESULT_20260720.json), SHA-256
  `e2ceb375c2fb83469db8eb537459b223d8e7f63e4bb58882882f8cdd8bdb22a5`;
  [`interpretation`](O1C0080_APPLE8_BOUND_CROSSING_INTERPRETATION_20260720.md);
  sealed
  [`capsule`](../runs/20260720_124516_O1C-0080_apple8-bound-crossing-v1/RUN.md),
  artifact-manifest SHA-256
  `400b79b01ed54addbd99db53b2cf5ad36afd388a18d1435dcd7ef850c8532c44`.

## O1C-0081 — Target-free bound-differential census

- **Verified/recorded:** 2026-07-20T13:02:41+02:00.
- **Protocol:** load only O1C-0080's sealed one-bit reader evidence by exact
  gzip/raw bytes and SHA-256. Analyze the `16,384` retained event objects from
  calls `1..74`; treat the remaining `269,341` events only as committed
  count/bytes/digest metadata and exclude the separately serialized global
  minimum witness. Make zero solver, target, truth, reveal, refit, science, MPS
  or GPU calls.
- **Result:** `TARGET_FREE_BOUND_DIFFERENTIAL_MECHANISM_CENSUS`. Raw
  `d=U0-U1` has mean `0.435558404488658` and is positive in
  `15,601/16,384` events (`95.220947%`), exposing a dominant common polarity
  rather than a posterior.
- **Centered field:** within-parent median subtraction and MAD scaling produce
  `8,172` positive / `8,172` negative / `40` zero residuals, mean
  `-0.006465018506553668`. Eligibility is frozen at at least `37/74` parent
  observations before ranking; this excludes sparse 10–12-sample spikes.
- **Persistent candidate:** variable `185`, count `73`, centered mean
  `-2.752744217128212`, directional stability `1.0`, robust-z mean
  `-10.738855030935364`, query-priority score `91.75281760473375`.
- **Controls:** one deterministic within-parent cyclic permutation preserves the
  global value multiset but lowers maximum priority to `3.0906512561469452`,
  priority correlation `-0.028412595664496245`, top-16 overlap 3. This is one
  control, not a p-value. The temporal 37/37-parent split has centered-mean
  correlation `0.8538130771826461`, sign agreement `0.8110599078341014` and
  top-16 overlap variables `{33,129,170,185}`; the second half is explicitly a
  capped prefix, not a balanced sample.
- **State/resources:** packed 256-coordinate bank `24,576 B` plus one-parent
  median/MAD scratch `4,096 B`, total `28,672 B` and O(256) in stream length.
  Deterministic verification takes `0.23 s` real / `0.22 s` user / `0.01 s`
  system with maximum RSS `169,885,696 B`.
- **Claim boundary:** mechanism evidence supports query priority only. Neither
  raw nor centered sign is mapped to a hidden key bit; key-bit claims, entropy
  reduction, science gain and recovery remain zero.
- **Decision:** activate O1C-0082. Reproduce the state/rank online, select the
  coordinate by centered residual priority and use its current lower-UB child
  only as a target-free failure-first/proof-mining action. Compose typed
  one-shot ownership/release before at most one fresh Page-8/lineage-21 call.
- **Artifacts:** canonical
  [`JSON`](O1C0081_BOUND_DIFFERENTIAL_CENSUS_20260720.json), SHA-256
  `666854f8ba323fcbf100d86457fbc4eaa3cb3b6bab12d9e47982f4b28a86a389`;
  [`report`](O1C0081_BOUND_DIFFERENTIAL_CENSUS_20260720.md); sealed zero-solver
  [`capsule`](../runs/20260720_130241_O1C-0081_bound-differential-census-v1/RUN.md).

## O1C-0082 — APPLE8 live parent-centered proof mining

- **Executed/recorded:** 2026-07-20T14:30:11+02:00 through
  2026-07-20T14:30:55+02:00.
- **Protocol:** consume fresh Page 8 SHA-256 `89e085e7…`, local episode 0 and
  lineage 21 exactly once at seed 0 / 128 requested conflicts. Import the sealed
  O1C-0081 24,576-byte coordinate bank, maintain 4,096 bytes of parent scratch,
  choose the highest persistent centered-priority coordinate and return only its
  current lower-UB child as a one-shot failure-first proof-mining action. Keep
  belief orientation disabled. Zero truth/target/reveal/refit/MPS/GPU calls.
- **Result:** `PARENT_CENTERED_NOVEL_CLAUSE_GAIN`; operational activation and
  science gain both pass. The reader scans 512 parents, returns exactly 255
  one-shot actions over the complete score-observed key-coordinate population,
  and confirms all 255. The action literals are 151 positive / 104 negative;
  nine later release, none is unobserved and none coincides with an already
  pending threshold clause.
- **Exact work:** 33,106 probes / 66,212 child-bound evaluations; every direct
  child pair is still `NEITHER_PRUNABLE` and the selected direct-child minima
  range `18.73032392446294..259.3541483754725`. The guided descendant search
  nevertheless reaches minimum UB `13.019691682287633 <
  tau=14.606178797892962` and emits 257 safe trail-threshold cuts.
- **Durable science:** all 257 emitted no-goods are new to active Page 8 and,
  by exact canonical-clause comparison, new to the complete prior causal-attic
  union. They contain 743,129 literals; witness scores range
  `13.019691682287633..14.556639837436045`, all strictly below tau; aggregate
  SHA-256 `bcc424b009ff132348d5ac73227162395853d894c68ced65f9cd6494c3c0868d`.
- **Zero-call clause geometry:** all `257` clauses contain all `255` action
  coordinates. Sequence `1..247` has fixed original polarity; tail sequence
  `248..255` is `[100,55,66,153,49,24,90,21]` and realizes all `2^8=256`
  key-projection orientations exactly once plus one additional distinct clause
  at the all-original key pattern. The agreement histogram is
  `247:1,248:8,249:28,250:56,251:70,252:56,253:28,254:8,255:2`. The common
  signed intersection is `2,764` literals (`247` key + `2,517` internal);
  `2,870` variables are common, while `106` switch sign.
- **Resolution/core boundary:** the projected cube has `1,024` Hamming-1 edges
  and `1,032` clause-pairs including the duplicate projection. It yields zero
  non-tautological simple resolvents: every pair has `6..23` other complementary
  non-pivot literals (median `10`, mean `12.25`). Exact grouped common-core
  `U=18.66656376905567` is `+4.0603849711627085` above
  `tau=14.606178797892962`; deleting assignments can only increase `U`.
  Therefore the audit provides no prefix closure, key recovery, tail-free
  no-good, resolution compression or prunable common-core subset. Core SHA-256
  is `9aa383f819d1aa4b1216937ee341aa6a773d1d3456e1ea622494ef1a4345ea06`.
  Solver/native/target/truth/reveal calls were all zero.
- **Capacity terminal:** Page 8 starts with 256 clauses. Adding the 257th new
  clause would create 513 combined clauses, one above the sealed 512-clause
  active-vault cap. The native terminator therefore stops fail-closed at status
  `UNKNOWN` after only 9 actual/billed conflicts, leaving 119 requested
  conflicts unused. No next combined vault is serialized; the complete emitted
  clause set remains archived in the capsule.
- **Resources:** 512 decisions, 3,209,096 propagations; native wall
  `0.778217 s`, CPU `1.572724 s`, peak RSS `320,897,024 B`; runner wall
  `43.43645295800525 s`. Final priority-bank SHA-256 `05b8acf3…`.
- **Claim boundary:** no public model, key, closure, direct certified one-bit
  crossing, attacker-valid entropy estimate or domain-size estimate. O1C-0080
  and O1C-0082 use different pages/operators and are not a matched causal
  ablation; the sharp 0→257 exclusion change is therefore a high-value
  mechanism result, not isolated effect size.
- **Decision:** burn Page 8 / lineage 21 permanently. O1C-0083 has ingested
  all 257 clauses into the external causal attic and derived one deterministic
  bounded Page-9 projection with capacity headroom. Implemented and sealed
  explicit `next_active_limit=255` is the minimal one-slot sacrifice:
  `255` clauses / `721,187` literals / `2,885,959 B`, SHA-256
  `8c3b8cc33badd4aa23920caabc5ea3fc5006675d93805578b74b2b20788c8204`,
  categorized `roots=4`, `pinned=43`, `new_debt=208`, leaving `257` clause
  slots rather than hard-inheriting `256` and leaving `256`. No production call
  or intent exists. Continue from the final priority bank on fresh lineage 22
  only after a dedicated live-continuation parser and full preflight are sealed.
  Do not replay, raise RAM blindly or treat action sign as a key posterior.
- **Artifacts:** authoritative
  [`result`](O1C0082_APPLE8_PARENT_CENTERED_RESULT_20260720.json), SHA-256
  `013692cf836e594c8580734e0c95a9f0dd18ad7536c457274a1fe5684df1ad4f`;
  [`interpretation`](O1C0082_APPLE8_PARENT_CENTERED_INTERPRETATION_20260720.md);
  sealed
  [`capsule`](../runs/20260720_143008_461948_O1C-0082_apple8-parent-centered-v1/RUN.md),
  artifact-manifest SHA-256
  `3256a85e1095ffeaee349d3248035cb53470b1921abd58dd230e1617696134e6`.

## O1C-0083 — APPLE8 causal-attic Page-9 rollover preparation

- **Prepared/recorded:** `2026-07-20T15:31:57+02:00` (`Europe/Berlin`). Code
  commit `ddb9368c0a2f5cf469148c30748c416ace805225`; capacity API commits
  `b9eff33` and monotone fix `65c122b`.
- **Protocol:** reconstruct O1C-0082's sealed parent from result SHA-256
  `013692cf836e594c8580734e0c95a9f0dd18ad7536c457274a1fe5684df1ad4f`,
  capsule-manifest SHA-256 `3256a85e1095ffeaee349d3248035cb53470b1921abd58dd230e1617696134e6`
  and telemetry SHA-256 `9c7705591948e1f3b4ee1589cf431c8bd9a5844bad670ddb1c713c4d1d3e5445`;
  ingest all 257 emitted clauses, advance residency with explicit
  `next_active_limit=255`, and publish atomically with zero solver/native/science/
  target/truth/reveal/refit calls.
- **Result:** `CAUSAL_ATTIC_PAGE9_ROLLOVER_PREPARED`; zero-call enabling and
  mechanism gain only, not new cryptanalytic/key/entropy/domain gain. New chunk
  SHA `19e29482…` is 257 clauses / 743,129 literals / 2,973,735 B, with every
  occurrence new and unique. The attic becomes 13 chunks / 807 unique clauses /
  815 occurrences / 9 strict relations / 801 undominated clauses.
- **Page 9:** fresh SHA `8c3b8cc3…`, 255 clauses / 721,187 literals /
  2,885,959 B, categories 4 roots + 43 pinned + 208 new debt. Headroom is 257
  clauses / 878,813 literals / 5,502,649 B. Page 9 / lineage 22 are not burned;
  no intent or production call exists.
- **Continuation gate:** bank SHA `05b8acf3…` is 24,576 B as 256x96-byte records,
  255 eligible, variable 241 zero-count and maximum evolved count 575. Receipt
  `e3512587…` is 51,949 B and byte-validates the bank. It is incompatible with
  the fresh 74-parent seed parser; the future runner must accept the live
  continuation digest and receipt.
- **Audit:** common-core SHA `9aa383f8…`, 2,764 literals, exact grouped
  `U=18.66656376905567 > tau=14.606178797892962` by
  `4.0603849711627085`; nonprunable. Focused tests 8 passed in 90.91 s;
  historical suite 120 passed in 162.13 s; Ruff/Pyright clean.
- **Decision:** support `H-PARENT-CENTERED-ATTIC-ROLLOVER-087` at preparation level. Activate
  `H-PARENT-CENTERED-COMPOUNDING-088`: build and preflight a live-continuation-
  bank-capable Page-9 runner, freeze every hash, then authorize at most one fresh
  lineage-22 call. Accept novel clauses, closure/model/key, or attacker-valid
  entropy/domain gain. No replay or cap sweep.
- **Artifacts:** authoritative [result](O1C0083_APPLE8_CAUSAL_ROLLOVER_RESULT_20260720.json),
  [interpretation](O1C0083_APPLE8_CAUSAL_ROLLOVER_INTERPRETATION_20260720.md),
  [config](../configs/o1c83_apple8_causal_rollover_v1.json), and sealed
  [manifest](o1c83_causal_rollover_seed_20260720/causal-rollover-preparation-manifest.json)
  SHA-256 `b8a829a642159640a10cc553c6c27e5312cae4fbda8f75975688c6d14afe7dda`.

## O1C-0084 — APPLE8 parent-centered Page-9 continuation

- **Started:** `2026-07-20T16:26:10.201735+02:00`; **recorded:**
  `2026-07-20T16:26:29.631899+02:00` (`Europe/Berlin`).
- **Protocol:** validate the O1C-0083 manifest, unchanged 807-clause attic,
  Page 9, evolved `05b8acf3…` bank and `e3512587…` state receipt; persist one
  local-0 / lineage-22 intent; then issue at most one seed-0 native call at 128
  requested conflicts with no retry, reveal, target/truth input, refit, MPS or
  GPU use.
- **Preflight:** passed before intent. The production executable was frozen at
  `1,696,712 B`, SHA-256 `1ba38064…`, after being linked with
  `-Wl,-no_uuid`. Intent SHA-256 is
  `89483dda835275adba37a3cbb9099c12590cf26f439913eb4d91bbd6c912d20c`.
- **Terminal result:** `PARENT_CENTERED_CONTINUATION_OPERATIONAL_TERMINAL`, stop
  `burned-terminal-failure-no-retry`. Darwin `dyld` rejected the executable for
  a missing `LC_UUID` load command. One adapter/native process call was issued
  and consumed, but native `main` and CaDiCaL solver construction were never
  reached; no native JSON/stdout returned. Actual and billed conflicts are
  `null`.
- **Science boundary:** no priority-state update, probe/action/bound telemetry,
  prune, clause, model, key, closure, entropy or domain result exists. Science
  gain is false because execution never began. This is a build-transport
  failure, not a cryptanalytic negative and not evidence against O1C-0082.
- **State boundary:** persisted intent burns Page 9 / lineage 22 permanently.
  Never retry or replay it. The attic remains 807 unique clauses and the
  continuation bank remains exact SHA `05b8acf3…`; no O1C-0084 output exists to
  ingest.
- **Hypothesis:** refute `H-PARENT-CENTERED-COMPOUNDING-088` operationally at
  its launch gate, while leaving its cryptanalytic proposition untested.
  Activate `H-PARENT-CENTERED-PAGE10-COMPOUNDING-089`.
- **Next action:** derive fresh Page 10 from the unchanged attic and bank. Build
  once without `-Wl,-no_uuid`, seal the observed dynamic executable hash before
  intent, and require a non-science `--help` smoke on those exact bytes. Heavy
  checks protect irreversible Page/provenance/atomicity gates; reversible
  hygiene is one focused pass. After the burn gate passes, make the real call
  without a comfort-control cycle. Track pre-burn defect yield and shrink after
  2–3 no-find milestones; 66.35-second preparation is provenance cost, not
  solver-resource progress.
- **Resources:** runner wall `19.430220374983037 s`, CPU
  `18.90933000000001 s`; child user/system
  `0.0006740000000000634/0.001696000000000003 s`. These are build/loader costs,
  not solver work.
- **Artifacts:** authoritative
  [result](O1C0084_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json),
  SHA-256
  `4ae1238203ef10c03a1dd325242ccb59bd0f8f67c0b93fa5debd95259c7f7b96`;
  [interpretation](O1C0084_APPLE8_PARENT_CENTERED_CONTINUATION_INTERPRETATION_20260720.md);
  sealed
  [capsule](../runs/20260720_162606_777761_O1C-0084_apple8-parent-centered-continuation-v1/RUN.md),
  artifact-manifest SHA-256
  `811ad89955b383c4ac1303fc3f510c4169278e19cec73d465adf7a76e65cc2bf`.

## O1C-0085 — APPLE8 parent-centered Page-10 continuation

- **Started:** `2026-07-20T17:04:30.283656+02:00`; **recorded:**
  `2026-07-20T17:04:54.424693+02:00` (`Europe/Berlin`).
- **Protocol:** validate the O1C-0084 terminal receipt, unchanged 807-clause
  attic, fresh 254-clause Page 10, live `05b8acf3…` bank and `e3512587…`
  receipt; build once with the normal Darwin UUID, seal the observed executable
  and require exact-byte `--help`; persist one local-0 / lineage-23 intent; then
  issue at most one seed-0 native call at 128 requested conflicts with no retry,
  reveal, target/truth input, refit, MPS or GPU use.
- **Preflight:** passed before intent. The focused suite caught a wrong `_seed_`
  adapter path, which was corrected to the sealed v24 direct call before burn;
  no extra comfort-control cycle followed. The launchable executable is
  `1,696,712 B`, SHA `b37cc3b4…`; exact-byte help smoke returned zero with
  `169 B` stdout SHA `701fc730…` and empty stderr. Intent SHA-256 is
  `18607add506d55a3b3286b3954415a5d6a65c3760aa0fe0dedd82ec10cea3114`.
- **Terminal result:** `PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN`, stop
  `globally-novel-clause`, native status `0` / `UNKNOWN`. Exact work is
  requested/actual/billed `128/128/128`, `430` decisions and `5,389,742`
  propagations. The run fully emits `23` trail-upper-bound no-goods / `67,130`
  literals, all new to Page 10 and globally novel against the 807-clause attic;
  witness UBs are `13.63202340517244..14.595345982194171`, all below
  `tau=14.606178797892962`.
- **Science boundary:** the base sieve records `threshold_prunes=23` and emits
  all 23 safe local trail-prune clauses. The separate action-crossing counter is
  `actual_certified_prunes=0`: `255` confirmed failure-first actions make
  `32,840` probes / `65,680` child evaluations, but no realized certified action
  crossing. Science gain is exact global clause novelty only; key/model,
  closure and attacker-valid entropy/domain gain remain zero.
- **State boundary:** Page 10 enters at 254 clauses / 718,295 literals /
  2,874,387 B. A 277-clause / 785,425-literal / 3,142,999 B next vault is
  available, SHA `21c53865…`; no capacity stop occurs. The final 24,576-byte
  bank evolves to SHA `2c0c4ccb…`. Page 10 / lineage 23 are burned and must
  never be retried or replayed.
- **Hypothesis:** support
  `H-PARENT-CENTERED-PAGE10-COMPOUNDING-089` for continued globally novel
  exact-exclusion gain, not for key polarity, closure, entropy or recovery.
  Activate `H-PARENT-CENTERED-PAGE11-ROLLOVER-COMPOUNDING-090`.
- **Next action:** ingest all 23 clauses into the immutable attic with zero
  solver work, bind the evolved `2c0c4ccb…` bank, and derive a fresh bounded
  Page-11 projection with explicit headroom. After parser/source/executable/
  help-smoke/intent seals pass, authorize at most one fresh successor call. Do
  not replay Page 10 or change the operator/cap/RAM without a measured cause.
- **Resources:** native wall `1.398980 s`, CPU `2.130116 s`, peak RSS
  `358,400,000 B`; runner wall `24.141075249994174 s`, CPU `21.846302 s`;
  exactly one native solver call.
- **Artifacts:** authoritative
  [result](O1C0085_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json),
  SHA-256
  `d65fcaa76caa50905b5061b99cdf3ea10841449bdec6e9d20344e17bbe1e2ca4`;
  [interpretation](O1C0085_APPLE8_PARENT_CENTERED_CONTINUATION_INTERPRETATION_20260720.md);
  sealed
  [capsule](../runs/20260720_170426_298664_O1C-0085_apple8-parent-centered-continuation-v1/RUN.md),
  artifact-manifest SHA-256
  `c6f4cb50ab5e7b0e57afbe5bbaccf53106008094be824c35bb7f849a8d4be492`.

## O1C-0086 — APPLE8 parent-centered Page-11 continuation

- **Started:** `2026-07-20T18:12:16.473483+02:00`; **recorded:**
  `2026-07-20T18:12:54.951542+02:00` (`Europe/Berlin`).
- **Protocol:** atomically validate the 830-clause attic, fresh 254-clause Page
  11, `2c0c4ccb…` live bank and canonical state receipt; build native v22 once
  with normal Darwin UUID, seal and help-smoke those exact executable bytes;
  persist one local-0 / lineage-24 intent; then issue exactly one seed-0 call at
  128 requested conflicts with no retry, reveal, target/truth input, refit, MPS
  or GPU use.
- **Preflight:** one focused static/config pass and one real sealed CLI preflight
  passed with 3.27 GB available RAM and no sibling solver. All 25 source seals,
  Page/manifest/bank/receipt identities and 830-clause novelty baseline matched.
  No second comfort-control cycle ran.
- **Terminal result:** `PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN`, stop
  `globally-novel-clause`, native status `0` / `UNKNOWN`. Work is
  requested/actual/billed `128/131/131`, with conflict-limit overshoot 3,
  `1,009` decisions and `2,617,401` propagations. The run fully emits `202`
  trail-upper-bound no-goods / `546,864` literals.
- **Independent novelty:** the emitted set contains 202 distinct clause hashes;
  the prior attic contains 830 distinct hashes; sorted-set intersection is
  exactly zero. All 202 are `source=trail_upper_bound` and `classification=new`.
  Witness UBs are `8.269907850393242..14.604191886555723`, all strictly below
  `tau=14.606178797892962`; closest margin is `0.00198691133723905`.
- **Science boundary:** `threshold_prunes=202` is the safe trail-UB path. The
  separate action counter is `actual_certified_prunes=0`: `255` failure-first
  actions made `100,038` exact probes without a realized one-bit crossing.
  Science gain is exact global clause novelty only; no key/model/closure or
  attacker-valid entropy/domain gain is claimed.
- **State boundary:** a direct next vault is available at 456 clauses /
  1,265,745 literals / 5,064,995 B, SHA `bdac04a2…`; capacity did not stop the
  call. The 24,576-byte bank evolves to `658fd285…`. Page 11 / lineage 24 are
  burned and must never be retried or replayed.
- **Hypothesis:** support
  `H-PARENT-CENTERED-PAGE11-ROLLOVER-COMPOUNDING-090`; activate
  `H-PARENT-CENTERED-PAGE12-ROLLOVER-COMPOUNDING-091`.
- **Next action:** ingest all 202 clauses with zero solver work, bind the evolved
  bank and derive fresh bounded Page 12 / lineage 25 with explicit headroom.
  Then reuse the unchanged live mechanism for at most one fresh sealed call;
  never replay Page 11 or blindly raise cap/RAM.
- **Resources:** native wall `1.566374 s`, CPU `2.329425 s`, peak RSS
  `399,785,984 B`; runner wall `38.4777073750156 s`; exactly one native call.
- **Artifacts:** authoritative
  [result](O1C0086_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json),
  SHA-256
  `535b8fa095013d4b87cadfc5e54e62698a21ab285d92becfbba88dc9c6f0ee6e`;
  [interpretation](O1C0086_APPLE8_PARENT_CENTERED_CONTINUATION_INTERPRETATION_20260720.md);
  sealed
  [capsule](../runs/20260720_181212_319263_O1C-0086_apple8-parent-centered-continuation-v1/RUN.md),
  artifact-manifest SHA-256
  `d4ff926b1c2183ca2c70b499acd9e3aa00e9c6575aee43479dc6238e690953fb`.

## O1C-0087 — APPLE8 Page-12 causal rollover preparation

- **Recorded:** `2026-07-20T18:39+02:00` (`Europe/Berlin`).
- **Protocol:** with zero native/science calls, ingest all 202 fully emitted
  O1C-0086 clauses into the immutable causal attic, bind the exact final
  `658fd285…` live bank and `e5ffda54…` state receipt, then deterministically
  project fresh bounded Page 12 / lineage 25 with explicit capacity accounting.
- **Result:** all 202 occurrences are unique and globally novel against the
  prior 830-clause union. The new chunk is 202 clauses / 546,864 literals /
  2,188,455 B, SHA `d5338ef8…`. The attic reaches 15 chunks / 1,032 unique /
  1,040 occurrences / 10 strict relations / 1,025 undominated.
- **Page 12:** 254 clauses / 681,054 literals / 2,725,423 B, SHA `44205f81…`.
  Composition is five structural roots, 43 pinned core, 202 new debt and four
  recycled; all O1C-0086 clauses are resident. Headroom is 258 clauses /
  918,946 literals / 5,663,185 B. Clause slots prove capacity for 256 actions
  plus two; literal and byte safety for unknown future emissions are not claimed.
- **State:** the 24,576-byte bank and 52,009-byte receipt match exactly; 255
  coordinates are eligible and variable 241 is the sole zero record. The
  fresh-seed parser is incompatible by design; live continuation is mandatory.
- **Claim boundary:** `CAUSAL_ATTIC_PAGE12_ROLLOVER_PREPARED`; enabling/mechanism
  only. Native solver/science/target/truth/reveal/refit/MPS/GPU calls are zero.
  No intent exists and Page 12 / lineage 25 remain unburned and unauthorized.
- **Defect yield:** the focused gate caught inherited Page-11 writer delegation
  reapplying old seals. O1C-0087 now validates its own contract before the
  existing atomic low-level writer; only the failed test target was rerun. A
  malformed 63-character parent digest was also rejected before publication.
- **Next action:** finish Page-12-specific native/adapter/runner seals around the
  unchanged one-shot operator, then issue at most one lineage-25 call after one
  real preflight. Do not replay Page 11, rearm crossing actions or raise caps.
- **Artifacts:** [interpretation](O1C0087_APPLE8_CAUSAL_ROLLOVER_INTERPRETATION_20260720.md)
  and canonical
  [manifest](o1c87_page12_causal_rollover_seed_20260720/causal-rollover-preparation-manifest.json),
  SHA-256
  `64427e4861507e373cc02b52b9c0f2d25d62f26cf9362af681b9bc90ef4a57b6`.

## O1C-0088 — APPLE8 parent-centered Page-12 continuation

- **Started:** `2026-07-20T19:00:40.615684+02:00`; **recorded:**
  `2026-07-20T19:01:26+02:00` (`Europe/Berlin`).
- **Protocol:** validate the complete 1,032-clause attic, fresh 254-clause Page
  12, `658fd285…` live bank and canonical state receipt; build native v23 once
  with normal Darwin UUID, seal and help-smoke those exact executable bytes;
  persist one local-0 / lineage-25 intent; then issue exactly one seed-0 call at
  128 requested conflicts with no retry, reveal, target/truth input, refit, MPS
  or GPU use.
- **Preflight:** one focused native/adapter/runner gate and one real sealed CLI
  preflight passed with zero solver calls, capsules or intents. Production
  followed immediately; no repeated comfort-control cycle ran.
- **Terminal result:** `PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN`, stop
  `globally-novel-clause`, native status `0` / `UNKNOWN`. Work is
  requested/actual/billed `128/55/55`, leaving 73 conflicts unused, with `570`
  decisions and `2,598,280` propagations. The call fully emits `259`
  trail-upper-bound no-goods / `744,973` literals.
- **Independent novelty:** the emitted set contains 259 distinct clause hashes;
  the prior attic contains 1,032 distinct hashes; sorted-set intersection is
  exactly zero. All 259 are `source=trail_upper_bound` and globally new.
  Witness UBs are `13.374795503825057..14.605893028674872`, all strictly below
  `tau=14.606178797892962`; closest margin is
  `0.0002857692180899818`.
- **Science boundary:** `threshold_prunes=259` is the safe trail-UB path. The
  separate action counter is `actual_certified_prunes=0`: `255` failure-first
  actions made `33,413` exact probes / `66,826` child evaluations without a
  realized one-bit crossing. Science gain is exact global clause novelty only;
  no key/model/closure or attacker-valid entropy/domain gain is claimed.
- **State boundary:** the complete harvest is archived. A combined successor
  vault is unavailable only because `254+259=513`, exactly one above the
  512-clause cap; no pending or partial clause exists. The 24,576-byte bank
  evolves to `0203de9f…`, with receipt `9ecec7df…`. Bank conservation closes at
  `182,368→215,781`, delta `33,413`, equal to both probe count and outcome
  counters; variable 241 remains the sole zero record. Page 12 / lineage 25 are
  burned and must never be replayed.
- **Hypothesis:** support
  `H-PARENT-CENTERED-PAGE12-ROLLOVER-COMPOUNDING-091`; activate
  `H-PARENT-CENTERED-PAGE13-ROLLOVER-COMPOUNDING-092`.
- **Next action:** ingest all 259 clauses with zero solver work, bind the evolved
  bank and derive fresh bounded Page 13 / lineage 26 at the minimal active limit
  253. Do not replay Page 12, rearm crossing actions or raise cap/RAM to avoid a
  one-slot overflow.
- **Resources:** native wall `0.792959 s`, CPU `1.544974 s`, peak RSS
  `369,213,440 B`; runner wall `41.791541 s`; exactly one native call.
- **Artifacts:** authoritative
  [result](O1C0088_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json),
  SHA-256
  `f1f6807c99951eff9a274a882753e5d18867b56490de2f5dbd9646bf0cbe4ba0`;
  [interpretation](O1C0088_APPLE8_PARENT_CENTERED_CONTINUATION_INTERPRETATION_20260720.md);
  sealed
  [capsule](../runs/20260720_190040_615684_O1C-0088_apple8-parent-centered-continuation-v1/RUN.md),
  artifact-manifest SHA-256
  `8ae16f758ee4c5e1f489c7f9c5d40d2dc001037a9b215ca60f973432af953f84`.

## O1C-0089 — APPLE8 Page-13 causal rollover preparation

- **Recorded:** `2026-07-20T19:27+02:00` (`Europe/Berlin`).
- **Protocol:** with zero native/science calls, ingest all 259 fully emitted
  O1C-0088 clauses into the immutable causal attic, bind the exact final
  `0203de9f…` live bank and `9ecec7df…` state receipt, then deterministically
  project fresh bounded Page 13 / lineage 26 at minimal active limit 253.
- **Result:** all 259 occurrences are unique and globally novel against the
  prior 1,032-clause union. The new chunk is 259 clauses / 744,973 literals /
  2,981,119 B, SHA `d02b2ca0…`. The attic reaches 16 chunks / 1,291 unique /
  1,299 occurrences / 10 strict relations / 1,284 undominated. The prior union
  and relation set are exact prefixes; the new burst adds no subsumption pair.
- **Page 13:** 253 clauses / 711,355 literals / 2,846,623 B, SHA `4c1b7d5a…`.
  Composition is five structural roots, 43 pinned core and 205 new debt. All
  259 new clauses remain in the attic; 205 are resident and 54 nonresidents are
  explicitly hash/index recorded. Headroom is 259 clauses / 888,645 literals /
  5,541,985 B. Clause slots prove capacity for 256 actions plus three; literal
  and byte safety for unknown future emissions are not claimed.
- **State:** the 24,576-byte bank and 52,009-byte receipt match exactly; 255
  coordinates are eligible and variable 241 remains the sole zero record.
  Aggregate count is 215,781; variable 21 has maximum count 1,752. The
  fresh-seed parser is incompatible by design; live continuation is mandatory.
- **Claim boundary:** `CAUSAL_ATTIC_PAGE13_ROLLOVER_PREPARED`; enabling/mechanism
  only. Native solver/science/target/truth/reveal/refit/MPS/GPU calls are zero.
  No intent exists and Page 13 / lineage 26 remain unburned and unauthorized.
- **Cross-burst decision:** O1C-0085/86/88 clauses per 1,000 probes rise
  `0.7004→2.0192→7.7515`; all cross-burst clause/witness intersections and
  subsumption counts are zero. O1C-0088 is capacity-censored. Preserve the
  unchanged one-shot action operator for the next single call.
- **Next action:** finish Page-13-specific native/adapter/runner seals around the
  unchanged operator, then issue at most one lineage-26 call after one real
  preflight. Do not replay Page 12, change actions, rearm crossings or raise
  caps. Diversity residency is predeclared only for a zero-novelty outcome.
- **Validation:** focused 9-case gate passed; Ruff clean; Pyright zero errors and
  warnings. Atomic publication revalidated all ten final artifact seals.
- **Artifacts:** [interpretation](O1C0089_APPLE8_CAUSAL_ROLLOVER_INTERPRETATION_20260720.md),
  [cross-burst audit](O1C0088_PAGE12_CROSS_BURST_CAUSAL_AUDIT_20260720.md) and
  canonical
  [manifest](o1c89_page13_causal_rollover_seed_20260720/causal-rollover-preparation-manifest.json),
  SHA-256
  `467e519df281db4fc10de9223195dfedba9fd51edc93b40883f59fd3821e29ec`.
