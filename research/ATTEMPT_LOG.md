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
