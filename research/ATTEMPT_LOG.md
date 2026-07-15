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
