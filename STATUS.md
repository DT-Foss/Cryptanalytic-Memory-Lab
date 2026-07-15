# O1 Cryptanalytic Memory Lab — Current Status

- **Last updated:** 2026-07-15T12:33:22+02:00 (`Europe/Berlin`)
- **Lab commit:** `5f456c616b50458cba97a0201d636b5fdb743d32`
- **Research phase:** Stage 3 — independently frozen joint trajectory readers
- **Strongest internal result:** `RETROSPECTIVE / NEGATIVE_BOUND` — a real
  12-target, 12,288-stage reader tournament is complete and hash-bound; the first
  selected single-channel mechanism failed the transfer gate
- **Strongest external frontier anchors:** confirmed Threefish-1024 W39 complete
  domain and ChaCha20 A325 W46 strict-subset recovery; both remain read-only inputs
- **Active runs:** none
- **Last completed attempt:** `O1C-0002` — frozen retrospective reader tournament
- **Primary uncertainty:** whether independently specified joint temporal/XOR
  geometry transfers where validation-selected single-channel evidence did not
- **Blockers:** none

## Headline

The lab has crossed from scaffold into real solver telemetry. `O1C-0001` normalized
12 manifest-pinned episodes without labels. `O1C-0002` then fit 119 executable
TRAIN-only readers, froze one on VALIDATION, persisted complete holdout orders, and
only then opened holdout labels through a child-process broker. The selected
`h8.search_propagations` rank signal was positive but unstable: 0.801 mean bits on
the A296 holdout and 1.104 on W32 transfer, below the relevant controls. The exact
familywise validation null gives `p=0.664`, so the 3.348-bit validation result is
selection multiplicity, not a discovery claim.

## Active process table

| Attempt | PID | Started | Command | Progress | ETA |
|---|---:|---|---|---|---|
| None | — | — | — | — | — |

## Highest-ROI next actions

1. `O1C-0003`: pin the richer Direct12 dependency set into a lab-owned source
   ledger, explicitly recording that it comes from an uncommitted sibling tree.
2. Reimplement and hash-check the independent 532-dimensional temporal/XOR feature
   transform and frozen A342 two-view Laplacian score.
3. Use A272/A348 only for calibration, then freeze an O1 spectral/slot compression
   order for the already-unlabeled A349 4,096-prefix stream without reading progress.

## Recent attempts

| Attempt | Time | Hypothesis | Result | Claim level | Cost | Main breadcrumb | Artifact |
|---|---|---|---|---|---|---|---|
| `O1C-0002` | 2026-07-15 | A 57-feature reader selected on A296 validation transfers to disjoint A296/W32 targets | Gate failed; validation 3.348 bits, A296 holdout 0.801, W32 1.104; familywise `p=0.664` | `RETROSPECTIVE` | 119 readers; 65,536 exact null label pairs; zero solver/GPU work | Replace single-channel selection with independently fixed joint temporal/XOR geometry | [Run capsule](runs/20260715_123236_O1C-0002_retrospective-reader-tournament/RUN.md) |
| `O1C-0001` | 2026-07-15 | A296/A297 can be normalized without post-reveal access | 12 episodes, 3,072 cells, 12,288 stages, 57 features; 24/24 members verified; zero labels read | `SMOKE` | 0.360 s; zero solver/GPU work | The real observability experiment can run entirely offline | [Run capsule](runs/20260715_122529_O1C-0001_stage3-a296-a297-ingest/RUN.md) |
| `O1C-0000` | 2026-07-15 | The three architectures can share a typed, bounded and reproducible control seam | Harness complete; no cipher signal tested | `INSTRUMENT` | 42 tests; five synthetic seeds | Stage 3 is the first unresolved scientific gate | [First results](docs/FIRST_RESULTS.md) |

## Reproducibility anchors

| Artifact | SHA-256 |
|---|---|
| `runs/quick.json` | `755e0ebee06337ac576a19d8408e4f5d9ae5d29b0c87063b021210b5b29e39da` |
| `runs/o1o-2026-02-18-replay.json` | `2f106c488c7eab15aee1cbed80114f6de2c33a9a2858152b1e2dc373d2b8dac1` |
| `runs/fullround-source-verification.json` | `8920811c6424a9d81be36ae658bcbbc3f09f5c826f04c768e493ea33a5d8458b` |
| `O1C-0001` capsule manifest | `376e3b27f107d132421e29c2669f468a57c8417924928ce41badadf14d3dd05f` |
| `O1C-0002` capsule manifest | `b4a242708ae30481deed5346df519bb5123c7601fa6c58b6c06bd514be314ff9` |
| Stage-3 dataset | `ccd1c4e236cba798362745b0430beecf294599e1ac4332fd5d8ad4f8625161c1` |
| Frozen reader plan | `ae2bda0e6a337b5396cbbab2e72108c38f67543b137f2e266a4f3943d7d7a587` |

## Resume here

Read [Next actions](research/NEXT_ACTIONS.md), then the top active hypothesis in
[Hypotheses](research/HYPOTHESES.md). Do not restart the repository audit.
