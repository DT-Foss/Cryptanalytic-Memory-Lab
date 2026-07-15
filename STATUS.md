# O1 Cryptanalytic Memory Lab — Current Status

- **Last updated:** 2026-07-15T12:05:14+02:00 (`Europe/Berlin`)
- **Lab commit:** `5bb39913bec2712ce1348bc5b9667b6d5798326b`
- **Research phase:** Stage 3 — frozen recovery-artifact ingestion
- **Strongest internal result:** `INSTRUMENT` — deterministic bounded-memory,
  weak-evidence, provenance and O1-O replay harnesses are operational
- **Strongest external frontier anchors:** confirmed Threefish-1024 W39 complete
  domain and ChaCha20 A325 W46 strict-subset recovery; both remain read-only inputs
- **Active runs:** none
- **Last completed attempt:** `O1C-0000` — integration-instrument baseline
- **Primary uncertainty:** whether any attacker-computable pre-result
  solver/carry/trajectory feature contains stable held-out information about the
  target ordering
- **Blockers:** none

## Headline

The scaffold is reproducible but has not yet crossed the cryptanalytic observability
gate. The immediate task is to convert manifest-verified full-round publication
artifacts into a provenance-typed dataset without importing target secrets or
post-result ranks into discovery.

## Active process table

| Attempt | PID | Started | Command | Progress | ETA |
|---|---:|---|---|---|---|
| None | — | — | — | — | — |

## Highest-ROI next actions

1. `O1C-0001`: select the best manifest-pinned publication family and implement
   its Stage-3 dataset adapter.
2. Extract the first attacker-computable pre-result feature stream with a matched
   shuffled/control arm and immutable split assignment.
3. Run the cheapest discriminating train/validation experiment before committing
   compute to a frozen test.

## Recent attempts

| Attempt | Time | Hypothesis | Result | Claim level | Cost | Main breadcrumb | Artifact |
|---|---|---|---|---|---|---|---|
| `O1C-0000` | 2026-07-15 | The three architectures can share a typed, bounded and reproducible control seam | Harness complete; no cipher signal tested | `INSTRUMENT` | 42 tests; five synthetic seeds | Stage 3 is the first unresolved scientific gate | [First results](docs/FIRST_RESULTS.md) |

## Reproducibility anchors

| Artifact | SHA-256 |
|---|---|
| `runs/quick.json` | `755e0ebee06337ac576a19d8408e4f5d9ae5d29b0c87063b021210b5b29e39da` |
| `runs/o1o-2026-02-18-replay.json` | `2f106c488c7eab15aee1cbed80114f6de2c33a9a2858152b1e2dc373d2b8dac1` |
| `runs/fullround-source-verification.json` | `8920811c6424a9d81be36ae658bcbbc3f09f5c826f04c768e493ea33a5d8458b` |

## Resume here

Read [Next actions](research/NEXT_ACTIONS.md), then the top active hypothesis in
[Hypotheses](research/HYPOTHESES.md). Do not restart the repository audit.
