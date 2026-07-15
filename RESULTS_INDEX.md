# Results Index

This index separates instrumentation from real cryptanalytic evidence. A result is
listed at the strongest claim level actually supported by its retained artifact.

## Instrument and harness results

| ID | Result | Claim level | Metrics | Artifact |
|---|---|---|---|---|
| `O1C-0000-MEM` | Closed-gate MQAR-256 storage ladder | `INSTRUMENT` | Direct vault 100%; equal-cell holography 83.5938%; under-capacity CountSketch 70.1562% at 65,536 distractors over five seeds | [Run JSON](runs/quick.json) |
| `O1C-0000-EVID` | Synthetic weak-evidence accumulator | `INSTRUMENT` | Independent 55% stream reaches 99.8438% mean bit accuracy; chance and correlated controls do not accumulate | [Run JSON](runs/quick.json) |
| `O1C-0000-FLOW` | Provenance-typed operator chain | `INSTRUMENT` | Legal public-to-confirmation chain exists; post-reveal laundering is rejected | [Run JSON](runs/quick.json) |

## Real O1-O replay

| ID | Result | Claim level | Metrics | Artifact |
|---|---|---|---|---|
| `O1C-0000-REPLAY` | Read-only replay of session `2026-02-18_013412` | `INSTRUMENT` | 16 tasks, 54 typed events, deterministic bounded neutral ingestion; generated programs never executed | [Replay JSON](runs/o1o-2026-02-18-replay.json) |

## Verified publication source

| ID | Result | Claim level | Metrics | Artifact |
|---|---|---|---|---|
| `O1C-0000-SOURCE` | Fullround publication manifest verification | `INSTRUMENT` | 570/570 members; zero missing; zero mismatched | [Verification JSON](runs/fullround-source-verification.json) |
| `O1C-0003-SOURCE` | Honest dirty-source Direct12 dependency snapshot | `SMOKE` | 71/71 members; 9,882,690 bytes; zero progress/outcome reads | [Capsule](runs/20260715_123734_O1C-0003_direct12-source-snapshot/RUN.md) |

## Mechanistic signals

| ID | Result | Claim level | Metrics | Artifact |
|---|---|---|---|---|
| `O1C-0002-SIGNAL` | Validation selected the rank of horizon-8 solver propagations | `RETROSPECTIVE` | Validation ranks 79 and 8; mean 3.348 bits | [Frozen plan](runs/20260715_123236_O1C-0002_retrospective-reader-tournament/artifacts/frozen_reader_plan.json) |
| `O1C-0004-SHAPE` | Independent 133→532 temporal/XOR and A342 pair reconstruction | `VALIDATION` | 52 shards, 13,312 cells, 53,248 stages; all A348/A349 score/order commitments exact | [Reproduction](runs/20260715_130047_O1C-0004_direct12-532-reproduction/artifacts/direct12_reproduction.json) |
| `O1C-0005-BOUND` | O1-O-selected dense 4-bit multi-slot Bit-Vault | `VALIDATION` | A348-only selection; 6,668 B online state, zero clips; A349 rank-Spearman 0.990198 and top-32 overlap 0.71875; 86 receipt-bound orders; zero A349 labels | [Tournament](runs/20260715_135434_O1C-0005_bounded-spectral-memory-tournament/artifacts/bounded_memory_tournament.json) |
| `O1C-0005-DIST` | Distributed A272 spectral support transfers better than matched structural/null controls | `VALIDATION` | At K=2,048: A272 multi-slot 0.871477 Spearman versus low-degree 0.494256, best candidate-ID random 0.716923, single-A348 sparse 0.797225 | [Metrics](runs/20260715_135434_O1C-0005_bounded-spectral-memory-tournament/artifacts/tournament_metrics.json) |
| `O1C-0006-CODEC` | Corrected W46 word0-bits-20-through-31 Direct12 codec and exact historical replay | `VALIDATION` | A355/A356 fields and complete orders exact; 64 source members copied; zero sibling writes | [Bridge](runs/20260715_154553_O1C-0006_corrected-codec-adaptive-dc-bridge/artifacts/corrected_codec_bridge.json) |
| `O1C-0006-CEILING` | Adaptive DC-complete 6-bit full-basis streaming ceiling | `VALIDATION` | 8,014 B maximum logical state; worst Spearman 0.999224, Kendall 0.976426, top-32 0.96875, zero clips; 24/24 complete orders | [Metrics](runs/20260715_154553_O1C-0006_corrected-codec-adaptive-dc-bridge/artifacts/bridge_metrics.json) |

## Replicated validation

`O1C-0004` exactly replicates the independently specified feature geometry and frozen
score/order commitments. `O1C-0005` demonstrates positive bounded-state transfer,
but the bank is full rank. `O1C-0006` corrects the codec, exactly reproduces two more
fields and establishes the high-fidelity full-basis ceiling under an irreversible
one-shot lifecycle. It also proves that ceiling is information-equivalent to and
larger than the matched direct table. None is yet a fresh recovery advantage.
`O1C-0002` remains a failed signal-transfer audit.

## Frozen tests and independently confirmed results

None yet.

## Frontier and state-of-the-art results

None produced by this lab yet. Existing sibling-project recoveries are baselines,
not results of this integration.

## Negative bounds

| ID | Boundary | Claim level | Evidence | Breadcrumb |
|---|---|---|---|---|
| `O1C-0000-N1` | Equal-cell single-state holography is crosstalk-limited on MQAR-256 | `NEGATIVE_BOUND` | 83.5938% mean bit accuracy, 0/5 exact | Test structured slots/polyphase separation instead of more identical superposition |
| `O1C-0000-N2` | Repeating correlated weak evidence does not create independent information | `NEGATIVE_BOUND` | 55.8594% mean bit accuracy after 1,024 repetitions | Estimate effective evidence independence before assigning confidence |
| `O1C-0002-N1` | Selecting 1 of 119 readers on two validation targets is multiplicity-dominated | `NEGATIVE_BOUND` | Observed 3.348 validation bits; exact familywise null `p=0.6641`, null mean best 3.823 bits | Reduce the hypothesis class using independently frozen semantic groups and joint temporal/XOR geometry |
| `O1C-0002-N2` | `h8.search_propagations` alone does not transfer reliably | `NEGATIVE_BOUND` | A296 holdout ranks 240/90, mean 0.801 bits; W32 ranks 41/244/245/82, mean 1.104 bits; loses the primary control gate | Retain it as one channel, not a standalone reader; test profiles, differences and hypercube residuals |
| `O1C-0005-N1` | Sparse modes selected from one calibration field do not transfer compactly | `NEGATIVE_BOUND` | Global A348-energy K=2,048 reaches only 0.797225 A349 Spearman; near-exact transfer requires almost the full float bank | Allocate precision across dense structured registers before pruning coefficients |
| `O1C-0005-N2` | A compact candidate-indexed table is not admissible evidence for bounded associative memory | `MECHANISM_BOUNDARY` | 14 dictionary ceilings are reported and persisted but all retain 4,096 candidate entries and are structurally ineligible | Compare valid spectral state to the ceiling without letting the ceiling win O1-O selection |
| `O1C-0006-N1` | Literal O1C-0005 scales/addressing do not transfer through the corrected codec | `NEGATIVE_BOUND` | A355/A356 Spearman -0.08289/0.07760; top-32 0/0.03125 | Recalibrate only through a frozen label-free corrected-codec rule; do not spend a fresh target on the old template |
| `O1C-0006-N2` | Complete fixed-domain Walsh state is a table-equivalent validation ceiling, not compression | `MECHANISM_BOUNDARY` | 4,096 degrees over 4,096 cells; 8,014 B versus matched direct table 3,918 B; identical quantized orders | Move upstream to bit/carry/solver evidence and require a sub-3,918-byte non-dictionary successor |
