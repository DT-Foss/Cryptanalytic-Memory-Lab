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

## Mechanistic signals

None yet.

## Replicated validation

None yet.

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
