# Results Index

This index separates instrumentation from real cryptanalytic evidence. A result is
listed at the strongest claim level actually supported by its retained artifact.

## Instrument and harness results

| ID | Result | Claim level | Metrics | Artifact |
|---|---|---|---|---|
| `O1C-0000-MEM` | Closed-gate MQAR-256 storage ladder | `INSTRUMENT` | Direct vault 100%; equal-cell holography 83.5938%; under-capacity CountSketch 70.1562% at 65,536 distractors over five seeds | [Run JSON](runs/quick.json) |
| `O1C-0000-EVID` | Synthetic weak-evidence accumulator | `INSTRUMENT` | Independent 55% stream reaches 99.8438% mean bit accuracy; chance and correlated controls do not accumulate | [Run JSON](runs/quick.json) |
| `O1C-0000-FLOW` | Provenance-typed operator chain | `INSTRUMENT` | Legal public-to-confirmation chain exists; post-reveal laundering is rejected | [Run JSON](runs/quick.json) |
| `O1C-0008-FOUNDATION` | Full-256 public-output attacker/teacher boundary and metric harness | `SMOKE` | 256 unknown bits; 72 contrasts across six families; 2,576 deployment features; 0 target-trace fields; random NLL exactly 256.0 bits; 1M-decoy and exact-beam harness | [Capsule](runs/20260717_031113_O1C-0008_full256-living-inverse-foundation/RUN.md) |
| `O1C-0011-CNF` | Exact target-independent full-256 public ChaCha20 CNF and causal bit map | `VALIDATION` infrastructure | 32,128 vars; 187,370 clauses; 656 operators x 32 exact bit ranges; public instance 640 public/0 key units; byte-identical compile; SAT/UNSAT/SAT self-tests | [Capsule](runs/20260717_054138_O1C-0011_full256-public-cnf-foundation-v1/RUN.md) |
| `O1C-0012-SENSOR` | Complete paired-assumption proof-prefix sensor feeding a bounded full-256 causal state | `TEST` mechanism | 512 polarity branches; 1,536 closed frontiers at 64/96/65; all 256 coordinates; 17,408 B state; exact signed swap antisymmetry; 0 transcripts/candidate keys | [Capsule](runs/20260717_065248_O1C-0012_full256-paired-causal-sensor-v1/RUN.md) |
| `O1C-0013-LIFECYCLE` | BUILD/CAL causal-reader freeze followed by fresh full-256 output-only inference | `TEST` lifecycle | 4 BUILD + 2 CAL + 2 sealed keys; reader reloaded before two entropy calls; all predictions persisted before reveal; 63/63 capsule members | [Capsule](runs/20260717_075537_O1C-0013_full256-multikey-causal-calibration-v1/RUN.md) |
| `O1C-0014-LIFECYCLE` | Exact-byte no-refit h96 replication on independent full-256 output-only targets | `VALIDATION` lifecycle | protocol freeze before 8 entropy calls; 8 factual plus 3 control predictions before any reveal; 124/124 capsule members; 0 reader changes/replays/sibling/GPU work | [Capsule](runs/20260717_084847_O1C-0014_full256-frozen-reader-blind-replication-v1/RUN.md) |

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
| `O1C-0007-MEM` | Upstream unary solver-evidence freeze with no candidate rows | `RETROSPECTIVE` | 12 registers; 266 B conservative logical-state bound; 162 B frozen binary; 672 complete target-blind A355 orders persisted before truth | [Report](runs/20260715_174537_O1C-0007_upstream-solver-evidence-bit-vault-freeze/artifacts/upstream_ising_retrospective.json) |
| `O1C-0007-FREEZE` | Exact selected decoder and future target-blind deployment template | `RETROSPECTIVE` | Selected `search_propagations/h1/signed-log1p/degree1/negative`; A355 rank 73; A356 complete order frozen with zero target/outcome reads | [Template](runs/20260715_174537_O1C-0007_upstream-solver-evidence-bit-vault-freeze/artifacts/selection/frozen_future_template.json) |
| `O1C-0012-STATE` | Coordinate-bound full-256 unary/ARX/holographic living state | `TEST` mechanism | 768 signed updates; 17,408 B exact serialization; 768 unary, 772 interaction and 512 holographic nonzeros; exact swap antisymmetry; 0 retained transcripts/keys | [State report](runs/20260717_065248_O1C-0012_full256-paired-causal-sensor-v1/artifacts/causal_bitfield.json) |
| `O1C-0013-READER` | Shared target-independent orientation over causal h96 proof features | `TEST` mechanism | selected on disjoint CAL: ridge 0.001, temperature 0.5, scale 1.0; 281,764 B static model; 58,368 B live target state; zero coordinate-specific parameters | [Frozen reader](runs/20260717_075537_O1C-0013_full256-multikey-causal-calibration-v1/artifacts/frozen_reader.json) |

## Replicated validation

`O1C-0004` exactly replicates the independently specified feature geometry and frozen
score/order commitments. `O1C-0005` demonstrates positive bounded-state transfer,
but the bank is full rank. `O1C-0006` corrects the codec, exactly reproduces two more
fields and establishes the high-fidelity full-basis ceiling under an irreversible
one-shot lifecycle. It also proves that ceiling is information-equivalent to and
larger than the matched direct table. `O1C-0007` establishes a genuine compact
non-dictionary state and freezes a prospective decoder, but its A355 selection-
adjusted result is negative and A356 is only target-/outcome-blind transductive
deployment from the same source capsule. None is yet a fresh recovery advantage.
`O1C-0002` remains a failed signal-transfer audit.

## Frozen tests and independently confirmed results

O1C-0008 freezes the full-width data and metric contract. O1C-0009 is the first
frozen efficacy test: its one-shot sealed lifecycle is valid, but all declared
readers calibrate to the exact random posterior. O1C-0010 independently and
prospectively tests its only post-reveal signed breadcrumb on 2,048 new keys with
no refit; the direction reverses to negative compression and fails every efficacy
control. This closes the tested raw end-output reader family. O1C-0007's historical
future decoder remains unevaluated on source-unseen paired-assumption events.
O1C-0011 now independently validates the complete full-width symbolic relation,
per-bit carry/clause ancestry and opposite-assumption instance contract needed to
generate those events. O1C-0012 executes all 512 branches and streams the resulting
proof prefixes into the bounded O1 state; its mechanism gates are independently
green, while its only known-key diagnostic is strongly negative. O1C-0013 then
learns orientation on disjoint known keys, freezes it, and produces a small positive
aggregate on two fresh targets. It is prospective evidence, but the panel is too
small to establish stable transfer or SOTA. O1C-0014 then reloads those exact bytes
on eight independent targets. Its aggregate remains positive, but the predeclared
target-robustness, paired-control and specificity gates fail, so it is explicitly
`NOT_REPLICATED`.

## Prospective full-256 inverse evidence

| ID | Result | Claim level | Metrics | Artifact |
|---|---|---|---|---|
| `O1C-0013-SIGNAL` | Frozen causal reader reduces aggregate code length on two sealed uniform full-round 256-bit keys | `TEST` prospective signal | 259/512 bits; NLL 255.911078 bit/key; compression +0.088922; shuffled compression -3.217332; target compressions -0.186702/+0.364545; 0 exact keys | [Sealed evaluation](runs/20260717_075537_O1C-0013_full256-multikey-causal-calibration-v1/artifacts/sealed_evaluation.json) |
| `O1C-0013-CONTROLS` | Public-evidence transforms do not inherit the small factual compression on the anchor key | `TEST` control | output-bit flip -0.272987 bit; wrong nonce -0.167376; byte rotation -0.040618; factual aggregate beats frozen shuffled reader by +3.306254 bit/key | [Result](runs/20260717_075537_O1C-0013_full256-multikey-causal-calibration-v1/artifacts/full256_multikey_calibration.json) |
| `O1C-0014-AGGREGATE` | Exact h96 bytes retain positive aggregate code-length direction on eight independent full-round keys | `VALIDATION` positive breadcrumb, not replicated | 1053/2048 bits; NLL 255.766216 bit/key; compression +0.233784; conditional z 1.819; shuffled -1.290981; best million-decoy rank 10,875; 0 exact keys | [Sealed evaluation](runs/20260717_084847_O1C-0014_full256-frozen-reader-blind-replication-v1/artifacts/sealed_evaluation.json) |
| `O1C-0014-DECISION` | Frozen-reader replication fails its predeclared robustness and specificity contract | `VALIDATION` negative | only 4/8 targets positive; paired primary-minus-shuffled z 0.838; output-bit-flip -0.212425, wrong nonce +0.045371, byte rotate +0.010570; classification `NOT_REPLICATED` | [Result](runs/20260717_084847_O1C-0014_full256-frozen-reader-blind-replication-v1/artifacts/full256_frozen_reader_replication.json) |
| `O1C-0014-BREADCRUMB` | Post-reveal pre-existing arm audit localizes the remaining direction to unary wavelengths | `POST_REVEAL` next-challenge diagnostic | h64 +0.139097, h96 +0.233784, h65 +0.188340 bit/key; ARX24 -0.374410, ARX24+Motif12 -0.355199; no O1C-0014 refit or result promotion | [Forensics](research/O1C0014_POST_REVEAL_FORENSICS_20260717.md) |

## Frontier and state-of-the-art results

None produced by this lab yet. O1C-0014 strengthens the aggregate causal breadcrumb
but is predeclared `NOT_REPLICATED`, not a stable frontier or state-of-the-art
claim. Existing sibling-project recoveries are baselines, not results of this
integration.

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
| `O1C-0007-N1` | The broad retrospective upstream panel does not establish decoder efficacy | `NEGATIVE_BOUND` | Selected A355 rank 73 looks favorable in isolation, but [exact enumeration](runs/20260715_174537_O1C-0007_upstream-solver-evidence-bit-vault-freeze/artifacts/calibration/a355_exact_label_null.json) of the frozen 152-view selection procedure gives `p=0.593505859375`; the null excludes pre-panel exploration and assumes random labels | Do not resweep A355 or promote the post-hoc rank-23/rank-26 controls; carry only the exact frozen decoder into fresh targets |
| `O1C-0007-N2` | Streamability alone does not resolve quantized ties | `MECHANISM_BOUNDARY` | Of 448 streamable views, only 152 survived the exact target-blind tie gate; the best tied streamable control had rank 26 but 3,328 score collisions beyond uniqueness | Require complete deterministic orders and explicit collision accounting before interpreting a compact accumulator |
| `O1C-0009-N1` | Linear direct, candidate-relative and teacher-distilled readers over full-round end-output features do not transfer under the declared calibration | `NEGATIVE_BOUND` | All four CAL-optimal scales are 0; on 128 broker-secret keys every arm has NLL 256.0, compression 0 and zero familywise transferable bits | Replicate the single signed-scale breadcrumb once, then replace end-output regression with paired public-CNF proof/propagation events |
| `O1C-0010-N1` | O1C-0009's signed direct end-output orientation is finite-panel selection noise, not a transferable sub-key signal | `NEGATIVE_BOUND` | Exact no-refit test on 2,048 new sealed keys: compression -0.019088 bit, conditional z -0.946, shuffled margin -0.017541 and output-permutation margin +0.000962; all efficacy gates fail | Close raw end-output regression; build exact full-256 public-CNF paired-assumption conflict/propagation/proof sensors |
| `O1C-0012-N1` | W52's fixed A465 `(7,1,4)` horizon mixture is not a calibrated full-256 inverse reader | `NEGATIVE_BOUND` | On one post-freeze known RFC key: 119/256 bits, NLL 342.779990, compression -86.779990 bit, million-decoy rank 999,898; A469 correction changes no bit sign | Keep the causal stream; learn sign and horizon weights across multiple known full-256 keys, freeze, then attack a fresh sealed target |
| `O1C-0012-B1` | Solver conflict cutoffs need not coincide with a proof event | `MECHANISM_BOUNDARY` | 1,472/1,536 frontiers have an event exactly at cutoff; explicit last-event gap max 4, mean 0.108073; final overshoot is billed and excluded | Define the sensor as the complete closed prefix at conflicts <= horizon; never fabricate an exact-cutoff counter |
| `O1C-0014-N1` | Positive aggregate h96 compression is not yet a replicated, target-robust or control-specific inverse channel | `VALIDATION` negative with breadcrumb | +0.233784 bit/key and conditional z 1.819, but 4/8 positive targets, paired z 0.838, mixed controls, 0 exact keys and 0 stable 8/8 coordinates | Freeze one h96+h65 two-wavelength successor and exact h96 baseline on 32 entirely new targets; never retune the O1C-0014 result |
