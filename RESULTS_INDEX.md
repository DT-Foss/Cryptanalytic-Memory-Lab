# Results Index

This index separates instrumentation from real cryptanalytic evidence. A result is
listed at the strongest claim level actually supported by its retained artifact.

## Instrument and harness results

| ID | Result | Claim level | Metrics | Artifact |
|---|---|---|---|---|
| `O1C-0000-MEM` | Closed-gate MQAR-256 storage ceilings | `INSTRUMENT` | Direct vault 100% with a no-op haystack path, not learned selection; equal-cell holography 83.5938%; under-capacity CountSketch 70.1562% at 65,536 distractors over five seeds | [Run JSON](runs/quick.json) |
| `O1C-0000-EVID` | Synthetic weak-evidence accumulator | `INSTRUMENT` | Independent 55% stream reaches 99.8438% mean bit accuracy; chance and correlated controls do not accumulate | [Run JSON](runs/quick.json) |
| `O1C-0000-FLOW` | Provenance-typed operator chain | `INSTRUMENT` | Legal public-to-confirmation chain exists; post-reveal laundering is rejected | [Run JSON](runs/quick.json) |
| `O1C-0008-FOUNDATION` | Full-256 public-output attacker/teacher boundary and metric harness | `SMOKE` | 256 unknown bits; 72 contrasts across six families; 2,576 deployment features; 0 target-trace fields; random NLL exactly 256.0 bits; 1M-decoy and exact-beam harness | [Capsule](runs/20260717_031113_O1C-0008_full256-living-inverse-foundation/RUN.md) |
| `O1C-0011-CNF` | Exact target-independent full-256 public ChaCha20 CNF and causal bit map | `VALIDATION` infrastructure | 32,128 vars; 187,370 clauses; 656 operators x 32 exact bit ranges; public instance 640 public/0 key units; byte-identical compile; SAT/UNSAT/SAT self-tests | [Capsule](runs/20260717_054138_O1C-0011_full256-public-cnf-foundation-v1/RUN.md) |
| `O1C-0012-SENSOR` | Complete paired-assumption proof-prefix sensor feeding a bounded full-256 causal state | `TEST` mechanism | 512 polarity branches; 1,536 closed frontiers at 64/96/65; all 256 coordinates; 17,408 B state; exact signed swap antisymmetry; 0 transcripts/candidate keys | [Capsule](runs/20260717_065248_O1C-0012_full256-paired-causal-sensor-v1/RUN.md) |
| `O1C-0013-LIFECYCLE` | BUILD/CAL causal-reader freeze followed by fresh full-256 output-only inference | `TEST` lifecycle | 4 BUILD + 2 CAL + 2 sealed keys; reader reloaded before two entropy calls; all predictions persisted before reveal; 63/63 capsule members | [Capsule](runs/20260717_075537_O1C-0013_full256-multikey-causal-calibration-v1/RUN.md) |
| `O1C-0014-LIFECYCLE` | Exact-byte no-refit h96 replication on independent full-256 output-only targets | `VALIDATION` lifecycle | protocol freeze before 8 entropy calls; 8 factual plus 3 control predictions before any reveal; 124/124 capsule members; 0 reader changes/replays/sibling/GPU work | [Capsule](runs/20260717_084847_O1C-0014_full256-frozen-reader-blind-replication-v1/RUN.md) |
| `O1C-0016-LIFECYCLE` | Budget-corrected 32-key polyphase replication with complete truth persistence | `VALIDATION` lifecycle | protocol before entropy; all factual/control predictions before reveal; 32/32 independent outputs and commitments recompute; 680/680 members; every resource gate passes | [Capsule](runs/20260717_115325_O1C-0016_full256-polyphase-blind-replication-v2/RUN.md) |
| `O1C-0017-LIFECYCLE` | Reveal-delayed online learner with prediction-before-score freeze on full-256 synthetic episodes | `VALIDATION` mechanism lifecycle | clean commit; 8 BUILD then 16 disjoint evaluation episodes; five-arm predictions persisted before labels; 18/18 capsule members; 0 fresh entropy/sibling/MPS/GPU calls | [Capsule](runs/20260717_140953_O1C-0017_full256-online-self-discovery-v1/RUN.md) |
| `O1C-0018-LIFECYCLE` | Full-round public-only proof-pool reader and learned-picker gate | `TEST` lifecycle | clean commit; 4 BUILD then 2 disjoint DEVELOPMENT targets; prediction/slow-state freeze before labels; exact 3,072 branches; 51/51 capsule members; all structural/resource gates pass | [Capsule](runs/20260717_152827_O1C-0018_full256-online-real-gate-dev-v1/RUN.md) |
| `O1C-0019-REAL` | Artifact-only packet learner and autonomous BUILD-LOO picker gate | `RETROSPECTIVE` completed negative | `BUILD_LOO_NO_TRANSFER`; learned policy `-0.271090` bit mean; raw learned `+0.312764` but raw untrained `+0.371233`; 2,467.325 elapsed s; 362,528,768 B peak; verified capsule | [Result](research/O1C0019_O1C0022_FULL256_BRIDGE_RESULT_20260718.md) |
| `O1C-0019-INTERLOCK` | Read-only deferred handoff from sibling W52 to the frozen CPU gate | `INSTRUMENT` operational | 17 tests; real ACK after process/RAM/hash preflight; 24 live W52 processes found despite stale PID files; fork/exec lock retention and PID-bound power assertion verified; watcher PID `67247`; zero sibling writes | [Interlock config](configs/o1c0019_w52_interlock_v1.json) |
| `O1C-0020-LIFECYCLE` | Learned-mask MQAR-256 with gate and predictions frozen before unseen streams/truth | `VALIDATION` mechanism lifecycle | clean commit; 32 BUILD + 8 CAL + 4 EVAL seeds; 12 frozen cells; no oracle deployment mask; truth revealed once after prediction freeze; second invocation is no-replay; 21/21 capsule members verify | [Capsule](runs/20260717_211433_O1C-0020_selective-mqar-256-learned-gate-v1/RUN.md) |
| `O1C-0021-HARNESS` | Full-width bounded causal-evidence accumulator and one-shot sealed runner | `INSTRUMENT` pre-run freeze | source `4ba1cc6`; 352-byte O1 state; independent 273-byte/64-byte-table public FSM; exact FSM work 262,144 BUILD / 524,288 CAL / 1,835,008 EVAL lookups; 31 focused tests and three read-only audits clear; formal EVAL unused | [Frozen config](configs/causal_evidence_stream_256_v1.json) |
| `O1C-0022-REAL` | Frozen real O1C-0019 packet deltas into the exact addressed O1C-0021 vault | `RETROSPECTIVE` completed negative | `CROSS_COORDINATE_DILUTION`; K256 int8 `-1.181837` bits, raw float `-0.989808`, normalized `-1.577524`, unit-sign `-0.115191`; best post-reveal complement ceiling `120/210` A325 and `118/204` A526; 70.218 elapsed s; verified capsule | [Result](research/O1C0019_O1C0022_FULL256_BRIDGE_RESULT_20260718.md) |
| `O1C-0023-COMPOSER` | Deterministic O1-O successor composer over an O1C-0022 result | `INSTRUMENT` parked; no run/result | Source `aa17eed` remains reusable, but authoritative O1C-0022 is null. Autonomous failure bookkeeping does not improve recovery and is not executed | [Design](research/O1C0023_POSTRESULT_NATIVE_COMPOSER_DESIGN_20260718.md) |
| `O1C-0024-FRONTIER` | Exact global product-Bernoulli top-K decoder over all 256 key coordinates with post-freeze public ChaCha20 verification | `RETROSPECTIVE` mechanism validation | exact exhaustive widths 3/6/10; synthetic 20-round key at global rank 4 outside matched local cube; burned 65,536-key frontier frozen before one reveal; 0 exact hits; 28/28 capsule members and every budget gate verify | [Capsule](runs/20260718_035947_O1C-0024_exact-factorized-posterior-frontier-v1/RUN.md) |
| `O1C-0025-LOGIT-FRONTIER` | Lossless logit-native handoff into O1C-0024's exact global 256-bit frontier | `INSTRUMENT` parked; no scientific run/result | Source `b008e21` remains reusable for a future positive posterior. The authoritative O1C-0022 K256 slice is negative and is not decoded | [Design](research/O1C0025_LOGIT_FRONTIER_HANDOFF_DESIGN_20260718.md) |
| `O1C-0026-ANCESTRY-PAIR-V2` | Bounded 768D FAP ancestry-touch x proof-context proxy with dedicated self lane, all-256 pair derangement, scale-invariant offset ridge and exact 8-KiB reader+posterior state | `INSTRUMENT` / `RETROSPECTIVE_STRUCTURAL_ONLY`; conditional, unreserved, no label/key-signal result | source `0af57fb`; four immutable BUILD FAPs emit primary+shuffle `1024x768` in 1.609594 s at 105,955,328 B process peak; RMS ratio 1.008770, cosine 0.027591, identical only on 85 branch-empty rows; self touch 4.87x denser and 8.82x stronger than one offdiagonal cell; 55 focused+neighbor tests green, one optional skip; activates iff finalized O1C-0023 selects `proof_ancestry_pair_residual_v1` | [Structural probe](research/O1C0026_BUILD_ONLY_STRUCTURAL_PROBE_V2_20260718.md) |
| `O1C-0026-FORMAL-RUNNER` | Conditional BUILD-LOO ancestry-pair proxy | `INSTRUMENT` parked; no run/result | Source `7855492` remains unreserved. Its obsolete O1C-0023 selection prerequisite is not invoked on the null O1C-0022 field; any future ancestry-pair experiment must be justified as a new all256 evidence source | [Config](configs/proof_ancestry_pair_residual_run_v1.json) |
| `O1C-0027-POLYPHASE-STATE` | One-pass all-256 polyphase sufficient state with late-bound slot/temperature readers and explicit hot/cold parameter boundary | `VALIDATION` synthetic mechanism; no ChaCha signal or recovery claim | `POLYPHASE_SUFFICIENT_STATE_PASS`; 25,096 B/state independent of T; `float32[384,3,256]`; four normalized-distinct readers from one state hash with zero reingestion/writes; exact rechunk, branch-swap and serialization; three basis changes require replay; 0.094719 measured wall s, 39.390625 MiB peak RSS; 22/22 capsule members verify | [Capsule](runs/20260718_090248_O1C-0027_polyphase-sufficient-state-full256-v1/RUN.md) |
| `O1C-0028-HOT-ROUTING` | Byte-exact K256 packet→horizon-major→self-describing V2 state with strict O1-O-shaped hot/cold binding | `VALIDATION` synthetic mechanism; no ChaCha signal, recovery or authoritative O1C-0023 claim | `HORIZON_MAJOR_HOT_ROUTING_PASS`; 14/14 gates; 25,128 B/state; three dense groups totaling 9,216 B/encoding; 64 allocation repeats exact; two zero-replay hot bindings and 13 cold replay probes; 0.123936 measured wall s, 42.8125 MiB peak RSS; verified manifest | [Capsule](runs/20260718_103518_O1C-0028_horizon-major-hot-routing-full256-v1/RUN.md) |
| `O1C-0029-STACKED-HOT` | Hot calibration over the real O1C-0022 H64/H65/H96 packet field | `INSTRUMENT` parked; no run/result | Source `22d417c` remains reusable, but every authoritative K256 O1C-0022 arm is negative. A hot readout changes no evidence and is not the next paid experiment | [Config](configs/o1c29_stacked_hot_calibration_v1.json) |
| `O1C-0030-DIAGONAL-FRONTIER` | Incremental exact-frontier self-ancestry lamp over four consumed full-round BUILD FAPs | `RETROSPECTIVE_BREADCRUMB_NO_STRONG_GATE`; no fresh efficacy claim | source `e7c1bf5`; feature and prediction freezes precede labels/score; primary `-0.680620` bit/key and beats cumulative 0/4; deranged confidence control `+0.779642`; 0 exact keys in four native-logit top-65,536 frontiers; 7.455637 measured wall s, 62.70 MiB peak, 168,648 persistent B, zero solver/entropy/sibling/MPS/GPU; repeat invocation is no-replay | [Capsule](runs/20260718_134406_O1C-0030_incremental-diagonal-frontier-v1/RUN.md) |
| `O1C-0031/0032-A448-TRANSFER` | Literal sibling A448 proof-antecedent/A442 Borda byte-3 reader on the standard all-256 public relation | `DIRECT_TRANSFER` closed; not replicated | unchanged consumed ranks `47/239`; second baseline/proof/hybrid `242/236/239`; 103.588 measured wall s total; other 248 bits unassigned; no fresh target spent | [Result](research/A448_FULL256_BYTE3_TRANSFER_20260718.md) |
| `O1C-0033/0034-A465-A469-TRANSFER` | Exact A460/A462/A463 rank wavelengths, A465 cubic PoE and A469 bucket-local correction over retained all256 A448 fields | `DIRECT_TRANSFER` closed; not replicated | A465 `47/239`; A469 `56/239`; zero new solver stages/targets; strongest sibling ranking chain does not survive removal of the known complement | [Result](research/A465_A469_FULL256_TRANSFER_20260718.md) |
| `A296-FULL256-BYTE2` | Literal sibling H1/2/4/8 learned-clause/XOR byte cube on the standard all-256 public relation | `DIRECT_TRANSFER` instrument with closed efficacy | 256 candidates x 1,024 UNKNOWN stages per target; 46–56 s/cube; other 248 bits unassigned; unchanged model/helper; exact public-only measurement and post-freeze rank | [Result](research/A296_FULL256_BYTE2_TRANSFER_20260718.md) |
| `RESIDUAL-HANDOFF` | Exact little-endian all256 completion handoff to A325/W46 and A526/W52 with public ChaCha verifier | `INSTRUMENT` terminal boundary | A325 fixes coordinates 46..255 and searches 46 bits; A526 fixes 52..255 and searches 52 bits; any wrong fixed bit excludes the true key; current completion gates `115/210` and `110/204` | [Gate](research/RESIDUAL_BACKEND_ENTRY_GATE_20260718.json) |
| `O1C-0035-A526-BRIDGE` | Exact top-K O1 complement frontier at A526's native fixed-coordinate interface | `RETROSPECTIVE` current-posterior closed; adapter retained | 4 consumed BUILD folds x 5 frozen arms x 65,536 = 1,310,720 complements in 0.832 s at 45,989,888 B peak; MAP max `118/204`; post-reveal oracle beam max `123/204`; exact complement `0/20`; backend correctly not launched | [Result](research/O1C0035_A526_NATIVE_COMPLETION_FRONTIER_RESULT_20260718.json) |
| `O1C-0036-EIGHT-BLOCK-O1` | Existing bounded O1 core streams eight public full-round output blocks and queries the native A526 complement | `TEST` completed negative | 1,024 uniform training keys; 128 disjoint read-only sibling BUILD targets with known complement stripped; mean MAP `102.5/204`; accuracy `50.2451%`; compression `-0.393341` bit; exact top-65,536 complement `0/128`; 36.542 s, 339,542,016 B peak | [Result](research/O1C0036_EIGHT_BLOCK_A526_READER_RESULT_20260718.json) |
| `O1C-0037-RELATIONAL-CDCL` | Frozen O1 full-256 scores drive reversible first-encounter decisions in the unchanged exact public ChaCha20-R20 CNF | `TEST` consumed-target result plus post-reveal ceilings | exact truth guidance verifies the full key in 5,065 us / 0 conflicts; real O1 has 117/256 MAP and 0 recovery; K256 telemetry matches shuffled and is 2.123x internal wall; one wrong hint remains unresolved through 32,768 conflicts | [Result](research/O1C0037_RELATIONAL_GUIDED_SEARCH_RESULT_20260718.md) |
| `O1C-0038-RESIDUAL-CEILING` | Corrected exact-sign, O1-confidence-ordered residual completion through the same full-round relation | `POST_REVEAL_CEILING`; no attacker-valid recovery claim | full 256-bit key verified for residual widths 0/1/2/4/8 at 512 conflicts; width 8 closes in 89 conflicts / 135,441 us; width 9 remains UNKNOWN through 32,768 conflicts; 11.495 s and 139,575,296 B peak | [Result](research/O1C0038_EXACT_RESIDUAL_COMPLETION_RESULT_20260718.md) |
| `ALL256-EFFECT-SCREENS` | Direct solver/O1 combinations between the all256 field and retained residual backends | `RETROSPECTIVE` closed negative | terminal wrong-bit branch still UNKNOWN at 262,144 conflicts; failed cores 255..256 bits; inverse AUC 0.498/0.508; frozen DEVELOPMENT correction -14 bits; neighbor repeat +2 split -4/+6; W8 correlation -0.158 then -0.014 | [Result](research/ALL256_EFFECT_FIRST_TRANSFER_SCREENS_20260718.md) |
| `O1C-0022-REAL-FAP-ABI` | Real immutable O1C-0018 FAP traverses the production O1C-0019 reader and 352-byte causal-vault bridge without labels | `SMOKE` transport only | source hardening `2d8bf69`; K12; four reader replays x 36 slots/x 2,304 work = 9,216; exact repeat; real q-deltas differ from same-resource zeroed-330D ablation; real polarity delta/logit residual <=1e-6; duplicate byte invariance; finite 7x256 logits; untrained reader and no efficacy score | [Regression](tests/test_o1c19_causal_vault_real_artifact.py) |

## Operational failures

| ID | Result | Claim level | Metrics | Artifact |
|---|---|---|---|---|
| `O1C-0015-RUNTIME` | Polyphase replication exceeded its old soft resource ceilings after target reveal | `OPERATIONAL_FAILURE`; no scientific result | capsule 579/579; 32 generated, 32 revealed once in memory, 0 persisted reveal/evaluation records; all targets burned; CPU >1600 s, wall >1400 s, RSS >384 MiB, exact values unavailable | [Failed capsule](runs/20260717_103252_O1C-0015_full256-polyphase-blind-replication-v1/RUN.md) |

## Real O1-O replay

| ID | Result | Claim level | Metrics | Artifact |
|---|---|---|---|---|
| `O1C-0000-REPLAY` | Read-only replay of session `2026-02-18_013412` | `INSTRUMENT` | 16 tasks, 54 typed events, deterministic bounded neutral ingestion; generated programs never executed | [Replay JSON](runs/o1o-2026-02-18-replay.json) |
| `O1C-0022-O1O-BRIDGE` | Literal CAUSAL graph selection and public-FSM fragment assembly through native local O1-O | `INSTRUMENT` composition parity | native and dependency-free MessagePack paths byte-identical; exact 64-byte int8[4,8,2] table; KnowledgeEngine selects the bridge triplet; CodeAssembler emits the replay wrapper; final state is byte-equal to the 273-byte O1C-0021 reference; 10 native tests plus 4 subtests; zero external writes | [Bridge source](src/o1_crypto_lab/o1o_public_fsm_bridge.py) |

## Read-only sibling mechanism intake

| ID | Result | Claim level | Metrics | Artifact |
|---|---|---|---|---|
| `A539/A541-CLAUSE-INTAKE` | Prospective RACF-DES replication closes the tested additive single-position learned-clause marginal as a portable reader and identifies the next representation | `EXTERNAL_READ_ONLY` mechanism breadcrumb, not an O1C result | A539 first-panel raw geometric rank `1.312e12`; A541 all 5 readers lose both controls; 0/108 executed candidates recover; unchanged A539 raw/centered 24-target rank ratios `0.984864/0.991111` to exact discrete-uniform expectation | [Hash-bound intake](research/A539_A541_TRANSFER_20260718.md) |

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
| `O1C-0016-COMMON-MODE` | Global h65 proof difficulty is predominantly public-target amplitude, not key orientation | `POST_REVEAL` mechanism diagnosis | target-level primary/shuffled h65 compression corr 0.999905; shuffled-h65 logits are 0.38857049 x primary-h65; O1C14-to-O1C16 coordinate corr approximately 0 | [Forensics](research/O1C0016_POST_REVEAL_FORENSICS_20260717.md) |
| `O1C-0017-AUTONOMY` | O1 autonomously discovers a useful oriented channel among 330 anonymous raw channels and retains its 256 addressed readings | `VALIDATION` synthetic mechanism | 3286/4096 bits; +42.308742 bits mean compression; 80.224609% accuracy; 16/16 positive; +46.701393 over ablation, +42.764897 over shifted labels, +47.231321 over raw end-state O1 | [Result](runs/20260717_140953_O1C-0017_full256-online-self-discovery-v1/artifacts/online_self_discovery.json) |
| `O1C-0018-PICKER` | True reveal-delayed reward causes a small real route perturbation before hard coverage dominates | `POST_REVEAL` mechanism breadcrumb | true reward is best W1 on both targets at +0.326847/+0.160175 and beats shifted reward in all 6 cells; true-shifted IAUC margins +0.177087/+0.265706; mean W1 learned score share only about 0.17% | [Forensics](research/O1C0018_POST_REVEAL_FORENSICS_20260717.md) |
| `O1C-0018-ACCUMULATION` | Live Bit-Vault re-adds an already cumulative O1 query and over-integrates weak evidence | `POST_REVEAL` mechanism diagnosis | deployed exhaustive mean -1.284644 bits versus direct final O1 -0.093388; avoiding double integration removes 1.191256 bits of damage; final coverage-normalized logits improve to -0.322875 mean | [Forensics](research/O1C0018_POST_REVEAL_FORENSICS_20260717.md) |
| `O1C-0020-RETENTION` | A learned O1 gate routes explicit bindings into an exact addressed vault through a long public stream with T-independent model state | `VALIDATION` synthetic mechanism | 12/12 unseen cells recover 256/256 with TP=256/FP=0/FN=0 at H=0/65,536/1,048,576; complete 352-byte state is nested-length byte-exact; zero model O(T) state/index; all longest-stream controls fail | [Result](runs/20260717_211433_O1C-0020_selective-mqar-256-learned-gate-v1/artifacts/selective_mqar.json) |
| `O1C-0020-ROUTE-CERT` | Learned public-token routing is globally separated, not merely sampled cleanly | `VALIDATION` mechanism certificate | zero errors on 8,192 CAL tokens; sampled margin +0.468235; analytic worst-case margin +0.454628 over every legal family/payload/address/nuisance value; shuffled-label certificate fails | [Gate freeze](runs/20260717_211433_O1C-0020_selective-mqar-256-learned-gate-v1/artifacts/gate_freeze.json) |
| `O1C-0027-HOT-READOUT` | One bounded full-256 state supports materially distinct post-ingestion readers without replay | `VALIDATION` synthetic mechanism | four readers from one state hash; minimum normalized pairwise RMS 0.081663 versus collapsed-bank control 1.24e-16; 3,072 slot contributions plus 256 temperature scalings per switch; zero state writes/reingestion; byte-exact rechunking and exact branch oddness | [Result](runs/20260718_090248_O1C-0027_polyphase-sufficient-state-full256-v1/artifacts/result.json) |
| `O1C-0028-ADAPTER-CERT` | Complete O1C-0022 wire packets can enter one allocation-invariant V2 state without coordinate-order decay or the Torch training stack | `VALIDATION` synthetic mechanism certificate | pure-stdlib codec is byte-exact against pinned O1C19 producer; canonical/reversed ledgers yield one state hash; sparse coordinate-major negative control diverges; result `ed3517f...`; primary state `02837fe6...`; zero target/key/solver/sibling/GPU/MPS work | [Result](runs/20260718_103518_O1C-0028_horizon-major-hot-routing-full256-v1/artifacts/result.json) |
| `O1C-0024-BURNED-NULL` | Exact global decoding shows that the opened O1C-0016 target posterior has no actionable 65,536-key recovery concentration | `POST_REVEAL` burned diagnostic; no cipher signal | 65,536 unique nonincreasing-score keys; MAP Hamming 117; best Hamming 110 at rank 15,405; legacy full 16-bit cube floor 108 but exact key impossible; global score band only -251.968003 to -251.975124; 0/4,096 public-prefix matches | [Burned result](runs/20260718_035947_O1C-0024_exact-factorized-posterior-frontier-v1/artifacts/burned/result.json) |

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
`NOT_REPLICATED`. O1C-0015 supplies no scientific evidence: its computation
crossed the old resource ceilings after all 32 targets had been revealed in memory,
while no reveal/evaluation artifacts persisted. O1C-0016 repeats the unchanged
experiment on entirely new keys under corrected lifecycle accounting and answers
it negatively: both frozen unary readers and their fixed ensemble are null-like.
O1C-0017 then validates the replacement fast/slow architecture on a synthetic
anonymous-channel gate: the learned reader and Bit-Vault pass every frozen control,
while ablation, shifted labels, no training and raw holographic end state remain
null or negative. O1C-0018 then executes deterministic known-key full-round proof
pools. Its raw reader gate fails, while an early true-versus-shifted picker margin
survives all six cells. Exact replay localizes the failure to cumulative-query
double integration, nonstationary credits, hash-shortlisting, compulsory breadth
and forced spending; O1C-0019 changes those mechanisms before any new target.
O1C-0020 independently closes the exact-retention prerequisite: learned selection
plus a 64-byte addressed vault recovers all 256 explicit bindings after `2^20`
distractors in a 352-byte live state. This is synthetic storage/routing validation,
not evidence that ChaCha20 emits an oriented channel. O1C-0027 independently
validates one-pass hot-reader sufficiency. O1C-0028 then closes its deployment
seam: packet order is canonically transposed, the allocation-dependent V1
recurrence is cold-migrated to a self-describing 25,128-byte V2 basis, and
factory-bound readers cannot cross the evidence/basis boundary. Neither is
attacker-valid cipher evidence.

## Prospective full-256 inverse evidence

| ID | Result | Claim level | Metrics | Artifact |
|---|---|---|---|---|
| `O1C-0013-SIGNAL` | Frozen causal reader reduces aggregate code length on two sealed uniform full-round 256-bit keys | `TEST` prospective signal | 259/512 bits; NLL 255.911078 bit/key; compression +0.088922; shuffled compression -3.217332; target compressions -0.186702/+0.364545; 0 exact keys | [Sealed evaluation](runs/20260717_075537_O1C-0013_full256-multikey-causal-calibration-v1/artifacts/sealed_evaluation.json) |
| `O1C-0013-CONTROLS` | Public-evidence transforms do not inherit the small factual compression on the anchor key | `TEST` control | output-bit flip -0.272987 bit; wrong nonce -0.167376; byte rotation -0.040618; factual aggregate beats frozen shuffled reader by +3.306254 bit/key | [Result](runs/20260717_075537_O1C-0013_full256-multikey-causal-calibration-v1/artifacts/full256_multikey_calibration.json) |
| `O1C-0014-AGGREGATE` | Exact h96 bytes retain positive aggregate code-length direction on eight independent full-round keys | `VALIDATION` positive breadcrumb, not replicated | 1053/2048 bits; NLL 255.766216 bit/key; compression +0.233784; conditional z 1.819; shuffled -1.290981; best million-decoy rank 10,875; 0 exact keys | [Sealed evaluation](runs/20260717_084847_O1C-0014_full256-frozen-reader-blind-replication-v1/artifacts/sealed_evaluation.json) |
| `O1C-0014-DECISION` | Frozen-reader replication fails its predeclared robustness and specificity contract | `VALIDATION` negative | only 4/8 targets positive; paired primary-minus-shuffled z 0.838; output-bit-flip -0.212425, wrong nonce +0.045371, byte rotate +0.010570; classification `NOT_REPLICATED` | [Result](runs/20260717_084847_O1C-0014_full256-frozen-reader-blind-replication-v1/artifacts/full256_frozen_reader_replication.json) |
| `O1C-0014-BREADCRUMB` | Post-reveal pre-existing arm audit localizes the remaining direction to unary wavelengths | `POST_REVEAL` next-challenge diagnostic | h64 +0.139097, h96 +0.233784, h65 +0.188340 bit/key; ARX24 -0.374410, ARX24+Motif12 -0.355199; no O1C-0014 refit or result promotion | [Forensics](research/O1C0014_POST_REVEAL_FORENSICS_20260717.md) |
| `O1C-0016-DECISION` | Exact h96, reconstructed h65 and fixed equal-logit polyphase fail larger prospective transfer | `VALIDATION` negative | ensemble 4093/8192, -0.078249 bit/key, 11/32 positive, paired z -0.555; h96 -0.175000; h65 -0.033913; 0 exact keys; `NOT_REPLICATED / DO_NOT_PROMOTE` | [Sealed evaluation](runs/20260717_115325_O1C-0016_full256-polyphase-blind-replication-v2/artifacts/sealed_evaluation.json) |
| `O1C-0016-RANKS` | The frozen posterior has no useful byte, block or million-decoy advantage | `VALIDATION` negative | byte top1/top4/top16 4/16/61 versus null 4/16/64; no 16-bit top16; best 1M-decoy rank 45,147 has 32-try null probability 0.772 | [Forensics](research/O1C0016_POST_REVEAL_FORENSICS_20260717.md) |
| `O1C-0039-RELATION` | A BUILD-frozen target-specific signed proof-clause field transfers key-to-internal relation orientation to both DEVELOPMENT keys | `TEST` attacker-valid relation signal; no recovery claim | target accuracies 55.09%/56.99%; pooled 397/711 = 55.84%; key-rotated 52.88%; factor-rotated 49.51%; bounded fields 3,512/2,288 B; Full-256 recoveries 0 | [Result](research/O1C0039_PROOF_CLAUSE_RELATION_TRANSFER_RESULT_20260718.md) |
| `O1C-0041-CHAIN-RANK` | Branch-exclusive proof-chain identity concentrates complete true-key executions after one BUILD-only global rank-product orientation | `RETROSPECTIVE` joint-rank signal with control margin; fresh replication pending | DEVELOPMENT ranks 80/4097 and 998/4097; geometric 6.90% versus key rotation 27.02% and factor rotation 16.26%; 31.552 s; 131,629,056 B peak | [Result](research/O1C0041_ANTECEDENT_CHAIN_RANK_RESULT_20260718.md) |
| `O1C-0042-FRESH-CHAIN` | Exact O1C-0041 unique-leaf chain objective on one sealed fresh Full-256 key | `TEST` not replicated; no recovery | primary 1371/4097 (33.46%), key rotation 1399/4097, factor rotation 3385/4097; best-quarter gate failed; 7.435 s; 131,579,904 B peak | [Result](research/O1C0042_FRESH_ANTECEDENT_CHAIN_RANK_RESULT_20260718.md) |
| `O1C-0043-PARENT-CRITICALITY` | BUILD-fitted bounded reader over ordered RUP parent role and original functional-clause criticality | `CONSUMED_DIAGNOSTIC` joint-rank signal; fresh pending | DEVELOPMENT 5/4097 and 91/4097, geometric 0.52% versus best control 38.52%; unchanged consumed repeat 141/4097 versus controls 3623/3475; 63.609 s, 183,795,712 B peak | [Result](research/O1C0043_PARENT_CRITICALITY_RANK_RESULT_20260718.md) |
| `O1C-0044-FRESH-CRITICALITY` | Exact O1C-0043 reader on one sealed uniform Full-256 key | `TEST` prospective joint-rank transfer; no recovery | primary 54/4097 (1.318%, z +2.325), key rotation 3567/4097, clause rotation 2972/4097; 11.095 s, 142,262,272 B peak | [Result](research/O1C0044_FRESH_PARENT_CRITICALITY_RANK_RESULT_20260718.md) |
| `O1C-0045-LIVE-CRITICALITY` | Lossless local-factor compilation of O1C-0044 into reversible exact search | `CONSUMED_SEARCH_DIAGNOSTIC`; Full-256 attacker-valid, residual rows post-reveal | scores exact within 1.25e-14; Full-256 0/4; internal residual frontier 8, primary/key/clause 9; width-9 conflicts 281/69/129; no primary control margin | [Result](research/O1C0045_CRITICALITY_LIVE_SEARCH_RESULT_20260718.md) |
| `O1C-0046-KEY-ONLY-CRITICALITY` | Same frozen local factors with all variables observed but external decisions restricted to 126 key coordinates | `CONSUMED_SEARCH_DIAGNOSTIC`; Full-256 attacker-valid, residual rows post-reveal | Full-256 0/4; residual frontier unchanged at 8/9/9/9; primary conflicts fall to 43/87 at widths 8/9, but matched clause rotation remains better at 22/46 | [Result](research/O1C0046_KEY_ONLY_CRITICALITY_SEARCH_RESULT_20260719.md) |
| `O1C-0047-GLOBAL-RESIDUAL-BEAM` | Complete-state criticality ordering on nested exhaustive W8/W12/W16 cubes | `POST_REVEAL_CEILING`; 240 truth bits fixed | primary truth ranks 1/256, 5/4096, 50/65536 versus W16 rotations 60592/43059; primary top-256 contains unique verified key; 10.356 bits local search compression | [Result](research/O1C0047_GLOBAL_CRITICALITY_RESIDUAL_BEAM_RESULT_20260719.md) |
| `O1C-0048-PAIR-ENVELOPE` | Soft reversible global max-envelope decisions over 63 frozen key pairs | `CONSUMED_SEARCH_DIAGNOSTIC`; Full-256 rows attacker-valid, residual rows post-reveal | Full-256 0/4; residual maxima 8/9/9/9; primary conflicts W8/W9 75/155 versus internal 217/UNKNOWN, key 195/331, clause 89/167; frozen all-arm gate fails | [Result](research/O1C0048_PAIR_ENVELOPE_SEARCH_RESULT_20260719.md) |
| `O1C-0049-ONLINE-PAIR-CREDIT` | 630-byte live credit over the same 63 frozen pair groups | `CONSUMED_EFFECT_SCREEN`; Full-256 pre-reveal, residual rows post-reveal | Full-256 unchanged at 513 conflicts/10,802 decisions; W8/W9 improve 75/155→65/128, W10 regresses 310→320; absolute gate fails because short tickets receive zero delayed Full-256 backtrack credit | [Result](research/O1C0049_ONLINE_PAIR_CREDIT_SCREEN_RESULT_20260719.md) |
| `O1C-0050-DELAYED-PAIR-CREDIT` | Trail-resident delayed credit over the same 63 pair groups | `POST_REVEAL_MECHANISM_SCREEN`; exact W10 | exact W10 conflicts 310→302 (-2.58%), decisions 315→307; 302 conflict-owner undos, seven differentiated groups, 1,134 B bounded state; prospective gate passed | [Result](research/O1C0050_DELAYED_PAIR_CREDIT_SCREEN_RESULT_20260719.md) |
| `O1C-0051-DELAYED-W11-PROMOTION` | Unchanged delayed owner credit at the next residual frontier | `CONSUMED_POST_REVEAL_PROMOTION_SCREEN`; W11 | `UNKNOWN` at 512 conflicts/513 decisions/11,983,327 propagations; exact gate fails after one call, so no static/rotation/Full256 work runs; dominant owner flips `(143,144)` 227→1 and `(59,60)` 55→382 after freeing bit 177 | [Result](research/O1C0051_DELAYED_PAIR_CREDIT_PROMOTION_RESULT_20260719.md) |
| `O1C-0052-PATTERN-ACTION-CREDIT` | Four exact mask cells per frozen pair with trail-owner undo attribution | `CONSUMED_POST_REVEAL_PATTERN_ACTION_CREDIT_SCREEN`; W11 negative | `UNKNOWN` at 512 conflicts/513 decisions/12,066,879 propagations; 162/448 later selections reordered and 18 cells differentiated, but 502/513 decisions repeat; all visited cells receive negative credit | [Result](research/O1C0052_PATTERN_CREDIT_SCREEN_RESULT_20260719.md) |
| `O1C-0053-DEEPEST-SURVIVOR-SUPPORT` | One positive `+32` update to the deepest exact pair action surviving each conflict backjump | `CONSUMED_POST_REVEAL_SURVIVOR_SUPPORT_SCREEN`; W11 negative | `UNKNOWN` at 512 conflicts/513 decisions/12,068,568 propagations; 512 support updates and 16,384 units reorder 111 actions but differentiate only two groups; 2,646 B state | [Result](research/O1C0053_DEEPEST_SURVIVOR_SUPPORT_SCREEN_RESULT_20260719.md) |
| `APPLE-VIEW-0005-SPARSE-CARRY` | Sparse exact c31-identity certificates for complete wrong Full-256 candidates | `CONSUMED_FULL256_CANDIDATE_FILTER`; no key-generation/entropy claim | 20/20 exact wrong-candidate conflicts; every reason-DAG slice independently replays with 250–265/336 identities, best 250 (86 omitted); 5/5 truth controls complete | [Result](research/apple_view_5/apple_view_5_report.md) |
| `APPLE-VIEW-0006-PROOF-CREDIT-TRANSFER` | One-pass 1,346-byte proof-frequency/recency state frozen before disjoint Full20/Full256 candidate filters | `HELDOUT_CERTIFICATE_TRANSFER_WITH_SCHEDULER_LOSS`; no key-generation/entropy claim | raw learned order loses 1,268 vs best structural 1,031 total first-conflict switches; independently replayed learned certificates win 4/4 at 248/248/251/250 vs best structural 251/252/257/255, aggregate 997 vs 1,015 and immediate-public 1,013; zero held-out updates, all truth controls complete | [Result](research/apple_view_6/apple_view_6_report.md) |
| `APPLE-VIEW-0007-PROOF-EDGE-TRANSFER` | One-pass 113,570-byte proof-DAG edge/root/terminal state with one frozen static strongest-predecessor reader | `HELDOUT_STATIC_EDGE_SCHEDULER_NEGATIVE`; no key-generation/entropy claim | raw edge order loses 1,340 vs exact APPLE6 unary 1,268 and best structural 1,031; certificate 1,003 beats fixed 1,015 but loses unary 997 and cannot pass; all 28 wrong passes, proof replays, freeze checks and truth controls exact | [Result](research/apple_view_7/apple_view_7_report.md) |

## Frontier and state-of-the-art results

No cryptanalytic frontier result has been produced by this lab yet. O1C-0020 is the
first result satisfying architecture terminal (a): exact 256/256 long-stream
retention under a learned non-oracle route and exact bounded-state accounting. It
does not satisfy causal full-round evidence condition (b) or recovery condition
(c). O1C-0018 remains the first live full-round O1 picker gate but fails its raw-
reader criterion. O1C-0016 closes the earlier O1C-0014 aggregate as panel noise for
this frozen global unary reader family. O1C-0028 strengthens the bounded-state
architecture by making K256 packet transport allocation-invariant and reader
weights/temperature genuinely hot after one pass; it advances neither causal-
evidence condition (b) nor recovery condition (c).
O1C-0038 adds a post-reveal decoder ceiling: the exact public relation completes
an O1-ordered eight-bit residual in 135,441 us, while nine bits remain unresolved
through 32,768 conflicts. This is a real completion-mechanism frontier but not an
attacker-valid cryptanalytic frontier because the supplied 248-bit prefix is
constructed from revealed truth.
O1C-0039 adds the first attacker-valid held-out relational signal: its frozen
bounded proof field exceeds chance on both DEVELOPMENT keys and beats both pooled
endpoint-rotation controls. It does not yet produce entropy/rank/search reduction,
so it is a progress-ladder level-one signal rather than a cryptanalytic frontier
or key-recovery result.
O1C-0040 closes its direct candidate-sum conversion: raw truth is near median and
the only frozen structural-surprise correction is dominated by key rotation. The
O1C-0039 relation observation remains valid, but terminal clause occurrence is not
promoted to entropy, rank or search reduction.
O1C-0041 preserves branch-exclusive antecedent-chain identity and produces the
first complete-key joint-rank concentration in this branch: both consumed truth
keys beat the best quartile and the geometric primary rank beats both endpoint
rotations. Because the exact representation was discovered on consumed targets,
it remains a retrospective frontier breadcrumb until one unchanged fresh target
confirms it.
O1C-0042 performs that sole fresh test and does not confirm the frozen threshold.
Its small primary-over-rotation margin is retained as a representation breadcrumb,
but the exact unique-leaf sum is not promoted to live solver guidance.
O1C-0043 preserves the ordered causal information that leaf union erased. Its
BUILD-fitted 15-channel reader concentrates both consumed DEVELOPMENT keys and
one unchanged consumed repeat with large endpoint-control margins. It is the
current joint-rank frontier and now requires exactly one sealed fresh replication.
O1C-0044 supplies that prospective replication at `54/4097` with large margins
over both endpoint rotations. Because scoring still performs a complete forward
execution for every candidate, promotion now requires equal-work exact-search or
residual-domain reduction, not another rank panel.
O1C-0045 supplies that conversion losslessly. Its potential family expands the
consumed post-reveal completion frontier from residual width eight to nine, but
both rotations outperform primary and Full-256 remains unresolved. O1C-0046
changes only the decision target to key variables. Primary width-8/9 work drops
from 152/281 to 43/87 conflicts, proving that internal-variable branching was
costly, but the matched clause rotation still wins at 22/46. This is real
relational-completion mechanism progress below 256, not a primary-specific or
attacker-valid recovery frontier. Greedy local marginal scheduling is closed;
the frozen global rank signal must next enter bounded prefixes or factor
activation without refitting.
O1C-0047 isolates that global signal directly. On a complete nested W16 cube the
exact consumed key ranks `50/65536`; rotations rank `60592/65536` and
`43059/65536`, and only the primary top-256 beam contains the independently
verified public match. The measured 10.356-bit compression is a strong decoder
ceiling, but 240 truth bits define the cube. It authorizes a soft reversible
pairwise group/max-envelope adapter, not a claim of Full-256 recovery and not a
hard prefix copied from the opened truth or the decoy panel.
O1C-0048 performs that soft conversion. The exact frozen gate remains negative
because internal search reaches only W8 while all potential arms reach W9, so
the all-arm conflict tier is unavailable and Full-256 remains unresolved.
Nevertheless the primary arm is fastest among all arms at W8 and among every
successful arm at W9. This reverses O1C-0046's clause-control advantage and is a
real consumed specificity breadcrumb below the promotion gate. Close the exact
static disjoint-pair adapter; the next mechanism must learn bounded group credit
from attacker-visible live solver outcomes and improve absolute work.
O1C-0049 tests that literal mechanism with a fixed 630-byte state. It changes
exact search work at W8/W9 but not Full-256 and is worse at the shared W10
frontier, so it does not advance the recovery frontier. Its telemetry localizes
the defect: all Full-256 tickets expire on the next decision and none survives
to a later conflict/backtrack. Close this update equation and extend only the
credit horizon with a bounded eligibility trace.
O1C-0050 makes that one change and passes: exact W10 work falls from 310 to 302
conflicts with a 1,134-byte state. This is an absolute consumed residual-search
gain, not public-only key recovery. One unchanged W11 call now decides whether
the effect expands the exact frontier before controls and Full-256 are paid.
O1C-0051 answers no: delayed primary is `UNKNOWN` at the unchanged 512-conflict
W11 cap, and the frozen branch correctly skips all six follow-ups. Freeing bit
177 reverses the dominant conflict-owner group from `(143,144)` to `(59,60)`.
O1C-0052 then separates all four actions and genuinely changes 162 selections,
but it also remains `UNKNOWN`; every visited action cell is penalized and
`(59,60)` cycles its masks almost uniformly. Close negative-only undo credit.
O1C-0053 runs the one positive-only discriminator. All 512 conflict backjumps
produce a survivor update, but W11 remains `UNKNOWN`, only two groups
differentiate and 111 actions reorder. Close trail survival without a sign,
scale, group or cap sweep; exact learned-clause/first-UIP antecedent membership
is the next causal discriminator. A parallel global-prefix best-first design is
being frozen separately and has no efficacy result yet.
APPLE-VIEW-0005 supplies a separate exact candidate-filter frontier. Its depth-30
base plus a proof-replayed subset of only 250 high-carry identities rejects a
complete wrong 256-bit key while omitting 86 of the 336 missing equations. This
does not generate candidates, but it proves that sparse global carry consistency
exists and that eventual proof participation is a stronger scheduler signal than
immediate propagation gain. APPLE-VIEW-0006 transfers that relevance through a
fixed 1,346-byte state: its exact held-out proof cores are strictly smaller on
all four cases and aggregate 997 identities versus 1,015 for the best fixed
structural comparator and 1,013 for immediate public gain. The same frozen order
still reaches first conflict much later, 1,268 total switches versus 1,031.
This advances held-out exact certificate compression, not online stopping or key
recovery. APPLE-VIEW-0007 executes the single static proof-edge successor and
answers no: raw `1,340 > 1,268 > 1,031`. Its exact certificate `1,003` remains
below fixed `1,015` but above unary `997`, and certificate gain cannot pass.
Identity 11 is a repeated proof root with zero incident edge support and reaches
position 335. Close static/global strongest-predecessor scheduling; the
cheap deepest-survivor mechanism is now also closed by O1C-0053. The convergent
causal successor is exact conflict-antecedent membership, not an Apple reader or
credit-weight rescue sweep.
Existing sibling-project recoveries are baselines, not results of this integration.

## Negative bounds

| ID | Boundary | Claim level | Evidence | Breadcrumb |
|---|---|---|---|---|
| `APPLE-VIEW-0001` | Public feed-forward fixed-point projection and output-Hamming local descent | `EXPLORATORY_FULL256_NEGATIVE` | 32 deterministic Full-256 targets; -0.484 holdout keybits, AUC 0.50572, direction accuracy 0.49854, 0 recoveries; 21,108 R20 core evaluations | Output score admits descent without key-distance descent; close this fixed-point/local-fitness path | [Result](research/apple_view/apple_view_result.md) |
| `APPLE-VIEW-0002` | Exact GF(2) quotient after independently lifting all addition carries | `EXPLORATORY_FULL256_NEGATIVE` | 8 deterministic Full-256 targets; carry rank 512, exact key rank 0, exact recoveries 0; all 8,192 lifted equations validate | Independent carries span the entire public output and erase every linear key parity; only globally restoring carry recurrence by depth is a new test | [Result](research/apple_view_2/apple_view_2_report.md) |
| `APPLE-VIEW-0003` | Uniform exact carry recurrence by bit depth with sound forward three-valued rejection | `EXPLORATORY_FULL256_NEGATIVE` | 32 output-independent Full-256 probes across depths 0..31; depths 0..30 determine 0 final bits and reject 0/32, depth 31 determines 512 and rejects 32/32; 0 recovery/entropy claim | Forward-only bitwise carry truncation has a depth-31 cliff; require correlation preservation or two-ended constraint propagation | [Result](research/apple_view_3/apple_view_3_report.md) |
| `APPLE-VIEW-0004` | Exact bidirectional GAC through partial-carry Full20 constraints | `EXPLORATORY_FULL256_NEGATIVE` | depth 30 infers 3,720–3,850 variables beyond fixed input/output but rejects 0/4 wrong probes; depth 31 rejects 4/4 and retains truth; 18.12 s, 87.9 MB | One free c31 per each of 336 additions absorbs every local contradiction; test sparse joined carry identities rather than more local propagation | [Result](research/apple_view_4/apple_view_4_report.md) |
| `APPLE-VIEW-0007` | Static target-independent strongest-predecessor traversal over exact BUILD proof-DAG paths | `HELDOUT_STATIC_EDGE_SCHEDULER_NEGATIVE` | 113,570 B state; raw 1,340 vs unary 1,268 vs fixed 1,031; certificate 1,003 vs fixed 1,015 and unary 997; all wrong/truth controls exact | Static/global path relation delays repeated zero-edge roots; close without root/threshold/traversal sweep and move to live action-conditioned context | [Result](research/apple_view_7/apple_view_7_report.md) |
| `O1C-0052-N1` | Negative conflict-undo credit over 252 exact pair actions | `CONSUMED_POST_REVEAL_PATTERN_ACTION_CREDIT_SCREEN` negative | W11 `UNKNOWN` at 512 conflicts; 162 action reorderings, 18 differentiated cells, 502/513 repeated decisions; every visited cell penalized | Exact addressing creates tabu diversity but not causal blame; O1C-0053 has now closed the one survivor test, so move to exact antecedent membership | [Result](research/O1C0052_PATTERN_CREDIT_SCREEN_RESULT_20260719.md) |
| `O1C-0053-N1` | Deepest surviving trail action as a proxy for retained conflict causality | `CONSUMED_POST_REVEAL_SURVIVOR_SUPPORT_SCREEN` negative | W11 `UNKNOWN` at 512 conflicts; 512 support updates/16,384 units, 111 reorders and only two differentiated groups; post-result truth view puts the true mask supported/top in 4/8 active groups and 9,472/16,384 units on true masks | Close survival despite nonzero truth alignment: the diagnostic is consumed, did not close W11 and authorizes exact antecedent membership, not `+32` tuning | [Result](research/O1C0053_DEEPEST_SURVIVOR_SUPPORT_SCREEN_RESULT_20260719.md) |
| `O1C-0040-N1` | H16 branch-difference clause occurrence transfers structural relation accuracy but does not rank the target key | `POST_REVEAL` consumed diagnostic | raw primary ranks 1905/4097 and 2292/4097; surprise 1078/4097 and 1461/4097; key-rotated surprise 107/4097 and 423/4097 | Close occurrence and its one structural-surprise correction; retain exact proof stream and extract branch-exclusive signed antecedent chains |
| `O1C-0042-N1` | Unique signed leaf collapse does not reproduce its consumed-panel chain-rank concentration on one fresh key | `TEST` fresh negative | primary 1371/4097 versus frozen best-quarter gate; key/factor controls 1399/3385; exact freeze/reveal lifecycle | Close this leaf-sum reader; preserve ordered parent role and clause criticality next |
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
| `O1C-0016-N1` | Global h96/h65 proof-prefix orientation and fixed equal-logit compounding do not transfer | `NEGATIVE_BOUND` | 32-key ensemble -0.078249 bit/key, paired z -0.555, 11/32 positive; exact h96 -0.175000; null-like byte/block/decoy ranks; pooled exact-h96 z +0.134 | Remove common-mode nuisance and learn residual event geometry on whole-key cross-fits; do not run another sealed panel of these readers |
| `O1C-0016-N2` | A shuffled label fit can collapse to a scaled common-mode copy rather than an independent null geometry | `MECHANISM_BOUNDARY` | shuffled-h96 zero; shuffled-h65 = 0.38857049 x primary-h65 to residual <4e-9; both h65 signs and correct-bit count identical | Add a frozen norm/spectrum-matched balanced rotation in zero-sum coordinate space plus a common-mode-only sentinel |
| `O1C-0017-N1` | The raw final holographic O1 field is crosstalk-limited as a 256-polarity retention layer | `MECHANISM_BOUNDARY` | learned Bit-Vault +42.308742 bits and 80.224609%; same reader's raw end field -4.922579 bits and 50.244141%; paired margin +47.231321 bits | Keep O1 for learned streaming representation and the exact Bit-Vault for addressed retention; preserve the raw field as a sentinel in O1C-0018 |
| `O1C-0018-N1` | The frozen full-round learned reader does not establish raw portable key orientation | `NEGATIVE_BOUND` | learned exhaustive field -1.400387/-1.168901 bits; coordinate rotation mean +0.203963; only 0/2 raw targets positive | Fix accumulation and packet observability on consumed pools before allocating new targets; do not tune a coordinate rotation |
| `O1C-0018-N2` | The learned critic does not yet control the live route | `MECHANISM_BOUNDARY` | coverage contribution 0.5 versus first true reward 0.001955; about 0.17% W1 learned score share; true/shifted and cross-target W1 rank correlations 0.970-0.994 | Score all affordable addresses, use soft coverage plus finite starvation and add learned HOLD/STOP/DECAY |
| `O1C-0018-N3` | Historical BUILD action rewards are nonstationary and do not transfer as a static action map | `MECHANISM_BOUNDARY` | mean pairwise per-action reward corr 0.013824; LOO corr 0.023765; static score versus realized DEV reward corr 0.003751/0.038186 | Freeze reader first, bind credit to reader SHA and replay bounded BUILD memories into a state-conditioned critic |
| `O1C-0020-N1` | Closed-gate/no-op haystack handling is insufficient evidence for learned selective retention | `MECHANISM_BOUNDARY` | O1C-0020 evaluates every unified token; shuffled/untrained/ablated routes recover 0 exact cells, all-open fails all longest cells, CountSketch/holographic stores recover 0 exact cells, while the primary is 12/12 exact | Preserve learned routing plus addressed vault; next require learned confidence accumulation rather than merely explicit value writes |
| `O1C-0022-N1` | Hand-summed family masses destroy rather than reveal portable orientation in the consumed full-round BUILD pools | `NEGATIVE_BREADCRUMB` exploratory, not efficacy | 4 rank regimes x 8 feature families under BUILD-LOO beta-binomial orientation; every K and alpha negative; least-negative alpha16 K256 aggregate 519/1,024 correct but -213.404152 code bits | Do not replace the learned 330D O1C-0019 reader with a handcrafted 32-scalar collapse; preserve native incremental q-deltas and let O1C-0022 controls localize the next bottleneck |
| `O1C-0019/0022-N2` | Learned unary proof-packet routing and 352-byte addressed accumulation do not bridge all256 evidence into the residual recovery complement | `NEGATIVE_BOUND` completed real BUILD-LOO chain | Learned live policy `-0.271090` bit; learned raw reader loses untrained by `0.058470`; K256 int8 vault `-1.181837`; no precommitted raw arm exceeds `120/210` A325 or `118/204` A526 bits | Close the complete unary packet field. Do not hot-read, compose, frontier-decode or rescale it; require a genuinely new all256 evidence source before A325/A526 |
| `O1C-0030-N1` | Same-coordinate exact-cutoff confidence does not amplify summarized diagonal self-ancestry | `NEGATIVE_BREADCRUMB` retrospective, consumed BUILD only | primary mean `-0.680620` bit/key, cumulative `-0.097788`, primary-cumulative `-0.582832` and 0/4 fold wins; deranged confidence `+0.779642` is a control win; active cumulative rows are 312/574 correct only in an uncorrected post-result diagnostic and one fold reverses; 0/4 exact top-65,536 hits | Close this local hard-q lamp only. Preserve raw antecedent identity, signed interaction pairs, the learned full 330D reader and a recurrent global scout-to-focus policy |
| `A296-FULL256-N1` | The unchanged selected-eight shallow A296 reader does not generalize from residual W24/W28 cubes to byte-2 ranking with 248 other bits unknown | `NEGATIVE_BOUND` direct transfer with one fresh target | consumed ranks `118/61/9`; fresh rank `230/256`; geometric rank `62.129`; exact uniform rank-product lower tail `p=0.1766`; 201.244 s total | Keep the exact cheap cube adapter, but close this reader without byte/sign/coefficient/target resweeps; move to an all256-compatible channel and the exact residual entry boundary |
| `O1C-0027-N1` | Hot readout changes do not make the encoder, recurrence kernel or phase basis hot | `MECHANISM_BOUNDARY` | four weight/temperature readers query one unchanged state with zero replay, while three foreign encoder/kernel/phase commitments each raise `ReplayRequiredError`; collapsed-bank pseudo-diversity is rejected | Have O1-O classify proposals as hot `PolyphaseReadoutSpec` changes or cold replay-required basis changes; never reinterpret old state under a new basis |
| `O1C-0028-N1` | Vectorized complex64 V1 recurrence is not an allocation-invariant serialization ABI on this NumPy/macOS runtime | `MECHANISM_BOUNDARY` | identical O1C-0027 inputs can select two one-ULP state variants from pointer alignment; V2 freezes nine float32 rounding points, 64/64 fresh allocations agree, and legacy/foreign prefixes raise `ReplayRequiredError` | Preserve O1C-0027 bytes as immutable V1; cold-replay once into self-describing V2, then switch only factory-bound readers hot |
