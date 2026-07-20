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
| `O1C-0054-GLOBAL-FACTOR-BOUND` | Admissible independent factor maxima over all partial key prefixes with an unconditional width-256 public Full256 beam | `CONSUMED_POST_REVEAL_GLOBAL_BOUND_SCREEN`; Full256/W11 negative | Full256 0/256, truth first lost at pair stage 5, final top/min Hamming 120/116; W11 1,024 pops/14 forwards/zero certified leaves; 24,624 B logical Full256 state | [Result](research/O1C0054_GLOBAL_FACTOR_BOUND_SCREEN_RESULT_20260719.md) |
| `O1C-0055-LEARNED-CLAUSE-CREDIT` | Exact minimized learned-clause membership with `-32` on every represented live-owner action | `CONSUMED_POST_REVEAL_EXACT_LEARNED_CLAUSE_SCREEN`; W11 negative | `UNKNOWN` at 512 conflicts/513 decisions/12,083,477 propagations; all 512 clauses match, but only 18 unique cells/seven groups differentiate; 2,662 B state | [Result](research/O1C0055_LEARNED_CLAUSE_CREDIT_SCREEN_RESULT_20260719.md) |
| `O1C-0056-CLAUSE-ROLE-CREDIT` | One fixed `-32` update to the deepest exact live-owner role in each matched learned clause | `CONSUMED_POST_REVEAL_EXACT_CLAUSE_ROLE_CREDIT_SCREEN`; W11 negative | `UNKNOWN` at 512 conflicts/513 decisions/12,013,641 propagations; all 512 clauses select exactly one current-level role, discarding 2,150/2,662 matched members; 508 multi-member clauses, zero ties, 18 cells/seven groups, 2,662 B state | [Result](research/O1C0056_CLAUSE_ROLE_CREDIT_SCREEN_RESULT_20260719.md) |
| `O1C-0057-MULTIBLOCK-CRITICALITY` | Unchanged O1C-0043 parent-criticality reader compounded across 1/2/4/8 public blocks from one fresh uniform Full-256 target | `MULTIBLOCK_PARENT_CRITICALITY_COMPOUNDING_TRANSFER`; prospective scorer/orderer, no key generation or recovery | primary truth ranks 8/7/1/1 of 4,097; prefix-8 key/clause rotations 3581/4037; truth z +5.57888245; ~12.000352 rank bits inside supplied panel; 95.8946 s, 193,544,192 B peak | [Result](research/O1C0057_MULTIBLOCK_PARENT_CRITICALITY_RANK_RESULT_20260719.md) |
| `O1C-0058-MULTIBLOCK-BIT-VAULT` | Signed one-bit finite differences around the highest-scoring eight-block decoy streamed into a 256-cell vault | `MULTIBLOCK_BIT_VAULT_NO_DIRECTIONAL_TRANSFER`; fresh Full-256 negative conversion test | base/primary prefix-8 correct bits 127/127, gain 0, longest confidence prefix 0; controls 127/128; all 13 candidates match 0/8 blocks; 99.077 s, 211,124,224 B peak, 2,048 B primary state | [Result](research/O1C0058_MULTIBLOCK_BIT_VAULT_GRADIENT_RESULT_20260719.md) |
| `O1C-0061-JOINT-SIEVE-BASELINE` | Exact eight-block shared-key CNF with the frozen O1C-0057 potential under a corrected soft-stop conflict ledger | `EXACT_JOINT_SCORE_SIEVE_ACTIVE_NO_RECOVERY`; active bound mechanism, not a search-space-gain claim | requested 512/billed 513 conflicts; material pre-model bound drop 267.511666784; zero trail prunes, no complete model/key; 0.419657 s native, 383,713,280 B native peak | [Result](research/O1C0061_MULTIBLOCK_JOINT_SCORE_SIEVE_SOFT_STOP_RESULT_20260719.json) |
| `APPLE-VIEW-0008-MATCHED` | Exact public P20 and cross-block key-lane consequences added to the O1C61 body at matched target/potential/threshold/work | `APPLE_VIEW_0008_STRICT_INCREMENTAL_EFFECT_NO_RECOVERY`; first certified Full-256 trail-pruning/search-branch removal in this line | requested 512/billed 513 both arms; minimum UB 24.7944466611→13.1979307788 below threshold 14.6061787979; trail prunes 0→6; decisions 9166→4471; propagations 1227877→1178185; no key/truth read | [Result](research/apple_view_8/apple_view_8_matched_result.json) |
| `O1C-0062-APPLE8-4K` | First frozen 4,096-conflict promotion of APPLE-VIEW-0008 | `O1C62_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT`; callback/lifecycle defect, no retry | one native call; invalid disconnect masked an exception while solver was active; no native result/key/truth read | [Result](research/O1C0062_APPLE8_CROSSBLOCK_SIEVE_4K_RESULT_20260719.json) |
| `O1C-0063-APPLE8-4K-REPAIR` | Lifecycle-safe teardown and pending no-good backtrack retention over unchanged O1C62 science | `O1C63_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT`; high-confidence guarded-memory stop, no retry | repaired path survives 17.763142674 s versus O1C62's ~1 s; old wrapper loses cause; no native result/key/truth read | [Diagnosis](research/O1C0063_RESOURCE_WATCHDOG_DIAGNOSIS_20260719.md) |
| `O1C-0064-APPLE8-4K-RESOURCE` | Cause-preserving telemetry with unchanged science under a 1-GiB/45-s envelope | `O1C64_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT`; exact memory boundary, no retry | `watchdog_memory` after 29.804627625 s; observed 1,040,285,696 B at guarded 1,040,187,392 B; no native result/key/truth read | [Result](research/O1C0064_APPLE8_CROSSBLOCK_SIEVE_4K_RESOURCE_FIX_RESULT_20260719.json) |
| `APPLE-VIEW-0009-EXACT-GROUPED-BOUND` | Deterministic score-aware exact width-6 compatibility groups over the frozen public eight-block potential | `PUBLIC_EXACT_GROUPED_BOUND_STRICTLY_DOMINATES_PAIR_RELAXATION_NO_SEARCH_CLAIM`; positive bound mechanism | root UB 269.7472723039718→262.68644197084643; groups 3805→2885; rows 265256→176912; indexed bytes 2510008→1710776; zero solver/truth | [Result](research/APPLE_VIEW_0009_EXACT_GROUPED_BOUND_RESULT_20260719.json) |
| `O1C-0065-APPLE8-WIDTH6-GROUPED` | Exact APPLE-VIEW-0009 width-6 bound integrated into the repaired native APPLE8 Full-256 sieve at matched 512/513 work | `O1C65_GROUPED_WIDTH6_EFFICACY_RETAINED`; tighter bound and smaller logical cache, no strict pruning/search gain or recovery | root UB 292.30611344510277→262.68644197084643; minimum UB 13.197930778790159→12.934208247009447; cuts 6→6; decisions 4471→4471; propagations 1178185→1178185; cache 60456→23080 B; peak RSS 388644864→386547712 B contextual; no key/truth read | [Result](research/O1C0065_APPLE8_WIDTH6_GROUPED_SIEVE_RESULT_20260719.json) |
| `O1C-0066-APPLE8-EPISODIC-VAULT` | Canonical score-threshold no-goods persisted across fresh bounded APPLE8 solver episodes with no solver-local state replay | `EPISODIC_VAULT_OPERATIONAL_TERMINAL`; positive bounded efficacy before the operational stop, neither a scientific negative nor recovery | completed ep0 vault 0→6 clauses / 17,804 literals / 71,431 B; ep1 6→12 with +6 novel / +17,257 literals / 1 duplicate / 140,483 B; at requested 512 decisions 4471→4666, propagations 1178185→1230568, minimum UB 12.934208247009447→7.973483108047071, peak RSS 388907008→389234688 B; ep2 exceeds false +1/513 cap (`solve>=514`, overshoot `>=2`) and stdout is lost; 3 calls/intents, 2 completed, requested 1536/billed 1025, no key/truth | [Result](research/O1C0066_APPLE8_EPISODIC_VAULT_RESULT_20260719.json) · [Capsule](runs/20260719_135856_O1C-0066_apple8-episodic-vault-v1/RUN.md) |
| `O1C-0067-APPLE8-VAULT-CONTINUATION` | One correctly billed sealed continuation from O1C-0066's retained 12-clause vault | `EPISODIC_VAULT_SATURATED_NO_GAIN`; exact reader/seed/horizon fixed point, not global vault exhaustion or recovery | lineage ordinal 3/local 0; requested/actual/billed 512/514/514; one 2,951-literal input duplicate, SHA `b5da89ef…`, matching vault index 7 (zero-based; eighth clause); vault unchanged at 12 clauses/35,061 literals/140,483 B; decisions 4,517 (-149), propagations 1,192,529 (-38,039), minimum UB 9.111031965569408 (+1.1375488575223374); 0.333463 s native wall, 392,609,792 B peak; no key/truth/reveal/MPS/GPU | [Result](research/O1C0067_APPLE8_EPISODIC_VAULT_CONTINUATION_RESULT_20260719.json) · [Interpretation](research/O1C0067_APPLE8_EPISODIC_VAULT_CONTINUATION_INTERPRETATION_20260719.md) · [Capsule](runs/20260719_152601_O1C-0067_apple8-vault-continuation-v1/RUN.md) |
| `O1C-0068-APPLE8-COMPLEMENTARY-PHASE` | One fresh phase-0 complementary reader from O1C-0067's sealed 12-clause vault at matched bounded work | `EPISODIC_VAULT_COMPLEMENTARY_PHASE_GAIN`; large distinct exact-exclusion population and meaningful mechanism frontier, not recovery, UNSAT or global exhaustion | local 0/lineage 4; requested/actual/billed 512/512/512, zero overshoot; 195 fully emitted, 190 novel, 5 duplicates, pending 0; vault 12→202 clauses, 35,061→599,728 literals, 140,483→2,399,911 B, SHA `cd523334…`; decisions 1,330, propagations 31,944,523, minimum/root UB 12.8607806294803/262.68644197084643; 5.331635 s native wall, 5.925889 s CPU, 397,099,008 B peak; status `UNKNOWN`, no model/key/truth/reveal/MPS/GPU | [Result](research/O1C0068_APPLE8_COMPLEMENTARY_PHASE_RESULT_20260719.json) · [Interpretation](research/O1C0068_APPLE8_COMPLEMENTARY_PHASE_INTERPRETATION_20260719.md) · [Capsule](runs/20260719_161838_O1C-0068_apple8-complementary-phase-v1/RUN.md) |
| `O1C-0069-APPLE8-ALTERNATING-READER` | One explicit forced-phase-1 read from O1C-0068's sealed 202-clause mixed-reader vault | `EPISODIC_VAULT_ALTERNATING_READER_NO_GAIN`; exact passive phase-1 fixed point, not vault-global exhaustion or recovery | local 0/lineage 5; requested/actual/billed 512/514/514; one 2,951-literal input duplicate at zero-based vault index 7/eighth clause, 0 novel; vault unchanged at 202 clauses/599,728 literals/2,399,911 B, SHA `cd523334…`; decisions 4,517, propagations 1,192,529, minimum/root UB 9.111031965569408/262.68644197084643; native trace SHA `676386a0…` exactly equals O1C-0067 despite 190 extra clauses; 0.367456 s native wall, 1.080018 s CPU, 398,032,896 B peak; no key/truth/reveal/MPS/GPU | [Result](research/O1C0069_APPLE8_ALTERNATING_READER_RESULT_20260719.json) · [Interpretation](research/O1C0069_APPLE8_ALTERNATING_READER_INTERPRETATION_20260719.md) · [Capsule](runs/20260719_170824_O1C-0069_apple8-alternating-reader-v1/RUN.md) |
| `O1C-0070-APPLE8-VAULT-PHASE-READER` | One target-free-derived suffix-cut majority field applied as per-variable polarity over O1C-0069's sealed 202-clause vault | `EPISODIC_VAULT_ACTIVE_PHASE_READER_NO_GAIN`; active-not-inert steering but failed key/novel-clause gate, not recovery or global exhaustion | local 0/lineage 6; requested/actual/billed 512/514/514; reader `139/116/1`, 255 phase calls, polarity only; 0 emitted/novel/duplicate; vault unchanged at 202 clauses/599,728 literals/2,399,911 B, SHA `cd523334…`; decisions 2,297, propagations 1,169,826, minimum/root UB 18.846601115977638/262.68644197084643; trace `5c5fb773…` differs from O1C-0069 `676386a0…`; 0.316808 s native wall, 406,568,960 B native peak; 16.315104458 s runner, 326,664,192 B runner peak; no key/truth/reveal/MPS/GPU | [Result](research/O1C0070_APPLE8_VAULT_PHASE_READER_RESULT_20260719.json) · [Interpretation](research/O1C0070_APPLE8_VAULT_PHASE_READER_INTERPRETATION_20260719.md) · [Capsule](runs/20260719_181048_O1C-0070_apple8-vault-phase-reader-v1/RUN.md) |
| `O1C-0071-APPLE8-VAULT-RANKED-DECISION` | One target-free-derived 255-variable confidence order applied through `cb_decide` over O1C-0070's sealed 202-clause vault | `EPISODIC_VAULT_ACTIVE_RANKED_DECISION_NO_GAIN`; strong order control but static same-sign reassertion creates a propagation furnace and fails the key/novel-clause gate | local 0/lineage 7; requested/billed 512/513, status 0, one call, no phase; callback 763 calls / 499 nonzero / 264 zero / 255 unique / 244 redecisions / first fallback 256; 0 emitted/novel/duplicate and no model; vault unchanged at 202 clauses/599,728 literals/2,399,911 B; versus O1C-0070 decisions 2,297→763 (-1,534, -66.78%), propagations 1,169,826→91,260,183 (+90,090,357, 78.01x), minimum UB 18.846601115977638→19.297551436176224 (+0.45095), native wall 0.316808→14.818087 s (46.77x); tail ranks 249..255 add 1/3/7/15/31/62/125 redecisions while ranks 1..248 form a callback-visible stable prefix and are never returned twice | [Result](research/O1C0071_APPLE8_VAULT_RANKED_DECISION_RESULT_20260719.json) · [Interpretation](research/O1C0071_APPLE8_VAULT_RANKED_DECISION_INTERPRETATION_20260719.md) · [Tail analysis](research/O1C0071_RANKED_DECISION_TAIL_CASCADE_ANALYSIS_20260719.json) · [Capsule](runs/20260719_192742_O1C-0071_apple8-vault-ranked-decision-v1/RUN.md) |
| `O1C-0072-APPLE8-VAULT-BACKTRACK-RELEASE` | The unchanged frozen O1C-0071 rank consumed monotonically, with every signed literal returned at most once and permanently delegated after backtrack | `EPISODIC_VAULT_BACKTRACK_RELEASE_MECHANISM_WORK_GAIN_NO_RECOVERY`; bounded release removes the reassertion furnace and passes its matched-work mechanism gate, but yields no recovery, entropy reduction or novel exact clause | local 0/lineage 8; requested/actual/billed 512/512/512, status 0, exactly one call, no phase; callback 1,155 calls / 255 nonzero / 900 zero / 255 once-returns / 255 guided releases / 0 redecisions / first fallback 256; 0 emitted/novel/duplicate and no model; vault unchanged at 202 clauses/599,728 literals/2,399,911 B; versus O1C-0071 decisions 763→1,155 (+392), propagations 91,260,183→5,763,035 (-85,497,148; 15.8354379246x or 93.6850% reduction), minimum UB 19.297551436176224→19.57599384995442; 23.258629542 s end-to-end, 286,539,776 B runner peak | [Result](research/O1C0072_APPLE8_VAULT_BACKTRACK_RELEASE_RESULT_20260719.json) · [Capsule](runs/20260719_204421_O1C-0072_apple8-vault-backtrack-release-v1/RUN.md) |
| `O1C-0073-APPLE8-VAULT-RELEASE-CONTRAST` | After exhausting O1C-0072's immutable original rank, return each genuinely released coordinate's hard opposite at most once, deferring assigned entries without loss | `EPISODIC_VAULT_CAPACITY_TERMINAL`; fail-closed operational archive stop after discovering a large novel exact-exclusion population, not persisted gain, recovery, entropy reduction, UNSAT or threshold-region exhaustion | local 0/lineage 9; requested/actual/billed 512/179/179; all 255 originals and 255 contrasts returned, two assigned contrasts deferred and retained, 0 same-signed redecisions, 0 phase calls; 313 eligible / 803,144 literals contain 311 novel / 798,046 literals and 2 duplicates; imported 202 + novel 311 = 513, exactly one above the 512-clause archive cap, so no next vault/model/key is archived and final vault remains 202 clauses; decisions 6,250, propagations 3,278,941, minimum/root UB 13.16709627777236/262.68644197084643; 40.378152 s elapsed, 431,915,008 B native peak | [Result](research/O1C0073_APPLE8_VAULT_RELEASE_CONTRAST_RESULT_20260719.json) · [Design](research/O1C0073_APPLE8_VAULT_RELEASE_CONTRAST_DESIGN_20260719.md) · [Capsule](runs/20260719_215617_O1C-0073_apple8-vault-release-contrast-v1/RUN.md) |
| `O1C-0074-APPLE8-CAUSAL-ATTIC-STREAM` | Complete immutable exact-clause/occurrence attic with a separately bound reader source and deterministic 256-clause active projection recomputed between four bounded episodes | `CAUSAL_ATTIC_STREAM_NOVEL_CLAUSE_GAIN`; recurrence-weighted bounded attention yields durable new exact exclusions, not recovery, entropy reduction, UNSAT or global threshold-region exhaustion | local 0..3/lineage 10..13; four exact 128/128 calls, aggregate 512/512; attic 513→550 unique clauses, 1,397,774→1,488,224 literals, 515→558 occurrences, duplicates 2→8; active always 256 clauses. Episode 0 emits six global duplicates at indices 202..207 and changes projection `fb7528bf…→ccfad8b3…`; episode 1 emits 37 globally novel clauses at indices 513..549 and changes projection to `78696f2b…`; episodes 2/3 are bit-identical at minimum UB 14.67138759145431 with zero emissions. 204.957842 s, 504,233,984 B runner peak, 30,567,197 B persistent; no model/key/truth/reveal/MPS/GPU | [Result](research/O1C0074_APPLE8_CAUSAL_ATTIC_STREAM_RESULT_20260719.json) · [Interpretation](research/O1C0074_APPLE8_CAUSAL_ATTIC_STREAM_INTERPRETATION_20260719.md) · [Design](research/O1C0074_APPLE8_CAUSAL_ATTIC_STREAM_DESIGN_20260719.md) · [Capsule](runs/20260719_231823_O1C-0074_apple8-causal-attic-stream-v1/RUN.md) |
| `O1C-0075-APPLE8-CAUSAL-RESIDENCY-STREAM` | Target-free nonrepeating K256 residency pages over the immutable O1C-0074 attic, with inherited activation history and debt-first full undominated coverage | `CAUSAL_RESIDENCY_STREAM_NO_NOVEL_GAIN`; exact pager/coverage success but pure rotation is behaviorally inert at this horizon, not recovery, entropy reduction, UNSAT or exhaustion | local 0..1/lineage 14..15; two exact 128/128 calls, aggregate 256/256; input SHAs `82b1512a…` / `db3acd5e…` are distinct and, with parent, cover 545/545 undominated clauses with debt 0. Both reproduce trace `f64441a2…`, decisions 2,288, propagations 2,890,144, minimum/root UB 14.67138759145431/262.68644197084643 and 0 prunes/emissions/novel/model, exactly matching O1C-0074 episodes 2/3. Attic unchanged 550/558/8; 93.295922 s, 482,541,568 B runner peak, 20,788,748 B persistent | [Result](research/O1C0075_APPLE8_CAUSAL_RESIDENCY_STREAM_RESULT_20260720.json) · [Interpretation](research/O1C0075_APPLE8_CAUSAL_RESIDENCY_STREAM_INTERPRETATION_20260720.md) · [Design](research/O1C0075_APPLE8_CAUSAL_RESIDENCY_STREAM_DESIGN_20260719.md) · [Capsule](runs/20260720_002724_O1C-0075_apple8-causal-residency-stream-v1/RUN.md) |
| `O1C-0076-APPLE8-CAUSAL-FRONTIER` | Parent-first live falsify/release-contrast wrapper over union clause 526's 29 public residuals on fresh Page 3 | `CAUSAL_FRONTIER_NO_ACTIVATION_NO_GAIN`; negative activation and science result | local 0/lineage 16; exact 128/128 conflicts; 2,288 decisions, 2,890,144 propagations, minimum/root UB 14.67138759145431/262.68644197084643, unchanged trace `f64441a2…`, 0 substitutions/prunes/emissions/novel/model. First parent zero is callback 256; all 29 rows are already assigned and consumed as 18 falsifying-sign plus 11 rescue-sign skips, with 0 releases/contrasts. 47.790948 s runner, 0.566478 s native wall, 408,944,640 B native peak | [Result](research/O1C0076_APPLE8_CAUSAL_FRONTIER_RESULT_20260720.json) · [Interpretation](research/O1C0076_APPLE8_CAUSAL_FRONTIER_INTERPRETATION_20260720.md) · [Design](research/O1C0076_APPLE8_CAUSAL_FRONTIER_DESIGN_20260720.md) · [Capsule](runs/20260720_013632_O1C-0076_apple8-causal-frontier-v1/RUN.md) |
| `O1C-0077-APPLE8-RESIDUAL-POLARITY-STAGING` | Two source-rank rescue signs changed to clause-falsifying effective originals before constructing the inherited release-contrast reader on fresh Page 4 | `RESIDUAL_POLARITY_STAGING_MECHANISM_ONLY`; qualified causal activation without prune, new exclusion, model or recovery | local 0/lineage 17; exact 128/128 conflicts; effective `-131/+130` at callbacks 225/227 and source contrasts `+131/-130` at 574/576; trace `f64441a2…→706ad4fa…`; decisions 2,288→884 (-61.36%), propagations 2,890,144→4,754,555 (+64.51%), minimum UB 14.67138759145431→14.656823218163392, still above tau with 0 prunes/emissions/novel/model. 48.235246 s runner, 0.838922 s native wall, 423,968,768 B native peak | [Result](research/O1C0077_APPLE8_RESIDUAL_POLARITY_STAGING_RESULT_20260720.json) · [Interpretation](research/O1C0077_APPLE8_RESIDUAL_POLARITY_STAGING_INTERPRETATION_20260720.md) · [Design](research/O1C0077_APPLE8_RESIDUAL_POLARITY_STAGING_DESIGN_20260720.md) · [Capsule](runs/20260720_025550_O1C-0077_apple8-residual-polarity-staging-v1/RUN.md) |
| `O1C-0078-APPLE8-RESCUE-PREFIX-PREEMPTION` | Complete sealed 11-row falsifying prefix placed before the inherited staged rank/release-contrast stack on fresh Page 5 | `RESCUE_PREFIX_PREEMPTION_OPERATIONAL_TERMINAL`; no native science result, neither scientific negative nor gain | local 0/lineage 18; requested 128, actual/billed unknown/null; exact throw `backtrack-release guided assignment sign differs`, stdout empty. Throw-path reachability proves all 11 prefix rows consumed and parent handoff reached, but no prefix-return/rescue-skip/trace/prune/clause/model measurement. 31.2118055 s runner, 29.3178874 s native failure, 404,815,872 B native/watchdog peak, 12,137,843 B persistent; Page 5 burned, no retry | [Result](research/O1C0078_APPLE8_RESCUE_PREFIX_PREEMPTION_RESULT_20260720.json) · [Interpretation](research/O1C0078_APPLE8_RESCUE_PREFIX_PREEMPTION_INTERPRETATION_20260720.md) · [Design](research/O1C0078_APPLE8_RESCUE_PREFIX_PREEMPTION_DESIGN_20260720.md) · [Capsule](runs/20260720_065505_O1C-0078_apple8-rescue-prefix-preemption-v1/RUN.md) |
| `O1C-0079-APPLE8-DECISION-OWNERSHIP` | One typed decision-instance owner composes the unchanged prefix, rank and frontier readers on fresh Page 6 | Corrected `DECISION_OWNERSHIP_QUALIFIED_PREFIX_MECHANISM_ONLY`; operational ownership and qualified prefix activation, no science gain | local 0/lineage 19; exact requested/actual/billed `128/128/128`; proposals=bindings=releases `549`, confirmed `547`, unobserved `2`, live/omitted `0`, foreign/opposite `9,966/0`; tokens 75/110 retire `-108/-112` before later `+108/+112` are foreign token 0. Prefix 11 consumed / 9 bound-released / 2 preassigned falsifying / 0 rescue skips; rank `254+254`, frontier `16+16`; 1,587 callbacks (`549/1,038` nonzero/zero); minimum UB `18.742222666780805`, `4.136043868887843` above tau, 0 prunes/clauses/models/key. Raw no-activation field is a preserved substring-validator false negative corrected by zero-call erratum | [Raw result](research/O1C0079_APPLE8_DECISION_OWNERSHIP_RESULT_20260720.json) · [Erratum](research/O1C0079_APPLE8_DECISION_OWNERSHIP_ZERO_CALL_ERRATUM_20260720.json) · [Interpretation](research/O1C0079_APPLE8_DECISION_OWNERSHIP_INTERPRETATION_20260720.md) · [Design](research/O1C0079_APPLE8_DECISION_OWNERSHIP_DESIGN_20260720.md) · [Capsule](runs/20260720_085738_O1C-0079_apple8-decision-ownership-v1/RUN.md) |
| `O1C-0080-APPLE8-BOUND-CROSSING` | Exact same-parent `U0/U1` evaluation for every eligible key coordinate on fresh Page 7, with intervention only on a certified threshold crossing/closure | `BOUND_PROBE_OPERATION_ONLY`; exact probe operation succeeds, crossing activation and science gain fail | local 0/lineage 20; exact requested/actual/billed `128/128/128`; 1,587 parents, 285,725 probes, 571,450 child evaluations over 255 candidates; all `NEITHER_PRUNABLE`. Minimum witness variable 115 at callback 413 has `U0/U1=19.10564473318062/18.464862193097684`, minimum margin `+3.8586833952047215` above tau and identical pre/post state hashes; 0 bound proposals/interventions/prunes/closures/clauses/models/key. Full trace 285,725 events / 16,286,325 B / SHA `c6f6c2a9…`; first 16,384 objects retained, 269,341 digest-only. 48.718023834 s total, 6.803373 s native wall, 467,042,304 B native peak; no truth/reveal/refit/retry/MPS/GPU | [Result](research/O1C0080_APPLE8_BOUND_CROSSING_RESULT_20260720.json) · [Interpretation](research/O1C0080_APPLE8_BOUND_CROSSING_INTERPRETATION_20260720.md) · [Design](research/O1C0080_APPLE8_ONE_BIT_BOUND_CROSSING_DESIGN_20260720.md) · [Capsule](runs/20260720_124516_O1C-0080_apple8-bound-crossing-v1/RUN.md) |
| `O1C-0081-BOUND-DIFFERENTIAL-CENSUS` | Target-free common-mode removal and bounded coordinate accumulation over O1C-0080's exact retained child-bound prefix | `TARGET_FREE_BOUND_DIFFERENTIAL_MECHANISM_CENSUS`; query-priority mechanism candidate, no belief/key-bit/science/recovery claim | exact 16,384 events / 74 parents only; omitted 269,341 values never inferred and global min witness excluded. Raw `d=U0-U1` positive 15,601/16,384 (95.2209%); parent-median centering gives 8,172 positive / 8,172 negative / 40 zero. Frozen eligibility >=37 parents; var185 score 91.7528/stability 1.0 vs within-parent permuted max 3.0907 and priority corr -0.0284. Temporal mean corr 0.8538/sign agreement 81.11%; packed live state 28,672 B O(256). Zero solver/target/truth/reveal/refit/MPS/GPU; 0.23 s verification | [JSON](research/O1C0081_BOUND_DIFFERENTIAL_CENSUS_20260720.json) · [Report](research/O1C0081_BOUND_DIFFERENTIAL_CENSUS_20260720.md) · [Capsule](runs/20260720_130241_O1C-0081_bound-differential-census-v1/RUN.md) |
| `O1C-0082-APPLE8-PARENT-CENTERED` | Live O(256) parent-median/MAD coordinate state selects the strongest persistent coordinate, while the current lower-UB child supplies a one-shot failure-first proof-mining action rather than a key-bit belief | `PARENT_CENTERED_NOVEL_CLAUSE_GAIN`; operational activation and globally novel exact-exclusion science gain, no key/model/closure/certified one-bit crossing/entropy-domain claim | fresh Page 8 / local 0 / lineage 21; requested/actual/billed `128/9/9`; `512` parents, `255` confirmed actions, `33,106` probes / `66,212` child evaluations; 257 safe prunes and globally novel clauses / 743,129 literals, aggregate `bcc424b0…`; capacity stop at `256+257=513`. Zero-call audit: every clause has all 255 action coordinates; fixed first 247 plus 256-orientation eight-variable tail and one duplicate projection; agreement `247:1,248:8,249:28,250:56,251:70,252:56,253:28,254:8,255:2`; common signed core 2,764 (`247+2,517`), 2,870 common variables / 106 sign switches; 1,024 edges / 1,032 pairs, zero simple resolvents, other complements 6..23 (median 10, mean 12.25); core `U=18.66656376905567`, margin `+4.0603849711627085`, SHA `9aa383f819d1aa4b1216937ee341aa6a773d1d3456e1ea622494ef1a4345ea06`. No prefix/key/tail-free/resolution gain; zero solver/native/target/truth/reveal audit calls | [Result](research/O1C0082_APPLE8_PARENT_CENTERED_RESULT_20260720.json) · [Interpretation](research/O1C0082_APPLE8_PARENT_CENTERED_INTERPRETATION_20260720.md) · [Capsule](runs/20260720_143008_461948_O1C-0082_apple8-parent-centered-v1/RUN.md) |
| `O1C-0083-APPLE8-CAUSAL-ROLLOVER` | Zero-call ingestion of O1C-0082's complete exclusion harvest into the immutable attic plus one explicit-headroom Page-9 projection and sealed evolved priority bank | `CAUSAL_ATTIC_PAGE9_ROLLOVER_PREPARED`; enabling/mechanism gain at preparation level, not new cryptanalytic/key/entropy/domain gain | 257 new unique occurrences / 743,129 literals / 2,973,735 B, chunk `19e29482…`; attic 13 chunks / 807 unique / 815 occurrences / 9 strict relations / 801 undominated. Fresh Page 9 `8c3b8cc3…` is 255 clauses / 721,187 literals / 2,885,959 B (`4` roots + `43` pinned + `208` new debt), leaving 257 clauses / 878,813 literals / 5,502,649 B headroom. Evolved bank `05b8acf3…` is 24,576 B / 256x96 records / 255 eligible; Page 9 / lineage 22 were unburned at preparation and are later burned by O1C-0084 | [Result](research/O1C0083_APPLE8_CAUSAL_ROLLOVER_RESULT_20260720.json) · [Interpretation](research/O1C0083_APPLE8_CAUSAL_ROLLOVER_INTERPRETATION_20260720.md) · [Manifest](research/o1c83_causal_rollover_seed_20260720/causal-rollover-preparation-manifest.json) |
| `O1C-0084-APPLE8-PARENT-CENTERED-CONTINUATION` | One sealed live-bank Page-9 / lineage-22 continuation intent and process launch | `PARENT_CENTERED_CONTINUATION_OPERATIONAL_TERMINAL`; build-transport failure before native `main`, neither cryptanalytic negative nor gain | Intent `89483dda…` burns Page 9. The 1,696,712-byte `-Wl,-no_uuid` executable (`1ba38064…`) is rejected by Darwin `dyld` for missing `LC_UUID`; one adapter/native call consumed, native result absent, actual/billed conflicts null, no solver construction/science/state update. Attic remains 807 unique clauses and bank remains `05b8acf3…`; never retry Page 9 | [Result](research/O1C0084_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json) · [Interpretation](research/O1C0084_APPLE8_PARENT_CENTERED_CONTINUATION_INTERPRETATION_20260720.md) · [Capsule](runs/20260720_162606_777761_O1C-0084_apple8-parent-centered-continuation-v1/RUN.md) |
| `O1C-0085-APPLE8-PARENT-CENTERED-CONTINUATION` | Repaired build-once live-bank continuation over fresh Page 10 / lineage 23 | `PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN`; globally novel exact-exclusion science gain, no key/model/closure/entropy-domain claim | Exact requested/actual/billed `128/128/128`; 430 parents/decisions, 255 confirmed failure-first actions, 32,840 probes / 65,680 child evaluations, 5,389,742 propagations. Base sieve emits 23 safe trail-UB clauses / 67,130 literals, all active-page new and globally novel against the 807-clause attic; minimum UB `13.63202340517244 < tau`. `actual_certified_prunes=0` is the separate realized action-crossing count. Next vault 277 clauses / 785,425 literals / 3,142,999 B is available; final bank `2c0c4ccb…`; Page 10 burned, never replay | [Result](research/O1C0085_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json) · [Interpretation](research/O1C0085_APPLE8_PARENT_CENTERED_CONTINUATION_INTERPRETATION_20260720.md) · [Capsule](runs/20260720_170426_298664_O1C-0085_apple8-parent-centered-continuation-v1/RUN.md) |
| `O1C-0086-APPLE8-PARENT-CENTERED-CONTINUATION` | Fresh Page-11 / lineage-24 continuation after atomic ingestion of O1C-0085's 23 clauses and evolved live bank | `PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN`; 202 globally novel exact exclusions, no key/model/closure/entropy-domain claim | Requested/actual/billed `128/131/131`; 255 failure-first actions, 100,038 exact probes, 1,009 decisions and 2,617,401 propagations. Base sieve emits 202 safe trail-UB clauses / 546,864 literals; all are unique and absent from the complete 830-clause attic (`intersection=0` by independent hash-set audit). Witness range `8.269907850393242..14.604191886555723 < tau`; `actual_certified_prunes=0` remains the separate action-crossing count. Next vault 456 clauses / 1,265,745 literals / 5,064,995 B is available; final bank `658fd285…`; Page 11 burned, never replay | [Result](research/O1C0086_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json) · [Interpretation](research/O1C0086_APPLE8_PARENT_CENTERED_CONTINUATION_INTERPRETATION_20260720.md) · [Delta audit](research/O1C0086_PAGE11_CAUSAL_DELTA_AUDIT_20260720.md) · [Capsule](runs/20260720_181212_319263_O1C-0086_apple8-parent-centered-continuation-v1/RUN.md) |
| `O1C-0087-APPLE8-CAUSAL-ROLLOVER` | Zero-call ingestion of O1C-0086's complete 202-clause harvest into the immutable attic plus fresh Page-12 / lineage-25 projection and evolved live-bank receipt | `CAUSAL_ATTIC_PAGE12_ROLLOVER_PREPARED`; enabling/mechanism gain, no new key/clause/closure/entropy-domain claim | 202 new unique occurrences / 546,864 literals / 2,188,455 B, chunk `d5338ef8…`; attic 15 chunks / 1,032 unique / 1,040 occurrences / 10 strict relations / 1,025 undominated. Fresh Page 12 `44205f81…` is 254 clauses / 681,054 literals / 2,725,423 B (`5` roots + `43` pinned + `202` new debt + `4` recycled), leaving 258 clauses / 918,946 literals / 5,663,185 B headroom. Evolved bank `658fd285…` and receipt `e5ffda54…` bind exactly; Page 12 remains unburned and unauthorized at preparation | [Interpretation](research/O1C0087_APPLE8_CAUSAL_ROLLOVER_INTERPRETATION_20260720.md) · [Manifest](research/o1c87_page12_causal_rollover_seed_20260720/causal-rollover-preparation-manifest.json) |
| `O1C-0088-APPLE8-PARENT-CENTERED-CONTINUATION` | One unchanged one-shot parent-centered continuation over fresh Page 12 / lineage 25 and the fully refreshed `658fd285…` live bank | `PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN`; 259 globally novel exact exclusions, no key/model/closure/entropy-domain claim | Requested/actual/billed `128/55/55`; 255 failure-first actions, 33,413 exact probes, 570 decisions and 2,598,280 propagations. Base sieve emits 259 safe trail-UB clauses / 744,973 literals; all are unique and absent from the complete 1,032-clause attic (`intersection=0`). Witness range `13.374795503825057..14.605893028674872 < tau`; `actual_certified_prunes=0`. Combined successor vault is unavailable only at `254+259=513>512`; all clauses archive, final bank `0203de9f…`; Page 12 burned, never replay | [Result](research/O1C0088_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json) · [Interpretation](research/O1C0088_APPLE8_PARENT_CENTERED_CONTINUATION_INTERPRETATION_20260720.md) · [Cross-burst audit](research/O1C0088_PAGE12_CROSS_BURST_CAUSAL_AUDIT_20260720.md) · [Capsule](runs/20260720_190040_615684_O1C-0088_apple8-parent-centered-continuation-v1/RUN.md) |
| `O1C-0089-APPLE8-CAUSAL-ROLLOVER` | Zero-call ingestion of O1C-0088's complete 259-clause harvest into the immutable attic plus fresh Page-13 / lineage-26 projection at the minimal one-slot active limit 253 | `CAUSAL_ATTIC_PAGE13_ROLLOVER_PREPARED`; enabling/mechanism gain, no new key/clause/closure/entropy-domain claim | 259 unique globally novel occurrences / 744,973 literals / 2,981,119 B; attic 16 chunks / 1,291 unique / 1,299 occurrences / 10 relations / 1,284 undominated. Fresh Page 13 `4c1b7d5a…` is 253 clauses / 711,355 literals / 2,846,623 B (`5` roots + `43` pinned + `205` new debt), leaving exactly 259 clause slots. All 259 remain in attic; 205 resident and 54 explicitly nonresident. Bank `0203de9f…` / receipt `9ecec7df…` exact; Page 13 unburned | [Interpretation](research/O1C0089_APPLE8_CAUSAL_ROLLOVER_INTERPRETATION_20260720.md) · [Manifest](research/o1c89_page13_causal_rollover_seed_20260720/causal-rollover-preparation-manifest.json) |
| `O1C-0090-APPLE8-PARENT-CENTERED-CONTINUATION` | One unchanged one-shot parent-centered continuation over fresh Page 13 / lineage 26 and evolved `0203de9f…` live bank | `PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN`; 260 globally novel exact exclusions, no key/model/closure/entropy-domain claim | Requested/actual/billed `128/46/46`; 255 failure-first actions, 33,890 exact probes, 540 decisions and 1,369,570 propagations. Base sieve emits 260 safe trail-UB clauses / 743,794 literals; all are unique and absent from the complete 1,291-clause attic (`intersection=0`). Witness range `13.057051120644449..14.605986705470585 < tau`; `actual_certified_prunes=0`. Combined successor unavailable only at `253+260=513>512`; all clauses archive, final bank `715bfbc2…`; Page 13 burned, never replay | [Result](research/O1C0090_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json) · [Interpretation](research/O1C0090_APPLE8_PARENT_CENTERED_CONTINUATION_INTERPRETATION_20260720.md) · [Cross-burst audit](research/O1C0090_PAGE13_CROSS_BURST_CAUSAL_AUDIT_20260720.md) · [Capsule](runs/20260720_195618_030937_O1C-0090_apple8-parent-centered-continuation-v1/RUN.md) |
| `O1C-0091-APPLE8-CAUSAL-ROLLOVER` | Zero-call ingestion of O1C-0090's complete 260-clause harvest plus fresh Page-14 / lineage-27 projection at active limit 252 | `CAUSAL_ATTIC_PAGE14_ROLLOVER_PREPARED`; enabling/mechanism gain, no new key/clause/closure/entropy-domain claim | 260 unique occurrences / 743,794 literals / 2,976,407 B; attic 17 chunks / 1,551 unique / 1,559 occurrences / 13 strict relations / 1,541 undominated. Fresh Page 14 `00a5a4a7…` is 252 clauses / 704,145 literals / 2,817,779 B (`8` roots + `43` pinned + `201` new debt), leaving exactly 260 clause slots. Of 260 new clauses, 190 are resident and 70 explicit nonresidents; 3 missing are dominated. Bank `715bfbc2…` / receipt `4e13df32…` exact; Page 14 unburned | [Interpretation](research/O1C0091_APPLE8_CAUSAL_ROLLOVER_INTERPRETATION_20260720.md) · [Manifest](research/o1c91_page14_causal_rollover_seed_20260720/causal-rollover-preparation-manifest.json) |
| `O1C-0092-APPLE8-PARENT-CENTERED-CONTINUATION` | One unchanged one-shot parent-centered continuation over fresh Page 14 / lineage 27 and evolved `715bfbc2…` live bank | `PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN`; 261 globally novel exact exclusions, no key/model/closure/entropy-domain claim | Requested/actual/billed `128/10/10`; 255 failure-first actions, 33,398 exact probes, 521 decisions and 2,074,835 propagations. Base sieve emits 261 safe trail-UB clauses / 756,414 literals; all are unique and absent from the complete 1,551-clause attic (`intersection=0`). Witness range `11.553303084092308..14.038279700095462 < tau`; `actual_certified_prunes=0`. Combined successor unavailable only at `252+261=513>512`; all clauses archive, final bank `97a325c9…`; Page 14 burned, never replay | [Result](research/O1C0092_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json) · [Interpretation](research/O1C0092_APPLE8_PARENT_CENTERED_CONTINUATION_INTERPRETATION_20260720.md) · [Cross-burst audit](research/O1C0092_PAGE14_CROSS_BURST_CAUSAL_AUDIT_20260720.md) · [Nine-axis audit](research/O1C0092_PAGE14_NINE_AXIS_QUOTIENT_AUDIT_20260720.md) · [Capsule](runs/20260720_205659_306771_O1C-0092_apple8-parent-centered-continuation-v1/RUN.md) |
| `O1C-0093-APPLE8-CAUSAL-ROLLOVER` | Zero-call ingestion of O1C-0092's complete 261-clause harvest plus fresh Page-15 / lineage-28 projection at active limit 251 | `CAUSAL_ATTIC_PAGE15_ROLLOVER_PREPARED`; enabling/mechanism gain, no new key/clause/closure/entropy-domain claim | Attic 18 chunks / 1,812 unique / 1,820 occurrences / 14 relations / 1,801 undominated. Fresh Page 15 `71f4b544…` is 251 clauses / 710,463 literals / 2,843,047 B (`9` roots + `43` pinned + `199` new debt), leaving exactly 261 clause slots. All newest clauses remain in the attic; 160 resident / 101 explicit nonresidents, one dominated. Bank `97a325c9…` / receipt `1c69bb32…` exact; Page 15 was unburned at preparation and is later burned by O1C-0095 | [Interpretation](research/O1C0093_APPLE8_CAUSAL_ROLLOVER_INTERPRETATION_20260720.md) · [Manifest](research/o1c93_page15_causal_rollover_seed_20260720/causal-rollover-preparation-manifest.json) |
| `O1C-0094-PAGE14-NINE-AXIS-QUOTIENT` | Lossless bounded-state factorization and streaming reconstruction of all 261 O1C-0092 clauses plus exact witness identities | `LOSSLESS_NINE_AXIS_COMPRESSION_QUOTIENT`; representation gain only, no logical substitution/key/entropy-domain claim | Exact 2,709-literal shared core + five explicit prefix residuals + 2,780-literal tail core + 118-variable nine-axis copy/complement map + 256 codewords. All 261 clause and witness identities round-trip exactly; aggregate remains `dad38833…`. Literal-entry accounting `756,414→47,514` (`15.9198x`, `93.7185%`); packed retained state 18,034 B and maximum streaming decoder 29,766 B. Zero solver/target/truth calls | [Result](research/O1C0094_PAGE14_NINE_AXIS_QUOTIENT_RESULT_20260720.json) · [Interpretation](research/O1C0094_PAGE14_NINE_AXIS_QUOTIENT_INTERPRETATION_20260720.md) · [Capsule](runs/20260720_214029_O1C-0094_page14-nine-axis-quotient-zero-call-v1/RUN.md) |
| `O1C-0095-APPLE8-PARENT-CENTERED-CONTINUATION` | One sealed Page-15 / lineage-28 continuation call through native v26 and adapter v29 | `PARENT_CENTERED_CONTINUATION_OPERATIONAL_TERMINAL`; exact producer/consumer contract failure after native completion, neither cryptanalytic negative nor gain | Intent `089d65e7…` burns Page 15. Native v26 runs the solver to completion, exits 0 and returns parsed JSON, but adapter v29 rejects `priority_seed` because `_SEED_FIELDS` omits `source_priority_state_receipt_sha256` and `source_priority_state_receipt_bytes`; stdout/result is not persisted. One call, 128 requested, actual/billed null, 21.109976 s; attic remains 1,812 clauses and bank remains `97a325c9…`; never retry Page 15 | [Result](research/O1C0095_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json) · [Interpretation](research/O1C0095_APPLE8_PARENT_CENTERED_CONTINUATION_INTERPRETATION_20260720.md) · [Capsule](runs/20260720_220052_433697_O1C-0095_apple8-parent-centered-continuation-v1/RUN.md) |
| `O1C-0096-PAGE16-TRANSPORT-RECOVERY` | Zero-call recovery from O1C-0095 plus fresh Page-16 / lineage-29 projection over the unchanged certified attic and bank | Zero-call transport/residency preparation; enabling gain only, no new clause/key/closure/entropy-domain claim | Fresh Page 16 `fb3b5669…` is 251 clauses / 707,566 literals / 2,831,459 B (`9` roots + `43` pinned + `167` new debt + `32` recycled), leaving 261 clause / 892,434 literal / 5,557,149 B headroom. All 167 prior never-resident-undominated clauses are admitted and residual debt becomes zero. Attic stays 18 chunks / 1,812 unique / 1,820 occurrences / 14 relations / 1,801 undominated; bank `97a325c9…` / receipt `1c69bb32…` exact; Page 16 was unburned at preparation and is later burned by O1C-0097 | [Interpretation](research/O1C0096_PAGE16_TRANSPORT_RECOVERY_INTERPRETATION_20260720.md) · [Manifest](research/o1c96_page16_transport_recovery_seed_20260720/transport-recovery-preparation-manifest.json) |
| `O1C-0097-APPLE8-PARENT-CENTERED-CONTINUATION` | One repaired-contract parent-centered continuation over fresh Page 16 / lineage 29 | `PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN`; exact-clause science gain, no key/model/closure/entropy-domain claim | Requested/actual/billed `128/21/21`; 533 decisions, 2,835,645 propagations, 255 failure-first actions, 33,243 probes and zero certified direct crossings. The 263 occurrences contain 262 unique globally novel clauses; sole duplicate indices 6/7 share 2,859 literals, UB `13.293490727958314` and SHA `d479f133…`. All witnesses are strict below tau; exact rollover chunk is 262 clauses / 745,152 literals / 2,981,847 B. Bank evolves `97a325c9…→8100bccf…`; Page 16 burned, never replay | [Result](research/O1C0097_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json) · [Interpretation](research/O1C0097_APPLE8_PARENT_CENTERED_CONTINUATION_INTERPRETATION_20260720.md) · [Capsule](runs/20260720_224639_665221_O1C-0097_apple8-parent-centered-continuation-v1/RUN.md) |
| `O1C-0098-PAGE17-CAUSAL-ROLLOVER` | Zero-call ingestion of O1C-0097's complete 263-occurrence harvest plus fresh Page-17 / lineage-30 projection at active limit 249 | `CAUSAL_ATTIC_PAGE17_ROLLOVER_PREPARED`; enabling representation/state gain only, no new science clause/key/model/closure/entropy-domain claim | The 263 occurrences become one 262-clause / 745,152-literal / 2,981,847-byte chunk, SHA `c5e9c357…`; occurrence 7 exactly duplicates 6. Attic reaches 19 chunks / 2,074 unique / 2,083 occurrences / 9 duplicates / 14 relations / 2,063 undominated. Fresh Page 17 `0c25ce47…` is 249 clauses / 693,183 literals / 2,773,919 B (`9` roots + `43` pinned + `197` new debt), leaving 263 clause / 906,817 literal / 5,614,689 B headroom; 65 new undominated clauses remain nonresident. Bank `8100bccf…` / receipt `050551fc…` exact; Page 17 unburned | [Interpretation](research/O1C0098_PAGE17_CAUSAL_ROLLOVER_INTERPRETATION_20260720.md) · [Manifest](research/o1c98_page17_causal_rollover_seed_20260720/causal-rollover-preparation-manifest.json) |
| `O1C-0099-APPLE8-PARENT-CENTERED-CONTINUATION` | One unchanged parent-centered continuation over Page 17 / lineage 30 | `PARENT_CENTERED_CONTINUATION_OPERATIONAL_TERMINAL`; telemetry transport only, neither cryptanalytic negative nor gain | One native call consumed after persisted intent; requested conflicts 128, actual/billed `null`, no native result and empty stdout. Native v28 exits 1 after 19.822776 s with `decision ownership event cap exceeded`; Page 17 burned, never replay. The fixed 65,536-row ledger stores every assignment, while O1C-0097 already used 47,005 rows, 46,231 of them non-claiming foreign assignments. No O1C-0099 clause/bank/state output is admissible; certified O1C-0098 attic and `8100bccf…` bank remain the continuation basis | [Result](research/O1C0099_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json) · [Interpretation](research/O1C0099_APPLE8_PARENT_CENTERED_CONTINUATION_INTERPRETATION_20260721.md) · [Capsule](runs/20260721_004001_986566_O1C-0099_apple8-parent-centered-continuation-v1/RUN.md) |
| `APPLE-VIEW-0005-SPARSE-CARRY` | Sparse exact c31-identity certificates for complete wrong Full-256 candidates | `CONSUMED_FULL256_CANDIDATE_FILTER`; no key-generation/entropy claim | 20/20 exact wrong-candidate conflicts; every reason-DAG slice independently replays with 250–265/336 identities, best 250 (86 omitted); 5/5 truth controls complete | [Result](research/apple_view_5/apple_view_5_report.md) |
| `APPLE-VIEW-0006-PROOF-CREDIT-TRANSFER` | One-pass 1,346-byte proof-frequency/recency state frozen before disjoint Full20/Full256 candidate filters | `HELDOUT_CERTIFICATE_TRANSFER_WITH_SCHEDULER_LOSS`; no key-generation/entropy claim | raw learned order loses 1,268 vs best structural 1,031 total first-conflict switches; independently replayed learned certificates win 4/4 at 248/248/251/250 vs best structural 251/252/257/255, aggregate 997 vs 1,015 and immediate-public 1,013; zero held-out updates, all truth controls complete | [Result](research/apple_view_6/apple_view_6_report.md) |
| `APPLE-VIEW-0007-PROOF-EDGE-TRANSFER` | One-pass 113,570-byte proof-DAG edge/root/terminal state with one frozen static strongest-predecessor reader | `HELDOUT_STATIC_EDGE_SCHEDULER_NEGATIVE`; no key-generation/entropy claim | raw edge order loses 1,340 vs exact APPLE6 unary 1,268 and best structural 1,031; certificate 1,003 beats fixed 1,015 but loses unary 997 and cannot pass; all 28 wrong passes, proof replays, freeze checks and truth controls exact | [Result](research/apple_view_7/apple_view_7_report.md) |

O1C-0066 is source-bound to
`881c461c79dc1fd9aa51aed89d3f2a8b298c2284`; authoritative result SHA-256 is
`b8b61d0f2feaa9c544c1fef30cba4c7cead90c390a577a444405d45ad85000e3` and
capsule manifest SHA-256 is
`b0022997a1c316e71131268b3e3e5524aee4de8167013463f845646c8982d562`.
O1C-0067 is source-bound to
`865634458ef3f5b01a5881208eb028404b96f135`; authoritative result SHA-256 is
`c01ffe69198e997c6d3798e0b9f3190065bd7b58ec3ab1ba67a66a7ccd799f1f` and
capsule manifest SHA-256 is
`2562db062186fb5168e66c69943af83ba19a151bdc17489111a15dbb114f9341`.
O1C-0068 is source-bound to
`8446414d73e871de829c182ca4cd5b500e4d9d14`; authoritative result SHA-256 is
`d494887d2be96516211acf09ff8852a88a44576044723223b9057942fd7aea80` and
capsule manifest SHA-256 is
`dd0236774c1352238cce86458a8f01380aa32dc538dbe80a3c1744b0f126a745`.
O1C-0069 is source-bound to
`d6dfc06f3e7d6dfcc29d696829927b132bad23aa`; authoritative result SHA-256 is
`43512370d7243d57bb3ffaed445ee9196315e350d3ee1169ee0c0d8ad94ba89b` and
capsule manifest SHA-256 is
`2a78e568f0be7eafad4d117cd84aeadd0d495d19296d8ba85676496219377cb8`.
O1C-0070 is source-bound to
`c5ad5c40f0ac84f65d281cf2366d2ca6b6c49a52`; authoritative result SHA-256 is
`778d2b91935ff2ae663ea706e5b7b66c8cfed2f02007ba8359e8c1cb7ff45cd7` and
capsule manifest SHA-256 is
`ca5e0dfc724dc541b5311e2fc1453fc017f4ccd562d510aad341a53188d194c2`.
O1C-0071 is source-bound to
`66400bc6cc76653fb0a4b2c5bd64af498f4a49d3`; authoritative result SHA-256 is
`84ffbe35ae83266dd4993ad70b6dc988f4a13a8595861c23f36f0d610334cb41`,
tail-cascade analysis SHA-256 is
`8172db9a9d8265f61a1b1191682db06f879939d99271b0f5ba96108f7ccb8259`, and
capsule artifact-manifest SHA-256 is
`c7bbbd9d7ad0d37b80b956a3ad8141254a460ddf763ae84109a067e0343294d9`.
O1C-0072 is source-bound to
`bf1ffaad30ac276c2fcc3b332207c5933bf96443`; authoritative result SHA-256 is
`e441a32de808ee33e2245ea69af4e6ad6f246311e5a410b0cbab4a63dbd165d8` and
capsule artifact-manifest SHA-256 is
`83bbc2438fc33e3a61fdf5b23b589574c6a12cfaefd9fc2f0e7c4c4e84b521f8`.
O1C-0073 is source-bound to
`a1a447f47b4e7bec833f1148330573fefa8e3119`; authoritative result SHA-256 is
`43fb980b50fef20f9bc4bdcfd2ecd6e0f1f7df3bcee9297b0005bb55e4ea0cdc` and
capsule artifact-manifest SHA-256 is
`ad2791ff4ae09e9426878be4ba2f3b55eb77c85f46308c7a506d0dc96111317d`.
O1C-0074 is source/execution-bound to
`a5f2ad130e2e13c39a5e888f927d86d5fdd68d78`; authoritative result SHA-256 is
`b6bc2895459e3256fa4c857b67bd786b36d80ab5018a9c73709a2096cd169127` and
capsule artifact-manifest SHA-256 is
`7a3f272268296005c5c6e532d377eb100244f38e941a102876abbfd732a8049b`.
Capsule `result.json` is byte-identical to the published result and all `54/54`
manifest entries validate. `publication_source.json` is pre-finalization only;
its persistent-artifact count is `0`, not the authoritative final
`30,567,197 B`.
O1C-0075 is source/execution-bound to
`1b30cc06b3ab28d94df773cc854a7814af9fb210`; authoritative result SHA-256 is
`1307be5e1c140f27ec76873a212785f7dae9b5dd986ca8f953e94809e31639c9` and
capsule artifact-manifest SHA-256 is
`3a421ee236af5afe46011314d74c25b726a2e7f35e9963ae8d4a862e070327f9`.
Capsule `result.json` is byte-identical to the published result and all `41/41`
manifest entries validate.
O1C-0076 is source/execution-bound to
`f78424e92b1035a07a70350f0ad5666f2c9459e4`; authoritative result SHA-256 is
`9459f80444b2dc196251623dfc1f59f014e6593b3b5cd7d8bbaaa5c62f0b671e` and
capsule artifact-manifest SHA-256 is
`875655a95a30a4f0df01e130a074b0b6a82b98c683575818ad5110cc6a6f1366`.
Capsule `result.json` is byte-identical to the published result and all `35/35`
manifest entries validate.
O1C-0077 is source-frozen at
`d4f9b3aa066b22a38ead63d83cbb76b4ead673de` and execution-bound to
`8eba8614fc9d19ef893a0e7f093737ed6b23dc68`; authoritative result SHA-256 is
`8b87d7cdc39f6380a887b2e45d4879544ff88cd7c53e22f44876e46c334cf103`
and capsule artifact-manifest SHA-256 is
`6b8526c5eaa2c318d4eef1e8c4dc87e744307c95f30699a90e4444021d2dbece`.
Capsule `result.json` is byte-identical to the published result and all `39/39`
manifest entries validate.
O1C-0078 is source-frozen at
`ced7e5917194362b84d44625f7f9f6484bb555ad` and execution-bound to
`2840824b2aa482f30dfbd39060c200994fc09957`; authoritative result SHA-256 is
`f72821443ed7e7dd80698a39288ff31f9c8f52a120bb745e713e3b23b1822fed`
and capsule artifact-manifest SHA-256 is
`5d358863162a64f27d215fc4b91258c73194d2458f89d9dd7495bb1e05e50a69`.
Capsule `result.json` is byte-identical to the published result and all `33/33`
manifest entries validate.
O1C-0079 is execution-bound to
`8b058cbfe62d93d0263a275f4081982f382a4355`. Its immutable raw result SHA-256 is
`ce68d10eed83d9a0d90518c579f4e1841cd8a6791e4cd975d0d27a64bcc6251e`
and capsule artifact-manifest SHA-256 is
`f7cd0de5ba58a59de913db88ba3e9ce2ae1b486a4e922700f65dff3aa5d39475`.
The additive zero-call erratum SHA-256 is
`b5c2465a532486aaf68a6a622f2312de29ec8a52ea6cea70c9d9c36f19985fa9`;
corrected validator commit is
`665ea8260ae7127baabc83af2fe208080f6f58f9`. Native gzip/uncompressed evidence
is sealed by `ec75d6c…` / `acda128d…`; ownership evidence by `6403d8a6…` /
`87e64764…`. The correction changes no result, capsule or evidence byte and uses
zero solver/truth/reveal/refit/MPS/GPU calls.
O1C-0080 is source-frozen at
`0c18e064ae792ee719db34ff702f249994f4aab4` and execution-bound to
`9469c988375673c901be453e199078ad61c42c1c`. Its authoritative result SHA-256 is
`e2ceb375c2fb83469db8eb537459b223d8e7f63e4bb58882882f8cdd8bdb22a5`
and capsule artifact-manifest SHA-256 is
`400b79b01ed54addbd99db53b2cf5ad36afd388a18d1435dcd7ef850c8532c44`.
The complete probe-event stream is committed by count `285,725`, byte count
`16,286,325` and SHA-256
`c6f6c2a9ecf17bdd8f74891f5ffc7fba7f9658c4c95310d0c2f00f8b65093f5c`;
only `16,384` event objects are retained. Page 7 / lineage 20 are terminal and
must not be retried.
O1C-0081 is bound to the sealed reader input SHA-256 `3b846663…`, canonical JSON
SHA-256 `666854f8ba323fcbf100d86457fbc4eaa3cb3b6bab12d9e47982f4b28a86a389`
and capsule artifact-manifest SHA-256 `f0ef6f75fd945958ce7e57113d9a95b177b90085e9fb3813add968af0e49e052`.
It makes zero solver/science calls and analyzes only the 16,384 materialized
events. The 37-parent persistence threshold is part of the frozen ranking rule;
without it, sparse 10–12-observation spikes are not comparable to persistent
coordinates.
O1C-0082 is source-frozen at commit
`b0cf256ef43a85bd7f16c522f1e048a139908dc8`. Its authoritative result SHA-256
is `013692cf836e594c8580734e0c95a9f0dd18ad7536c457274a1fe5684df1ad4f`,
capsule artifact-manifest SHA-256 is
`3256a85e1095ffeaee349d3248035cb53470b1921abd58dd230e1617696134e6`,
and final continuation-bank SHA-256 is
`05b8acf3ecd5423016e5d7ef7d649f790e758e3477a943fe7306280064a4c630`.
All manifest entries verify and authoritative/capsule result bytes are identical.
Page 8 / lineage 21 are terminal and must not be retried or replayed.
The zero-call common-core canonical SHA-256 is
`9aa383f819d1aa4b1216937ee341aa6a773d1d3456e1ea622494ef1a4345ea06`.
O1C-0083 made no production call or intent and sealed Page 9 with explicit
`next_active_limit=255`: `255` clauses / `721,187` literals / `2,885,959 B`,
categories `roots=4`, `pinned=43`, `new_debt=208`, SHA-256 `8c3b8cc3…`, leaving
257 clause slots. O1C-0084 subsequently persisted its sole Page-9 / lineage-22
intent, then stopped at Darwin `dyld` before native `main` because
`-Wl,-no_uuid` removed the required `LC_UUID`. Page 9 is burned; no solver or
science state ran. The attic remains 13 chunks / 807 unique clauses / 815
occurrences and the live bank remains `05b8acf3…`. The next gate at that point
was fresh Page 10 plus build-once dynamic executable sealing and mandatory
`--help` before intent; never retry Page 9. O1C-0085 passes that gate: executable SHA
`b37cc3b4…` launches, help-smoke SHA `701fc730…` passes, and fresh Page 10 /
lineage 23 adds 23 globally novel exact trail-UB clauses at `128/128/128` work.
Authoritative result SHA-256 is
`d65fcaa76caa50905b5061b99cdf3ea10841449bdec6e9d20344e17bbe1e2ca4`
and capsule-manifest SHA-256 is
`c6f4cb50ab5e7b0e57afbe5bbaccf53106008094be824c35bb7f849a8d4be492`;
the result bytes are identical and every manifest entry verifies. Page 10 /
lineage 23 are burned. Preserve all 23 clauses and the evolved `2c0c4ccb…` bank
through a fresh Page-11 rollover; never replay Page 10. O1C-0086 completes that
rollover and its sole Page-11 / lineage-24 call emits 202 globally novel clauses
against the 830-clause attic at `128/131/131`. Result SHA-256 is
`535b8fa095013d4b87cadfc5e54e62698a21ab285d92becfbba88dc9c6f0ee6e` and
capsule-manifest SHA-256 is
`d4ff926b1c2183ca2c70b499acd9e3aa00e9c6575aee43479dc6238e690953fb`.
Page 11 is burned; preserve all 202 clauses and `658fd285…` through Page 12.

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
then-current joint-rank frontier and requires exactly one sealed fresh replication.
O1C-0044 supplies that prospective replication at `54/4097` with large margins
over both endpoint rotations. Because scoring still performs a complete forward
execution for every candidate, promotion now requires equal-work exact-search or
residual-domain reduction. O1C-0057 separately tests the predeclared multi-block
compounding question before the score enters that conversion.
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
is the next causal discriminator. O1C-0054 then executes the parallel global
prefix design separately. Its public Full256 beam loses the true prefix at stage
5 and its post-reveal W11 queue certifies zero leaves under the frozen cap.
Independent factor maxima are too loose; close that global relaxation without a
beam, pair-order, cap or scale sweep.
O1C-0055 then makes contradiction membership exact. All 512 learned clauses
match live owners, but indiscriminate `-32` reproduces O1C-0052's 18-cell,
seven-group diffusion and still fails W11. Retain the hook and select one exact
member by current-level/deepest clause role; do not tune sign or scale.
O1C-0056 performs that localization exactly, selects one unique current-level
owner in all 512 conflicts and still leaves W11 unresolved. This closes fixed
negative conflict credit, not the address. O1C-0057 then returns to the stronger
public-evidence frontier: on one fresh target, the unchanged parent-criticality
reader ranks truth `8/7/1/1` of 4,097 across 1/2/4/8 public blocks, while the
prefix-8 rotations rank `3581/4037`. The frozen prediction passes at truth z
`+5.57888245`, establishing prospective multi-block compounding and roughly 12
bits of discrimination inside the supplied panel. Candidates were supplied, so
this is the current complete-key scoring/order frontier—not key generation,
domain enumeration or exact recovery. The next conversion must order
attacker-generated partial assignments or bounded exact-search branches under a
matched-work/width/beam gate; a larger decoy panel alone is not progress.
O1C-0058 tests the shortest local conversion and answers no. Around the highest-
scoring eight-block decoy, accumulating all 256 one-bit finite differences
leaves the primary prefix-8 candidate at the base's `127/256` correct bits with
zero correct confidence prefix; controls reach `127/128`, and neither base nor
any of 12 syntheses matches even one public block. This closes only attended-
decoy positive-delta direction. The two locally score-improving primary flips do
not improve truth alignment. The O1C-0057 complete-key scorer remains valid.
O1C-0061 then compiles it into an exact joint partial-assignment bound and
records material pre-model bound progress, but zero trail prunes; do not call
O1C-0061 alone a search-space gain. Its matched APPLE-VIEW-0008 augmentation
makes logically redundant public P20 units and
`P_b = P_0 + (Z_b - Z_0)` key-lane consequences explicit. At identical
requested 512/billed 513 conflicts it produces six certified safe trail prunes,
moves the minimum upper bound below threshold and roughly halves decisions.
O1C-0062 exposes the callback lifecycle failure, O1C-0063 repairs it, and
O1C-0064 then localizes 4K scaling to a guarded-memory stop at 992 MiB. None is a
science result or retry. APPLE-VIEW-0009 supplies an exact width-6 bound that is
both tighter and smaller than the frozen pair relaxation. O1C-0065 integrates it
into the repaired native path and closes the standalone question at matched
work: root/minimum bounds and logical cache improve, but the same six clauses
are emitted with identical decisions and propagations. O1C-0066 then carries
canonical score-threshold clauses across fresh solver processes and shows
positive bounded efficacy before an operational terminal: its two completed
episodes grow the vault `0→6→12` clauses, episode 1 contributes six novel
clauses, lowers minimum UB to `7.973483108047071` and changes the search path at
the same requested 512 conflicts. The third intent stops during adapter
validation on `joint-score-sieve-v5 soft conflict ledger differs`; this is not a
scientific negative, recovery or retriable ordinal. Native conflict identities
are exact; the failure means only `solve_conflicts >= 514` and overshoot `>= 2`,
past an unsupported frozen `+1`/513 cap. Exact work was lost because raw stdout
was not retained. Preserve stdout, replace the false cap with an honest actual-observed
soft-limit ledger while retaining algebraic consistency and hard process/time/RSS caps, freeze those
target-free gates, then use a distinct non-replay O1C-0067 continuation.
O1C-0067 completes that call under actual-observed billing and reaches
`EPISODIC_VAULT_SATURATED_NO_GAIN`: the sole `2,951`-literal emission is the
already stored zero-based vault-index-7/eighth clause, so the vault remains at
12 clauses even though
decisions and propagations fall by `149/38,039` versus the parent. Minimum UB is
`1.1375488575223374` higher and no key or truth is read. Close this exact
reader/seed/horizon; use complementary phase selection (`forcephase=true`,
`phase=false`) or another explicit reader operator, not replay or blind scaling.
O1C-0068 performs the complementary selection once, with exact
`512/512/512` requested/actual/billed work and no overshoot. It emits 195
complete clauses—190 novel and five duplicates—and grows the vault from 12 to
202 clauses, 35,061 to 599,728 literals and 140,483 to 2,399,911 bytes. This
large distinct exact-exclusion population is a meaningful mechanism frontier,
but no model, key or UNSAT result exists and it is not a global exhaustion
certificate. The interpretation note formally audits the frozen threshold and
why the earlier episode minimum UB is not a population score or exhaustion
claim. O1C-0069 then executes the sole precommitted forced-phase-1 composition
call from those 202 clauses. It adds zero novelty and reproduces O1C-0067's
phase-1 trace exactly—514 conflicts, 4,517 decisions, 1,192,529 propagations,
the same bounds, emitted clause, terminal assignment and trace SHA—despite the
190 extra phase-0 clauses. This refutes passive one-step composition, not the
vault or active reading. O1C-0070 then binds the target-free `139/116/1` field
as per-variable polarity exactly once. It changes the trace, cuts decisions and
propagations to `2,297/1,169,826`, and raises minimum UB to
`18.846601115977638`, proving active steering; nevertheless it emits no clause
or key, so phase-only gain fails. O1C-0071 then applies the frozen 255-variable
confidence order once with no phase calls. It cuts decisions `2,297→763`, but
propagations explode `1,169,826→91,260,183` and native wall
`0.316808→14.818087 s`, while producing zero clauses/model. The exact sequence
localizes all 244 redecisions to tail ranks 249..255 as
`1/3/7/15/31/62/125` extras; ranks 1..248 form a callback-visible stable prefix
and are never returned twice. This proves strong order
control but closes static same-sign reinjection as a propagation furnace.
O1C-0072 then tests the causal fix exactly once. Its monotone cursor returns all
255 ranked literals once, observes all 255 guided releases, and delegates the
remaining 900 callbacks with zero redecisions. At the same requested
512-conflict horizon, propagations fall `91,260,183→5,763,035`, a
`15.8354379246x` (`93.6850%`) reduction, while decisions rise `763→1,155`.
The static reinjection furnace is therefore removed and bounded one-shot release
is validated. Zero emitted clauses, no model/key and minimum UB
`19.57599384995442` mean this is mechanism/work gain only—not recovery, entropy
reduction or a new exclusion. O1C-0073 then adds the hard opposite exactly once
after each genuine original release. All 255 pairs complete, including two
assigned contrasts deferred without loss, and the run discovers 311 novel exact
exclusions in 179 billed conflicts. The active mechanism therefore succeeds at
generating new information, but `202+311=513` crosses the operational
512-clause archive cap by one. The fail-closed terminal persists no next vault,
model or key, so it is not a gain/recovery/exhaustion classification. The direct
successor is a complete external causal attic plus a deterministic bounded
active solver reservoir; do not retry/replay O1C-0073 or ordinal 9.
O1C-0074 implements that successor and completes all four frozen 128-conflict
episodes. The complete attic retains 37 new exact exclusions and grows from 513
to 550 unique clauses while active residency stays exactly 256. Episode 0's six
global duplicate occurrences promote six previously inactive clauses; episode 1
then emits the 37 novel clauses. The resulting projection is an exact fixed point
in episodes 2 and 3: active/reader/sieve evidence is bit-identical and both emit
nothing. This supports the causal-attic mechanism and closes only static replay.
The next successor is a target-free nonrepeating bounded residency/attention
rule, not a K/horizon/rank/phase/RAM sweep.
O1C-0075 executes that successor through two distinct K256 pages. Together with
the inherited projection they cover all 545 undominated clauses and leave zero
residency debt, yet both calls reproduce O1C-0074's exact fixed-point trace,
decisions, propagations, bounds and zero-emission outcome. This closes pure
residency rotation at the frozen horizon while retaining a valid bounded pager.
The next mechanism is the target-free nearest-clause live causal frontier:
unused Page 3 contains unique union clause 526 (`c4a9c471…`) at 2,409 false /
29 unassigned / 0 true literals under the sealed public terminal assignment.
The ten exact pair resolvents remain later compiler material because they are
farther from this live boundary; neither derivation nor activation trace alone
counts without a measured frontier result.
O1C-0076 tests that parent-zero-only frontier once and does not activate it. The
first parent zero arrives at callback 256 after all 29 residuals are assigned;
the wrapper consumes 18 falsifying-sign and 11 rescue-sign rows without one
substitution, release or contrast. Trace and science output remain unchanged.
O1C-0077 executes that target-free two-row staging once and activates exactly:
effective originals `-131/+130` and their later source contrasts all return,
and trace changes to `706ad4fa…`. Decisions fall 61.36% and the minimum UB
moves 0.014564 closer to the threshold, while propagations rise 64.51%. Zero
prunes, emissions, novel clauses or model keep this at mechanism-only level.
Close lineage 17 without retry. The next distinct test is the predeclared exact
11-row falsifying prefix before the inherited rank, using fresh Page 5
`07c73013…`; this directly preempts the nine rescue rows that propagation
previously assigned before the parent frontier could act.
O1C-0078 consumes that Page-5/lineage-18 call but returns no native result. Its
exact release-sign throw proves all 11 outer rows were consumed and parent
handoff was reached; empty stdout leaves actual prefix returns, rescue skips,
trace and every science output unmeasured. This parks prefix efficacy rather
than refuting it. O1C-0079 then installs explicit signed ownership and consumes
fresh Page 6 / lineage 19 once. All 549 proposals bind and release; 547 confirm,
two retire unobserved, and later opposite-sign observations cannot claim their
tokens. The unchanged prefix consumes all 11 rows, binds/releases nine, skips
two preassigned falsifying rows and zero rescue rows. Operational ownership and
qualified prefix activation therefore pass. The immutable raw false label is a
substring-validator defect, corrected additively with zero calls; science stays
false with zero prune, clause, model or key. Page 6 and lineage 19 must not be
replayed.
The score audit is unchanged: `tau=14.606178797892962` and O1C-0066 episode
1's `7.973483108047071` use the same compiled score metric, units and retained
maximization direction, but the latter is a minimum over that run's visited
partial trails rather than the complete-score cutoff. Admissibility proves only
that a particular `U(a)<tau` removes descendants of `a`; it does not prove
global exhaustion. O1C-0077 records `14.656823218163392>tau` and zero prunes;
O1C-0078 has no bound result; O1C-0079 records
`18.742222666780805>tau` and zero prunes. O1C-0080 then evaluates every eligible
same-parent child pair on fresh Page 7: all `285,725` probes remain live and the
minimum `18.464862193097684` is still `3.8586833952047215` above tau. Exact
operation passes, crossing/science fail, and Page 7 / lineage 20 are closed
without depth 2. O1C-0068 remains untouched. O1C-0081's target-free common-mode
census supports persistent centered coordinate priority in `28,672 B`, while
bit orientation remains withheld. O1C-0082 converts it into a live one-shot
failure-first action field and, on fresh Page 8, harvests 257 globally novel
exact exclusions after only nine conflicts. The direct one-bit action itself
never crosses tau; the guided descendant trails do. This is real sub-recovery
search-space gain, not a key or matched causal ablation. The measured blocker is
now the 512-clause active-vault cap. The zero-call audit also closes an apparent
shortcut: the exact tail cube has no non-tautological simple resolvent and its
common core remains `4.0603849711627085` above tau, so it supplies no prefix
closure, key recovery, tail-free no-good or resolution compression. Preserve
the complete harvest by immutable attic ingestion, then confirm and seal the
sealed 255-clause Page-9 projection and live-continuation parser before lineage
22; never replay Page 8. O1C-0084 burns that Page at the Darwin loader without
science output. O1C-0085 repairs the launch path and adds 23 more globally novel
trail-UB clauses on fresh Page 10. Its `actual_certified_prunes=0` refers only
to realized action crossings, whereas `threshold_prunes=23` counts the safe
local trail exclusions. The next vault is available and the bank evolves to
`2c0c4ccb…`; capacity is no longer the immediate blocker. Roll the complete
gain into fresh Page 11 before any new production intent, and never replay
Pages 8–10.
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
| `O1C-0076-N1` | Parent-zero-only activation of the nearest 29-residual resident no-good | `CAUSAL_FRONTIER_NO_ACTIVATION_NO_GAIN`; negative | First parent zero at callback 256; all rows already assigned, split 18 falsifying / 11 rescue; cursor 29, zero substitutions/releases/contrasts, unchanged trace and zero prunes/emissions/model | Close lineage 16; first stage the two ranked rescue originals as falsifying on fresh Page 4, then escalate once to the sealed 11-row preemptor only if needed |
| `APPLE-VIEW-0001` | Public feed-forward fixed-point projection and output-Hamming local descent | `EXPLORATORY_FULL256_NEGATIVE` | 32 deterministic Full-256 targets; -0.484 holdout keybits, AUC 0.50572, direction accuracy 0.49854, 0 recoveries; 21,108 R20 core evaluations | Output score admits descent without key-distance descent; close this fixed-point/local-fitness path | [Result](research/apple_view/apple_view_result.md) |
| `APPLE-VIEW-0002` | Exact GF(2) quotient after independently lifting all addition carries | `EXPLORATORY_FULL256_NEGATIVE` | 8 deterministic Full-256 targets; carry rank 512, exact key rank 0, exact recoveries 0; all 8,192 lifted equations validate | Independent carries span the entire public output and erase every linear key parity; only globally restoring carry recurrence by depth is a new test | [Result](research/apple_view_2/apple_view_2_report.md) |
| `APPLE-VIEW-0003` | Uniform exact carry recurrence by bit depth with sound forward three-valued rejection | `EXPLORATORY_FULL256_NEGATIVE` | 32 output-independent Full-256 probes across depths 0..31; depths 0..30 determine 0 final bits and reject 0/32, depth 31 determines 512 and rejects 32/32; 0 recovery/entropy claim | Forward-only bitwise carry truncation has a depth-31 cliff; require correlation preservation or two-ended constraint propagation | [Result](research/apple_view_3/apple_view_3_report.md) |
| `APPLE-VIEW-0004` | Exact bidirectional GAC through partial-carry Full20 constraints | `EXPLORATORY_FULL256_NEGATIVE` | depth 30 infers 3,720–3,850 variables beyond fixed input/output but rejects 0/4 wrong probes; depth 31 rejects 4/4 and retains truth; 18.12 s, 87.9 MB | One free c31 per each of 336 additions absorbs every local contradiction; test sparse joined carry identities rather than more local propagation | [Result](research/apple_view_4/apple_view_4_report.md) |
| `APPLE-VIEW-0007` | Static target-independent strongest-predecessor traversal over exact BUILD proof-DAG paths | `HELDOUT_STATIC_EDGE_SCHEDULER_NEGATIVE` | 113,570 B state; raw 1,340 vs unary 1,268 vs fixed 1,031; certificate 1,003 vs fixed 1,015 and unary 997; all wrong/truth controls exact | Static/global path relation delays repeated zero-edge roots; close without root/threshold/traversal sweep and move to live action-conditioned context | [Result](research/apple_view_7/apple_view_7_report.md) |
| `O1C-0052-N1` | Negative conflict-undo credit over 252 exact pair actions | `CONSUMED_POST_REVEAL_PATTERN_ACTION_CREDIT_SCREEN` negative | W11 `UNKNOWN` at 512 conflicts; 162 action reorderings, 18 differentiated cells, 502/513 repeated decisions; every visited cell penalized | Exact addressing creates tabu diversity but not causal blame; O1C-0053 has now closed the one survivor test, so move to exact antecedent membership | [Result](research/O1C0052_PATTERN_CREDIT_SCREEN_RESULT_20260719.md) |
| `O1C-0053-N1` | Deepest surviving trail action as a proxy for retained conflict causality | `CONSUMED_POST_REVEAL_SURVIVOR_SUPPORT_SCREEN` negative | W11 `UNKNOWN` at 512 conflicts; 512 support updates/16,384 units, 111 reorders and only two differentiated groups; post-result truth view puts the true mask supported/top in 4/8 active groups and 9,472/16,384 units on true masks | Close survival despite nonzero truth alignment: the diagnostic is consumed, did not close W11 and authorizes exact antecedent membership, not `+32` tuning | [Result](research/O1C0053_DEEPEST_SURVIVOR_SUPPORT_SCREEN_RESULT_20260719.md) |
| `O1C-0054-N1` | Sum of independent per-factor maxima as an admissible global prefix bound | `CONSUMED_POST_REVEAL_GLOBAL_BOUND_SCREEN` negative | Public Full256 recovers 0/256 and loses truth at stage 5; post-reveal W11 reaches 1,024 unscored pops with 14 forwards and zero certified leaves | Exact W12 truth rank 5 requires coordinated factor assignments that the separable envelope discards; close without width/order/cap tuning and retain exact learned-clause membership as the active path | [Result](research/O1C0054_GLOBAL_FACTOR_BOUND_SCREEN_RESULT_20260719.md) |
| `O1C-0055-N1` | Negative credit to every exact live-owner member of each learned clause | `CONSUMED_POST_REVEAL_EXACT_LEARNED_CLAUSE_SCREEN` negative | 512/512 clauses match; average 5.24 owners/4.02 cells per conflict, yet W11 is `UNKNOWN`, 18 unique cells/seven groups match O1C-0052 and 502/513 decisions repeat | Exact membership is real but all-member blame is diffuse; close sign/scale tuning and select one exact role-conditioned member | [Result](research/O1C0055_LEARNED_CLAUSE_CREDIT_SCREEN_RESULT_20260719.md) |
| `O1C-0056-N1` | Fixed negative credit to one deepest/current-level exact owner role per learned clause | `CONSUMED_POST_REVEAL_EXACT_CLAUSE_ROLE_CREDIT_SCREEN` negative | 512/512 clauses select one unique current-level role and discard 2,150 matched members, but W11 remains `UNKNOWN`; propagations fall 69,836 while native wall rises 0.337276 s, and 18 cells/seven groups persist | Owner localization is complete; close fixed negative credit without sign/scale/cap tuning. Park utility-conditioned work behind O1C-0059 and APPLE8 | [Result](research/O1C0056_CLAUSE_ROLE_CREDIT_SCREEN_RESULT_20260719.md) |
| `O1C-0058-N1` | Positive one-bit finite differences around the supplied-panel-best complete eight-block decoy as independent key-bit correction evidence | `MULTIBLOCK_BIT_VAULT_NO_DIRECTIONAL_TRANSFER`; fresh Full-256 negative | base and primary prefix 8 both 127/256, gain 0, longest confidence prefix 0; controls 127/128; every public candidate matches 0/8 blocks | Two locally improving primary score directions do not improve truth alignment. Close only attended-best-decoy positive-delta vault; consensus is outside the formal run | [Result](research/O1C0058_MULTIBLOCK_BIT_VAULT_GRADIENT_RESULT_20260719.md) |
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
