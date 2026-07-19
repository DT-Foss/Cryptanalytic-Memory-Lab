# O1 Cryptanalytic Memory Lab — Current Status

- **Last updated:** 2026-07-19T12:36:04+02:00 (`Europe/Berlin`)
- **Current truth:** the exact O1C-0019 → O1C-0022 full256 chain has run. Both
  attempts are operationally complete, verified and scientifically negative.
- **O1C-0019:** `BUILD_LOO_NO_TRANSFER`; 2,467.325 s elapsed, 362,528,768 B peak;
  learned policy `-0.271090` bit mean compression. Raw learned reader
  `+0.312764`, raw untrained reader `+0.371233`; learning loses `0.058470` bit.
- **O1C-0022:** `CROSS_COORDINATE_DILUTION`; 70.218 s elapsed, 297,910,272 B
  peak, exact 352-byte vault. K256 int8 compression is `-1.181837` bits; raw,
  normalized and unit-sign K256 arms are also negative.
- **Recovery gate:** no precommitted O1C-0022 raw arm exceeds `120/210` A325 or
  `118/204` A526 complement bits on any post-reveal fold. The true key is absent
  from both residual domains; do not run either backend.
- **Decision:** close the unary O1C-0019 packet/vault field. Do not spend compute
  on O1C-0023, O1C-0025 or O1C-0029 over the same null evidence, and do not tune
  its scale, quantizer, horizon weights, reader or frontier size.
- **Sibling reuse:** A325/W46 and A526/W52 remain unchanged terminal recovery
  engines. Their real recoveries require 210/204 already-correct complement bits;
  those bits are an input contract, not an output of the sibling engine.
- **Closed exact transfers:** A296 `118/61/9/230`, A448/A465 `47/239`, A469
  `56/239`, plus the O1C-0019/O1C-0022 unary full256 bridge.
- **Literal A526 combination completed:** O1C-0035 decoded 1,310,720 exact
  complement candidates in 0.832396 s at 45,989,888 B peak. Across four consumed
  folds and five frozen arms, no top-65,536 beam contains the exact 204-bit
  complement. MAP max is `118/204`; post-reveal oracle beam max is `123/204`.
- **O1C-0036:** the direct eight-block public O1 reader completed on 1,024
  synthetic uniform training keys and 128 unseen sibling BUILD targets with the
  published known complements stripped from deployment input. Mean MAP is
  `102.5/204`, aggregate accuracy `50.2451%`, mean compression `-0.393341` bit,
  and exact top-65,536 complements `0/128`. Close this raw-output reader.
- **O1C-0037:** the first direct O1-to-exact-ChaCha adapter is operational. Exact
  256-bit truth guidance recovers in `5,065 us` with zero conflicts, but the real
  frozen O1 field (`117/256` MAP on the consumed target) gives no recovery and
  key-only guidance cannot repair one wrong hint through 32,768 conflicts.
- **O1C-0038:** the corrected post-reveal ceiling recovers and independently
  verifies the full 256-bit key with `8` O1-ordered bits left unknown: `89`
  conflicts and `135,441 us`. Residual width `9` remains unresolved through
  `32,768` conflicts. This is a mechanism ceiling, not attacker-valid recovery.
- **O1C-0039:** the BUILD-frozen H16/`|J|=0.5` signed proof-clause field transfers
  to both DEVELOPMENT targets: `238/432` (`55.09%`) and `159/279` (`56.99%`),
  pooled `397/711` (`55.84%`) versus key-rotated `52.88%` and factor-rotated
  `49.51%`. Fields are 3,512/2,288 B. Full-256 and residual-9 recovery remain
  `0`; classification `RELATION_TRANSFER_ONLY`.
- **O1C-0040:** complete-candidate scoring closes the direct conversion. Raw
  primary truth ranks are `1905/4097` and `2292/4097`; structural-surprise ranks
  are `1078/4097` and `1461/4097`, while key rotation is much better at
  `107/4097` and `423/4097`. Clause occurrence is structural, not a usable
  target-key objective.
- **O1C-0041:** branch-exclusive antecedent-chain identity restores complete-key
  rank concentration on the consumed panel. BUILD rank-product selects `-1`;
  DEVELOPMENT truth ranks are `80/4097` and `998/4097`, geometric `6.8967%`,
  versus key-rotated `27.0187%` and factor-rotated `16.2556%`. Classification is
  `RETROSPECTIVE_CHAIN_RANK_SIGNAL_WITH_CONTROL_MARGIN`.
- **O1C-0042:** the only fresh replication ranks primary `1371/4097` (`33.46%`),
  key rotation `1399/4097` and factor rotation `3385/4097`. The control margin
  survives narrowly, but the frozen best-quarter gate fails; classification
  `FRESH_CHAIN_RANK_NOT_REPLICATED`. No retry.
- **O1C-0043:** ordered RUP parent-role and original-clause criticality ranks the
  two consumed DEVELOPMENT truths `5/4097` and `91/4097`, geometric `0.52%`,
  versus best control `38.52%`. The unchanged consumed O1C-0042 repeat ranks
  `141/4097` versus key/clause rotations `3623/4097` and `3475/4097`.
  Classification `CONSUMED_PARENT_CRITICALITY_RANK_SIGNAL`.
- **O1C-0044:** exact unchanged fresh replication passes at primary `54/4097`
  (`1.318%`, z `+2.325`) versus key rotation `3567/4097` and clause rotation
  `2972/4097`. One entropy call, reveal after score freeze, independent ChaCha
  verification; classification `FRESH_PARENT_CRITICALITY_RANK_TRANSFER`.
- **O1C-0045:** exact algebraic compilation preserves every frozen score within
  `1.25e-14` and primary rank `54/4097`. Full-256 is still unresolved at 512
  conflicts. On the post-reveal ceiling, internal search closes residual 8 but
  not 9; primary closes 9 in 281 conflicts, while key/clause rotations also close
  9 in 69/129. The factor family expands 8→9, but primary has no control margin.
- **O1C-0046:** key-only scheduling retains all internal observations while
  restricting external choices to 126 key coordinates. Primary width-8/9 work
  falls from `152/281` to `43/87` conflicts, but the matched clause rotation is
  still better at `22/46`; Full-256 remains unresolved. The exact frontier stays
  at 9 bits and greedy local marginal scheduling is closed.
- **O1C-0047:** the unchanged complete-state score ranks consumed truth `1/256`,
  `5/4096` and `50/65536` on nested post-reveal residual cubes W8/W12/W16.
  Width-16 rotations rank `60592/65536` and `43059/65536`; the primary top-256
  beam contains the uniquely verified exact key at rank 50. This is 10.356 bits
  of privileged local search compression, not attacker-valid Full-256 recovery.
- **O1C-0048:** the reversible 63-pair global max-envelope adapter is complete.
  Full-256 is unresolved in all four arms. Exact residual frontiers are
  internal/primary/key/clause `8/9/9/9`; W8 conflicts are `217/75/195/89` and W9
  conflicts are `UNKNOWN/155/331/167`. The frozen global all-arm gate fails
  because frontiers are untied, but primary is pairwise lexicographically better
  than every comparator. This is a consumed specificity breadcrumb, not a
  promoted recovery result.
- **O1C-0049:** the first 630-byte live pair-credit state has run on the same
  consumed target. Full-256 is byte-for-byte unchanged at 513 conflicts and
  10,802 decisions. W8/W9 improve from `75/155` to `65/128` conflicts, but W10
  regresses from `310` to `320`, so the absolute gate fails. All 3,301 Full-256
  tickets closed before the solver's 590 later backtracks, leaving 62/63 group
  credits identical. Close the short-ticket formula, not delayed live credit.
- **O1C-0050:** trail-resident owner eligibility passes its one-call gate. The
  exact W10 key needs `302` conflicts versus frozen static `310` (`-2.58%`) with
  exactly 1,134 state bytes. All 302 backtracks carry conflict credit; seven
  groups differentiate and no assignment/propagation bonus remains. This earns
  one W11 primary call before any rotations or Full-256 promotion.
- **O1C-0051:** the unchanged delayed-primary scheduler does not extend to W11.
  Its sole call returns `UNKNOWN` at `512` conflicts / `513` decisions, so the
  exact gate fails and all six static/rotation/Full256 follow-ups remain unrun.
  Freeing bit 177 flips conflict-owner concentration from `(143,144)` at
  `227→1` to `(59,60)` at `55→382`; close unary group credit as context/sequence
  blind. All four pair masks share one credit while 502/513 decisions repeat;
  test bounded context/action-conditioned per-pattern credit next.
- **O1C-0052:** exact four-action credit also fails W11: `UNKNOWN` at the same
  `512` conflicts / `513` decisions and 12,066,879 propagations. The 2,646-byte
  state genuinely changes 162/448 later selections and differentiates 18 action
  cells across seven groups, but repeated decisions remain `502/513`. Every
  visited cell is penalized; `(59,60)` cycles all four masks with
  `48/50/48/51` conflict-owner undos. Negative undo credit is anti-repetition,
  not localized key evidence. Close it without a scale/group/cap sweep.
- **O1C-0053:** positive deepest-survivor support also fails W11: its only call
  returns `UNKNOWN` at `512` conflicts / `513` decisions and 12,068,568
  propagations. All 512 conflict backjumps apply one `+32` survivor update
  (`16,384` support units), yet only two groups differentiate and just 111
  actions reorder. The same 2,646-byte state is operational, but survival is too
  coarse a causal proxy. A consumed post-result truth view puts 9,472 units on
  true masks and the true mask supported/top in 4/8 active groups; it did not
  close W11 and is not fresh evidence. Close H-DEEPEST-SURVIVOR-SUPPORT-062
  without tuning.
- **O1C-0054:** the independent global factor-bound path is now executed and
  closed. Its unconditional public-only Full256 beam recovers no key, loses the
  true prefix at stage 5 on pair `(9,10)` and finishes at top/minimum Hamming
  `120/116`. The post-reveal W11 queue hits 1,024 unscored pops after 14 forward
  evaluations with zero certified leaves. Exact W12 score rank 5 survives only
  as the breadcrumb: independent factor maxima destroy the required joint
  geometry. Do not tune width, pair order, cap or bound scale.
- **O1C-0055:** exact minimized learned-clause membership is operational but
  all-member `-32` still fails W11: `UNKNOWN` at 512 conflicts/513 decisions/
  12,083,477 propagations. All 512 clauses match live owners, producing 2,684
  members and 2,057 per-clause cell penalties, yet the state again touches only
  18 unique cells/seven groups like O1C-0052. Close indiscriminate negative
  credit.
- **O1C-0056:** exact one-role localization also fails W11: `UNKNOWN` at 512
  conflicts/513 decisions/12,013,641 propagations. Every one of 512 clauses
  selects exactly one current-level owner; 2,150 of 2,662 matched members are
  discarded, with 508 multi-member clauses and zero deepest-level ties. The
  fixed 512 `-32` updates reduce O1C-0055 by 69,836 propagations and 25
  reorderings but still occupy 18 cells/seven groups and are slower natively.
  Close fixed negative deepest/current-owner credit without tuning.
- **O1C-0057:** the unchanged O1C-0043 parent-criticality reader compounds on
  one fresh uniform Full-256 target across 1/2/4/8 public blocks. Primary truth
  ranks are `8/7/1/1` of 4,097, while prefix-8 key/clause rotations rank
  `3581/4037`; prefix-8 truth z is `+5.57888245`. This passes the frozen
  prediction and establishes approximately 12 bits of complete-candidate
  discrimination inside the supplied panel. It is a transferred scorer/orderer,
  not key generation or exact recovery.
- **O1C-0058:** the direct complete-decoy-to-bit conversion is closed on one
  fresh uniform Full-256/eight-block target. The attended base and primary
  prefix-8 synthesis both have `127/256` correct bits; gain is `0`, longest
  correct confidence prefix is `0`, controls have `127/128`, and all 13 public
  candidates match `0/8` blocks. No partial or exact gate passes. Preserve
  O1C-0057's complete-key score; close only attended-best-decoy plus positive
  one-bit-delta vault. A separate crowd-consensus scratch was control-negative
  but is not part of O1C-0058 and does not create a formal consensus closure.
- **O1C-0061:** the corrected one-call joint-sieve baseline is terminal as
  `EXACT_JOINT_SCORE_SIEVE_ACTIVE_NO_RECOVERY`. It records a material safe-bound
  drop before any complete model at requested 512/billed 513 conflicts, but zero
  safe trail prunes and no key. This establishes an active exact bound mechanism;
  O1C-0061 alone is not a search-space-gain result.
- **APPLE-VIEW-0008:** the matched augmentation passes strictly at the same
  requested 512/billed 513 conflicts. Minimum safe upper bound falls
  `24.7944466611→13.1979307788`, below threshold `14.6061787979`; safe trail
  prunes rise `0→6`, decisions fall `9166→4471`, and propagations fall
  `1227877→1178185`. Classification is
  `APPLE_VIEW_0008_STRICT_INCREMENTAL_EFFECT_NO_RECOVERY`: the first certified
  Full-256 trail-pruning/search-branch removal in this line, with no returned key
  and no truth read.
- **O1C-0062/0063/0064 scaling boundary:** none of the three 4K promotions is a
  science result and none is retried. O1C-0062 exposed the native callback/
  teardown defect after about one second. O1C-0063 repaired that lifecycle and
  entered the real Full-256 path for `17.763142674 s`, then most likely reached
  the guarded `736 MiB` ceiling; its old wrapper discarded the underlying cause.
  O1C-0064 preserved the cause exactly and confirms the resource boundary:
  `watchdog_memory` after `29.804627625 s`, observed `1,040,285,696 B` against
  the guarded `1,040,187,392 B` threshold. No key, native result, or truth read.
- **APPLE-VIEW-0009:** the public exact score-aware width-6 grouping artifact is
  positive. It lowers the safe root upper bound from the frozen
  pair relaxation's `269.7472723039718` to `262.68644197084643`, while reducing
  `3,805→2,885` groups, `265,256→176,912` rows and estimated indexed state
  `2,510,008→1,710,776 B`. Exhaustive synthetic completion checks and 10,000
  exact-outward rounding checks pass. This artifact alone is a bound/mechanism
  result; O1C-0065 below supplies its native pruning test. The byte reduction is
  strictly versus the legacy
  pair index, not O1C-0064's independent-factor native: on the same partial
  accounting width-6 adds `1,199,632 B` there and can move the 992-MiB wall only
  indirectly by changing search/pruning.
- **O1C-0065:** the exact width-6 grouping is now integrated into the repaired
  native Full-256 path and has completed its one frozen matched-work call. It
  tightens root UB `292.30611344510277→262.68644197084643`, minimum observed UB
  `13.197930778790159→12.934208247009447`, and shrinks the derived live cache
  `60,456→23,080 B`, but emits the same `6` safe cuts with exactly the same
  `4,471` decisions and `1,178,185` propagations. Native peak RSS is effectively
  unchanged (`388,644,864→386,547,712 B`, contextual). Classification is
  `O1C65_GROUPED_WIDTH6_EFFICACY_RETAINED`: no strict efficacy gain, no key and
  no truth read. Do not repeat the same 512-conflict comparison or promote it
  directly to the known 4K memory wall.
- **Apple parallel tracks:** fixed-point/output-fitness descent is closed at
  `-0.484` gained key bits, AUC `0.50572`, and zero recoveries. Independent-carry
  quotienting is also closed: carry rank is 512 and exact key rank 0 on all eight
  Full-256 targets. Two-ended exact local propagation at depth 30 now infers
  3,720–3,850 internal variables per wrong probe but rejects 0/4 because one
  free high carry per each of 336 additions absorbs the contradiction. The
  sparse-switch successor is positive: all 20 wrong candidate/order runs reject
  exactly, and independently replayed conflict certificates need only
  `250–265/336` high-carry identities. The best omits 86 identities; all five
  truth controls remain complete. This is an exact candidate filter, not key
  generation or entropy reduction. APPLE-VIEW-0006 then streams 4,603 exact
  BUILD proof-participation events once into a frozen 1,346-byte state. On four
  disjoint held-out wrong probes its raw order loses to final→early at
  `1,268` versus `1,031` total first-conflict switches, but its independently
  replayed exact certificates are smaller on all four cases:
  `248/248/251/250` versus the best fixed structural
  `251/252/257/255` (aggregate `997` versus `1,015`) and aggregate immediate
  public gain `1,013`. Proof relevance transfers; early scheduling does not.
  APPLE-VIEW-0007 then replaces unary membership with one frozen 113,570-byte
  proof-DAG edge/root/terminal state. Its static strongest-predecessor reader
  fails raw at `1,340 > 1,268 > 1,031` for edge, exact unary and final→early.
  Certificate `1,003` beats fixed `1,015` but loses unary `997` and cannot pass.
  All 28 wrong passes, proof replays, freeze checks and truth controls are exact.
- **Next paid experiment:** build a bounded causal no-good vault around the
  repaired width-6 native path. Each short Full-256 episode starts a fresh solver,
  imports only canonical threshold-certified score-feasibility clauses from earlier
  episodes, exports newly emitted clauses, and then destroys all solver memory.
  The first paid call waits for synthetic soundness, archive identity, deduplication
  and lifecycle/RSS-reset gates. This tests whether exact pruning compounds while
  keeping per-episode memory bounded instead of repeating the monolithic 4K path.
- **Goal correction:** A526 is a retained terminal branch, not the whole research
  objective. Transferable held-out entropy, joint true-key rank, effective
  residual-width and time-to-hit gains now count as real sub-256 progress. A
  relational completion branch may combine O1 scores with exact ChaCha relations
  without first demanding 204 independently correct bits.
- **Constraint boundary:** A513's six bases and A518B's K4,4 frame are equivalent
  solver compilations of the same public relation. They can improve conditioning
  and proof geometry but are not counted as extra independent key constraints.
- **Latest effect-first screens:** direct second-order proof pairs, terminal
  single-bit UNSAT, failed cores, inverse fixed points, one-bit candidate
  neighbors and W8 cells are all negative at their tested surfaces. The final W8
  correlation collapsed from `-0.158165` to `-0.014003` on the unchanged repeat;
  do not scale or reorient it.
- **Active local run:** no scientific process is active. O1C-0065 is sealed as a
  matched Full-256 retained-efficacy result: tighter bounds and smaller logical
  state, but the same six cuts and identical search work. Immediate ROI is the
  bounded episodic causal no-good vault, not another 512 comparison or a direct
  4K promotion. O1C-0053..0056 and the exact O1C-0058 rule remain negative and
  closed.
  Sibling repositories remain read-only and untouched.
- **SOTA target:** an exactly verified uniformly random 256-bit ChaCha20 key is
  the north star; the scored objective is the strongest reproducible
  attacker-valid point reached on entropy, joint rank, effective residual width,
  matched search work or time-to-hit, not a binary `256-or-zero` gate.
- **Latest results:**
  [O1C-0065 exact width-6 native result](research/O1C0065_APPLE8_WIDTH6_GROUPED_SIEVE_RESULT_20260719.json),
  [O1C-0064 exact memory boundary](research/O1C0064_APPLE8_CROSSBLOCK_SIEVE_4K_RESOURCE_FIX_RESULT_20260719.json),
  [APPLE-VIEW-0009 exact grouped bound](research/APPLE_VIEW_0009_EXACT_GROUPED_BOUND_RESULT_20260719.json),
  [O1C-0063 watchdog diagnosis](research/O1C0063_RESOURCE_WATCHDOG_DIAGNOSIS_20260719.md),
  [APPLE-VIEW-0008 matched Full-256 pruning](research/apple_view_8/apple_view_8_matched_result.json),
  [O1C-0061 joint-sieve baseline](research/O1C0061_MULTIBLOCK_JOINT_SCORE_SIEVE_SOFT_STOP_RESULT_20260719.json),
  [O1C-0058 multi-block bit-vault close](research/O1C0058_MULTIBLOCK_BIT_VAULT_GRADIENT_RESULT_20260719.md),
  [O1C-0057 multi-block rank transfer](research/O1C0057_MULTIBLOCK_PARENT_CRITICALITY_RANK_RESULT_20260719.md),
  [O1C-0056 clause-role close](research/O1C0056_CLAUSE_ROLE_CREDIT_SCREEN_RESULT_20260719.md),
  [O1C-0055 learned-clause all-member close](research/O1C0055_LEARNED_CLAUSE_CREDIT_SCREEN_RESULT_20260719.md),
  [O1C-0054 global factor-bound close](research/O1C0054_GLOBAL_FACTOR_BOUND_SCREEN_RESULT_20260719.md),
  [O1C-0053 deepest-survivor W11 close](research/O1C0053_DEEPEST_SURVIVOR_SUPPORT_SCREEN_RESULT_20260719.md)
  and [APPLE-VIEW-0007 static proof-edge close](research/apple_view_7/apple_view_7_report.md).

## Headline

The program is now transfer-first, effect-first and joint-aware. A296/A448/A465/A469 were
real but representation-level projections; their nulls close those projections,
not the native W52 architecture. The complete O1C-0019/O1C-0022 all256 chain
also ran and is negative. The best post-reveal O1C-0022 raw arm still misses at
least 90 of 210 A325 complement bits and 86 of 204 A526 bits. O1C-0035 now freezes
the exact 204-bit completion frontier feeding the unchanged W52 backend. That
factorized branch remains active. O1C-0037 now closes simple key-phase-only CDCL
guidance on the frozen unary field, while O1C-0038 proves that the unchanged exact
relation can complete an O1-ordered residual width of eight in `135,441 us`.
O1C-0039 now answers the first H-RELATIONAL-037 subquestion positively: a tiny
attacker-valid signed proof field transfers at `55.84%` pooled relation accuracy
on both held-out keys. O1C-0040 shows why that did not reduce search: the raw true
complete execution is near median among decoys, and the fixed surprise correction
is dominated by key rotation. The exact occurrence reader is now closed. The
branch-exclusive O1C-0041 successor then ranks the two consumed true keys
`80/4097` and `998/4097` with geometric fraction `6.90%`, beating both endpoint
rotations. O1C-0042 tests its unchanged prospective transfer and answers no:
rank `1371/4097` retains a small control margin but misses the frozen top
quarter. The frontier moves from unordered unique leaves to ordered parent-role
and clause-criticality factors without tuning the closed reader. O1C-0043 makes
that move concrete: frozen Development ranks `5/4097` and `91/4097` beat both
endpoint controls, and the unchanged consumed O1C-0042 repeat ranks `141/4097`.
That earned exactly one prospective replication. O1C-0044 answers yes at
`54/4097` with both rotations in the bottom third. The
O1C-0045 exact compiler then turns that score into local factors. The factor
family expands the consumed residual ceiling from eight to nine bits, but both
rotations beat primary. O1C-0046 removes internal variables from external
branching: primary work improves 3.5x/3.2x at residual 8/9, yet the clause
rotation with the identical key-decision set remains faster. The loss is
therefore not only internal-variable competition; local greedy marginals do not
carry the global rank orientation into search. Preserve the global score and
change the handoff geometry, not the reader, target or conflict cap. O1C-0047
now proves why: the unchanged global score places truth at rank `50/65536` on a
complete W16 cube while both rotations are in the bottom third. Its top-256 beam
contains and independently verifies the exact key. The remaining problem is no
longer whether this consumed score has local joint information; it is how to
approximate that complete-state order before the 240-bit complement is known.
O1C-0048 supplies the first live global approximation. Its disjoint pair
envelope does not recover Full-256 and misses the frozen all-arm gate, yet it
restores primary ordering over both rotations at W8 and W9 while expanding the
internal W8 frontier to W9. This is the exact point to introduce live causal
credit: preserve the ordering, remove the static pair scheduler's extra work,
and keep the next comparison pairwise-lexicographic and frozen in advance.
O1C-0049 performs that smallest live update. It cuts W8/W9 work by 13–17% but
loses at W10 and leaves Full-256 exactly unchanged. The state telemetry explains
the failure without a sweep: action tickets expire at the next decision, while
all Full-256 backtracks arrive later. The next adapter changes only this causal
horizon by retaining a bounded eligibility trace across advances.
O1C-0050 makes that repair and reduces exact W10 work from 310 to 302 conflicts,
but O1C-0051 stops `UNKNOWN` at the unchanged W11 cap. The dominant conflict
owner reverses from `(143,144)` to `(59,60)` when bit 177 joins the residual.
O1C-0052 then separates every mask and changes 162 live choices, but remains
`UNKNOWN`; all visited cells are penalized and repeats stay 502/513. Delayed
unary and negative exact-mask credit are therefore closed. The distinct next
operator rewards the deepest action that survives each conflict backjump.
O1C-0053 executes that operator and still returns `UNKNOWN` after 512 conflicts.
Its 512 positive updates reorder 111 actions but differentiate only two groups,
so trail survival is closed as the causal proxy. Exact learned-clause/first-UIP
antecedent membership is the next causal discriminator. O1C-0054 executes the
parallel global-prefix path independently: the unconditional public Full256 beam
loses truth at pair stage 5 and the post-reveal W11 queue certifies zero leaves
under its frozen cap. The separable factor-max envelope is therefore closed too.
O1C-0055 then installs exact learned-clause membership. Every conflict supplies
matched live owners, but penalizing all of them again reaches only the same 18
cells/seven groups as O1C-0052 and remains `UNKNOWN`. Exact membership is kept;
collective negative blame is closed. O1C-0056 then selects exactly one deepest
owner for every matched clause. All 512 selections are uniquely current-level,
including 508 clauses with multi-owner fan-out, but W11 remains `UNKNOWN` and
the same 18 cells/seven groups persist. Localization is solved; fixed negative
conflict credit is not useful enough. Close it without tuning and defer any
outcome/utility-conditioned successor. O1C-0057 then executes the higher-ROI
public-evidence path and transfers decisively: the unchanged parent-criticality
reader moves fresh complete-key truth from rank 8/4,097 on one public block to
rank 1/4,097 on four blocks and retains rank 1 on eight. Prefix-8 rotations fall
to 3,581/4,097 and 4,037/4,097, while truth reaches z `+5.57888245`. This is the
first prospective multi-block compounding of the complete-candidate score and
approximately 12 bits of discrimination inside the supplied panel. It does not
generate that panel or recover the key. The direct next step is therefore to
apply the frozen prefix-8 scorer to attacker-generated partial assignments or
bounded exact-search branches, not to enlarge another decoy panel. O1C-0058
tests the simplest local conversion first: one-bit finite differences around the
best eight-block decoy. It leaves primary at the base's `127/256` correct bits,
with gain `0`, confidence prefix `0` and `0/8` public-block matches for every
candidate. The complete-key scorer remains valid. The supplied-panel optimum
has two locally score-improving primary directions, but those flips do not align
with truth. Close only this attended-base positive-delta rule; crowd/elite
consensus is outside the formal O1C-0058 run. O1C-0061 now supplies the exact
joint-CNF bound baseline: material pre-model bound progress, but zero trail
prunes and therefore no standalone search-space-gain claim. Its matched
APPLE-VIEW-0008 augmentation retains the same target, potential, threshold and
requested/billed work while making redundant public P20 units and
`P_b = P_0 + (Z_b - Z_0)` key-lane consequences explicit. It crosses the safe
bound below threshold and removes six live trail branches, with decisions down
`9166→4471`. This is certified Full-256 pruning, not key recovery. The
O1C-0062→0064 promotion chain localizes its 4K failure to native memory growth;
APPLE-VIEW-0009 supplies the distinct tighter/smaller bound and O1C-0065 now
closes its standalone native test: bounds/cache improve, but the same six cuts
and identical search work remain. The next distinct lever is cross-episode
threshold-certified clause persistence with solver memory reset.
In parallel APPLE-VIEW-0005 finds the first exact sparse carry certificate:
250 of 336 high-carry identities suffice to reject a complete wrong key on the
fixed matrix, with independent proof replay. APPLE-VIEW-0006 then performs the
held-out transfer instead of more same-target pruning. Its 1,346-byte frozen
frequency/recency state loses raw stopping position (`317` switches per probe),
but yields smaller replayed proof cores on every held-out case and beats the best
fixed structural certificate aggregate `997` versus `1,015`. The transferable
object is proof membership. APPLE-VIEW-0007 then makes sequence explicit with a
113,570-byte edge state and one frozen strongest-predecessor reader, but loses
raw at `1,340` versus unary `1,268` and fixed `1,031`. Its certificate `1,003`
beats fixed `1,015` yet loses unary `997` and cannot pass. A repeated zero-edge
root lands at position 335: static/global path credit is insufficient. O1C-0053
now also closes the cheap live-survival proxy, so the convergence point is exact
conflict-antecedent attribution, not an Apple or credit-weight rescue sweep.

`O1C-0030` finalized from source commit `e7c1bf5` on the four already-consumed
full-round BUILD FAPs. Its precommitted same-coordinate exact-frontier lamp does
not pass: primary mean compression is `-0.680620` bit/key, it trails cumulative
replacement in every fold by `-0.582832` mean bit, and none of the four exact
top-65,536 frontiers contains the key. The deranged-confidence control reaches
`+0.779642`; that is a control win which contradicts local hard attachment, not
cryptanalytic evidence. The complete frozen run took 7.455637 measured seconds
at 62.70 MiB peak and repeated without replay. Preserve the narrow active-row
breadcrumb only; move confidence routing global/live after authoritative packet
deltas exist rather than sweeping this diagonal again.

`O1C-0029` remains source-frozen at `22d417c` but is parked and unrun. It changes
only the hot readout of the now-authoritative null O1C-0022 packet field, so it
cannot be the next paid recovery experiment. Preserve the implementation for a
future positive evidence field.

`O1C-0028` is finalized from source commit `17c02df` with capsule manifest
`aab7484b36b4a7c6e59ad556d41f44fbb88477b2f3f1f45270c0685e7a16ce09`.
One complete synthetic 256-coordinate H64/H65/H96 packet ledger is canonically
transposed into three `float32[3,256]` horizon-major groups and consumed once by
a self-describing 25,128-byte V2 state. Sixty-four fresh allocations, reversed
packet order, complement, permutation, independent complex128 reference and
serialization controls all pass. Two factory-bound readers query the identical
state with zero replay or writes; all 13 evidence/addressing/basis-changing
operators require cold replay.

The formal capsule completes in 0.143779 seconds, with 0.123936 measured wall,
42.8125 MiB peak RSS and no failed budget. A pure-stdlib wire codec is byte-exact
against the immutable O1C-0019 packet producer while leaving Torch and the legacy
controller stack unloaded. The V2 basis fixes the one-ULP allocation-dependent
V1 recurrence by freezing every float32 rounding point and prefixing serialized
state with basis SHA `75b0c13e...`; V1 bytes require one cold migration and are
never reinterpreted. This is synthetic transport/state/routing validation only:
it contains no ChaCha20 evidence and claims neither signal nor key recovery.

`O1C-0027` is finalized from source commit `f47a6da` with capsule manifest
`1361823ceb8711090b4773fd8409ced7123e490b71c30a2a9e41c5ec205c2023`.
It consumes a complete 384-group, three-wavelength, all-256 evidence field once
into exactly 25,096 persistent bytes per state, independent of stream length.
Four slot/temperature readers then query the same final state with zero stream
reingestion and zero state writes. Rechunking is byte exact, branch swap negates
slots and readouts exactly, direct complex128 reference error stays inside the
derived float32 bound, and encoder/kernel/phase basis changes correctly require
replay.

The four hot readers are not merely differently scaled copies: their minimum
pairwise RMS after normalization is `0.0816628445`, while a deliberately
collapsed slot bank gives only `1.23956887e-16` and is rejected. Scientific work
is 4,131,840 production resonator-cell updates; the measured path takes 0.094719
wall seconds at 39.390625 MiB peak RSS with no target, label, entropy, solver,
GPU, MPS or sibling access. This validates the constant-streaming parameter
boundary: reader weights and temperature are hot; encoder, recurrence and phase
basis remain cold. It is a synthetic mechanism result, not ChaCha signal or key
recovery. The next light bridge must feed O1C-0022-compatible causal packets into
this unchanged state and bind O1-O-selected reader operators without bypassing
the W52/O1C-0019/O1C-0022 lifecycle.

`O1C-0025` is source-frozen at `b008e21` as an `INSTRUMENT` only. It is the exact
logit-native global 256-bit frontier: ranking uses common-power-of-two integer
units of the absolute binary64 natural logits themselves, never rounded sigmoid
probabilities or rounded `/ln(2)` penalties. The fixed O1C-0022 handoff validates
the complete 57,344-byte `float64[4,7,256]` prediction tensor and selects exactly
the K256 `quantized_int8_vault` 2,048-byte `float64[256]` slice.

The lifecycle chain is supplied capsule manifest to artifact index to O1C-0022
prediction freeze to O1C-0019 prediction freeze to the public target. Candidate
limit is fixed at 65,536. Fourteen focused plus eighteen neighboring tests pass
(32 tests / 80 subtests). A non-formal 65,536-candidate CPU smoke completed in
`0.937653` wall seconds at `44,384,256` B peak RSS. No scientific run, target,
result or attempt was reserved, and no signal claim follows from this source
freeze. The constructor proves internal consistency of the supplied chain; the
future formal caller must still resolve the authoritative finalized O1C-0022
capsule through `RunCapsuleManager`.

`O1C-0026` now has a source-frozen conditional proxy instrument at `0af57fb`.
The v2 reader keeps a dedicated self-touch lane plus 15 off-diagonal CountSketch
buckets, globally divides the touch field by `sqrt(256)`, binds it bilinearly to
eight proof-context buckets and emits 768 features per coordinate. A fixed
all-256 derangement supplies the pair-identity control; polarity-odd additive and
polarity-even common-mode arms are dimension/work matched. Scale-invariant ridge
weights have alpha folded in, so one reader plus its 256 logits is exactly
`6,144 + 2,048 = 8,192` bytes.

The label-free replay over all four immutable BUILD FAPs emitted primary plus
shuffle `1024x768` matrices in `1.609594` wall seconds at `105,955,328` B process
peak RSS. Their RMS ratio is `1.008770`, cosine `0.027591`, and they are identical
only in the 85 genuinely branch-empty rows. Raw self-touch is `4.87x` denser and
`8.82x` stronger than one off-diagonal cell, justifying retention without letting
it dominate the matched control. Thirteen focused and 42 neighboring tests pass
(55 total, one optional native integration skip); Ruff, Mypy, JSON and pycompile
are green. This is structural/resource evidence, not a label fit or key signal.

O1C-0026 remains unreserved and may activate if and only if authoritative
finalized O1C-0023 selects `proof_ancestry_pair_residual_v1` after the O1C-0022
all-real-primary-null branch. A future null closes only
`fap_ancestry_touch_bilinear_proxy_v2`, never parent R07 or every interaction in
the 330D FAP. It cannot bypass the W52/O1C-0019/O1C-0022/O1C-0023 sequence.

Its conditional one-shot runner is now source-frozen at `7855492` with config
`configs/proof_ancestry_pair_residual_run_v1.json`. If selected, it opens exactly
4 BUILD and 0 DEVELOPMENT FAPs, executes 64 ridge fits, 4,927,488 alpha-bit and
4,096 diagnostic-bit evaluations, and loads four persisted 6,144-byte primary
weight vectors into transient 8,192-byte streaming states over 1,024 coordinates.
Their four 2,048-byte logit vectors are then persisted and reloaded for scoring;
projection scratch has a hard 16,384-byte ceiling. The synthetic lifecycle verifies 120 indexed
artifacts (121 files including the index); 23 focused tests pass. Result JSON is
candidate-only: only completed operational metrics after semantic graph, source
and budget verification may close the exact proxy instance. Operational,
stopped or publication failures close nothing and never replay science.

`O1C-0024` is finalized from source commit `36133bc` with capsule manifest
`44d2f75b53c7f0d0f08a431a12ee6bc90d24b860ef6d7de9218b34b535250c3f`.
It replaces the misleading assumption that the old least-uncertain 16-bit cube
was a global beam: exact integer-scaled subset penalties now emit the true global
factorized top-K over all 256 coordinates in `O(K log K)`. Exhaustive widths
3/6/10 match exactly; a standard 20-round synthetic target is recovered at global
rank four while the matched two-bit cube cannot contain it, and wrong-nonce plus
output-flip controls remain null.

The burned O1C-0016 target-0000 frontier contains 65,536 unique score-ordered keys
and no exact match. MAP is Hamming 117; the best global candidate is Hamming 110 at
rank 15,405, while the complete legacy 16-bit cube has an oracle Hamming floor of
108 but still cannot contain the key. The top-K score band is only
`-251.968003` to `-251.975124` log2 probability, so this is a decoder/mechanism
milestone and a flat-posterior null, not cryptanalytic evidence. The full run took
2.438 CPU / 2.454 wall seconds at 109.922 MiB peak RSS. Its candidate bytes and
scores froze before one selected reveal read; one selected evaluation read
followed, the 680-member source capsule was never scanned, and all 28 final capsule
members verify.

`O1C-0023` is source-frozen at `aa17eed` without starting or reserving an
attempt. It verifies the authoritative complete O1C-0022 publication down to its
exact 384-artifact lifecycle, four 352-byte K256 states, result, metrics, source
ancestry and recomputed resource gates before emitting one canonical successor
operator. The policy separates operational/integrity replay, width dilution,
scale, nonlinear int8 denoising, quantizer precision, true residual capacity,
sensor null, binding, compounding, confidence, robustness and prospective pass.
Immutable failure memory closes only an exact scientific no-lift context;
operational failure remains replayable and a closed ladder advances to a novel
policy-extension requirement.

Native O1-O then routes one opaque token into one data-only fragment twice under
Python `-I -B -S`. Each child sees only a disposable byte-exact copy of eight
pinned core files, seven pinned runtime dependencies and a sanitized environment;
the original O1-O path is not disclosed. An inherited exclusive lifecycle lease,
35-second child timeout, exact AST marker, before/after tree audit and structural
work ledger prevent false recovery or fabricated zero-work claims. CPU/wall
accounting begins immediately after lease acquisition and therefore includes the
complete 384-artifact preflight plus both children. Thirty-two focused tests pass
(one optional environment-driven integration skips), two final semantic/adversarial
audits clear, and the real preflight remains pending without an O1C-0023
reservation. This is autonomous experiment composition infrastructure, not a new
cryptanalytic efficacy result.

`O1C-0022` is source-frozen at `ce56ba4` without starting or reserving a scientific
attempt. It is the first literal join from the corrected real full-round packet
reader to the exact addressed causal vault: each future frozen O1C-0019 fold emits
native `q_after-q_before` packet deltas, a label-free per-horizon median scale
quantizes them, and nested `K=12/52/128/256` public sensors feed the 352-byte O1C21
state while all 256 key bits remain unknown. Exact frozen work is 32 reader replays,
17,664 packet slots, 1,130,496 public work units and 7,391,232 nonnegative
calibration evaluations, with zero new pools, solver branches, entropy, sibling,
MPS or GPU calls. Post-freeze commit `2d8bf69` additionally proves the real
`.fap -> 330D Torch reader -> q-delta -> quantizer -> vault` ABI at K12 without
opening a label: base, exact repeat, actual polarity swap and a same-resource/
same-coordinate zeroed-330D ablation each bill 36 slots and 2,304 work units, or
9,216 total. The real and ablated q-deltas differ, proving payload sensitivity;
the primary state is exactly 352 bytes and actual polarity swap is antisymmetric
to `1e-6`. This is transport validation with an untrained reader, not efficacy.

The seven-arm control matrix separates raw/normalized float evidence, int8 vault
retention, last-horizon-only, unit-sign, coordinate-shuffled and zero-prior paths.
A pass requires every fold positive, at least +1 mean bit, strict K-growth, at
least 90% of positive normalized-float compression and positive margins over all
three mechanism controls. Real polarity-swapped K256 replay, duplicate invariance,
coordinate commutation and fold-local label exclusion override efficacy. The
literal O1-O path now compiles the exact CAUSAL MessagePack envelope through the
real local KnowledgeEngine/CodeAssembler and byte-replays a 64-byte table into an
independent 273-byte FSM without writing to O1-O. The focused surface is now 28
tests including the real-artifact ABI test; all ten native O1-O tests plus four
subtests pass when `O1O_FORGE_ROOT` is supplied. Thirty-four upstream regression
tests with 575 subtests and three final audits are green.

The cheap handcrafted alternative is closed rather than forgotten: four rank
regimes times eight manually summed feature families were negative at every
K/alpha setting. The least-negative K256 member reached 519/1,024 aggregate bits
but lost 213.404152 code bits. That preserves the learned 330D O1C-0019 reader as
the higher-ROI path and records a reproducible negative breadcrumb, not efficacy.

The latest sibling intake is also bounded rather than transplanted. A539's
training-frozen RACF-DES clause reader beat both declared controls on its first
12-target panel, but A541's fresh 12-target panel put all five learned readers
behind both controls and recovered zero of 108 executed top candidates. Across 24
prospective targets the unchanged A539 raw/centered anchors return to
`0.984864/0.991111` of the exact discrete-uniform geometric-rank expectation.
O1C-0022 therefore remains unchanged; only an all-float sensor null activates a
fallback using clause identity plus interaction-bearing pairs, proof antecedents
or exact contradictions. Exact hashes and the direct-versus-derived boundary are
recorded in
[`research/A539_A541_TRANSFER_20260718.md`](research/A539_A541_TRANSFER_20260718.md).

`O1C-0021` is implementation-frozen at `4ba1cc6` without consuming formal EVAL.
The full-width BUILD/CAL/DEV scratch path previously recovered 256/256 bits on
both broad DEV seeds in `134.522567` seconds on one CPU thread with a 352-byte O1
live state. That is synthetic causal accumulation, not ChaCha20 recovery. The
hardened source now gives the outcome-learned public FSM its own 273-byte state,
route, delayed marker, duplicate ledger and serialized commitments; bills exactly
`262,144 / 524,288 / 1,835,008` BUILD/CAL/EVAL FSM lookups; freezes a 64-byte table;
and enforces complement, duplicate, opaque-ID and coordinate equivariance. Three
independent read-only audits report no remaining P0/P1 blocker, with 31 focused
tests green. The broad recheck and sealed four-seed run remain deferred solely to
respect the active sibling compute/resource contract.

`O1C-0020` completed from clean execution commit `3aefaf7` and is classified
`EXACT_256_LEARNED_GATE_RETENTION`. A frozen O1 input gate, trained only on 32
BUILD seeds and calibrated on eight disjoint CAL seeds, routed one unified public
token stream into a packed 256-coordinate Bit-Vault. The deployment API received
no route label or oracle update mask. Four never-used EVALUATION seeds were each
tested at `H=0/65,536/1,048,576`: all 12 cells accepted exactly 256 bindings with
`TP=256`, `FP=0`, `FN=0` and recalled all 256 bits in randomized query order.

The complete live model state is exactly `352` bytes: `288` bytes of O1 fast state
plus a `64`-byte value/validity vault. It has zero external-index bytes, retained
model transcript bytes or stream-length-dependent model bytes; the 2,216 learned
slow parameters are persisted and billed separately. For each seed the complete
live-state digest is identical from zero to `2^20` distractors. A separate
`2^20`-token no-binding stream produces zero accepts and a byte-identical held
state, while a literal 4,096-token masked replay exactly matches sparse compaction.
The evaluator's `3,475,712` retained mask bytes are audit state, explicitly
separate from the model boundary and process peak.

The result is learning-dependent and storage-specific. Shuffled-label, untrained,
cue-rotated, cue-ablated and all-open controls all fail every longest-stream cell.
Matched 64-slot CountSketch and 64-channel holographic stores reach only
`68.1641%` and `77.6367%` mean accuracy and zero exact cells. The learned route has
zero CAL errors, a sampled margin of `+0.468235` and a global legal-token
certificate margin of `+0.454628`; the oracle ceiling is replayed only after the
prediction freeze. All 21 capsule members verify. A second invocation returns
`already-finalized-no-replay` without executing science.

The run consumed `9.55336` CPU seconds, `9.914966` elapsed seconds and
`438,747,136` peak RSS bytes on one CPU thread, with zero entropy, sibling,
solver, MPS or GPU calls. Manifest
`8380a3a1bbf826e62fbaa99f25e0ea1ba41f7020c101238b867ac99201077c59` and
scientific result
`6c12a0fcb9e0b58a86b8bea340ea475294b530372c9a9a28ddaa62724cab8cb5`
bind the capsule. This closes retention terminal (a), not cipher inversion: the
next discriminator is whether the same route/vault API can accumulate weak,
contradictory causal evidence rather than merely retain explicit bindings.

`O1C-0019` is implementation-frozen at `27cd5b1` but deliberately unexecuted while
the sibling W52 production run remains active. The committed artifact-only runner
imports exactly four immutable O1C-0018 BUILD pools (`8,336,169` source bytes;
corpus SHA `d137a931782b19e2cd8fdd44f38a9109d239ba332605c3a512078ca314c1be64`),
generates no solver work and materializes no held-out key during discovery. It
trains three reveal-delayed episodes per fold, refits the critic only against the
final frozen reader, then freezes all five policy trajectories and both exhaustive
reader trajectories before deriving the held-out label.

The deferred execution is now armed at operational commit `4511a06`. PID `67247`
is a detached, read-only watcher with an exec-inherited exclusive lock and a parent
ACK only after a real process/RAM/hash preflight. It sees all 24 current W52 shell,
A528 and A526 processes despite eight stale launcher PID files. O1C-0019 can exec
only after three identical terminal polls, no matching W52 process, at least 25%
free memory, load at most `0.75` per logical CPU, a clean descendant tree, and exact
config/runtime hashes. The later run starts its own PID-bound `caffeinate`; neither
the watcher nor the run writes to the sibling repository.

The three nested physical-work caps are `16,384/32,768/49,152`; the last is the
complete H64/H65/H96 packet field. Controls are true ACTION/STOP, the identical
true picker with STOP disabled, shifted-label stationary credit, fold-local static
packet reward, pool-blind uniform hash, and learned versus deterministic untrained
reader on the same exhaustive order. The STOP route is required to be an exact
prefix of its no-STOP twin. The current targeted regression is `29 passed` plus
`5` subtests for the science surface plus `17` interlock lifecycle tests; pycompile,
Ruff, real manifest/index discovery and the exact run-config loader pass. A
non-scientific one-fold/three-action real-artifact smoke traversed
both freeze callbacks and scoring with every structural gate green in `2.559` CPU s,
`2.803` wall s and `315,359,232` B peak RSS; its deliberately undertrained outcome
is not efficacy evidence. A subsequent two-process reproduction gives byte-identical
scientific result `79648ab86896b3ea5ee1b7acb74983057ff32b9901da18905a46ae073c8f36a8`,
learning freeze, prediction freeze and slot ledgers; volatile timing/RSS now affect
only a separate execution-report hash. No O1C-0019 efficacy number exists yet.

`O1C-0018` completed from clean execution commit `f40e71a`. It is the first full
256-bit, standard twenty-round ChaCha20 run of the continuous O1 reader and learned
picker: four reveal-delayed BUILD keys, then two disjoint DEVELOPMENT keys, all 256
bits unknown at probe time and only public counter/nonce/output passed to the
deterministic paired-proof sensor. Its frozen classification is
`NO_RAW_SIGNAL_PICKER_UNINTERPRETABLE`.

The exhaustive learned Bit-Vault is negative on both targets at
`-1.400387/-1.168901` bits (mean `-1.284644`). Training still improves the
untrained mean by `+0.724371` bits, but the coordinate-rotation control reaches
`+0.203963` mean and the direct final O1 field is `-0.093388`; raw transferable
orientation is therefore not established.

The early learned picker preserves a real breadcrumb. At W1, true reward is the
best arm on both targets at `+0.326847/+0.160175` bits. It beats the shifted-reward
critic in all six target-by-checkpoint cells, with positive IAUC margins on both
targets. Yet the score replay shows why this cannot be promoted: the first
decision has coverage contribution `0.5` versus learned reward about `0.00195`,
and only `0.169%` mean W1 score mass comes from learned reward. The hard
minimum-coverage gate and hash-32 shortlist make true/shifted and cross-target
routes nearly identical; forced later spending then destroys target-0 compression.

Post-reveal forensics also finds a training/deployment mismatch: a cumulative O1
query is repeatedly added as though it were incremental evidence. The direct
field avoids `1.191256` mean bits of the exhaustive path's damage. BUILD per-action
reward transfer is near zero (`0.013824` pairwise, `0.023765` leave-one-out), so
the critic is additionally trained on a nonstationary reader. These observations
define O1C-0019: packetize same-coordinate horizons, train an incremental/gated
readout, refit credits against the exact frozen reader, let every affordable
address be scored, replace compulsory breadth with soft no-starvation attention,
and learn HOLD/STOP/DECAY. Full forensics are in
[`research/O1C0018_POST_REVEAL_FORENSICS_20260717.md`](research/O1C0018_POST_REVEAL_FORENSICS_20260717.md).

The capsule verifies 51/51 members. Manifest
`fcbf43c99994c0debe5b39bb3e734ea1d1e23ba58e89b10ff2bb7e23886493fb`;
internal result
`db92bd86849ff93e0f9b935a72f64f1b4bd46b134747c913ee82e5d772ac11c9`.

`O1C-0017` completed from clean freeze commit `22ea4dd` and is independently
verified `MECHANISM_PASS`. After eight reveal-delayed BUILD episodes, the unchanged
reader attacked 16 disjoint full-256 synthetic episodes and obtained `3286/4096`
bits (`80.224609%`), mean NLL `213.691258` and mean compression
`+42.308742` bits. Every target is positive; the weakest target still has 195/256
correct bits. All predictions were persisted before label scoring.

The controls isolate the mechanism. Hidden-channel ablation gives `-4.392651`
bits, shifted-label learning `-0.456155`, the untrained reader `-7.336737`, and the
same learned reader's raw end-of-stream O1 field `-4.922579`. Primary margins are
therefore `+46.701393`, `+42.764897`, and `+47.231321` bits respectively. Exact
polarity-swap antisymmetry, common-only zero orientation, complete coordinate
coverage and fixed fast-state bytes all pass. Capsule manifest
`59f1f59b4e24545391cb06cd2bee395285d4385c893af36d18def28bcb3858fd`
verifies 18/18 members; internal result
`609014695bc3013bb971d7d05b682d18797af5c9d9cd31561cdc41de120ff28c`.

This is the wanted autonomous-learning proof at the architecture level: the model
was not told which of 330 channels carried orientation, learned only after prior
episodes were frozen, and retained the useful addressed readings where the raw
holographic end field lost them to crosstalk. It is deliberately not evidence that
ChaCha20 exposes such a channel, not a stateless-baseline comparison, not proof
that O1 memory is necessary, and not a learned-picker result. O1C-0018 has now
tested that transition and localizes the next limits to reader accumulation,
critic stationarity and picker agency.

`O1C-0016` is complete and independently verified. The frozen equal-logit h96+h65
ensemble obtains `4093/8192` bits and `-0.078249097` bit/key compression on 32
entirely new full-256 targets. Exact h96 obtains `-0.175000`, h65 `-0.033913`, and
the matched shuffled ensemble `+0.001976` bit/key. Only 11/32 targets are positive;
the primary loses to shuffled by `-0.080225` bit/key (`z=-0.555358`). The ensemble
improves h96 but loses to h65, and its promotion z is only `1.004470`. The frozen
classifications are therefore `NOT_REPLICATED` and `DO_NOT_PROMOTE`; exact keys are
zero.

The result is null-like at useful resolutions: byte top-1/top-4/top-16 counts are
`4/16/61` against uniform expectations `4/16/64`, zero 16-bit groups are top-16,
and the best million-decoy rank 45,147 is unexceptional across 32 tries. Six
coordinates reach 22/32 correct against 6.41 expected; the best 24/32 coordinate
has familywise null probability about 0.592. O1C-0014-to-0016 coordinate transfer
is approximately zero.

The O1C-0016 common-mode diagnosis still determines the real-cipher transition:
per-target h65 primary and matched-shuffled compression correlate `0.999905`.
O1C-0017 shows that the replacement machinery can autonomously discover a hidden
orientation and retain it. O1C-0018 finds a positive early true-versus-shifted
picker margin but no raw full-round gate pass; O1C-0019 must give that learned
utility actual control over target-conditioned packet selection and stopping.

The O1C-0016 capsule verifies 680/680 members. All commitments open and every
output independently recomputes. It used `1972.624545` billed CPU seconds,
`1620.537008` wall seconds, `17,920` native branches, `414.8125` MiB conservative
peak RSS, `67,584` bytes of live target state and `6,768,561` persistent bytes.
Manifest:
`fd0469885ee436414f94d708006cc40d86fc730d25b618167c7d664b3fe195ea`;
internal result:
`6146dbfe10e1add60fe5d16f133c5b1acdced42bcf2249561926d26ee0e11652`.
Detailed forensics are in
[`research/O1C0016_POST_REVEAL_FORENSICS_20260717.md`](research/O1C0016_POST_REVEAL_FORENSICS_20260717.md).

`O1C-0015` remains an immutable operational resource failure, not a scientific
inverse result. It froze all 32 factual predictions and three controls, then
revealed all 32 targets once in process memory before the old late resource gate
fired. No reveal receipt, evaluation or final scientific report was persisted, so
no key metric may be reconstructed or claimed. All 32 targets are burned and may
never be replayed.

The failed capsule
`runs/20260717_103252_O1C-0015_full256-polyphase-blind-replication-v1/`
verifies `579/579`; manifest
`326bc30a1499f6479d306df43b17ec390c020832bb5d1816fa8ab9f7f9660314`
and prediction-set commitment
`f2958da162a2dca74f2c5dd62ccb45f3d764be7c8f71200ee3afba8409a62116`
are immutable. The run exceeded all three old soft ceilings: CPU `>1600 s`, peak
RSS `>384 MiB`, and wall `>1400 s`; the exact values were discarded by the old
exception path and are unavailable.

`O1C-0014` reloaded O1C-0013's exact primary reader
`796e79ec932b990a59ecbc34216c4878b9279bae3bb136fe0832e580bcb2e9f8`
and shuffled reader without fitting, reselection, sign, temperature or scale
changes. The protocol and reader bytes were persisted before exactly eight fresh
OS-random key calls; all eight factual predictions and three controls were
persisted before any reveal. Every target was standard twenty-round ChaCha20 with
all 256 key bits unknown and only public counter, nonce and output at inference.

The primary reader obtained `1053/2048` bits and NLL `255.766215857` bit/key,
equivalent to `+0.233784143` bit/key compression. The exact conditional-uniform
reference gives `z=1.819365` (`p≈0.034428`), every leave-one-target-out mean remains
positive, and the primary beats the shuffled reader by `+1.524765187` bit/key.
However only `4/8` targets are individually positive, the paired reader-control
comparison is only `z=0.838026`, and wrong-nonce/byte-rotate controls are positive.
The predeclared classification is therefore `NOT_REPLICATED`, not a stable signal
or SOTA result. There are zero exact keys; the best million-decoy rank is `10,875`.

Post-reveal mechanism diagnostics do not alter that verdict. All three already-
existing unary horizons are aggregate-positive (`h64 +0.139097`, `h96 +0.233784`,
`h65 +0.188340` bit/key), while the richer ARX24 and ARX24+Motif12 arms are
negative (`-0.374410` and `-0.355199`). This localizes the current breadcrumb to
  paired proof difficulty across wavelengths and rejects the present coarse ARX/
  motif aggregation as the next blind primary. A fixed h96+h65 equal-logit
  ensemble gives an exploratory `+0.229` bit/key, `1066/2048` bits, `6/8` positive
  targets and conditional `z=2.107`; O1C-0015 must test it only on fresh targets.

The O1C-0014 capsule verifies 124/124 members. It used `306.194798` billed CPU
seconds, `245.756482` wall seconds, `5,632` native branches, `302.578125` MiB peak
RSS and `2,947,408` persistent bytes. Sibling reads/writes, MPS and GPU calls are
zero. Capsule manifest:
`741718cbc6b63de24f4d9c89cd2aedc8e9779a0ebb38adc4d40666e97ce24bcf`;
internal result:
`ecc06b011a95f6ceeec08641b68e1105511cf714cc250f9fe3b62e66c2af4c4a`.

`O1C-0013` was the first complete learned full-256 causal-reader experiment. Four
deterministic BUILD keys and two disjoint CAL keys each generated the unchanged
O1C-0012 paired public-CNF field.  Labels were unavailable until each public state
was frozen.  BUILD fitted only shared signed orientation; CAL selected one of the
predeclared wavelengths and scale choices.  The selected `horizon_1` reader
(`h96`, ridge `0.001`, temperature `0.5`, logit scale `1.0`) was serialized and
reloaded before exactly two OS-random target entropy calls.

On those two fresh sealed standard-ChaCha20 targets the frozen reader obtains
`259/512` bits and mean NLL `255.911078` bits, or `+0.0889215` bit of effective
compression per key.  Its frozen shuffled-key counterpart obtains `239/512` and
`-3.217332` bit/key, a primary margin of `+3.306254` bit/key.  The two individual
compressions are `-0.186702` and `+0.364545` bit, so the aggregate is not yet a
stable effect.  Full-key million-decoy ranks are `580,519` and `194,708`; exact
keys recovered are zero.  Across 64 factorized bytes the best truth rank is `2`
and five are top-16; no byte or 16-bit block is exactly mode-correct.

All three preregistered target controls are directionally negative against the
anchor key: output-bit flip `-0.272987`, wrong nonce `-0.167376`, and output-byte
rotation `-0.040618` bit.  Every lifecycle, public-recompute, swap, containment,
memory and work gate passes.  Live target state is exactly `58,368` bytes
(`17,408` causal state + `39,936` bounded feature bank + `1,024` logits), with no
candidate keys or transcripts.  The static primary reader is `281,764` bytes.

The capsule verifies 63/63 members.  It used `392.187980` billed CPU seconds,
`314.384032` wall seconds, `5,632` billed native branches and a conservative
process-group peak of `321.90625` MiB; persistent artifacts are `2,479,016` bytes.
Sibling reads/writes, MPS and GPU calls are zero.  Capsule manifest:
`a0d4df5c01f7de3c65a429f9589e46d784f802bc1f8e0aa90dffb011be46922c`;
internal result:
`a70610d3d589e97048c6045747c0821e5669c5dc89e420df79b0fca43476d4cd`.

`O1C-0011` compiled the complete standard twenty-round ChaCha20 block relation
directly at full key width.  Variables `1..256` are the unknown key, `257..384`
the public counter/nonce and `385..896` the public 512-bit output; internal wires
begin at `897`.  The immutable template contains `32,128` variables, `187,370`
clauses and `656` semantically named add/XOR operators.  Every operator carries
32 exact LSB-first bit ranges with explicit sum, carry or XOR variables and
one-based inclusive clause ancestry.

The public attacker instance adds exactly `640` counter/nonce/output units and
zero key units (`188,010` clauses).  Two persisted bit-173 probes share the exact
public relation and differ only in the final opposite key literal.  Byte-identical
double compilation passed; the RFC fixed-key instance is SAT, its one-bit output
flip is UNSAT, and an independent second 256-bit vector is SAT.  This validates
the inversion substrate and causal address map; it does not yet claim an unknown-
key solve or inverse signal.

The capsule verifies 18/18 members.  CPU work was `8.692029` s, peak through
artifact persistence `163.59375` MiB, maximum temporary workspace `25,414,624`
bytes and persistent CNF artifacts `21,069,379` bytes.  Sibling reads/writes,
MPS/GPU calls and fresh random targets were all zero.  Capsule manifest:
`b7a07e6461805946897adbfb90da9e9f55ff1074e9aa1343f602eecb0645b7b4`;
internal result:
`6c4fd7becd5307d60b30e16ea1fae8d3f4739b06c888204d638950c94b53adfe`.

`O1C-0010` prospectively copied the exact O1C-0009 direct and shuffled model bytes,
froze the post-reveal signed scales and every gate before target entropy, then
attacked 2,048 new broker-secret uniform keys with all 256 bits unknown.  The six
`2048 x 256` posterior/control matrices (`25,165,824` bytes) were persisted before
the first reveal.  Direct mean NLL was `256.0190884625`, i.e. compression
`-0.0190884625` bit, conditional reference `z=-0.94608`, and target-level 3-SE
lower bound `-0.032620` bit.  It lost to the signed shuffled control by
`0.0175411` bit and beat output permutation by only `0.0009622` bit (`z=0.1902`).
Only the algebraic reverse-polarity checksum passed; every efficacy criterion
failed.  The O1C-0009 `+0.023159`-bit observation was finite-panel selection noise,
not a transferable orientation.

The O1C-0010 capsule verifies 23/23 members.  All 2,048 commitments open, all keys
recompute their standard twenty-round outputs and every receipt binds prediction
blob `4643e0e849178014ede98e355037829158ca2eadc9b404671a8f64d6904e2dee`.
CPU work was `2.424391` s; peak through outcome persistence `201.96875` MiB and
end-to-end process peak `245.390625` MiB, with zero sibling, MPS or GPU work.
Capsule manifest:
`a87b7a9fb799d667e9d2e670f759ca4f389aac2be9cb932c3f308ab669f4ab7c`.

`O1C-0009` attacked 128 broker-secret uniform keys with all 256 bits unknown.  The
four frozen readers and every factual/control posterior were persisted before the
one-shot reveal.  Calibration selected scale zero for direct, relative, distilled
and shuffled-key arms, so all declared DEV posteriors remained exactly uniform:
mean NLL `256.0`, effective compression `0.0`, zero familywise transferable bits.
This closes the first linear full-round end-output reader, not the moonshot.

The immutable capsule verifies 25/25 members.  Its 128 publications are unique,
all 128 revealed keys exactly reproduce their public ChaCha20 outputs, and every
reveal receipt binds prediction blob
`8431b3c19a697ce0d48e66d29b199ec6d199670870d40231564c9516e3c34ad2`.
Peak RSS was `182.90625` MiB, CPU work `6.923216` s, with zero sibling, MPS or GPU
work.  Capsule manifest:
`f31d7672921dc0c2ec684cf8c5247a3ff2386fbea316c2eab98072cd22fb29d2`.

One post-reveal diagnostic was retained rather than discarded: allowing a signed
global scale chosen from CAL only gives the frozen direct reader scale
`-0.03860970720667151`, CAL NLL `255.984754` and O1C-0009 DEV NLL `255.976841`
(`+0.023159` bit).  This was not preregistered and is not a result claim.  Its
target-level standard deviation is `0.199937` bit. O1C-0010 has now closed it on a
16-times larger prospective panel. The sealed broker remains public-view-only in
memory and retains no privileged round traces.

The 2026-07-17 read-only W52 intake supplied mechanism, not target data.  A447/A448
show that exact proof ancestry transfers where flattened clause provenance does
not.  A460/A462/A463 expose complementary switching wavelengths `64/96/65`; A465
combines them with a cubic Product-of-Experts; A469 shows that interaction evidence
must be positive, bucket-local and identity-preserving.  These become the sensor,
timescale, backbone and correction layers of the Living Inverse.

The immutable foundation contains four build and two development targets, 72
deployment contrasts across six proposal families, 2,576 attacker-valid features
per one-block contrast, exact RFC-compatible round/carry traces, one-bit output and
wrong-nonce controls, a million-decoy rank path and a sealed full-256 broker.  The
random posterior measures exactly `256.0` bits; the metric oracle reaches `3.71189`
bits, exact mode, rank one and the exact verification beam.  No target trace field,
fresh target, sibling read/write, MPS or GPU call occurred.  Capsule manifest:
`50cd1dcd83034d69aafd2e7890d62b9f2c25b6e65c5a929d3119027a71105449`.

O1C-0007 remains a useful boundary: a pure unary state is structurally compact but
its selected result has exact conditional `p=0.593505859375`.  The new architecture
therefore includes pair/causal interaction from its first trained arm rather than
repeating the unary decoder on another narrow target.

The full design and exact attacker boundary are in
[`docs/O1_256_LIVING_INVERSE.md`](docs/O1_256_LIVING_INVERSE.md); the measured W52
transfer map is in
[`research/W52_TRANSFER_20260717.md`](research/W52_TRANSFER_20260717.md), and the
latest result audit is in
[`research/O1C0016_POST_REVEAL_FORENSICS_20260717.md`](research/O1C0016_POST_REVEAL_FORENSICS_20260717.md).
The implemented continuous fast/slow learner, its frozen controls and the
O1C-0017 result boundary are documented in
[`docs/O1_ONLINE_MOBIUS_CONTROLLER.md`](docs/O1_ONLINE_MOBIUS_CONTROLLER.md).

## Active process table

| Attempt | PID | Started | Command | Progress | ETA |
|---|---:|---|---|---|---|
| Main scientific run | — | 2026-07-19 09:19 | O1C-0061 exact joint-score baseline | terminal: active pre-model bound drop, zero trail prunes, no recovery | complete |
| Matched augmentation | — | 2026-07-19 09:55 | APPLE-VIEW-0008 Cross-Block CNF | terminal: six safe trail prunes and strict matched effect, no recovery | complete |
| 4K resource promotion | — | 2026-07-19 11:45 | O1C-0064 instrumented Full-256 sieve | terminal: guarded memory stop at 1,040,285,696 B after 29.805 s; no science result | complete |
| Parallel bound build | — | 2026-07-19 11:23 | APPLE-VIEW-0009 exact width-6 grouping | terminal: strictly tighter and 799,232 B smaller than frozen pairs; current-native RSS benefit must come indirectly from pruning | complete |
| Matched grouped native | — | 2026-07-19 12:36 | O1C-0065 exact width-6 Full-256 sieve | terminal: tighter bounds/smaller logical cache, but 6→6 cuts and identical decisions/propagations; no recovery | complete |
| Sibling W52 (external, read-only) | — | — | no live process after reboot | last durable checkpoint 417,495/16,777,216 cells (2.488464%) | unknown |

## Highest-ROI next actions

1. Extend the lifecycle-safe width-6 native path with a canonical bounded archive
   of emitted threshold-certified no-goods and deterministic preload. Bind every
   archive to CNF, variable numbering, potential, threshold bits, grouping and
   score semantics; these clauses are not CNF-only consequences.
2. Prove clause soundness, canonicalization/deduplication, episode isolation and
   solver-RSS reset on synthetic and public geometry without a scientific call.
3. After those gates pass, execute one frozen Full-256 multi-episode stream:
   short fresh solver episodes, cumulative exact no-good memory, fixed total
   episode/work budget, zero truth access and no retry.
4. Keep O1C-0056 fixed negative clause-role credit closed. If the causal branch
   resumes later, condition the unique exact role on outcome/utility; do not tune
   sign, scale, groups or cap.
5. Keep O1C-0054's global separable factor-bound beam closed; do not widen its
   beam, reorder pairs, raise the queue cap or tune the bound.
6. Keep O1C-0058's attended-decoy positive one-bit-delta vault closed; do not
   flip signs, tune thresholds or rerun that exact local rule. Do not extend its
   formal closure to crowd/elite consensus; the separate cheap scratch was only
   control-negative.
7. Keep APPLE-VIEW-0007's static strongest-predecessor reader closed; do not
   root-weight, threshold, retraverse or rescore its held-out panel. Its only
   retained breadcrumb converges on the active live context/action branch.
8. Reuse A325/A526 unchanged only when their native complement gate is met, and
   keep every sibling repository read-only.

## Recent attempts

| Attempt | Time | Hypothesis | Result | Claim level | Cost | Main breadcrumb | Artifact |
|---|---|---|---|---|---|---|---|
| `O1C-0065` | 2026-07-19 12:36 | Exact width-6 compatibility groups turn their tighter public bound into more native Full-256 pruning at matched work | Root UB `292.3061134451→262.6864419708`, minimum UB `13.1979307788→12.9342082470`, cache `60,456→23,080 B`; cuts remain `6→6`, decisions `4471→4471`, propagations `1178185→1178185`; no key/truth read | `O1C65_GROUPED_WIDTH6_EFFICACY_RETAINED`; no strict efficacy gain or recovery | 3.328 s elapsed; 1.985 child CPU; 0.346 s native; 386,547,712 B native peak; one call | Standalone tighter bounding is terminal at 512; persist the six certified clauses across clean bounded episodes instead of repeating or jumping to 4K | [Result](research/O1C0065_APPLE8_WIDTH6_GROUPED_SIEVE_RESULT_20260719.json) |
| `O1C-0064` | 2026-07-19 11:45 | Cause-preserving telemetry plus a 1-GiB envelope lets the repaired APPLE8 4K path reach a valid terminal result | Guarded memory stop after `29.804627625 s`: observed `1,040,285,696 B` at `1,040,187,392 B`; no native result/key/truth read | `O1C64_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT`; exact resource boundary, negative operational result | 30.914 s elapsed; 30.314 child CPU; one call; no fresh/reveal/MPS/GPU | Do not retry or merely raise RAM; couple the already-positive exact width-6 bound to reduce the measured bottleneck | [Result](research/O1C0064_APPLE8_CROSSBLOCK_SIEVE_4K_RESOURCE_FIX_RESULT_20260719.json) |
| `APPLE-VIEW-0009` | 2026-07-19 11:23 | Exact score-aware compatibility groups retain more public factor geometry with less state than frozen pairs | Safe root UB `269.7472723039718→262.68644197084643`; groups `3805→2885`; rows `265256→176912`; indexed bytes `2510008→1710776` | `PUBLIC_EXACT_GROUPED_BOUND_STRICTLY_DOMINATES_PAIR_RELAXATION_NO_SEARCH_CLAIM`; positive bound mechanism, no search/recovery claim | 0.705 s width-6 construction; zero solver/truth/fresh calls | O1C65 later integrates it and retains exactly six cuts with identical search work; use it inside the episodic vault, not as another standalone test | [Result](research/APPLE_VIEW_0009_EXACT_GROUPED_BOUND_RESULT_20260719.json) |
| `O1C-0063` | 2026-07-19 11:04 | Lifecycle-safe teardown and pending no-good retention repair O1C62 | Repaired path runs `17.763142674 s`, then terminates opaquely under the old wrapper; high-confidence guarded `736 MiB` stop, no science result | `O1C63_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT`; predecessor diagnosis only | one call; zero truth/fresh/reveal | O1C64 later confirms the same memory-growth class with exact telemetry | [Diagnosis](research/O1C0063_RESOURCE_WATCHDOG_DIAGNOSIS_20260719.md) |
| `APPLE-VIEW-0008-MATCHED` | 2026-07-19 09:55 | Explicit exact public P20 and cross-block key-lane consequences improve the O1C61 joint sieve at matched target, score, threshold and work | Requested 512/billed 513 conflicts in both arms; minimum UB `24.7944466611→13.1979307788` below threshold `14.6061787979`; safe trail prunes `0→6`; decisions `9166→4471`; propagations `1227877→1178185`; no key/truth read | `APPLE_VIEW_0008_STRICT_INCREMENTAL_EFFECT_NO_RECOVERY`; first certified Full-256 trail-pruning/search-branch removal in this line, not recovery | 36.8121 s total; 0.451725 s native; 388,644,864 B native peak; one solver call; zero fresh/reveal/MPS/GPU | Six emitted pruning clauses are deep (length 2964..2974); O1C65 retains exactly those six under width-6, so the next lever is episodic persistence | [Capsule](runs/20260719_095509_APPLE-VIEW-0008-MATCHED_crossblock-consequence-sieve-v1/RUN.md) |
| `O1C-0061` | 2026-07-19 09:19 | Corrected soft-stop accounting lets the exact O1C57 joint potential expose useful pre-model bound progress | `UNKNOWN` at requested 512/billed 513 conflicts; material root-to-minimum bound drop `267.511666784`, zero trail prunes, no complete model/key | `EXACT_JOINT_SCORE_SIEVE_ACTIVE_NO_RECOVERY`; active bound baseline, explicitly not a search-space-gain claim | 76.6567 s total; 0.419657 s native; 383,713,280 B native peak; one call; zero fresh/sibling/MPS/GPU | Use only as the matched baseline: APPLE-VIEW-0008 now turns the bound into six certified trail prunes | [Capsule](runs/20260719_091954_O1C-0061_multiblock-joint-score-sieve-soft-stop-v1/RUN.md) |
| `O1C-0058` | 2026-07-19 07:08 | Signed one-bit finite differences around the supplied-panel-best eight-block decoy expose key-bit correction direction | Base and primary prefix 8 are both `127/256`, improvement `0`, longest correct confidence prefix `0`; key/clause controls `127/128`; all 13 candidates match `0/8` public blocks; no partial/exact gate | `MULTIBLOCK_BIT_VAULT_NO_DIRECTIONAL_TRANSFER`; fresh Full-256 negative conversion test | 99.07695375 s; 211,124,224 B peak; 34,824 forwards; 112 direct blocks; 2,048 B primary/6,144 B all-arm state; one entropy/reveal; zero solver/sibling/MPS/GPU | Two locally score-improving primary flips do not improve truth alignment; O1C-0061 and APPLE-VIEW-0008 later convert the retained joint score into six safe trail cuts | [Capsule](runs/20260719_070833_O1C-0058_multiblock-bit-vault-gradient-v1/RUN.md) |
| `O1C-0057` | 2026-07-19 06:29 | Additional same-key public blocks compound the unchanged transferred parent-criticality score into stronger complete-key rank | Primary truth ranks `8/7/1/1` of 4,097 across prefixes 1/2/4/8; prefix-8 rotations rank `3581/4037`; truth z `+5.57888245`; frozen prediction passes | `MULTIBLOCK_PARENT_CRITICALITY_COMPOUNDING_TRANSFER`; prospective scorer/orderer, no recovery | 95.8946 s; 193,544,192 B peak; 32,776 forwards; 4,096 native branches; one fresh target/entropy/reveal; zero solver/sibling/MPS/GPU | Roughly 12 bits of discrimination transfer inside the supplied panel; convert the prefix-8 score into partial-assignment/search ordering rather than scaling decoys | [Capsule](runs/20260719_062932_O1C-0057_multiblock-parent-criticality-rank-v1/RUN.md) |
| `O1C-0056` | 2026-07-19 06:17 | One deepest/current-level exact clause owner concentrates causal negative credit enough to close W11 | `UNKNOWN` at 512 conflicts/513 decisions/12,013,641 propagations; 512/512 clauses select exactly one current-level owner, discard 2,150/2,662 matched members, and still touch 18 cells/seven groups; 142 reorders, 502 repeats | `CONSUMED_POST_REVEAL_EXACT_CLAUSE_ROLE_CREDIT_SCREEN`; negative | 5.687863334 s total wall; 1.928103 s native wall; 127,057,920 B peak; one call; 2,662 B state; zero tuning/fresh/sibling/MPS/GPU | Localization is exact and removes fan-out, but fixed negative conflict credit still fails; utility-conditioned work is parked behind O1C-0059 and its matched APPLE8 augmentation | [Capsule](runs/20260719_061710_O1C-0056_clause-role-credit-screen-v1/RUN.md) |
| `O1C-0055` | 2026-07-19 05:37 | Exact learned-clause membership localizes causal negative credit at W11 | `UNKNOWN` at 512 conflicts/513 decisions/12,083,477 propagations; 512/512 clauses match, 2,684 members and 2,057 penalties, but only 18 unique cells/seven groups; 167 reorders, 502 repeats | `CONSUMED_POST_REVEAL_EXACT_LEARNED_CLAUSE_SCREEN`; negative | 4.951483 s wall; 127,057,920 B peak; one call; 2,662 B state; zero fresh/sibling/MPS/GPU | Exact hook works, but all-member blame reproduces O1C-0052 diffusion; choose one member by exact clause role | [Capsule](runs/20260719_053703_O1C-0055_learned-clause-credit-screen-v1/RUN.md) |
| `O1C-0054` | 2026-07-19 05:23 | Independent admissible factor maxima can preserve O1C-0047's complete-state joint score through a bounded Full256 beam | Public Full256 0/256, truth prefix first lost at stage 5 `(9,10)`, top/min Hamming 120/116; post-reveal W11 reaches 1,024 pops/14 forwards with zero certified leaves | `CONSUMED_POST_REVEAL_GLOBAL_BOUND_SCREEN`; negative | 2.732337 s wall; 2.704926 s CPU; 88,031,232 B peak; 270 forward evaluations; 24,624 B logical Full256 state; zero solver/fresh/sibling/MPS/GPU | Exact W12 score rank 5 does not survive independent factorwise maxima; close the separable relaxation/beam and move to exact learned-clause membership | [Capsule](runs/20260719_052346_O1C-0054_global-factor-bound-screen-v1/RUN.md) |
| `O1C-0053` | 2026-07-19 04:38 | One positive `+32` update to the deepest surviving exact action identifies the retained causal frontier at W11 | `UNKNOWN` at 512 conflicts/513 decisions/12,068,568 propagations; 512 support updates (`16,384` units), 111 action reorderings, only two differentiated groups | `CONSUMED_POST_REVEAL_SURVIVOR_SUPPORT_SCREEN`; negative | 5.326337 s wall; 127,893,504 B peak; one call; 2,646 B state; zero fresh/sibling/MPS/GPU | Survival is too coarse: close it and credit exact learned-clause/first-UIP antecedent membership; the post-result truth diagnostic is not fresh evidence | [Result](research/O1C0053_DEEPEST_SURVIVOR_SUPPORT_SCREEN_RESULT_20260719.md) |
| `O1C-0052` | 2026-07-19 04:02 | Four addressed action cells per pair repair O1C-0051's polarity aliasing at W11 | `UNKNOWN` at 512 conflicts/513 decisions; 162/448 selections reordered, 18 cells differentiated, but 502/513 decisions still repeat and every visited cell is penalized | `CONSUMED_POST_REVEAL_PATTERN_ACTION_CREDIT_SCREEN`; negative | 5.098156 s wall; 128,303,104 B peak; one call; 2,646 B state; zero fresh/sibling/MPS/GPU | Conflict undo cannot identify the guilty action; reward the deepest surviving trail action once before exact proof attribution | [Capsule](runs/20260719_040242_O1C-0052_pattern-action-credit-screen-v1/RUN.md) |
| `APPLE-VIEW-0007` | 2026-07-19 03:37 | Exact proof-DAG predecessor paths in a bounded static state transfer conflict-closing order beyond APPLE6 unary membership | Raw edge order loses `1,340` vs exact unary `1,268` vs best fixed `1,031`; certificate `1,003` beats fixed `1,015` but loses unary `997` and cannot pass; all 28 wrong passes and truth controls exact | `HELDOUT_STATIC_EDGE_SCHEDULER_NEGATIVE`; no key-generation/entropy claim | 84.397724 s wall; 83.777569 s CPU; 68,321,280 B peak; 113,570 B frozen state; zero sibling/MPS/GPU | Root 11 occurs in 12 BUILD proofs with zero edge support and lands at position 335; close static/global reader and move to live action-conditioned context without rescue sweep | [Result](research/apple_view_7/apple_view_7_report.md) |
| `APPLE-VIEW-0006` | 2026-07-19 03:11 | BUILD proof participation in a bounded addressed state transfers a useful c31 switch order to disjoint Full20/Full256 candidate filters | Raw learned order loses `1,268` vs best structural `1,031` first-conflict switches; replayed certificates win 4/4 at `248/248/251/250` vs `251/252/257/255`, aggregate `997` vs `1,015`; all truth controls complete | `HELDOUT_CERTIFICATE_TRANSFER_WITH_SCHEDULER_LOSS`; no key-generation/entropy claim | 64.317798 s wall; 64.166830 s CPU; 62,226,432 B peak; 1,346 B frozen state; zero sibling/MPS/GPU | Unary proof membership transfers exact core relevance but not conflict-closing order; APPLE7 has now tested and closed its static edge successor | [Result](research/apple_view_6/apple_view_6_report.md) |
| `APPLE-VIEW-0005` | 2026-07-19 02:55 | Sparse joined c31 identities reject complete wrong Full256 candidates exactly | 20/20 exact conflicts; independently replayed slices use `250–265/336`, best 250; all truth controls complete | `CONSUMED_FULL256_CANDIDATE_FILTER`; no key-generation/entropy claim | 30.812515 s wall; 56,573,952 B peak | Eventual proof membership beats immediate gain on the consumed matrix; transfer it before any further same-target work | [Result](research/apple_view_5/apple_view_5_report.md) |
| `APPLE-VIEW-0003` | 2026-07-19 02:15 | Uniform low-to-high carry recurrence exposes a cheap Full256 wrong-key filter | Depths 0..30 determine 0 final bits and reject 0/32 probes; depth 31 determines 512 and rejects 32/32; 0 recovery/entropy claim | `EXPLORATORY_FULL256_NEGATIVE`; deterministic unsealed target | 13.291865 s; 27,295,744 B peak; 1,056 abstract blocks; zero sibling/MPS/GPU | Forward-only carry truncation has a full-computation cliff; preserve correlations or propagate from both ends | [Result](research/apple_view_3/apple_view_3_report.md) |
| `O1C-0048` | 2026-07-19 01:46 | Reversible global pair envelopes preserve O1C-0047's complete-state orientation in exact search | Full-256 0/4; residual maxima internal/primary/key/clause `8/9/9/9`; W8 conflicts `217/75/195/89`; W9 `UNKNOWN/155/331/167`; frozen global gate fails | `CONSUMED_SEARCH_DIAGNOSTIC`; residual rows post-reveal | 9.362067 s; 128,122,880 B peak; 12 calls; zero fresh/sibling/MPS/GPU | Static pairs restore primary-over-rotation specificity but not the all-arm gate; close this adapter and add attacker-visible online group credit | [Capsule](runs/20260719_014625_O1C-0048_pair-envelope-search-v1/RUN.md) |
| `APPLE-VIEW-0002` | 2026-07-19 | Quotient independent lifted addition carries out of the full public relation | Carry rank `512`, exact key rank `0`, exact recoveries `0/8`; every double-round carry group spans all output dimensions | `EXPLORATORY_FULL256_NEGATIVE`; deterministic unsealed targets | 5.851181 s; 34,553,856 B peak; zero MPS/GPU | Independent carries erase every linear key parity; only global exact carry-depth substitution remains meaningful | [Result](research/apple_view_2/apple_view_2_report.md) |
| `O1C-0047` | 2026-07-19 00:40 | The transferred signal is global over complete assignments and survives nested residual-cube ranking | Truth ranks W8 `1/256`, W12 `5/4096`, W16 `50/65536`; rotations W16 `60592/43059`; primary top-256 contains uniquely verified key | `POST_REVEAL_CEILING`; 240 truth bits fixed, no Full-256 attack claim | 67.546893 s; 89,325,568 B peak; 65,536 forward evaluations; zero fresh/sibling/MPS/GPU | Global score yields 10.356 bits local search compression; build a pre-reveal joint-group/prefix scheduler, not another unary marginal | [Capsule](runs/20260719_004019_O1C-0047_global-criticality-residual-beam-v1/RUN.md) |
| `APPLE-VIEW-0001` | 2026-07-19 | Public ChaCha feed-forward fixed-point projection or output-Hamming descent exposes Full-256 key direction | 32 targets; holdout gain -0.484 key bits, AUC 0.50572, direction accuracy 0.49854, exact recoveries 0 | `EXPLORATORY_FULL256_NEGATIVE`; deterministic unsealed targets | 10.478 s; 43.43 MB peak; 21,108 R20 core evaluations; zero MPS/GPU | Output distance can be optimized without approaching the key; close fixed-point/local-output-fitness descent | [Result](research/apple_view/apple_view_result.md) |
| `O1C-0046` | 2026-07-19 00:24 | Key-only external decisions preserve O1C-0044's primary orientation while native CDCL owns internal variables | Full-256 0/4; residual 9 internal UNKNOWN, primary SAT/87, key rotation SAT/331, clause rotation SAT/46; primary has no matched control margin | `CONSUMED_SEARCH_DIAGNOSTIC`; residual rows are post-reveal ceilings | 7.767220 s; 122,552,320 B peak; 12 calls; zero fresh/sibling/MPS/GPU | Internal-variable competition was costly, but key-only greedy marginals still lose to matched clause rotation; move the unchanged global score to bounded prefixes/activation | [Capsule](runs/20260719_002450_O1C-0046_key-only-criticality-search-v1/RUN.md) |
| `O1C-0045` | 2026-07-19 00:10 | The frozen rank-54 reader reduces exact search work after lossless local-factor compilation | Full-256 0/4; residual 9 internal UNKNOWN, primary SAT/281 conflicts, rotations SAT/69 and SAT/129 | `CONSUMED_SEARCH_DIAGNOSTIC`; residual rows are post-reveal ceilings | 17.290067 s; 130,269,184 B peak; 12 calls; zero fresh/sibling/MPS/GPU | Factor geometry expands 8→9, but all-variable scheduling erases primary specificity; decide keys only next | [Capsule](runs/20260719_001005_O1C-0045_criticality-live-search-v1/RUN.md) |
| `O1C-0040` | 2026-07-18 22:22 | The transferred occurrence field ranks the true complete execution above attacker-generated decoys | Raw truth ranks 1905/4097 and 2292/4097; surprise 1078/4097 and 1461/4097, dominated by key rotation 107/4097 and 423/4097 | `POST_REVEAL_DIAGNOSTIC` negative; consumed targets | 3.981557 s; 101,466,112 B peak; 8,194 forward evaluations; zero solver/sibling/MPS/GPU | Close clause-occurrence scoring; move to branch-exclusive signed antecedent chains | [Capsule](runs/20260718_222255_O1C-0040_relation-candidate-rank-v1/RUN.md) |
| `O1C-0039` | 2026-07-18 22:02 | A BUILD-frozen signed proof-clause contrast transfers target-specific key-to-internal relation orientation | Both DEVELOPMENT targets exceed chance: 55.09%/56.99%, pooled 397/711 = 55.84% versus key/factor rotations 52.88%/49.51%; Full-256 recovery 0 | `TEST` attacker-valid relation transfer; no entropy or recovery claim | 12.202150 s; 142,262,272 B peak; 18 exact calls; zero sibling/MPS/GPU | Freeze H16/`|J|=0.5`; test complete-candidate rank, then live reversible guidance only on a positive separation | [Capsule](runs/20260718_220217_O1C-0039_proof-clause-relation-v1/RUN.md) |
| `O1C-0038` | 2026-07-18 21:20 | The unchanged exact ChaCha relation can close a nonzero O1-ordered residual once every supplied prefix bit is correct | Full key verified for residual widths `0/1/2/4/8` at 512 conflicts; residual `8` takes 89 conflicts / 135,441 us; residual `9` remains UNKNOWN through 32,768 conflicts | `POST_REVEAL_CEILING`; consumed target, no attacker-valid recovery claim | 11.494730 s; 139,575,296 B peak; 10 calls; zero sibling/MPS/GPU | Exact bridge has an eight-bit completion zone; next reduce effective width with attacker-valid relation/proof factors | [Capsule](runs/20260718_212009_O1C-0038_exact-residual-completion-v1/RUN.md) |
| `O1C-0037` | 2026-07-18 21:10 | Frozen O1 scores improve exact full-round search when used as reversible first-encounter key decisions | Exact truth ceiling recovers in 5,065 us; real O1 and shuffled recover 0; one wrong hint is not repaired through 32,768 conflicts | `TEST` plus explicit post-reveal ceilings; consumed target | 14.513263 s; 139,853,824 B peak; 12 calls; zero sibling/MPS/GPU | Close key-phase-only guidance; retain exact adapter for relation factors and residual ceilings | [Capsule](runs/20260718_211056_O1C-0037_relational-guided-search-v1/RUN.md) |
| `O1C-0022` | 2026-07-18 19:06 | Frozen O1C-0019 packet deltas compound in the exact 352-byte addressed vault | `CROSS_COORDINATE_DILUTION`: K256 int8 `-1.181837` bits; every fixed arm negative or nonportable; best post-reveal complement ceiling `120/210`, `118/204` | `RETROSPECTIVE`; consumed BUILD folds | 70.218 elapsed s; 284.1 MiB peak; zero solver/entropy/sibling/MPS/GPU | Close this unary packet/vault line; do not run derivative hot readers or residual backend | [Capsule](runs/20260718_190629_O1C-0022_o1c19-causal-vault-build-loo-v1/RUN.md) |
| `O1C-0019` | 2026-07-18 18:18 | Learned O1 reader/picker extracts and routes portable fullround all256 proof evidence | `BUILD_LOO_NO_TRANSFER`: learned policy `-0.271090`; raw learned `+0.312764` but untrained `+0.371233` | `RETROSPECTIVE`; consumed BUILD folds | 2,467.325 elapsed s; 345.7 MiB peak; zero new solver/entropy/sibling/MPS/GPU | Learning and live routing add no effect; exact readers were consumed once by O1C-0022 | [Capsule](runs/20260718_181855_O1C-0019_full256-multiresolution-build-loo-v1/RUN.md) |
| `O1C-0034` | 2026-07-18 18:10 | Frozen A469 bucket-local positive interaction rescues the retained all256 A465 fields | `NOT_REPLICATED`: A465 `47/239` becomes A469 `56/239` | `TEST`; retained consumed fields | 0.002521 scientific-path s; zero solver stages/targets | Close A448--A469 all256 transfer family | [Capsule](runs/20260718_181054_O1C-0034_a469-retained-two-target-full256-transfer-v1/RUN.md) |
| `O1C-0033` | 2026-07-18 18:06 | Exact A460/A462/A463 switching wavelengths and A465 cubic PoE preserve A448's all256 byte advantage | `NOT_REPLICATED`: truth ranks remain `47/239` | `TEST`; retained consumed fields | 1.068837 scientific-path s; zero solver stages/targets | A465 does not repair the missing-complement transfer | [Capsule](runs/20260718_180604_O1C-0033_a465-retained-two-target-full256-transfer-v1/RUN.md) |
| `O1C-0032` | 2026-07-18 17:51 | The unchanged A448/A442 byte-3 ordering repeats on disjoint consumed DEVELOPMENT-0000 with 248 complement bits free | `NOT_REPLICATED`: baseline/proof/hybrid ranks `242/236/239`; final `239/256` after RFC `47/256` | `TEST`; consumed repeat, no fresh target | 48.298 measured wall s; 256 cells / 1,024 stages; 204.1 MiB peak; no MPS/GPU | Close A448 once; do not resweep | [Capsule](runs/20260718_175112_O1C-0032_a448-proof-byte3-development-repeat-v1/RUN.md) |
| `O1C-0031` | 2026-07-18 17:44 | Exact A448 proof/A442 ordering retains a better-than-median byte-3 rank with every other key bit unknown | consumed RFC rank `47/256`; repeat required before any fresh claim | `TEST`; consumed screen | 55.290 measured wall s; 256 cells / 1,024 stages; 180.1 MiB peak; no MPS/GPU | Positive single target authorized exactly one unchanged consumed repeat | [Capsule](runs/20260718_174416_O1C-0031_a448-proof-byte3-full256-transfer-v1/RUN.md) |
| A296 full256 byte-2 transfer | 2026-07-18 15:05 | The unchanged shallow sibling reader transfers from residual W24/W28 cubes to a byte intervention with 248 other bits unknown | `CLOSED_NULL_DOES_NOT_GENERALIZE`: consumed `118/61/9`, fresh `230/256`, rank-product `p=0.1766` | Exact direct transfer; one fresh EVALUATION target | 201.244 s wall across four 256-cell/1,024-stage cubes; no MPS/GPU | Literal mechanism is cheap and executable, but its ordering does not generalize to all256 | [Result](research/A296_FULL256_BYTE2_TRANSFER_20260718.md) |
| `O1C-0030` | 2026-07-18 13:44 | Exact-cutoff conflict asymmetry should amplify the matching coordinate's odd self-ancestry innovation across incremental H64/H65/H96 frontiers | `RETROSPECTIVE_BREADCRUMB_NO_STRONG_GATE`: primary `-0.680620` bit/key, cumulative `-0.097788`, deranged control `+0.779642`; primary beats cumulative 0/4; 0/4 exact keys in top 65,536 | `RETROSPECTIVE`; consumed BUILD only, no fresh efficacy claim | 7.381760 CPU / 7.455637 measured wall s; 62.70 MiB peak; 168,648 persistent B; zero solver/entropy/sibling/MPS/GPU | Local hard q-to-same-coordinate attachment is contradicted. Preserve the unstable active diagonal only as a post-result breadcrumb and test learned global/live routing next | [Capsule](runs/20260718_134406_O1C-0030_incremental-diagonal-frontier-v1/RUN.md) |
| `O1C-0029` source freeze | 2026-07-18 12:53 | Hot calibration over one persisted real packet field | `PARKED`; upstream O1C-0022 is finalized null | `INSTRUMENT`; unrun | zero scientific work | Preserve for a future positive field; do not execute on current packets | [Design](research/O1C0029_STACKED_HOT_CALIBRATION_DESIGN_20260718.md) |
| `O1C-0028` | 2026-07-18 10:35 | Complete K256 O1C-0022-shaped packets can be transposed once into an allocation-invariant V2 state and safely queried by O1-O-shaped hot readers | `HORIZON_MAJOR_HOT_ROUTING_PASS`; 14/14 gates, 64/64 allocation repeats byte-identical, two hot bindings, 13 cold replay probes, exact legacy wire ABI | `VALIDATION` synthetic mechanism only; no ChaCha20 signal/recovery or authoritative O1C-0023 claim | 0.112165 CPU / 0.123936 measured wall s; 42.8125 MiB peak RSS; 25,128 B/state; 378,809 persistent B | Horizon-major transposition removes artificial coordinate-order decay; V1→V2 is one cold migration, then reader iteration is sub-second and replay-free | [Capsule](runs/20260718_103518_O1C-0028_horizon-major-hot-routing-full256-v1/RUN.md) |
| `O1C-0027` | 2026-07-18 09:02 | A fixed all-256 resonator bank is a T-independent sufficient statistic for late-bound slot/temperature readers after one-pass ingestion | `POLYPHASE_SUFFICIENT_STATE_PASS`; 12/12 gates, four distinct normalized readers from one state hash, exact rechunk/swap/serialization invariants and three hard replay boundaries | `VALIDATION` mechanism only; no cryptanalytic signal/recovery claim | 0.081856 CPU / 0.094719 measured wall s; 39.390625 MiB peak RSS; 25,096 B/state; 164,132 artifact B | O1 can run continuously while reader weights/temperature change instantly; encoder/kernel/phase changes still require replay. Feed real causal packets next instead of rerunning synthetic streams | [Capsule](runs/20260718_090248_O1C-0027_polyphase-sufficient-state-full256-v1/RUN.md) |
| `O1C-0026` formal runner source freeze | 2026-07-18 | The selected proxy can execute exactly once with truth-safe BUILD-LOO freezes, bounded state and result authority derived only from a complete semantic capsule | Source `7855492`; exact O1C-0023 gate, 4 BUILD/0 DEVELOPMENT, 64 fits, 4,927,488 alpha-bit and 4,096 diagnostic evaluations, four transient 8-KiB state replays over 1,024 coordinates from persisted weights to persisted/reloaded logits, 120 indexed artifacts | `INSTRUMENT`; conditional, unreserved, no scientific run/result/signal; activated capsule is `RETROSPECTIVE` | 23 focused tests; 33 pass/1 skip/61 subtests plus 12 pass/5 subtests in neighbors; 0 formal scientific work | Candidate result is not closure authority; only completed verified metrics can close the exact proxy fingerprint, while all operational failures close nothing | [Config](configs/proof_ancestry_pair_residual_run_v1.json) |
| `O1C-0025` source freeze | 2026-07-18 | Native full-256 logits can enter the exact global frontier | `PARKED`; current O1C-0022 logits are negative | `INSTRUMENT`; no scientific run | zero scientific work | Reuse only for a future positive posterior | [Design](research/O1C0025_LOGIT_FRONTIER_HANDOFF_DESIGN_20260718.md) |
| `O1C-0026` proxy v2 source freeze | 2026-07-18 | A balanced self-plus-offdiagonal ancestry-touch x proof-context basis can expose interaction orientation collapsed by the frozen scalar output | Source `0af57fb`; 768D deterministic v2 projection, all-256 pair derangement, scale-invariant offset ridge and exact 8,192 B reader+posterior state; four real BUILD FAP primary/shuffle replay is equal-scale and distinct | `INSTRUMENT` / `RETROSPECTIVE_STRUCTURAL_ONLY`; conditional, unreserved, no label/key-signal result | 1.609594 wall s; 105,955,328 B process peak; 8,231,208 source B; 0 labels/targets/solver/entropy/MPS/GPU | Self-touch is 4.87x denser/8.82x stronger than one offdiagonal cell; global sqrt(256) scaling retains it without diagonal collapse; proxy null cannot close R07 | [Probe](research/O1C0026_BUILD_ONLY_STRUCTURAL_PROBE_V2_20260718.md) |
| `O1C-0024` | 2026-07-18 | The least-uncertain-bit cube is not a global factorized beam; an exact all-coordinate frontier can recover excluded high-probability keys and honestly measure burned search concentration | `EXACT_GLOBAL_FRONTIER_VALIDATED_BURNED_NULL`: synthetic 20-round truth rank 4 while legacy excludes it; burned target 0/65,536 exact, MAP H117, best H110 at rank 15,405; 4,096 exact public checks null | `RETROSPECTIVE` decoder validation and burned diagnostic; no cipher signal | 2.438 CPU s; 2.454 wall s; 109.922 MiB peak; 2,890,445 artifact B; 0 solver/entropy/sibling/GPU | Global beam geometry is fixed; O1C-0016 posterior remains far too flat, so improve evidence orientation rather than K | [Run capsule](runs/20260718_035947_O1C-0024_exact-factorized-posterior-frontier-v1/RUN.md) |
| `O1C-0022` source freeze | 2026-07-18 | Frozen incremental O1C-0019 packet evidence into the 352-byte vault | Superseded by completed O1C-0022 result above | `HISTORICAL INSTRUMENT` | zero scientific work in this freeze row | See real result; do not repeat | [Result](research/O1C0019_O1C0022_FULL256_BRIDGE_RESULT_20260718.md) |
| `O1C-0021` pre-run | 2026-07-17 | A bounded O1 state can autonomously learn delayed reliability and exactly accumulate weak contradictory evidence over 256 coordinates | Source frozen at `4ba1cc6`; prior broad scratch DEV 256/256 on 2/2 seeds in 134.523 s; independent 273-byte FSM and exact work ledgers hardened; 31 focused tests and three audits clear; formal EVAL untouched | `INSTRUMENT` pre-run only | no formal compute/entropy; source work only while sibling production is active | Enumerable operator has a smaller O1-O-targetable FSM ceiling, so the formal result measures autonomous learning/streaming rather than O1 necessity | [Config](configs/causal_evidence_stream_256_v1.json) |
| `O1C-0020` | 2026-07-17 | A BUILD-trained O1 gate can select all 256 bindings from a unified stream and preserve them exactly through at least `2^20` distractors without an oracle deployment mask | `EXACT_256_LEARNED_GATE_RETENTION`: 12/12 cells at 256/256, TP 256/FP 0/FN 0; nested live state byte-exact; all longest-stream controls fail | `VALIDATION` synthetic retention; terminal (a), no cipher claim | 9.553 CPU s; 9.915 elapsed s; 438,747,136 B peak; 352 B live state | Learned routing plus exact addressed vault closes retention; next test must learn causal evidence accumulation rather than explicit binding storage | [Run capsule](runs/20260717_211433_O1C-0020_selective-mqar-256-learned-gate-v1/RUN.md) |
| `O1C-0019` source freeze | 2026-07-17 | Incremental packet learning plus stationary credit | Superseded by completed O1C-0019 result above | `HISTORICAL INSTRUMENT` | zero scientific work in this freeze row | See real result; do not repeat | [Result](research/O1C0019_O1C0022_FULL256_BRIDGE_RESULT_20260718.md) |
| `O1C-0018` | 2026-07-17 | A reveal-delayed O1 reader can learn attacker-valid full-round paired-proof orientation and a true reward critic can select more information per work | `NO_RAW_SIGNAL_PICKER_UNINTERPRETABLE`: raw learned mean -1.284644 bits; W1 true +0.326847/+0.160175 and true beats shifted in all 6 cells, but static wins mean IAUC and hard coverage/hash dominate selection | `TEST` negative full-round gate with autonomous-picker breadcrumb | 545.024 CPU s; 510.875 wall s; 315,703,296 B peak; 3,072 native branches | Remove cumulative-query double integration; packetize horizons; stationary reader-bound credit; all-address preview; soft no-starvation plus STOP | [Run capsule](runs/20260717_152827_O1C-0018_full256-online-real-gate-dev-v1/RUN.md) |
| `O1C-0017` | 2026-07-17 | A bounded O1 reader can autonomously discover one oriented channel among 330 anonymous channels and retain all 256 addressed readings without target-time updates | `MECHANISM_PASS`: 3286/4096 bits, +42.308742 bits mean compression, 80.225% accuracy, 16/16 positive; +46.701 over ablation, +42.765 over shuffled, +47.231 over raw end state | `VALIDATION` synthetic mechanism; no crypto/picker claim | 78.089 CPU s; 79.853 wall s; 286.438 MiB peak; 29,184 action observations | Anonymous signal discovery works; raw holographic end state is crosstalk-limited while the exact Bit-Vault retains the learned readings | [Run capsule](runs/20260717_140953_O1C-0017_full256-online-self-discovery-v1/RUN.md) |
| `O1C-0016` | 2026-07-17 | Frozen h96 and equal-logit h96+h65 remove transferable code length on 32 new full-256 output-only keys | `NOT_REPLICATED / DO_NOT_PROMOTE`: 4093/8192 bits, -0.078249 bit/key, 11/32 positive, paired z -0.555, null-like byte/block ranks, 0 exact keys | `VALIDATION` negative; lifecycle/integrity pass | 1972.625 CPU s; 1620.537 wall s; 414.813 MiB peak; 17,920 branches | h65 primary/shuffled target compression corr 0.999905 exposes common-mode difficulty; learn nuisance rejection and residual orientation online | [Run capsule](runs/20260717_115325_O1C-0016_full256-polyphase-blind-replication-v2/RUN.md) |
| `O1C-0015` | 2026-07-17 | The fixed h96+h65 polyphase reader transfers to 32 new full-256 output-only keys | Operational resource failure after all 32 reveals occurred in memory; no evaluation or reveal receipt persisted, so no scientific metric or classification exists | `OPERATIONAL_FAILURE`; no scientific result | CPU >1600 s; wall >1400 s; RSS >384 MiB; exact values unavailable; 17,920 branches | Burn all 32 targets; rerun the identical science as O1C-0016 with truthful pre-reveal accounting and corrected soft ceilings | [Failed capsule](runs/20260717_103252_O1C-0015_full256-polyphase-blind-replication-v1/RUN.md) |
| `O1C-0014` | 2026-07-17 | O1C-0013's exact h96 bytes remove code length on eight new full-256 output-only keys without refit | `NOT_REPLICATED`: 1053/2048 bits, +0.233784 bit/key, conditional z 1.819, +1.524765 over shuffled, but 4/8 positive, paired z 0.838, controls mixed, 0 exact keys | `VALIDATION` negative with positive aggregate breadcrumb | 306.195 CPU s; 245.756 wall s; 302.578 MiB peak; zero sibling/GPU work | Unary h64/h96/h65 remain positive, coarse ARX/Motif arms turn negative; freeze h96+h65 once on 32 new keys | [Run capsule](runs/20260717_084847_O1C-0014_full256-frozen-reader-blind-replication-v1/RUN.md) |
| `O1C-0013` | 2026-07-17 | BUILD/CAL full-256 paired-proof fields can learn a target-independent causal orientation that lowers sealed output-only key NLL | First positive blind breadcrumb: 259/512 bits, +0.088922 bit/key, +3.306254 bit/key over shuffled; controls all negative; 0 exact keys | `TEST` prospective signal; replication required | 392.188 CPU s; 314.384 wall s; 321.906 MiB conservative peak; zero sibling/GPU work | Two targets split -0.186702/+0.364545; freeze the exact reader and replicate on eight new keys without refit | [Run capsule](runs/20260717_075537_O1C-0013_full256-multikey-causal-calibration-v1/RUN.md) |
| `O1C-0012` | 2026-07-17 | All 512 opposite assumptions can emit complete closed proof prefixes into a bounded full-256 O1 causal state | Mechanism passed: 256 bits, 1,536 frontiers, 17,408 B state; known-key diagnostic negative at 119/256 and -86.780 bit compression | `TEST` mechanism; no inverse claim | 58.032 CPU s; 49.199 wall s; 317.281 MiB conservative group peak; zero sibling/GPU work | The W52 `(7,1,4)` orientation is not portable; horizon 96 alone gives 139/256 on one key and must be tested cross-key | [Run capsule](runs/20260717_065248_O1C-0012_full256-paired-causal-sensor-v1/RUN.md) |
| `O1C-0011` | 2026-07-17 | A complete target-independent full-256 ChaCha20 CNF can expose exact coordinate-bound paired-assumption relations under bounded resources | Passed: 32,128 vars, 187,370 template clauses, 656 operators x 32 bit ranges; public instance has 640 public/0 key units; SAT/UNSAT/SAT self-tests | `VALIDATION` infrastructure | 8.692 CPU s; 163.594 MiB outcome peak; 25.415 MB workspace; zero sibling/GPU work | Full-width causal substrate is valid; stream paired solver deltas into O1C-0012 | [Run capsule](runs/20260717_054138_O1C-0011_full256-public-cnf-foundation-v1/RUN.md) |
| `O1C-0010` | 2026-07-17 | O1C-0009's signed direct orientation transfers without refit | Refuted on 2,048 sealed keys: compression -0.019088 bit, z -0.946; loses to shuffled, output-permutation delta only +0.000962 | `VALIDATION` negative | 2.424 CPU s; 201.969 MiB outcome peak, 245.391 MiB end-to-end; zero sibling/GPU work | Raw end-output regression is closed; move to public-CNF assumption/proof events | [Run capsule](runs/20260717_045214_O1C-0010_full256-signed-direct-replication-v1/RUN.md) |
| `O1C-0009` | 2026-07-17 | Direct, candidate-relative or teacher-distilled full-width readers remove reproducible entropy from unseen public-output targets | Declared gate failed; all CAL scales 0, DEV NLL 256.0, compression 0, transferable bits 0; sealed lifecycle passed | `VALIDATION` negative | 6.923 CPU s; 182.906 MiB peak; 128 fresh keys; zero sibling/GPU work | Post-reveal CAL-only signed direct scale gives exploratory DEV +0.023159 bit; replicate once on a larger new panel, then move upstream | [Run capsule](runs/20260717_040741_O1C-0009_full256-output-only-reader-v1/RUN.md) |
| `O1C-0008` | 2026-07-17 | A strict full-256 public-output attacker/teacher foundation can execute without sibling or accelerator use | Gate passed; 256 unknown bits, 72 contrasts, 2,576 features, 1M decoys, random NLL 256.0, zero target-trace fields | `SMOKE` | 0.996 s; 78 logical blocks; zero sibling/GPU work | The moonshot is now measurable; train the first full-width reader and demand uniform held-out entropy gain | [Run capsule](runs/20260717_031113_O1C-0008_full256-living-inverse-foundation/RUN.md) |
| `O1C-0007` | 2026-07-15 | Low-degree upstream solver evidence can populate a genuine compact O1 memory | Protocol passed; 12 registers, 266 B; A355 rank 73 but exact conditional `p=0.593506`; target-blind A356 order frozen | `RETROSPECTIVE` | 10.799 s; 672 views; zero solver/GPU work | Compact mechanism exists, efficacy does not yet; run the exact decoder once on fresh paired-assumption trajectories | [Run capsule](runs/20260715_174537_O1C-0007_upstream-solver-evidence-bit-vault-freeze/RUN.md) |
| `O1C-0006` | 2026-07-15 | Corrected codec plus adaptive DC-complete registers can form a high-fidelity bounded ceiling | Gate passed; exact A355/A356; 8,014 B, worst Spearman 0.999224; 24/24 orders | `VALIDATION` | 7.347 s; 9 arms; zero solver/GPU work | Full-basis state is table-equivalent and 2.045× larger; move upstream to compact causal/bit evidence | [Run capsule](runs/20260715_154553_O1C-0006_corrected-codec-adaptive-dc-bridge/RUN.md) |
| `O1C-0005` | 2026-07-15 | Distributed slots and dense low-precision state transfer better than sparse single-field support | Gate passed; 4-bit/H1.25, 6,668 B; A349 Spearman 0.990198 | `VALIDATION` | 38.521 s; 72+72 arms; zero solver/GPU work | Precision allocation beats coefficient pruning, but the bank remains full rank | [Run capsule](runs/20260715_135434_O1C-0005_bounded-spectral-memory-tournament/RUN.md) |
| `O1C-0004` | 2026-07-15 | Independently reproduce the complete Direct12 reader and commitments | 52/52 shards, 13,312 cells, all score/order hashes exact | `VALIDATION` | 5.986 s; zero solver/GPU work | Verified input primitive for bounded memory | [Run capsule](runs/20260715_130047_O1C-0004_direct12-532-reproduction/RUN.md) |
| `O1C-0003` | 2026-07-15 | Pin the dirty-source Direct12 dependency set honestly | 71/71 members, 9,882,690 bytes | `SMOKE` | 0.069 s | Lab-owned provenance without sibling mutation | [Run capsule](runs/20260715_123734_O1C-0003_direct12-source-snapshot/RUN.md) |
| `O1C-0002` | 2026-07-15 | Validation-selected raw reader transfers | Failed; familywise `p=0.664` | `RETROSPECTIVE` | 119 readers | Replace scalar selection with structured evidence | [Run capsule](runs/20260715_123236_O1C-0002_retrospective-reader-tournament/RUN.md) |
| `O1C-0001` | 2026-07-15 | Normalize A296/A297 without post-reveal access | 24/24 members; zero labels read | `SMOKE` | 0.360 s | Offline observability path established | [Run capsule](runs/20260715_122529_O1C-0001_stage3-a296-a297-ingest/RUN.md) |

## Reproducibility anchors

| Artifact | SHA-256 |
|---|---|
| `O1C-0058` capsule manifest | `9367abdae4b8514eec3c9518c8cfc54f9b8a34ce45ec4ebc5c009280507b3b06` |
| `O1C-0058` authoritative result | `1ff36f9479b397f50c9421a7c0ba406df308ab8c9989d2e039e0874a1acbcb64` |
| `O1C-0058` original RUN.md | `05eadbcaef8db7003be3bd5a7144969a659cc2be52ffbc1c32e90d7dc1ed97f0` |
| `O1C-0058` science source | `09cc48b9d61b4cccbeaa7cf038404ac4f2a3b15a` |
| `O1C-0058` terminal recovery source | `d9d1a851f873ecd0afc33236adac52b8866ccb1f` |
| `O1C-0057` capsule manifest | `008b985868b18160711be70cc9fa2a7697d5888c5515702caef72228ea2a742e` |
| `O1C-0057` authoritative result | `bae7899503ec0d349dd7da51ebaca3cef2982c4e53d1ca560adcffe7bff47971` |
| `O1C-0057` source freeze | `ba44cbd064499b68e665aade71d15dca0c672b71` |
| `O1C-0056` capsule manifest | `ba7f92ebd96cc7879b2d3321be905ffb5b0ec52563fa0dcda08c821066f1dfac` |
| `O1C-0056` authoritative result | `f2dda492e7c6af7d0cea12a9aeb33ae5da7b08d8e4e352c18b695f9683a48740` |
| `O1C-0056` source freeze | `9de519a973595b76f8a2ef512a5edc518499901a` |
| `O1C-0055` capsule manifest | `7559c3fbf4a327356c6c04d9cf266b366bf8760092218dbcfa5cb2f5254c9729` |
| `O1C-0055` authoritative result | `569b9770a690357b64dcfc44bce79b1a7eedb1f9688e5c03ad6f185b50adc9b8` |
| `O1C-0055` source freeze | `8d7aa3d6053356ab7c5b95661df6548697505959` |
| `O1C-0054` capsule manifest | `442d6659e93d67c86d118373313bd624a37ace49089b1765f01a874aa7e808fc` |
| `O1C-0054` authoritative result | `91aa42c2b036a5709f0f093e091c017c568aea459098dd238800cea87d9c32d5` |
| `O1C-0054` source freeze | `2a63a749b5d0f92280a750ca79218ab841f2037a` |
| `O1C-0053` authoritative result | `ab616087ec4aaf5862dbda0b0139146ea845b9a1cbe3cff0881e9a596e00f16a` |
| `O1C-0053` source freeze | `0b89887f961f50fced087a987a6a2c4fb2122b18` |
| `O1C-0052` capsule manifest | `0a4113226727dd3caed1b5490a65003ead633d028cd15156fab6367aed719f32` |
| `O1C-0052` authoritative result | `7ef0f0416ef9d884c2041d8e6396291f4b3991e9cc5e485d2a6aa3cd36bea8de` |
| `O1C-0052` source freeze | `b32608d5cebbd547582a6dc8c371482e191e08a5` |
| `APPLE-VIEW-0007` scientific payload | `d6ae5f022ee5172a87660c9721839b0c880b83dc82a60e430ac052be05ba440a` |
| `APPLE-VIEW-0007` result | `c7c4355097b4f8e334f2700eab169e60c8c95d505cb1b17d2d529f77cbb3f533` |
| `APPLE-VIEW-0006` scientific payload | `7144a093c05cb3f834450a93160d9419688bdd9c8d72543340eb3eb5c4f51665` |
| `APPLE-VIEW-0006` result | `c44a6e2aecd6240c8789c1fca7975372ce8975d4554b247cb4d4ffd1cd0f677c` |
| `APPLE-VIEW-0003` scientific payload | `db62ceaa6de7568abfbda2d3abcb8ca56e99ea72a91141a17594774d3ec080d5` |
| `APPLE-VIEW-0003` result | `db8f803174f80df64639b343cf3e7906efd2cab8709e99a94c182c86d6ab8293` |
| `O1C-0048` source freeze | `72d7a9b14cba31bc7033490994c8da1580d6a027` |
| `O1C-0048` canonical config | `e5a9c1f5f6c68ee16f4f3313b6521763cab1f3f2ee6abca80e0b6b53815ff679` |
| `O1C-0048` runner source | `c1d6f63a2cee8535cd79debd363d8c1c155387bf39b320ceee2e7ff27d69a85d` |
| `O1C-0048` attacker freeze | `5069eb94d31be393ca4324477073fe54fd303764182603f18733c517529327c3` |
| `O1C-0048` formal result | `eb5ffc29dbadb0f3722204425309d16b6befe82ea5aabc1075226f856d599663` |
| `O1C-0048` capsule manifest | `bfb086fc000037b03b0c8fcbbe4aa83f4555e95ffc49bd577faf55266f8462f6` |
| `APPLE-VIEW-0002` result | `680182ea0880fccd8e5e682ccc43a6840b79ffc50e39768fdb2c1d97eea2a3c8` |
| `O1C-0047` source freeze | `0a34020cb1f3cd88929d55811c9b2b48fa247f7c` |
| `O1C-0047` canonical config | `c83fc9b8e35bb1fd6756ce45288583f328ce45c211cb9ddd21dc922abf9c907d` |
| `O1C-0047` runner source | `b4bfc452bde957e80985fce76eb2813ea5ffee371cdd26379cec9d6f0e19667f` |
| `O1C-0047` formal result | `91709eb6c7a0f378e8ef0046a81d4211a428d75fa6636553c218c023cab3380d` |
| `O1C-0047` capsule manifest | `2c4bbb4986b175e84748da9c2bf24f65aecff5e3ff0a3d95e3b0ee2bbd2bf117` |
| `O1C-0046` source freeze | `b0f8bcbd38fd5eb93d25712c1fd92fbeea5d18ae` |
| `O1C-0046` canonical config | `850693f456c146be6dfd10b4beca783acd46482c52047b21d331c4d62c87b2b9` |
| `O1C-0046` runner source | `c1dc705599f5c5544531caa24d4a69b6283c489f641625ad79bded819e46373a` |
| `O1C-0046` attacker freeze | `7dd7656728b70346d37796d1fc0cf8fc2d15f8760061fa5bd31187063bb9e308` |
| `O1C-0046` formal result | `0f2ffeb436114a35aabf2d4dea7f5fe3ab7bdc2c37665539b1df97ee14fd562b` |
| `O1C-0046` capsule manifest | `54ddd2f32ca76708a1530be3cbfd1ade8d420ee324cb2bd68114035d674620ec` |
| `O1C-0045` source freeze | `d3b927b6f9ff65b9520aa4c2631d5106fa592b70` |
| `O1C-0045` canonical config | `1cb62f0d746c86b1fa3c7ff1fb29546ad0222601af669e7745b72c69b8d67984` |
| `O1C-0045` runner source | `a2212c716775ef4af933f8a9ccee6693578dd6d5bfb5920707cb8f88f01a14e2` |
| `O1C-0045` attacker freeze | `df198262ee632496c855496e1d327b3717ad74ef346e17d1eda2f77ee5f7fbb2` |
| `O1C-0045` formal result | `fb35fab89c293e229c3adaf1c63de4274b29d5f84e1892baf410cf715b71d779` |
| `O1C-0045` capsule manifest | `dace5023b25b8a2fbe6d52f0eee239cecca32154f4bfcba712218899b5c67c63` |
| `O1C-0040` source freeze | `284f7f272611e926ea50bd310feba7bca758995b` |
| `O1C-0040` canonical config | `f76560431d38de051386fc0d233e399789e82ff848f127c6108bb26bdf1e9abc` |
| `O1C-0040` runner source | `22af4fc7aa270fa7d195de0723129e6e53e61ab732a2a4a563a569f6fb8d1bc8` |
| `O1C-0040` score freeze | `8662b53d75e4bb7849e5302a8f3b2a878ac75eff9810dee6910b4d3305d047da` |
| `O1C-0040` formal result | `941d7fe9b7bf52f223ad0c3571248dbd739bd3233aa981e3c6f1b114bed95b7d` |
| `O1C-0040` capsule manifest | `58f9350eafa2e0a842a00aecf7e32ea4d12f52e52af2f48b3c2c1ff8e247883f` |
| `O1C-0039` source freeze | `fdd0874fb499e9f4a6ac1e5a652a784e0937e044` |
| `O1C-0039` canonical config | `c151c3aea89b1834085db6f2b0c45692371d331c50e8c00a61b8c322eed99ca4` |
| `O1C-0039` runner source | `5a40d23545982feafbf37200168e9860b4e5b743d87266e343786e34c3671947` |
| `O1C-0039` relation field source | `24f16ad1dbf255c74bd62e5e4669a6895ee427f7b630a48248f2d00e9dafddd1` |
| `O1C-0039` native factor adapter | `687fa973a066053c841efe0405feceddab50189cc2ffc4431c8bfab34424c941` |
| `O1C-0039` attacker freeze | `a8ed2b3d7acdce935b07c052a05f64d7ad3e288e7b3707c706f2d56fdaaefb14` |
| `O1C-0039` formal result | `f1c6860f59db4fd5c1aca2123ac23c69b5f4f01e99d05ff53a2144f3fa594b87` |
| `O1C-0039` capsule manifest | `1bda99959ca5367a16e92d7c579d2f24e3b1216852ad04b2e1061b2b9f21898f` |
| `O1C-0038` source freeze | `1596c3eb9467124e1ba7e6c218277d0a7a1abebe` |
| `O1C-0038` canonical config | `b14b5948cbfd5530e05d737137e4befeb539de1f1b4a77a07a71b854a7dac0b5` |
| `O1C-0038` runner source | `d5876cd3438092b31f451220ebb4e12e68368536d59281c500a57b64a155e314` |
| `O1C-0038` formal result | `35199c4820bcd3c792d6bc902815a20eb93a7c23c5275056a39d881af506fcf1` |
| `O1C-0038` capsule manifest | `78798e6d1f0c1078482c09a2cb48df041e14bf8238c4e54f0d6843315c3f538e` |
| `O1C-0037` source freeze | `ae0bcd339f4cfef42bda10c7d345bc34b4750753` |
| `O1C-0037` canonical config | `180aac72cf5e6130749052fb11259006e8da007e33d82092583f8f408c7e0c8c` |
| `O1C-0037` runner source | `a4c74b7efb4f432b3f43b61d1ea7cb8976d728b95e9cb5be4b678f0ab5eb361c` |
| `O1C-0037` native adapter | `384870ffa73bf8b5fa404742669218c7d93918018507595c042d73d54a08eca9` |
| `O1C-0037` formal result | `4adcc63361e4d7376d3fa7413c7857a551627ff89dc9d3deb9f91b3a39c209b3` |
| `O1C-0037` capsule manifest | `1f3532e68fa15c4b1ced1e6456409f69b7f791c8f1def45f048b76049af0343a` |
| `O1C-0030` source freeze | `e7c1bf551f2abf3c00a82c46d48b021452dfd417` |
| `O1C-0030` config freeze commit | `3b2813845f9015b457eec74bcb53cf62fa15ec2d` |
| `O1C-0030` canonical config | `1ae60b05b12934fcd6d4e89aafc8b2f1bc0f2bbd940da1fe19f26d1a626768c0` |
| `O1C-0030` core source | `b13f509f00e52213deed5a55d74efe80d406f3771d6e40d82d4f8cb7db0920ef` |
| `O1C-0030` runner source | `07261a930154805dca693090fbce9a6049a6b2670e4da1581a0c899decdc4b03` |
| `O1C-0030` capsule manifest | `ed6ef945e0e05ebf3199b3526c71d70da8402cc07bd8d7c4ec6c66bed483b04e` |
| `O1C-0030` formal result | `d1aa33be2852f83e923fb29dd4b13ebd3340e466b624bf4fc5efe17ea2f73715` |
| `O1C-0030` feature freeze | `b258643338b126666ce7b6b3c861ae56cc93166552a47f890a4e2aa39d9141b0` |
| `O1C-0030` prediction freeze | `b442962f32498b706c7f1e624eda120e54ae6c76bafcd59356533a2451ae1943` |
| `O1C-0030` artifact index | `b0ed9e764544bb2856fc3e8a18b76ba39d4c1ea88c64f83da466d65f6bc98eca` |
| `O1C-0029` source freeze | `22d417ca73c73af59c8043c456c5475ed57f66a3` |
| `O1C-0029` canonical config | `86a34d70d714333adfd72ec9b6100ab475c872afffa7fcf707f401b7eac7d98f` |
| `O1C-0029` runner source | `747431b7c2f7dfa1fcf81aecbf58cc6f519db72cf81dcec22dbc2192ba9b6f72` |
| `O1C-0029` runtime closure | `dd9675a9017ed9be240dee0d50f195cbd938cbb6044c29851e736cdeeb6ba3ec` |
| `O1C-0028` source freeze | `17c02dfdbf56de6a81ae34700b258815bf0b7f88` |
| `O1C-0028` canonical config | `7d3f547032c11cfcf879ad97406c946a68e101762279047bfeb81897d0a19a48` |
| `O1C-0028` V2 basis | `75b0c13e830c2bf586c0df5fd180eb84ff0d7676b2f28759cc3ce0e3c4f579f6` |
| `O1C-0028` capsule manifest | `aab7484b36b4a7c6e59ad556d41f44fbb88477b2f3f1f45270c0685e7a16ce09` |
| `O1C-0028` internal result commitment | `ed3517f215be1c06e7b10882f2eeb6d494ab1f75916f9979edd04729c76abc6e` |
| `O1C-0028` result artifact | `8c6f845c9ac7a604bca51d3b07bcd648f1e7a0810f7d5c149f1cffd462a3ac1e` |
| `O1C-0028` primary V2 state | `02837fe664dc8b75b4dc651fc4d5fd6981b4c9a2653d4040c276fbe124047abe` |
| `O1C-0027` source freeze | `f47a6dacd54a7d9c93bc41c0ee08902bf855e85d` |
| `O1C-0027` canonical config | `6fab58bb10101067eecaa7c206f66e0b0463e9032bee6a3aeb7605778993747b` |
| `O1C-0027` state core source | `06d338e890a466d7723d60cbb56a63e069cc99f5cc25ecd9916fa4c0072a75c3` |
| `O1C-0027` runner source | `41f38290a2ab6595fa633934d39c59188f7944a83df67c0e402eb3c27d743872` |
| `O1C-0027` capsule manifest | `1361823ceb8711090b4773fd8409ced7123e490b71c30a2a9e41c5ec205c2023` |
| `O1C-0027` internal result commitment | `6041fbb157cb96c98a988da60b0a88f958507b3c5d0e1b5cd8ebe2733280a568` |
| `O1C-0027` result artifact | `a52f8d94a0202d9df508daedc812d3efb6d88c4bbfe3e30bd4e6ea04f376291c` |
| `O1C-0027` primary/rechunk state | `9d3cf08570f64a31eac9723b10105d5948e5898a2da6ee1b9543d3f10e1046e1` |
| `O1C-0026` formal runner source freeze | `7855492ac754f156d5de9bbea65fd2b6cf1910f9` |
| `O1C-0026` formal config | `17df7a8a1cc3100c13ef86d4d355783b97382700b6d68fcf045362183131efb4` |
| `O1C-0026` formal runner source | `0e3ae438b9df8189a2042dc1a78db1a734350ebab64de2764e2ec4c773ff1ddf` |
| `O1C-0026` proxy-v2 mechanism freeze | `0af57fbeb6beaf69be66e64c3f0981227f829fd7` |
| `O1C-0026` projection policy | `2e2c1e56d4a9db94a575337a74e6523fe300f05bc5a2b21228ecfd151f808a7f` |
| `O1C-0026` proxy source | `a9da57e829f1bb9e1eca326aa559931f717d71241c811e178b8bd233a83e6003` |
| `O1C-0026` structural probe JSON | `8abb3f886c2b0464cf6ef95fba410a0e7b68c17f0dce153721003f716c21aa5a` |
| `O1C-0022` frozen config | `ea313fd6bb80384e4ef73e4a72f3705c79b2a98ad5a69552d043657b56f1a10d` |
| `O1C-0022` bridge core source | `82b8f1724ce5c6e348aeb1e100340276bb84c842b9429203f0d2bef25e2cbb55` |
| `O1C-0022` runner source | `6fb6e639a1e17eedc0c974cd629c3cd55b788eb2fcfe73c543bc5b00cccde913` |
| `O1C-0022` native O1-O bridge source | `01df7ee111dc453b278ff968fe8f1d064bb078f35d4bd09389d17db749ddb6a1` |
| `O1C-0022` handcrafted diagnostic | `7d2dcc6d25f9a296e45b4e2febed60fcb4a56f05e540e9a5a3cfeddd9fcc59fc` |
| `O1C-0020` capsule manifest | `8380a3a1bbf826e62fbaa99f25e0ea1ba41f7020c101238b867ac99201077c59` |
| `O1C-0020` internal result commitment | `6c12a0fcb9e0b58a86b8bea340ea475294b530372c9a9a28ddaa62724cab8cb5` |
| `O1C-0020` result artifact | `be669301675432fc261ef9a77c78b60140993644c043a7745422ed860f00b97a` |
| `O1C-0020` canonical config | `2bd6509696986bf0f77e5b7aef9bbfa843deb85b1ed4a8140f93a60f1e2ae24d` |
| `O1C-0020` gate freeze | `0b027d4f0cd078fd775e8e20b8793b92231ad014205fb3ae644bbb24208ccfd0` |
| `O1C-0020` prediction freeze | `f898ef2fdff2180f1d7d66d53bf295d439761b0d13c7ba2f8072a3251d1d1523` |
| `O1C-0020` primary slow state | `853d8e643228924969d4488b6a0925c27eba2f9cf298575b58dcb9bdf6b4e5dd` |
| `O1C-0018` capsule manifest | `fcbf43c99994c0debe5b39bb3e734ea1d1e23ba58e89b10ff2bb7e23886493fb` |
| `O1C-0018` internal result commitment | `db92bd86849ff93e0f9b935a72f64f1b4bd46b134747c913ee82e5d772ac11c9` |
| `O1C-0018` result artifact | `a8e5940edc5887e404725c98631df89e1f91963abd47d1fa51263fc681e9df4d` |
| `O1C-0018` canonical config | `fd539d2a2461f879ebdbcad2c29f3c6de7c514385fece2ef1bf8ddb06707056a` |
| `O1C-0018` prediction freeze | `529356d380baec494ddfe0710e8b9cf0f85308c50b2913600e4c39b9a041c30e` |
| `O1C-0018` learning freeze | `09043f7dec8eb916baff3879706111add83f1c4337f321e01842bc351fc2564a` |
| `O1C-0018` primary slow state | `de7030eab45e7e88770d4789183e0ca604ecf943302d6c3e8b792f0a316c035c` |
| `O1C-0018` shifted slow state | `bc71d80b9f98feaf9c5f1ffe9244384f8fdd8775359b27fe62bc60076098f8b7` |
| `O1C-0017` capsule manifest | `59f1f59b4e24545391cb06cd2bee395285d4385c893af36d18def28bcb3858fd` |
| `O1C-0017` internal result commitment | `609014695bc3013bb971d7d05b682d18797af5c9d9cd31561cdc41de120ff28c` |
| `O1C-0017` prediction freeze | `a2f5a8ba939bdedf9fdce4bb1e0dabac9fc3ac850a3b9e249b9b2f1d3abafba7` |
| `O1C-0017` primary slow state | `481f8177a1d4cca0efc7a96daf09dbfa9615fcbeca5106845b976985c353c477` |
| `O1C-0017` representative fast state | `51c99f3a8a273863329f524b36909c24cdc1237ec17b8dc361ab6c54533f35bb` |
| `O1C-0017` canonical config | `6bab5437954da6b26e4db0ac3b0a5a613b0a3180c4a406500264615ff908971b` |
| `O1C-0016` capsule manifest | `fd0469885ee436414f94d708006cc40d86fc730d25b618167c7d664b3fe195ea` |
| `O1C-0016` internal result commitment | `6146dbfe10e1add60fe5d16f133c5b1acdced42bcf2249561926d26ee0e11652` |
| `O1C-0016` canonical config | `054e8b05c7824cf4c47f509d6a4977e3feac7e5df5ce006f55948b93554daaa6` |
| `O1C-0015` failed capsule manifest | `326bc30a1499f6479d306df43b17ec390c020832bb5d1816fa8ab9f7f9660314` |
| `O1C-0015` prediction set | `f2958da162a2dca74f2c5dd62ccb45f3d764be7c8f71200ee3afba8409a62116` |
| `O1C-0014` capsule manifest | `741718cbc6b63de24f4d9c89cd2aedc8e9779a0ebb38adc4d40666e97ce24bcf` |
| `O1C-0014` internal result commitment | `ecc06b011a95f6ceeec08641b68e1105511cf714cc250f9fe3b62e66c2af4c4a` |
| `O1C-0014` evaluation commitment | `69a3142f56b08f60890b4849ab9d71d4a68aecb4ad5db3a0f24b304cf041b6ef` |
| `O1C-0014` protocol freeze | `3664e586a30daa758f719bb918e64938690cf5aa47daaf6aa3a027720ca9c2b9` |
| `O1C-0014` prediction set | `5b5912420948fef68b4be4a4fb171c5927286e0c9e6acfb9d1c0f48d3302a683` |
| `O1C-0014` coordinate stability | `6fc66caf0ff3e26938e25f4e6cde15b2a58943c10dbd1cb482f32b06223d3364` |
| `O1C-0013` capsule manifest | `a0d4df5c01f7de3c65a429f9589e46d784f802bc1f8e0aa90dffb011be46922c` |
| `O1C-0013` internal result commitment | `a70610d3d589e97048c6045747c0821e5669c5dc89e420df79b0fca43476d4cd` |
| `O1C-0013` sealed evaluation | `11d3cdfffb6cb078f7d8a54e56ff827d3c9a4237df32632274c2176e7e5efa38` |
| `O1C-0013` primary frozen reader | `796e79ec932b990a59ecbc34216c4878b9279bae3bb136fe0832e580bcb2e9f8` |
| `O1C-0013` reader freeze receipt | `2d96c4582076818d1d101a10527535de8ed5be1f2e928658a14427043645a5e5` |
| `O1C-0012` capsule manifest | `a28acc299d2ed42b7f4eba14e653cd8d0c3f09347658fcb65d49936e0a255556` |
| `O1C-0012` internal result commitment | `33184e9245f4e31e56f16c9f8cfaa21e18849279058b278959cdb2c8acc54bd7` |
| `O1C-0012` bounded state | `aea9d4c0bd88d2c8480fb51b98d5524bc8c6fc319dd612c9dc345aa03035b664` |
| `O1C-0012` paired event stream | `b52bf4cce10f69672077f4b6b0d8496cfe0c633aac5ae0ce43502d2e9d5b26b1` |
| `O1C-0012` public baseline | `3061939c1ea041b73d82ada74b71c3265cb2a90b4cb1904030f178807844eaaf` |
| `O1C-0012` bit-173 sentinel pair | `3631a4e16ea5a7fde6dc3c096db89ab595494cf44e4e6fea0ae315cc8a60817c` |
| `O1C-0012` known-key diagnostic artifact | `35bbcc55dd1151a9cec1d7980a6126cd8c4b9f1f60a22acfa83cc7380257af73` |
| `O1C-0011` capsule manifest | `b7a07e6461805946897adbfb90da9e9f55ff1074e9aa1343f602eecb0645b7b4` |
| `O1C-0011` internal result commitment | `6c4fd7becd5307d60b30e16ea1fae8d3f4739b06c888204d638950c94b53adfe` |
| `O1C-0011` exact CNF template | `c293d36cab270b28ab2e89c073227fd50b75a6b357b9994d27c3acf7c01a0d52` |
| `O1C-0011` causal map commitment | `13c0dd32b1c0eec0b9b95e9c7c0f2a8390b8be6f98bd59e3b7d021c23762bfaf` |
| `O1C-0011` public attacker instance | `dde6a2791726e148c99064ec71f746fb8803e5d0f6b1996dd8b238c9c9b0a2a0` |
| `O1C-0011` bit-173 assumption-0 instance | `758c463982ce6222bf6dab9d130fc1c18a34fb2bf48d1f004d851ca46c9de003` |
| `O1C-0011` bit-173 assumption-1 instance | `10717d9dadd4aa60d04ea4e38ffb95d34be0867c2424a501e01c224a1b930e5d` |
| `O1C-0010` capsule manifest | `a87b7a9fb799d667e9d2e670f759ca4f389aac2be9cb932c3f308ab669f4ab7c` |
| `O1C-0010` internal result commitment | `76069cf7e25e194feee027d4e4a1e2cca0fed47ae4ec84fbaa9ff966845e3bc9` |
| `O1C-0010` pre-reveal prediction blob | `4643e0e849178014ede98e355037829158ca2eadc9b404671a8f64d6904e2dee` |
| `O1C-0010` prediction index | `2224ab10e3b3362ab374c4d5d90b7f19a697c9aca4cbfe094864e90d5a5313ca` |
| `O1C-0010` frozen protocol | `75d90a63501ca4c6671170b7b9ffb039f2c6e713279b63a2073f26d15d20e419` |
| `O1C-0010` publication root | `cb9868cce5fb79b2b7690e90e7047681b765a28c9f3507255dd419efb9b97b63` |
| `O1C-0010` reveal root | `203804994ae7dcae7eac6459a762911d9b7a550829762098b560de0057183fac` |
| `O1C-0009` capsule manifest | `f31d7672921dc0c2ec684cf8c5247a3ff2386fbea316c2eab98072cd22fb29d2` |
| `O1C-0009` internal result commitment | `40276d71516d4d150b02cc8235c08d00fb8ceb28daf64d1316826b38fd094bf9` |
| `O1C-0009` report artifact | `e007dd7964269036c427be53e9563a4bc450955cafecbd0b8ae2f6a9db064332` |
| `O1C-0009` pre-reveal prediction blob | `8431b3c19a697ce0d48e66d29b199ec6d199670870d40231564c9516e3c34ad2` |
| `O1C-0009` frozen calibration selection | `8e938893dcda020cadb5aa3d3cde0efc43cfe9cd6d34879ca00eb4538dd4d24d` |
| `O1C-0008` capsule manifest | `50cd1dcd83034d69aafd2e7890d62b9f2c25b6e65c5a929d3119027a71105449` |
| `O1C-0008` deterministic foundation result | `14bfa1dd9e4593cac223a779562ff8b591bf88c485486814be62e6f73baa79a2` |
| `O1C-0008` deployment contrast set | `ab28ca614b27c20e71acc7815a9daff33c8ec20c4d331496dad45fb1fa6e7496` |
| `O1C-0008` teacher-label set | `b1f467e44cbaca82ff1e6aa031148cab2268ba7565bf897095d381000a05fb8e` |
| `O1C-0007` capsule manifest | `2900adafb938ba470ae595b21895a0035a77621a667e04abacf1fd8d5654f3c1` |
| `O1C-0007` deterministic report artifact | `868f339b22e6b1bddbde944dffcebd22ad8f94287b829cd65d85670d4de2dec5` |
| `O1C-0007` internal deterministic report commitment | `c371ce0b100684b518c1e9094547f2acdb869c3a9aac660408058acc48ccdfe7` |
| `O1C-0007` 672-order blob | `2ed242ba8582798cd23618be18a230cecabe27c9aed2546f5a88814117f86949` |
| `O1C-0007` frozen future template artifact | `836d6f0b01a7b86d50b0b5f81eaaaef1df235dfa45804b2a5ccc2a18d24775fd` |
| `O1C-0007` internal future-template commitment | `39cd8db1f10e6366cc26cbc896a8f8a7418d0fa8804277e5b373df08436d73cf` |
| `O1C-0007` A355 selected order | `fdf7c3618f7c2b5d9fbb1c47a0826fb1293932016fe5602a346e9c247e188852` |
| `O1C-0007` A356 target-blind order | `0a6e32430a97c968c3a831ef23c58eaacaaf411fcc9f44e59661f62efa764159` |
| `O1C-0007` source receipts | `decffd6bd44ada221ea7ef91446983ff9823241c0274303ba84655ceb582e52f` |
| `O1C-0006` capsule manifest | `720bc88834e5ae2959ac960d4f5fe2ca1c8845283b0d32273c6ca2cfea34fdc6` |
| `O1C-0006` deterministic report | `64ace20f8798da49e6108352ea0c95459afb2a955439148cea8f357d643b870b` |
| `O1C-0006` complete order set | `964dd87ddf6cf506d9399ff6f1fb16245617bcec8f3ab66484031d79f9cd41e8` |
| `O1C-0006` source snapshot | `ef3da5d473a5a108ef3d212a1be88ac806c794a2a9c926c3fcc7330ddf8f30f3` |
| `O1C-0005` capsule manifest | `de67260cf44556a3fa48ef2b6daa1b738cf40b392739c6a05d835cbcdb1ab103` |
| `O1C-0004` capsule manifest | `ac3333606e0aaf47dc519553c0e9407fc8ab67dba5319ed340eac579cb25c7bf` |
| `O1C-0003` capsule manifest | `d7dcb2b2c3f39d866c7820dbc7423ce55b4d5c9df6634d5a00126a954a0a065d` |
| `O1C-0002` capsule manifest | `b4a242708ae30481deed5346df519bb5123c7601fa6c58b6c06bd514be314ff9` |
| `O1C-0001` capsule manifest | `376e3b27f107d132421e29c2669f468a57c8417924928ce41badadf14d3dd05f` |

## Resume here

Resume from [the ranked actions](research/NEXT_ACTIONS.md), the exact
[O1C-0065 matched width-6 result](research/O1C0065_APPLE8_WIDTH6_GROUPED_SIEVE_RESULT_20260719.json),
[O1C-0064 resource boundary](research/O1C0064_APPLE8_CROSSBLOCK_SIEVE_4K_RESOURCE_FIX_RESULT_20260719.json)
and the positive public
[APPLE-VIEW-0009 grouped bound](research/APPLE_VIEW_0009_EXACT_GROUPED_BOUND_RESULT_20260719.json).
APPLE-VIEW-0008 remains the first certified Full-256 branch removal: six safe
trail cuts at requested 512/billed 513 conflicts, no key or truth read. O1C-0062
exposed the callback lifecycle bug; O1C-0063 repaired it; O1C-0064 then proved
that the repaired 4K path reaches the guarded `992 MiB` threshold after
`29.804627625 s`. None of those operational failures is a science result or
retriable attempt. O1C-0065 has now integrated APPLE-VIEW-0009 exactly and
completed the sole matched 512-conflict test: its bound and live cache improve,
but cuts remain `6→6` and decisions/propagations are byte-for-byte equal. Do not
repeat that comparison or jump directly to 4K. Resume by implementing a bounded
causal no-good vault: canonical threshold-certified emitted clauses survive across
fresh short solver episodes, while each episode's CaDiCaL memory is destroyed.
Only after archive soundness, identity, deduplication and RSS-reset gates pass
should one frozen multi-episode Full-256 stream consume science work.
Do not enlarge the decoy panel or repeat O1C-0058's attended-base positive-delta
rule.

O1C-0055/0056 remain closed: exact clause membership and unique owner
localization do not rescue fixed negative conflict credit. A later causal
successor may condition the retained exact role on outcome or utility, but has
no efficacy claim yet.

APPLE-VIEW-0001..0004 are closed at their measured algebraic/local boundaries.
APPLE-VIEW-0005/0006 establish exact sparse certificates and held-out transfer
of their membership, but not better first-conflict scheduling. APPLE-VIEW-0007
closes its single static proof-edge successor at raw
`1,340 > 1,268 > 1,031`; certificate `1,003` cannot pass and loses unary `997`.
Do not refit unary or rescue the edge reader. Static/global relation and
negative action cycling, positive trail survival and fixed negative clause-role
credit are insufficient. Do not revisit owner localization.

The A325/A526 bit codec, search backends and public verifier remain ready for an
exact complement or bounded exact-containing beam. The relational branch need
not wait for that fixed-mask gate: score joint rank, effective residual width and
time-to-hit directly, while keeping the eight-bit oracle zone labelled as a
ceiling rather than recovered attacker information.

All writes remain in this lab. Every sibling repository remains read-only.
