# O1C-0079 — APPLE8 central decision ownership

- **Status:** zero-call design; no O1C-0079 science call has been issued.
- **Predecessor:** O1C-0078
  `RESCUE_PREFIX_PREEMPTION_OPERATIONAL_TERMINAL`.
- **Attacker surface:** unchanged public APPLE8 Full-256 CNF, public score
  potential/grouping, public threshold, sealed causal attic, and no key/truth
  input.
- **Scientific intervention:** unchanged sealed 11-row rescue prefix.
- **Operational intervention:** replace nested proposal-history inference with
  one typed decision-instance owner.
- **Fresh successor:** Page 6, lineage ordinal 19, derived without an O1C-0078
  native output or new evidence chunk.

## Why this successor exists

O1C-0078 consumed its sole fresh Page-5/lineage-18 call and returned no native
result. The exact v11 throw proves only this state:

```text
one rank row was proposed earlier and remained unreleased
+ the assignment now disappearing on that variable had the opposite sign
```

The throw path also proves that all 11 outer prefix rows were consumed before
the inherited parent was reached. Empty native stdout leaves the responsible
row, callback, counter-assignment origin, prefix activation, trace, bounds,
prunes, clauses and model unobserved.

The strongest code-path inference is a lifecycle alias. CaDiCaL assignment
notifications are not necessarily eager. A decision can therefore be proposed,
bound to a real solver decision level and backtracked before its assignment is
ever mirrored into a reader's shadow assignment. The old reader retains only a
`returned-ever` bit. A later opposite assignment to the same variable can then
be mistaken for the old proposal's release.

O1C-0079 tests that exact missing composition primitive. It does not change the
scientific prefix to fit the failure.

## Frozen predecessor boundary

The following inputs are consumed and immutable:

- O1C-0078 authoritative result SHA-256
  `f72821443ed7e7dd80698a39288ff31f9c8f52a120bb745e713e3b23b1822fed`;
- capsule artifact-manifest SHA-256
  `5d358863162a64f27d215fc4b91258c73194d2458f89d9dd7495bb1e05e50a69`;
- invocation SHA-256
  `06d74e30bcefeb97bbf631c4631353375022198dac615ae02fa69b0033f9e588`;
- persisted intent SHA-256
  `50a29a3f1d5882b15981acd962c91c1efb9ab2ab90209f13f1b400860bc60853`;
- incomplete episode SHA-256
  `8607130a7fc0389c21175a5a81da0de2c3327877fa8dfc7c7e10cf3166302446`;
- terminal-failure receipt SHA-256
  `a84fbdf7eeea4b5195a187eb357c711ab5a6a399bf24bd14a19214c1742574bc`;
- O1C-0078 prepared-manifest SHA-256
  `ee1a2144b2eb30ac3f69012f4e5085de1c6f668625f85b31e73c0aa188cfd30d`;
- consumed Page-5 SHA-256
  `07c73013705898e228a05b0578b0f8090a6f094c427dbd8f32d856467b08e208`;
- consumed lineage ordinal `18`, one issued native call, `128` requested
  conflicts, unknown actual/billed conflicts, no retry and no native result.

Page 5 and lineage 18 must never be replayed. No clause, occurrence, assignment,
bound, trace or residency may be invented from the missing O1C-0078 output.

## Central reader architecture

Frozen native v11 through v16 remain unchanged and are not instantiated as
runtime reader objects. The O1C-0079 native surface uses the unchanged v6 score
sieve as its solver core and composes the five decision origins centrally:

1. `PREFIX`;
2. `RANK_ORIGINAL`;
3. `RANK_CONTRAST`;
4. `FRONTIER_INITIAL`;
5. `FRONTIER_CONTRAST`.

Residual-polarity staging remains an immutable transformation of the rank
literals before the central scheduler is constructed. It is not a second
assignment owner.

At most one final outer decision is returned per callback. That return creates
one typed token:

```text
DecisionToken(
    instance_id,
    origin,
    row_index,
    signed_literal,
    proposal_callback,
    state,
    decision_level?,
    assignment_confirmed
)
```

The bounded lifecycle is:

```text
NONE
  -> PROPOSED
  -> LEVEL_BOUND
  -> CONFIRMED_ACTIVE       optional evidence
  -> RELEASED               confirmed release
     | UNOBSERVED_RELEASED  level-bound but notification was non-eager
```

Rules:

1. `cb_decide()` creates only `PROPOSED`. Proposal count is telemetry, not
   activation and not assignment ownership.
2. The immediately following `notify_new_decision_level()` binds that proposal
   to the new solver level. This creates the decision-instance ownership
   authority.
3. A same-sign decision assignment notification may confirm the token. It is
   useful evidence but is not required for ownership because notifications may
   be non-eager.
4. A backtrack below the bound level atomically retires that exact token. A
   confirmed token becomes `RELEASED`; an unconfirmed token becomes
   `UNOBSERVED_RELEASED`. Neither remains pending.
5. A later assignment of the same variable, including the opposite sign, is
   foreign unless it has its own token. It cannot release or mutate the old
   instance.
6. Original-to-contrast and frontier-initial-to-contrast eligibility is created
   only by release of the corresponding owned token. Variable identity or a
   historical returned bit is insufficient.
7. Duplicate binding, binding without a proposal, opposite-sign confirmation,
   release of an unbound proposal, second ownership of one live level, and
   telemetry overflow fail closed before science interpretation.
8. A second proposal, backtrack or snapshot while a proposal is still awaiting
   its immediate level binding fails before mutation. Mixed backtracks retire
   tokens in solver-stack order: deepest level first and newest observed trail
   entry first within one level.
9. Solve finalization serializes every live/terminal token and rejects any
   unaccounted level-bound owner.

## Mandatory zero-science reproducer

The pure lifecycle fixture must reproduce the old failure without a solver:

```text
propose PREFIX/+130
bind it to level 1
omit the +130 assignment notification
backtrack to level 0
later observe and remove foreign -130
propose RANK_ORIGINAL/+130
bind and confirm +130
backtrack to level 0
```

Required outcome:

- no sign exception;
- exactly one `PREFIX/+130` unobserved owned release;
- the later `-130` assignment is classified foreign and releases nothing;
- exactly one confirmed `RANK_ORIGINAL/+130` release;
- no token remains live;
- deterministic byte-identical telemetry and digest.

The frozen Python reference fixture serializes to `5157` bytes with SHA-256
`ba32ace4d839bf00daa35250dcc97ae9098a5dc5a1e1eaedbc54efdb99a118f9`.
Its `591`-byte typed event trace has SHA-256
`de1396b25195a345dc7e9c7f3ffb35ab102a25ba514c9dd9e08cfdde9af94bc3`.
The focused suite contains ten tests, including an orphan-proposal failure and
a mixed deep-unobserved/shallow-observed unwind-order regression.

A public CaDiCaL-3.0.0 fixture must then place variable 130 in prefix, rank and
frontier populations, force at least one real backtrack and a later opposite
assignment, and verify the same ownership totals. The fixture must not use the
O1C-0078 target, Page 5 or a production science call.

## Fresh Page 6 without fabricated evidence

Reconstruct the exact O1C-0078 Page-5 state from the sealed capsule once. Verify
the terminal receipt and then call only:

```text
reproject_causal_residency(
    same_attic,
    previous_state=page5_state,
    fully_emitted_union_indices=(),
    next_lineage_ordinal=19,
)
```

Do not call `advance_causal_residency`: an extra empty chunk would falsely
represent native evidence.

The deterministic zero-call Page-6 projection is frozen as:

- active vault SHA-256
  `69bde6adc23e9e89f97581175ecb85dc9f1d94cddc6d162dfb2f93f9d60f3846`;
- `256` clauses, `723,864` literals, `2,896,671` serialized bytes;
- selection-order SHA-256
  `f257f2e3c7b236434121f4f5157f0dbd21242687c0cce62868648abc5c0e4a6a`;
- state-document SHA-256
  `71d22c10280e4afcb51a9739d58aa8d9839bc4512cbbc6a5d98bcb5a902f0caf`;
- activation-ledger SHA-256
  `2e1f346a627cd3bdace0c4171436b047af530ea4359293c51e2de4de5a5d3323`;
- unchanged attic-union SHA-256
  `e99682c4d0c1cfb53a2b51284d810e5a0a07dd7023672549b8435a920d688307`;
- lineage ordinal `19`, empty fully-emitted-index set and zero native calls.

The gate must retain the complete eight-SHA science-input history before Page 6
and prove that Page 6 is absent from it. Preparation must be deterministic,
atomic, symlink-safe, extra-file rejecting and byte-identical across two
independent zero-call builds.

## Unchanged scientific intervention

The prefix remains exactly:

```text
130 -131 31874 63746 190565 190566 190569
191212 191213 191216 191234
```

Its signed-i32le SHA-256 remains
`b5debc5f55f7cbc1e728d00ce1d14d0c437249793f8c10e8b80e614a00ed155c`.
Rank source, frontier plan, staging overlays, public score threshold, seed,
conflict horizon, K, memory envelope and timeout remain unchanged. This is an
operational ownership repair, not a scientific parameter refit.

## Precommitted activation and science gates

The central ownership mechanism passes its activation gate only if:

- the synthetic lifecycle and public CaDiCaL alias fixtures pass exactly;
- every nonzero outer decision has one unique origin and decision instance;
- all level-bound decisions are released or remain correctly live at solve end;
- zero foreign/opposite assignments are claimed by a stale token;
- bounded telemetry validates and the old returned-ever sign assertion is
  absent from the runtime object graph.

Qualified prefix preemption on the fresh production call requires:

- all 11 prefix rows consumed before the first non-prefix decision;
- zero preassigned-rescue skips;
- at least one prefix proposal bound to a real decision level;
- every bound prefix token retired consistently;
- a native result returned and a trace distinct from O1C-0077.

Proposal count alone cannot satisfy activation. Assignment confirmation is not
mandatory because a level-bound decision may be released before notification.

Science gain then requires at least one attacker-valid frontier result:

- a safe local threshold prune;
- a globally novel exact threshold no-good;
- a certified frontier contraction/formal exhaustion result;
- a public complete model/key that passes exact ChaCha verification; or
- another predeclared sub-256 search/rank/entropy improvement measured from the
  returned native payload.

Trace change, fewer decisions, a lower minimum UB above threshold, or successful
ownership accounting alone is mechanism evidence, not cryptanalytic gain.

## Threshold boundary retained

The retained region remains `S(k)>=tau` with
`tau=14.606178797892962`. For any visited trail `a`, admissibility gives
`S(k)<=U(a)` for every completion. Only strict `U(a)<tau` safely prunes that
trail's descendants. The historical `7.973483108047071` is O1C-0066 episode
1's minimum over visited trails, not a global bound and not O1C-0068. O1C-0068
remains untouched at `12.8607806294803`. O1C-0078 returned no bound telemetry.

## One-call contract

No O1C-0079 science call is authorized until all of the following are frozen:

- central reader source and adapter;
- pure and CaDiCaL ownership fixtures;
- zero-call Page-6 seed and prepared manifest;
- native executable rebuilt twice byte-identically;
- config, exact source/executable digests and target-free gate;
- a clean source commit containing those exact bytes.

After that freeze, issue exactly one fresh local-0/lineage-19 call with Page 6,
`128` requested conflicts, the existing `512 MiB` episode envelope, `45 s`
timeout, seed 0, no retry and no sweep. If the call fails operationally, burn
Page 6 and lineage 19 and preserve the exact terminal receipt. Never report
requested conflicts as actual or billed work without a returned native ledger.

## Resource and project boundary

- Work only in `o1-cryptanalytic-memory-lab`.
- O1C-0068 and sibling projects remain untouched.
- No truth-key bytes, reveal, fresh target, refit, rank/K/phase/horizon/seed/
  threshold/RAM sweep, MPS or GPU work is permitted.
- Preparation and equivalence recovery should run in separate short processes;
  holding both reconstructed large states in one process can create avoidable
  memory pressure.
- Before the single production call, verify no sibling solver process is live
  and the memory envelope has adequate headroom.

## Required artifacts

Before execution, O1C-0079 must have:

- zero-call seed manifest;
- ownership fixture report;
- Page-6 state and activation ledger;
- exact source and executable hashes;
- target-free preflight JSON;
- frozen config and clean source commit.

After execution, it must add one immutable timestamped capsule, authoritative
result, interpretation and the normal status/index/attempt/breadcrumb/hypothesis
updates. The direct resume point must distinguish operational ownership success,
qualified prefix activation and scientific gain.
