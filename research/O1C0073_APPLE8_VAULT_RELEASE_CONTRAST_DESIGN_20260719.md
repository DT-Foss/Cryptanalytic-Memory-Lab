# O1C-0073 — APPLE8 vault release-contrast reader

## Precommitted question

O1C-0072 consumed the immutable 255-row vault rank exactly once and permanently
released every guided original literal after backtrack.  It removed the
O1C-0071 callback cascade, but produced no public model and no novel exact
threshold-relative clause.

O1C-0073 changes one mechanism only:

> After the O1C-0072 original rank is exhausted, does returning the hard
> complement of each genuinely released original literal exactly once expose
> a different useful branch at the same frozen APPLE8 inputs and horizon?

This is a new lineage attempt, not a retry, replay, phase variant, rank variant,
or horizon sweep.

## Frozen science surface

- Direct parent: O1C-0072 authoritative result, SHA-256
  `e441a32de808ee33e2245ea69af4e6ad6f246311e5a410b0cbab4a63dbd165d8`.
- Parent capsule manifest, SHA-256
  `83bbc2438fc33e3a61fdf5b23b589574c6a12cfaefd9fc2f0e7c4c4e84b521f8`.
- Parent source commit:
  `bf1ffaad30ac276c2fcc3b332207c5933bf96443`.
- Retained vault: `202` clauses, `599,728` literals, `2,399,911` bytes,
  SHA-256
  `cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858`.
- Same Full-256 APPLE8 CNF, potential, width-6 grouping, threshold
  `14.606178797892962`, seed `0`, requested `512`-conflict soft horizon,
  `45 s` process timeout, and `512 MiB` RSS cap.
- Same immutable 255-literal rank and signs; variable `241` remains the sole
  zero-delta omission.
- Rank-order SHA-256
  `26c0063f4eed586ef67535cccabacc07d945587a603cbb56dbb3b2225a32a2f5`;
  rank-table SHA-256
  `d3a007ebee7c515289d33be30757f769b2c1fde618fb5c6c312ea9f3509380ae`.
- Zero phase calls, rank sweeps, horizon sweeps, truth-key reads, fresh targets,
  scientific entropy calls, reveal calls, refits, MPS calls, and GPU calls.

## Two-stage reader mechanism

The native-v12 reader preserves O1C-0072's original stage exactly:

1. Scan the immutable rank with a monotone cursor.
2. Consume an assigned original row before its opportunity.
3. Otherwise return its frozen signed original literal once.
4. Never unconsume or reassert that original after backtrack.
5. Record only a real release of a previously returned original literal as
   eligible contrast evidence.

The contrast stage is closed until the original cursor reaches row `255`.
After original-rank exhaustion:

1. Visit genuinely released originals in their deterministic release queue.
2. For released original `l`, define the hard contrast literal as exactly
   `-l`.
3. If `abs(l)` is assigned during a bounded queue scan, skip it for that
   callback but retain its contrast opportunity in the queue.
4. Otherwise return `-l` once.
5. Never return the same-sign original again and never return a contrast twice.
6. Return zero whenever no currently unassigned queued contrast is eligible;
   assigned opportunities may remain queued at the terminal soft horizon.

At most `255` original decisions and at most `255` complement decisions are
possible.  There is no callback-length-dependent decision stream and no phase
API call.  The trace must independently bind original returns, original
releases, contrast enqueue events, contrast returns, contrast releases,
pair records, rank-index bitsets, bounded nonzero events, and the incremental
hash of the full callback stream.

## Exactly-one lifecycle

Exactly one fresh local-`0`, lineage-`9` production call may eventually be
authorized.  O1C-0072 consumed nine lineage calls through ordinal `8`; its
known completed billed-conflict total is `4,104`.  Failed ordinal `2` remains
historical and is neither replayed nor assigned a replacement.

The runner durably writes invocation and intent journals before entering the
adapter.  Crossing the intent boundary consumes ordinal `9` on success,
timeout, resource failure, adapter rejection, malformed native output, or any
other post-intent terminal.  No retry is authorized.

Publication uses a draft-to-final protocol.  A completed draft capsule may be
recovered with zero new native calls only after revalidating the frozen config,
commit-bound preflight, deterministic build identity, invocation, intent,
native result, telemetry, vault sidecars, terminal classification, and every
journaled hash.  The capsule `result.json` and authoritative research result
must be byte-identical canonical JSON before the capsule is accepted as
immutable.

## Target-free gates

No production/science call is authorized while any required gate remains
`PENDING`.  Final authorization requires all of the following:

- final native-v12 and adapter-v15 source hashes;
- the release-contrast policy and reader binding hashes;
- a strict public fixture proving original-rank exhaustion precedes every
  contrast return;
- proof that each contrast is `-l` for one genuinely released original `l`;
- proof that assigned contrasts are deferred without return and remain bounded;
- proof of at most one original and at most one complement per rank variable;
- zero same-signed redecisions and zero phase calls;
- deterministic native repeats from independent builds;
- deterministic adapter repeats over actual native payloads;
- source-hash and deterministic executable identity gates, using the fixed
  production basename `native-joint-score-sieve`;
- the one-call/no-retry/no-replay/no-sweep protocol gate; and
- commit-bound resource checks for free memory, free disk, normalized load,
  conflicting science processes, timeout, RSS, and persistent artifact caps.

The current config intentionally uses `PENDING` only for not-yet-frozen
native-v12/adapter-v15 outputs, the still-editable runner/design, and the
target-free artifacts derived from them.
No result, capsule, or target-free preflight is created by this design step.

The authoritative threshold-12 v12 public gadget already fixes the causal fixture expectation:
original returns `[3, -1, -2]`; real original releases `[-2, 3, -1]` after
callback `254`; the first eligible hard contrast is `+1` at callback `255`
because the earlier `+2` and `-3` candidates are then assigned and deferred.
The complete fixture has `507` callbacks, one contrast return, `503` zero
returns, queue size `2`, maximum queue size `3`, and `706` bounded guidance
bytes.  It records exactly two assigned-contrast deferrals and binds their
retained rank indices `{0, 2}` in the dedicated 256-bit state
(`05` followed by 31 zero bytes), with SHA-256
`aae761377f3b4f1f07d982783b902314b61a9cbe6ccfdfa96559039f07e332ed`.
The seven bounded bitsets increase bounded telemetry to `33,490` bytes without
changing the `706`-byte live guidance bound.  Its signed order hash is
`74304fb799ce8ce1d8e355bb244b4c18fadec0722a4b0c4e36fcafbf69377f30`,
raw fixture rank-table hash is
`ad0656f1968a47f2cb4eb9229a8ee034bf5690b7f93224f2d19e4ef57678e6e6`,
and actual-callback hash is
`142448052b524afe08a51ac6ccc0b6053ecd3ab64c593bdfbf22e41175731315`.
The contrast is also genuinely released.  The canonical native payload with
runtime resources removed is `16,356` bytes,
SHA-256
`e856105aab55758924f9cdd22c9e1607b9e0f79a67f438061f6ba9c9d7bde961`.
Adapter-v15 must validate these facts from the actual native payload before its
own deterministic hashes can replace the remaining `PENDING` gates.
The threshold-50 gadget remains an optional independent native unit fixture and
is not the authoritative target-free gate.

## Precommitted classifications

Classification priority is:

1. `PUBLIC_EXACT_RECOVERY` only for a publicly verified 8/8-block model.
2. `EPISODIC_VAULT_THRESHOLD_REGION_EXHAUSTED` only for native status `20`,
   the explicit precommitted frontier improvement proving exhaustion of the
   frozen score-greater-than-or-equal-threshold region.
3. `EPISODIC_VAULT_ACTIVE_RELEASE_CONTRAST_NOVEL_EXCLUSION_GAIN` only when at
   least one novel exact threshold-relative no-good clause or exclusion is
   independently reconstructed and added.
4. Otherwise `EPISODIC_VAULT_ACTIVE_RELEASE_CONTRAST_NO_GAIN`, or the exact
   bounded capacity, operational, or invalid-result terminal classification.

A complete 255-pair contrast, fewer decisions, fewer propagations, lower wall
time, or any other work reduction is diagnostic mechanism evidence only.  None
of those measurements is cryptanalytic gain.  A minimum visited upper bound is
also not accepted as an exhaustive frontier certificate.

## Formal threshold / upper-bound clarification

Let `S(k)` be the compiled joint score of a full key `k`, and retain

`R_tau = { k : S(k) >= tau }`, where `tau = 14.606178797892962`.

For a visited partial solver trail `a`, let `C(a)` be its compatible full-key
completions.  The width-6 grouped calculation supplies a conservative bound

`U(a) >= max { S(k) : k in C(a) }`.

The threshold and upper bound therefore use the same score and retained
direction, but different populations and statistics.  Strict inequality gives
the safe local implication

`U(a) < tau  =>  C(a) intersect R_tau is empty`.

This justifies negating that visited trail.  It does not justify pruning every
live branch or the root.

The value `7.973483108047071` is the minimum visited upper bound from O1C-0066
episode 1, not O1C-0068.  O1C-0068's minimum upper bound is
`12.8607806294803`.  Both are below `tau`, so each can be a safe local prune
witness in its own visited-trail population.  Neither is a global exhaustion
certificate.  The shared root upper bound is
`262.68644197084643 > tau`, which prevents a global root prune absent an
exhaustive frontier proof.

This clarification changes no O1C-0068 or sibling file.

## Freeze boundary

The runner, config, design, native-v12 source, adapter-v15 source, strict
fixture, repeat artifacts, executable hash, and final target-free preflight
must be sealed in a clean commit before science.  The present task stops at the
draft runner/config/design and focused software validation.  It issues zero
production calls and creates no science result, run capsule, or target-free
preflight.
