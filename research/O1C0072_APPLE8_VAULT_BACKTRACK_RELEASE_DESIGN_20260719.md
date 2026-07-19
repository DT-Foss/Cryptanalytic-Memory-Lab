# O1C-0072 — APPLE8 vault backtrack-release reader

## Precommitted question

O1C-0071 proved that the frozen vault rank is an active control surface, but
its static `cb_decide()` policy rebuilt the last seven decisions after every
backtrack.  The exact extra-return counts `1/3/7/15/31/62/125` formed a
truncated binary-counter cascade: `763` decisions produced `91,260,183`
propagations and no novel clause or public model.

O1C-0072 changes one mechanism only:

> Does consuming every immutable rank row exactly once, and permanently
> releasing a guided literal after backtrack, remove that propagation furnace
> while preserving the useful first encounter with the O1C-0071 rank?

This is a new lineage attempt, not a retry or sweep of O1C-0071.

## Frozen science surface

- Parent result: O1C-0071, SHA-256
  `84ffbe35ae83266dd4993ad70b6dc988f4a13a8595861c23f36f0d610334cb41`.
- Parent capsule manifest: SHA-256
  `c7bbbd9d7ad0d37b80b956a3ad8141254a460ddf763ae84109a067e0343294d9`.
- Retained vault: `202` clauses, `599,728` literals, `2,399,911` bytes,
  SHA-256
  `cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858`.
- Same Full-256 APPLE8 CNF, potential, width-6 grouping, threshold
  `14.606178797892962`, seed `0`, requested `512`-conflict soft horizon,
  `45 s` process timeout and `512 MiB` RSS cap.
- Same immutable `255`-literal rank and signs; variable `241` remains the sole
  zero-delta omission.
- Rank order SHA-256
  `26c0063f4eed586ef67535cccabacc07d945587a603cbb56dbb3b2225a32a2f5`;
  rank-table SHA-256
  `d3a007ebee7c515289d33be30757f769b2c1fde618fb5c6c312ea9f3509380ae`.
- Zero phase calls, zero rank sweeps, zero horizon sweeps, zero truth-key reads,
  zero fresh targets, reveals, refits, MPS or GPU calls.

## Reader mechanism

The native reader owns a monotone rank cursor.  On every outer decision
callback it performs the following state transition:

1. Consume the next rank row before taking any action.
2. If its variable is already assigned, record
   `assigned-before-opportunity` and continue forward.
3. Otherwise return the frozen signed literal once.
4. Never decrement the cursor after backtrack.
5. After every row is consumed, return zero forever and delegate direction to
   native CDCL.

Consequently each ranked literal can be injected at most once.  A guided
literal removed by a real backtrack is recorded as released and can never be
reasserted by the reader.  The separate 540-byte release-policy specification
has SHA-256
`bfa752664e19d5899d114ee8cf75dd15a52a8306ff2399fde046a5bb6ebdc132`.

The bounded guidance state is a 32-bit cursor, three 256-bit rank-index masks,
and at most one signed 32-bit once-return plus one signed 32-bit release record
per candidate.  Its production bound is

`4 + 3 * 32 + 8 * 255 = 2,140 bytes`,

independent of callback count and stream length.

## Target-free falsification fixture

The public fixture ranks `[3, -1, -2, -6]`.  A four-clause CNF gadget makes
the `-2` subtree backtrack; a public unit assigns variable `6` before its rank
opportunity.  The required v11 behavior is therefore:

- once-return sequence `[3, -1, -2]`;
- cursor / consumed / returned / preassigned `4 / 4 / 3 / 1`;
- `-6` consumed without return;
- at least one real guided release, including `-2`;
- first zero fallback on callback `4`, followed only by zeros;
- zero redecisions and zero phase calls;
- base and outer callback counts identical while base nonzero returns remain
  zero.

The frozen v10 control must show the causal contrast by returning the prefix
`[3, -1, -2, -1]`, i.e. at least one repeated guided literal.

No production target, truth key or retained production vault is used by this
fixture.

## Precommitted classifications

One and only one local-`0`, lineage-`8` Full-256 call is authorized after all
target-free hashes, strict tests, clean commit binding and resource gates pass.

Classification priority is:

1. `PUBLIC_EXACT_RECOVERY` only for a publicly verified 8/8-block model.
2. `EPISODIC_VAULT_ACTIVE_BACKTRACK_RELEASE_NOVEL_CLAUSE_GAIN` for at least
   one novel exact threshold-relative no-good.
3. `EPISODIC_VAULT_BACKTRACK_RELEASE_MECHANISM_WORK_GAIN_NO_RECOVERY` only
   with a valid reader, zero redecisions and at most `45,630,091`
   propagations at the same requested horizon.  This is a furnace-removal
   mechanism result, not recovery, key entropy or a search-frontier claim.
4. Otherwise no gain or the exact bounded operational/capacity/status-20
   terminal classification.

No retry, replacement ordinal or second release-reader call is authorized.

## Formal threshold / minimum-upper-bound clarification

Let `S(k)` be the compiled joint score of a full key `k`, and let the retained
region be

`R_tau = { k : S(k) >= tau }`, with `tau = 14.606178797892962`.

For a visited partial solver trail `a`, let `C(a)` be its compatible full-key
completions.  The width-6 grouped calculation supplies a conservative bound

`U(a) >= max { S(k) : k in C(a) }`.

The threshold and upper bound therefore use the same score metric and the same
retained direction.  Strict inequality gives the local proof

`U(a) < tau  =>  for every k in C(a), S(k) < tau`

and hence `C(a) intersect R_tau` is empty.  Negating trail `a` is therefore a
safe threshold-relative prune for that trail.

They do **not** have the same population or statistic.  The often-cited
`7.973483108047071` is
`min { U(a) : a visited in O1C-0066 episode 1 }`; it belongs to O1C-0066, not
O1C-0068.  O1C-0066 episode 1 recorded seven trail-threshold prunes.  O1C-0068
instead reported minimum upper bound `12.8607806294803`.

A minimum below threshold is existential: it proves that at least one visited
trail is prunable, not that every live branch or the root is prunable.  The
shared root upper bound is `262.68644197084643 > tau`, and there is no exhaustive
frontier certificate.  Thus `7.973... < 14.606...` is already a safe **local**
prune witness, but it is not a global prune, UNSAT proof or threshold-region
exhaustion result.

This clarification changes no O1C-0068 file or artifact.

## Freeze boundary

Before science, the final source/config/design hashes, two independent native
builds, deterministic native and adapter fixture repeats, public fixture
binding and target-free preflight are sealed in a clean commit.  A call intent
is durably persisted before entering native; after that point ordinal `8` is
consumed on success, timeout, invalid output or resource failure.  Publication
recovery may issue zero native calls only and must revalidate the frozen
preflight plus every persisted sidecar.

The target-free seal is complete with zero production/science calls:

- native-v11 canonical payload: `18464` bytes,
  `3c02e78826e66c9751a46fd0a5bd8833ab57686d279d725fdcfbb4550772fc57`
  across three runs and two independent public-fixture builds;
- normalized v14 adapter projection: `20239` bytes,
  `58ba011e53a285a4af8618e7a3dc39ca60dce6e32376f812b9952a9984e03720`
  across three actual native-payload parses;
- production build basename `native-joint-score-sieve`: two byte-identical
  rebuilds at
  `180be51b9108bab7a15fb23aa25eec012e11c8df9cef182025b8afed116e959e`;
- fixture release sequence `[-2, 3, -1]`, `759` callbacks, three nonzero
  one-shot returns, `756` permanent zero fallbacks and zero redecisions;
- v10 control: literal `-1` is redecided once.

Direct resume point: freeze this source tree in a clean commit, run the
commit-bound resource preflight, and only then execute the sole authorized
O1C-0072 call.
