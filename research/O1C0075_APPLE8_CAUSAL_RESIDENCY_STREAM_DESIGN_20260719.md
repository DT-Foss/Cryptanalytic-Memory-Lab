# O1C-0075 — APPLE8 causal-residency stream design

Date: 2026-07-19  
Status: zero-call preparation complete; science remains a separate, bounded
runner action

## Decision

O1C-0075 replaces repeated use of O1C-0074's terminal K=256 projection with a
target-free residency pager over the complete immutable causal attic. The
purpose is narrow: make every undominated inherited exclusion solver-resident
at least once without increasing K, changing the rank source, or discarding
any evidence.

The attempt is frozen to at most two fresh calls:

| Local call | Lineage ordinal | Requested conflicts | Input page |
|---:|---:|---:|---|
| 0 | 14 | 128 | Page 1 prepared here |
| 1 | 15 | 128 | deterministic post-call Page 2 |

The runner must stop after the second call. There is no retry, horizon sweep,
K sweep, reader sweep, rank sweep, or resource sweep.

## Sealed parent

The preparation accepts only the manifested O1C-0074 capsule and verifies the
entire 54-file regular-file inventory before replay. Symlinks, special files,
missing files, extra files, and any digest difference are rejected. Private
O1C-0074 recovery helpers are used only after their source file is pinned to
SHA-256
`24d7c30ae69059b006127ec2eccee131615d42bbc8fd7ac40f76a78e879f3ecc`.

The parent bindings are:

- result SHA-256:
  `b6bc2895459e3256fa4c857b67bd786b36d80ab5018a9c73709a2096cd169127`;
- capsule manifest SHA-256:
  `7a3f272268296005c5c6e532d377eb100244f38e941a102876abbfd732a8049b`;
- immutable rank-source vault SHA-256:
  `cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858`;
- terminal parent active SHA-256:
  `78696f2b662beda4b371aa547350cc66b2105bc4dcaf0b982af2d1279e3012ed`.

Replay preserves the exact six-chunk topology, including empty rollover
boundaries:

| Chunk | Clauses | Meaning |
|---:|---:|---|
| 0 | 202 | immutable rank source |
| 1 | 311 | O1C-0073 rollover |
| 2 | 0 | O1C-0074 lineage 10 rollover boundary |
| 3 | 37 | O1C-0074 lineage 11 rollover |
| 4 | 0 | O1C-0074 lineage 12 rollover boundary |
| 5 | 0 | O1C-0074 lineage 13 rollover boundary |

The reconstructed attic contains 550 unique clauses, 558 fully emitted witness
occurrences, eight duplicate occurrences, eight strict subsumption relations,
and 545 undominated clauses. Its clause aggregate SHA-256 is
`840cc5cecdfe998fe1b0b2d4b7c4dbc3ee554112fc9ec550b0720c765f9c1911`.
All chunks, occurrences, duplicates, and relations remain evidence even when a
clause is inactive or strictly dominated.

## Separation of roles

Three identities must not be conflated:

1. `chunk-00.vault` is the immutable rank source.
2. The six chunks plus occurrence and relation ledgers are the immutable attic.
3. A residency page is an encoding-only solver input and is not a cumulative
   vault-v1 archive.

The residency description therefore uses
`o1-score-threshold-residency-projection-v1`; it does not reuse the causal
attic module's older hard-coded active-projection description.

No target, truth key, reveal output, outcome label, scientific entropy,
refitted parameter, MPS object, or GPU result is an input to selection.

## Initial pinned causal core

The attempt-scoped core C46 is frozen before science as the union of:

- strict subsumption roots `{9, 123, 144}`; and
- every unique union clause with a fully emitted O1C-0074 event:
  `202..207` and `513..549`.

All 46 remain pinned on both O1C-0075 science pages. This is stronger than the
generic later-generation rule, where the three structural roots are the
permanent subset and fresh events receive bounded hot attention.

## Page 1

The O1C-0074 terminal active page is first recorded as inherited residency at
lineage 13. Its 256 clauses are treated as already resident. The other 289
undominated clauses are inherited residency debt.

Page 1 contains C46, then 210 debt clauses ordered by:

1. occurrence count descending;
2. literal count ascending;
3. clause SHA-256 ascending;
4. union index ascending.

The chosen population is deduplicated and serialized in ascending union order.
The result is:

- 256 clauses;
- 703,070 literals;
- 2,813,495 bytes;
- clause aggregate SHA-256
  `83fc23233b6e63b5755bda4a3354d10602d2440db3f3c7b16f2b3b4dde6910e7`;
- vault SHA-256
  `82b1512a393f9d595a1207253e2b623ee8ece9bd2f5b92f8283857c3dd9b2911`;
- overlap with the parent final page: 46;
- parent/Page-1 joint undominated coverage: 466/545;
- remaining inherited debt: 79.

## Post-call projection policy

After a complete call, the new immutable chunk and every fully emitted
occurrence are appended to the attic in memory and validated before a next
page may be published. Selection priority is:

1. current structural roots;
2. the remaining attempt-pinned C46 members;
3. all never-resident undominated debt inherited from the O1C-0074 terminal
   attic;
4. globally new never-resident undominated debt;
5. newest fully emitted event clauses as bounded hot attention, with exact
   duplicates collapsed to their latest occurrence;
6. remaining undominated clauses by activation count ascending, oldest
   last-active lineage ascending, occurrence count descending, literal count
   ascending, clause SHA-256 ascending, and union index ascending.

Priority order is not byte order. The selected set is always deduplicated and
serialized in global attic-union order.

If inherited debt, new debt, or hot events exceed the remaining capacity, the
same deterministic ranking truncates the active population and the omitted
clauses remain in the attic. If mandatory roots plus the pinned core exceed K,
the transition fails closed; it does not silently violate the core guarantee.
New clauses and newly discovered subsumption relations are recomputed over the
whole union. A new undominated subsumer is promoted as a structural root, while
the subsumed clause remains evidence.

Every candidate page is compared with all active SHA-256 identities recorded
by the residency state. A collision is resolved by the first deterministic
lowest-priority tail exchange that preserves mandatory core and inherited-debt
obligations. If no fresh encoding exists, no science input is authorized. The
runner additionally carries all earlier O1C-0074 science-input identities, so
the attempt cannot reuse a page predating the terminal parent page.

## Compact activation ledger and replay

Each ledger row binds:

- lineage ordinal;
- role (`inherited-parent-final` or `causal-residency-page`);
- active vault SHA-256;
- selected union indices and their canonical index-list digest.

Replay reconstructs every vault from the immutable union, rejects a repeated
SHA, and recomputes activation counts and last-active lineages. The full
residency description also binds the pinned core, frozen inherited debt,
current projection categories, and current page. `replay_causal_residency`
requires its rebuilt description to equal the canonical input document.

An attic transition must be append-only: identity, observed scope, chunk
prefix, occurrence prefix, and union-clause prefix must all match. Any rewrite
fails before residency selection.

## Zero-event Page 2 fixture

If lineage 14 emits no event, Page 2 is completely predetermined:

- C46;
- all remaining 79 inherited-debt clauses;
- the first 131 clauses from parent-final-active minus C46 under the same
  occurrence/length/SHA/index order.

The fixture has:

- 256 clauses;
- 684,922 literals;
- 2,740,903 bytes;
- clause aggregate SHA-256
  `d1a0f2a4d9730f4174d412cf1946ead73b3e6bb06d2cccf4bcea9f4319995085`;
- vault SHA-256
  `db3acd5e6b7eb27529fd141a99865623530258f3aa2f7db6e84f03f16ecf4f0f`;
- Page-1 overlap: 46;
- parent-final overlap: 177;
- parent/Page-1/Page-2 undominated coverage: 545/545;
- remaining inherited debt: zero.

The generic policy may add lineage-14 new debt or hot event clauses after the
frozen inherited 79, subject to remaining capacity. It may not displace those
79 with a recycled clause.

## Later-only signed-set breadcrumb

The following analysis is persisted now so a later attempt does not have to
rediscover it. It is explicitly excluded from O1C-0075 selection, ranking,
reader decisions, stopping, and result classification.

For clauses represented as signed-literal sets, distance is the cardinality of
their symmetric difference. Each clause chooses its nearest other clause by
distance, clause SHA-256, then union index. A pair is retained once when the
directed choices are reciprocal.

This gives:

- 223 reciprocal pairs covering 446/550 clauses;
- distance minimum/median/maximum 2/16/44;
- 219 pairs with distance at most 32;
- exactly one distance-2 pair: union indices 109/110.

Among these are 93 clean key-side flips: the key-variable part of the signed
difference is exactly `{-v,+v}`. They span
`{32,59,73,106,115,133,193,201,210,244,246,249,251,255}`.

For each pair, the higher first-occurrence witness upper bound U supplies a
soft local orientation: prefer the pruned-trail assignment equal to the
negation of that clause's key literal. Thirteen variables are unanimous under
this rule; variable 251 is mixed. This is a soft empirical orientation only.
Witness U certifies the clauses but does not turn orientation into an exact
key-bit claim.

The published canonical breadcrumb documents are:

| Artifact | Bytes | Published SHA-256 |
|---|---:|---|
| reciprocal nearest pairs | 69,512 | `aee463bf40cc116163f2eb3a4621876573418fe5edd15e2f9f5e5ca60cca56f0` |
| clean key flips | 38,200 | `a6727c59b9d89cf33f7e0a08a60e9d6a32b293198773f6fca56d0f790eef65a9` |
| witness-oriented pairs | 67,261 | `d5e50da60b75b3d9f4d85cbc7a7f3f29e985c41b942fcc6657e5f931f855d9c9` |
| 14-row orientation summary | 2,302 | `17df7e8bdfde2a5b005c4a19b8073e8412dd7b764682a6e982e1b8488b9c624e` |

An analyst previously reported different JSON byte lengths and hashes
(`56,497/93a74f...`, `29,604/63da89...`, `45,277/b25730...`, and
`2,052/85e2f9...`) without preserving the generating field layout. Those byte
identities are therefore references, not reproducible serialization
contracts. The versioned documents above freeze the same numeric and semantic
invariants under an explicit canonical schema. This distinction is recorded
in the preparation manifest. Binary vault identities below are fully
encoding-defined and do match their references.

## Exact resolution breadcrumb

Clauses 109 and 110 have SHA-256 values
`85cc003852858447eac3630235b1e56e7612d5042abd5d8b33e328a0f0e0171d`
and
`35058f118d9da7673eea00a28324d8154fceac8bde8695ddde709654b2c3f864`.
Their first-occurrence witness U values are respectively
`14.044979902836593` and `14.293096759046755`. Their signed difference is
exactly `{-201,+201}`. Resolution on variable 201 therefore yields an exact,
non-tautological 2,972-literal clause with SHA-256
`c26dd0bdc72e3087aef76c6075cd0e201ec1141245fc30b87d0bd615f60a6839`.

The one-clause vault is 12,083 bytes with SHA-256
`a7d73d9fbc6ad9f5a98937792d84425a3398b4a6fe2e9a47243fa7b9df5f9766`.

Resolving all 93 clean key-flip pairs produces ten non-tautological exact
resolvents; the other 83 are tautological. The ten source pairs are:

`105/106, 109/110, 135/136, 137/138, 147/148, 158/159, 160/161,
162/163, 164/165, 178/179`.

Nine use pivot 73 and contain 2,970 literals; 109/110 uses pivot 201 and
contains 2,972. The ten-clause vault contains 29,702 literals, is 119,039
bytes, has clause aggregate SHA-256
`363c171f7d769cb0802cc6ce40a6ebc9e5da347b12d0facca9ad7da3ad9b19b5`,
and vault SHA-256
`01811dd834b6ec4fc4dd65a8c94e65fb985320a6c4af34cd43c0e67f8564b8b6`.

These clauses are exact logical consequences of certified exclusions. They
are not native O1C-0075 emissions, are not admitted to the O1C-0075 attic or
active pages, and cannot be claimed as empirical cryptanalytic gain in this
attempt.

## Prepared artifact set

The zero-call seed is
`research/o1c75_causal_residency_seed_20260719/`. Its manifest SHA-256 is
`342e31fbf3112c5469e460ceb0c0d549428ad498c20a3ff063401bab95b2ce33`.
It contains 21 manifested artifacts plus the manifest itself:

The runtime loader requires this exact 22-entry regular-file inventory and
rejects every missing, additional, symlinked, or non-regular entry before
reconstructing residency state.

- six immutable parent chunks;
- parent-final, Page-1, and zero-event Page-2 binary projections;
- the complete 558-occurrence compact ledger and recomputed relation closure;
- activation ledger and two-call projection plan;
- four signed-set/orientation documents;
- the focused resolution record and one-clause vault;
- the ten-resolvent record and ten-clause vault.

Preparation records zero native calls, zero science calls, zero reveal calls,
and no truth-key bytes read.

## Science and claim gates

The separate runner may classify only the strongest validated terminal:

1. public exact recovery after independent public verification;
2. threshold-region exhaustion only under the frozen formal proof contract;
3. causal-residency novel-clause gain only when every complete occurrence and
   globally new exact clause is durably archived and replayable;
4. no novel gain after both complete calls;
5. operational terminal for any incomplete call, identity mismatch, repeated
   input SHA, missing evidence, persistence failure, or resource breach.

Residency coverage, pair geometry, soft orientation, a lower visited bound,
and the exact later-only resolvents are diagnostics or future mechanisms. None
alone is an O1C-0075 cryptanalytic result.

## Stop rules

- Stop after lineage 15 even if another unused page can be constructed.
- Never replay ordinals 14 or 15 and never retry a consumed ordinal.
- Never mutate, flatten, or relabel an immutable attic chunk.
- Never discard duplicate witness occurrences or dominated clauses from the
  evidence attic.
- Never admit the later-only pair/resolution artifacts to O1C-0075 selection.
- Never reuse a science-input active SHA-256.
- Never use truth, reveal data, hidden-key labels, or post-call outcomes to
  choose a page.
