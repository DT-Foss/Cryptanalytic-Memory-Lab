# O1C-0074 — APPLE8 causal-attic stream

## Decision

O1C-0073 is not retried. Its sole local-0/lineage-9 call is sealed as
`EPISODIC_VAULT_CAPACITY_TERMINAL`: the release-contrast reader discovered 311
novel exact score-threshold exclusions, but the single resident archive stopped
at `202+311=513` against a 512-clause cap.

O1C-0074 implements the missing O1 memory split:

1. a complete immutable causal attic retains every certified exact exclusion and
   every witness occurrence in first-occurrence lineage order;
2. a deterministic 256-clause active reservoir is projected from that attic;
3. the immutable O1C-0073 202-clause vault remains a separate rank source, so
   active-residency changes cannot silently change the frozen 255-coordinate
   reader;
4. four predeclared 128-conflict episodes append new exact evidence to immutable
   attic chunks and recompute the active projection between episodes.

This is not a larger fixed vault. Capacity rollover is the mechanism under test.

## Parent facts

- O1C-0073 result SHA-256:
  `43fb980b50fef20f9bc4bdcfd2ecd6e0f1f7df3bcee9297b0005bb55e4ea0cdc`.
- O1C-0073 capsule manifest SHA-256:
  `ad2791ff4ae09e9426878be4ba2f3b55eb77c85f46308c7a506d0dc96111317d`.
- Source freeze: `a1a447f47b4e7bec833f1148330573fefa8e3119`.
- Rank-source vault: 202 clauses / 599,728 literals / 2,399,911 B, SHA-256
  `cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858`.
- O1C-0073 novel population: 311 clauses / 798,046 literals / 3,193,619 B,
  clause aggregate SHA-256
  `5cbe1f9c402679ba607564cc9fcec56df513144200b624ecd9b6face5fc7d58f`.
- Exact union: 513 unique clauses / 1,397,774 literals / 5,593,339 B.
- O1C-0073 measured emission rate: `311/179 = 1.7374301676` novel clauses per
  billed conflict.

The 513-clause union exceeds only the old clause cap. It retains 202,226 literal
slots and 2,795,269 serialized bytes of headroom.

## Why a fixed subset cannot solve the measured problem

At the observed rate, the raw clause headroom of a fixed active vault is:

| Active clauses | Free slots | Linear conflicts to cap |
|---:|---:|---:|
| 0 | 512 | 294.69 |
| 192 | 320 | 184.18 |
| 256 | 256 | 147.34 |
| 384 | 128 | 73.67 |
| 508 | 4 | 2.30 |

Even an empty resident vault cannot reach the requested 512-conflict horizon
under raw cumulative-append semantics. Raising the clause cap would postpone the
same failure and would not implement O1's bounded live state.

## Exact subsumption audit

Signed-literal subset analysis finds eight strict subset edges, all inside the
retained population. They reduce to three roots:

- retained index 9 covers retained indices 8, 7 and 6;
- retained index 123 covers retained index 120;
- retained index 144 covers retained index 143.

Five retained supersets `{6,7,8,120,143}` are logically redundant in an active
projection but remain immutable attic evidence. Removing only those supersets
produces a 508-clause exact-equivalent antichain, which still has only four live
slots and is therefore not the active design.

## Frozen K=256 projection

The active projection is target-free and deterministic:

1. concatenate attic chunks in lineage order;
2. exact-deduplicate by canonical signed clause, preserving every duplicate
   witness occurrence separately;
3. build strict signed-literal subsumption edges `A subset B`;
4. remove strictly dominated clauses from the candidate set;
5. greedily choose 256 candidates by descending new unique-clause coverage,
   descending new witness-occurrence coverage, ascending literal count and
   ascending clause SHA-256;
6. serialize selected clauses in global first-occurrence order, never greedy
   selection order.

The frozen initial projection contains 253 O1C-0073 novel clauses plus retained
roots 9, 123 and 144. It has:

- 256 clauses;
- 654,753 literals;
- 2,620,227 serialized bytes;
- coverage 261/513 unique exclusions (`50.8772%`);
- coverage 263/515 witness occurrences (`51.0680%`);
- clause aggregate SHA-256
  `dd601f9bd60b143d31136a1c8144be4ef0656638d6c3e114a4fa3e41a7d80fc7`;
- projection-vault SHA-256
  `fb7528bf1cccf76e57dfa34dd8d5b13a9c96b331dad9ebf4443e7caa45d6f2b7`.

The zero-call prepared artifact set is bound by manifest SHA-256
`fa018d15d1edfe9e3e3614873b0866c90989aeb1752ce8a5f7c9bd25510c7005`.
Its immutable retained/novel chunk hashes are `cd523334...` / `79be5483...`;
the compact witness-occurrence and strict-subsumption documents are
`cdf1d1649f626e4a356ac3ee0d6d347c314e6c0d6490eb1e742c1f2723b05110` and
`ce09299a3bd76ccc4384cc70e9e586bcb6248188399d21d6b517cb188942261f`.

K=384 covers 389/513 unique exclusions but spends 128 additional active slots,
359,458 literals and 1,438,344 bytes for exactly 128 additional covered records.
It is rejected because it halves the only dimension that caused O1C-0073 to
stop. K=192 preserves more slots but covers only 197/513. K=256 is the frozen
balance; there is no K sweep in science.

Witness slack is not a utility rank. In every observed dominance chain, the
stronger shorter clause has the higher witness score and smaller slack. Witness
score certifies validity; signed subsumption and clause length determine active
coverage.

## Separate rank source

Native v12 and adapter v15 use one `--vault-in` both to preload exact clauses and
to derive the sealed vote/rank field. Passing the K256 projection through that
interface would either fail the production identity or silently change the
reader. O1C-0074 therefore introduces a new interface:

- `--rank-vault` is always the immutable O1C-0073 202-clause source with SHA-256
  `cd523334...`;
- `--vault-in` is the current K256 active projection;
- the rank order/table remain exactly
  `26c0063f4eed586ef67535cccabacc07d945587a603cbb56dbb3b2225a32a2f5` /
  `d3a007ebee7c515289d33be30757f769b2c1fde618fb5c6c312ea9f3509380ae`;
- vault telemetry and preload identity must equal the active projection;
- rank-source and active-vault identities are both archived and independently
  stability-checked before and after every native call.

Existing native v12, adapter v15 and O1C-0073 remain immutable.

## Stream schedule

O1C-0074 authorizes at most four fresh subprocesses and no retry:

| Local episode | Lineage ordinal | Requested conflicts | Input active state |
|---:|---:|---:|---|
| 0 | 10 | 128 | frozen initial K256 projection |
| 1 | 11 | 128 | deterministic projection after episode 0 attic append |
| 2 | 12 | 128 | deterministic projection after episode 1 attic append |
| 3 | 13 | 128 | deterministic projection after episode 2 attic append |

The aggregate requested horizon is 512 conflicts. A native active-vault capacity
event is a rollover boundary, not a scientific terminal, only if every fully
emitted exact clause and duplicate witness event is validated, durably written
to a new immutable attic chunk, reread, and included in the next deterministic
projection. Any incomplete/pending/empty clause, missing event, chunk mismatch,
identity mismatch or persistence failure stops the whole attempt fail-closed and
consumes the ordinal without retry.

Each native episode receives only its predeclared 128-conflict soft horizon. The
choice is derived before science from 256 raw active slots and the measured
147.34-conflict fill point; it is not a post-result horizon sweep.

## Artifact contract

The capsule preserves:

- immutable rank-source vault;
- immutable initial retained and release-contrast attic chunks;
- compact causal-attic manifest with all clause identities, witness scores,
  witness hashes, duplicate events and subsumption edges;
- every per-episode new-clause chunk, including a zero-clause manifest when no
  novelty occurs;
- active projection before every call and the terminal next projection;
- exact invocation, intent, call ledger, reader telemetry, resources and hashes;
- deterministic gzip-compressed native payloads when compression is used, with
  canonical uncompressed SHA-256 and byte count also recorded;
- no truth, reveal, target-key, entropy, refit, MPS or GPU artifact.

The vault-v1 format is never relabeled as evicting or subsuming. Each chunk is an
immutable valid vault-v1 payload. Selection and coverage live in a distinct
active-projection manifest schema that references chunk identities.

## Result gates

The highest result wins:

1. `PUBLIC_EXACT_RECOVERY` only after independent public ChaCha verification;
2. `THRESHOLD_REGION_EXHAUSTED` only for native status 20 under the frozen CNF,
   potential, grouping and threshold, with the exceptional no-retry audit;
3. `CAUSAL_ATTIC_STREAM_NOVEL_CLAUSE_GAIN` only if every completed call is
   ledgered, every novel exact clause is durably retained in the complete attic,
   all rollover projections validate, and at least one globally new exclusion is
   added;
4. `CAUSAL_ATTIC_STREAM_NO_GAIN` if the complete four-episode stream adds no
   globally new exclusion and returns no model/frontier proof;
5. `CAUSAL_ATTIC_STREAM_OPERATIONAL_TERMINAL` for any incomplete call, missing
   artifact, resource breach, identity mismatch or unsafe rollover.

Low work, active-pair count, clause-cap avoidance, projection coverage and a lower
minimum upper bound are diagnostics, not cryptanalytic gain by themselves.

## Formal threshold boundary

Let `R_tau={x:S(x)>=tau}` with `tau=14.606178797892962`, and let `U(a)` be an
admissible upper bound for every completion of visited trail `a`. Then strict
`U(a)<tau` safely prunes only the descendants of that trail. The historical
`7.973483108047071` is O1C-0066 episode 1, not O1C-0068; O1C-0068's minimum is
`12.8607806294803`, and O1C-0073's is `13.16709627777236`. These use the same
score units and retained direction but different run-specific visited
populations/statistics. Root `U(root)=262.68644197084643>tau`; none of those
minima is a global prune or exhaustion certificate.

## Stop and non-repetition rules

- Do not retry O1C-0073 or replay lineage ordinal 9.
- Do not sweep K, episode horizon, rank, phase, reader sign, RAM or clause caps.
- Do not select clauses using truth, the hidden key, reveal data or post-call
  outcome labels.
- Do not discard attic clauses merely because they are inactive or dominated.
- Do not start science until native rank/active separation, adapter validation,
  deterministic attic preparation, four-episode rollover logic, resource gates,
  source hashes and zero-call fixtures are committed and the worktree is clean.
- O1C-0068 and every sibling repository remain read-only.
