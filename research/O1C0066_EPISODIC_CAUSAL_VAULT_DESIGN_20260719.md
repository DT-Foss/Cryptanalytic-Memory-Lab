# O1C-0066 — Bounded Episodic Causal No-Good Vault

- **Frozen design:** 2026-07-19T12:53:09+02:00 (`Europe/Berlin`).
- **Parent result:** O1C-0065 at source commit
  `8f231003161c17608c3daba63da2a6ccf4d567da`.
- **Design commit base:** `ec4185bf8f1265005c7eeeea0d3f629175e8fd2d`.
- **North star:** publicly verified exact recovery of all 256 unknown ChaCha20
  key bits from the standard full-round output relation.

## Why this is the next mechanism

APPLE-VIEW-0008 emits six exact score-threshold no-goods in its first requested
512/billed 513 conflicts. O1C-0065 tightens the bound and shrinks its logical
cache, but emits exactly the same six clauses with identical decisions and
propagations. O1C-0064 shows that one monolithic 4,096-conflict process reaches a
guarded 992-MiB memory wall before returning science output.

O1C-0066 changes the execution shape instead of repeating either boundary:

1. run one short fresh solver episode;
2. preserve only fully emitted, threshold-certified no-goods;
3. destroy the solver, its learned database, trail, assignments, allocator and
   grouped cache;
4. preload the cumulative bounded vault into the next fresh episode;
5. repeat only while a completed episode adds at least one novel clause.

This is the smallest real O1 memory test available here: the large transient
reasoner dies, while a compact exact causal state survives the stream.

## Exact semantic boundary

For a partial observed assignment `P`, the grouped sieve computes an admissible
upper bound `U(P)`. If `U(P) < T`, every completion of `P` has potential score
below `T`, so the emitted clause excluding `P` is valid for

`CNF ∧ potential_score >= T`.

It is not entailed by the ChaCha CNF alone. The vault therefore binds exact CNF
bytes and variable numbering, potential bytes, grouping bytes, observed-variable
identity, grouped-bound rule and threshold binary64 bits. Version 1 accepts only
an exact threshold match. It never carries clauses into a lower threshold or a
different score field. A complete-model rejection is independently checked with
the original-factor exact score rather than an outward grouped upper bound.

This means a positive publicly verified candidate is exact key recovery, while
failure or UNSAT closes only the frozen threshold-constrained search region.

## Frozen episode protocol

- Maximum episodes: `8`.
- Requested conflicts per episode: `512`.
- Maximum billed conflicts per episode: `513`.
- Maximum total requested/billed conflicts: `4,096 / 4,104`.
- Seed and all CaDiCaL options: identical in every episode.
- Per-episode wall/RSS limit: `45 s / 536,870,912 B`.
- Vault caps: `512` clauses, `1,600,000` literals and `8,388,608 B` serialized.
- Policy state: canonical fixed-policy zero state; no target-driven adaptation.
- Stop immediately on public exact recovery, SAT/UNSAT terminality, invalid
  output, resource/cap terminality, or zero novel eligible clauses.
- A written episode intent consumes that ordinal. No failed or completed ordinal
  is replayed. It also consumes the episode's 512 requested-conflict budget even
  if no result is returned; billed conflicts remain unknown/zero until reported
  by a completed native result. Publication recovery may only adopt an already
  completed sidecar.
- The first fully emitted novel clause that would cross a vault cap latches an
  immediate native termination request; no later clause is eligible for export.
  A publicly verified SAT model or threshold-region UNSAT reached by that same
  synchronous solver transition has semantic precedence over archive capacity.

Eight fresh calls are explicitly eight native solver calls, not one call and not
a retry. Total conflict accounting is resource-matched to the failed 4K
promotion, not trajectory-equivalent because every restart discards ordinary
CaDiCaL learning.

## Vault representation

The cumulative binary archive uses first-emission order and no subsumption:

1. 19-byte magic `O1-NOGOOD-VAULT-V1\0`;
2. raw SHA-256 identities for CNF, potential, grouping, observed variables and
   bound rule;
3. threshold IEEE-754 bits as `u64le`;
4. clause count as `u32le`;
5. for each clause, `u32le` length followed by signed `i32le` DIMACS literals.

Literals are nonzero, use observed variables only and are strictly ordered by
absolute variable number. Duplicate variables, tautologies, duplicate clauses,
trailing bytes and identity drift fail closed. Only a clause whose external
callback reached its terminating zero is eligible; queued or pending clauses are
never archived.

## Promotion gates

No Full-256 episode is authorized until all of these pass without truth access:

- exhaustive synthetic clause validity under `score >= T`;
- complete-model exact-score validity;
- polarity and canonical binary round-trip;
- identity, threshold, duplicate, tautology and tamper rejection;
- real CaDiCaL preload equivalence to explicit CNF augmentation;
- fully-emitted versus queued/pending separation;
- two fresh subprocess episodes with deterministic hash chaining and process
  destruction;
- deterministic first-crossing capacity and no-replay terminality, including
  SAT-plus-cap and threshold-UNSAT-plus-cap precedence;
- public target-free 257,024-variable geometry smoke;
- clean, source-commit-bound zero-call preflight.

The geometry gate is a reproducible O1C-0066 control, not an inherited prose
claim. Its dedicated command builds the frozen native v6 binary, pairs the
public APPLE8 potential and exact width-6 grouping with an empty
`p cnf 257024 0` relation, and uses a threshold strictly above the grouped root
upper bound. The expected result is an immediate threshold-region root-empty
UNSAT with no candidate, no archived empty clause and no target or truth bytes.
It publishes
`research/O1C0066_TARGET_FREE_GEOMETRY_SMOKE_20260719.json`; the config and
commit-bound preflight bind that artifact before the scientific target run.

## Measured outcomes

Every episode records input/output vault hashes, clause/literal/byte counts,
new/duplicate clauses, conflict/decision/propagation/cut counts, root/minimum
upper bounds, wall/CPU/RSS series, lifecycle evidence and public model
verification. The useful efficacy question is simple: does episode `n > 0`
produce a novel certified exclusion and change real search work while keeping
peak memory bounded?

Adaptive O1/O1-O branching remains a later promotion. It is justified only if
the fixed vault proves that causal persistence compounds; adding a chooser now
would mix two mechanisms and obscure the cheapest result.
