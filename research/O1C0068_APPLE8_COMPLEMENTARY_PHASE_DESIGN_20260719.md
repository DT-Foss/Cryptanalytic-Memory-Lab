# O1C-0068 — APPLE8 complementary phase-reader design

- **Recorded:** 2026-07-19T15:56:45+02:00 (`Europe/Berlin`).
- **Attempt:** `O1C-0068`.
- **Invocation:** `O1C-0068-apple8-complementary-phase-v1-call-0004`.
- **Scientific calls authorized:** exactly `1`.
- **Fresh target/truth/reveal/refit/MPS/GPU calls:** `0/0/0/0/0/0`.

## Question

O1C-0067 reached a duplicate-only fixed point from the sealed 12-clause vault
with the unchanged native reader, seed and 512-conflict soft horizon. It still
reduced decisions and propagations relative to O1C-0066's last completed call,
so the vault remains useful even though that exact trajectory added no clause.

O1C-0068 changes one thing only: the solver's deterministic initial phase. Does
the complementary phase reader reach a distinct exact score-threshold exclusion,
remain duplicate-only, exhaust the frozen threshold region, or return a public
candidate?

This is one call, not a phase or horizon sweep.

## Sealed parent and lineage

The parent is O1C-0067 at source commit
`865634458ef3f5b01a5881208eb028404b96f135`:

- authoritative result SHA-256
  `c01ffe69198e997c6d3798e0b9f3190065bd7b58ec3ab1ba67a66a7ccd799f1f`;
- capsule
  `runs/20260719_152601_O1C-0067_apple8-vault-continuation-v1`;
- capsule manifest SHA-256
  `2562db062186fb5168e66c69943af83ba19a151bdc17489111a15dbb114f9341`;
- output sidecar `episodes/00/vault-output.bin`, SHA-256
  `371dd8454e46eb6c53549efa53e6412f5798b22a06e6f96c927ab74df2ba687a`;
- retained state `12` clauses / `35,061` literals / `140,483 B`.

O1C-0067 consumed lineage ordinal `3`; O1C-0068 uses local ordinal `0` and
lineage ordinal `4`. Ordinal `3` is never replayed. The invocation and
`episodes/00/intent.json` are durable before the native process starts, and the
intent is not retriable.

Completed calls with known billing total `1,539` conflicts before O1C-0068.
O1C-0066 ordinal `2` remains unknown, so the complete lineage total remains
`null`; no inferred bill is published.

## Complementary reader

Native v7 inherits the native-v6 CNF, potential, grouping, vault, propagation,
termination and accounting path. Adapter v10 validates the added top-level
reader identity independently. The reader is frozen to:

- schema `o1-256-cadical-forced-initial-phase-reader-v1`;
- operator `forced-initial-phase`;
- CaDiCaL configuration `plain`, default phase before override `1`;
- seed/quiet/factor/rephase `0/1/0/0`;
- `forcephase=true`, `phase=0` (false polarity), `lucky=false`, `walk=false`;
- complement pair ID `forced-initial-phase-v1`;
- reader-spec SHA-256
  `a68b3c3b1721b756314dac11ce725adf0709e9f358125cb1f8d388737d1ddddc`.

The config, preflight, invocation, intent and result all bind the native-v7
source, adapter-v10 source, result/adapter schemas and this reader object. Any
wrong field or JSON scalar type is terminal after a returned call and cannot be
retried. The draft's `PENDING` source/build identities must all be replaced by
exact hashes and commit-bound before science authorization.

## Fixed work and evidence contract

Target, Full-256 CNF, O1C-0057 potential, width-6 grouping, threshold, vault and
seed remain unchanged. Requested work is a `512`-conflict soft horizon:

```text
solve_conflicts = conflicts - conflicts_before_solve
unused          = max(requested - solve_conflicts, 0)
overshoot       = max(solve_conflicts - requested, 0)
billed          = solve_conflicts
```

There is no numeric overshoot ceiling. Hard limits are one native process,
`45 s` wall time and `536,870,912 B` RSS. Process failures retain command,
return code, full stream byte counts/hashes and at most `1 MiB` from each stream.

The runner records decisions, propagations, minimum/root upper bounds, actual
conflicts, novel/duplicate clauses, literal growth, vault bytes, native wall/CPU
and peak RSS. A candidate is checked against the eight public blocks only when
native status is SAT. No truth artifact is read.

## Authorization and recovery gates

Before the call, preflight verifies exact parent result/manifest/vault bytes,
dual vault parsing, CNF/potential/grouping identities, source hashes, reader
identity, committed cleanliness, resource gates and zero target/truth/reveal/
entropy/refit/MPS/GPU work.

Publication writes a completed episode sidecar before terminal sealing. If
publication fails after the native call, recovery may seal only those completed
sidecars and must report zero native calls during recovery. Before sealing, it
revalidates the journaled invocation, intent, imported vault, native result,
vault telemetry, archived output vault or bounded failure-evidence hashes. It
never reconstructs or reissues lineage ordinal `4`.

## Result boundary

- `PUBLIC_EXACT_RECOVERY`: the returned SAT key independently verifies on all
  eight public blocks.
- `EPISODIC_VAULT_COMPLEMENTARY_PHASE_GAIN`: at least one novel exact clause
  survives.
- `EPISODIC_VAULT_COMPLEMENTARY_PHASE_NO_GAIN`: the complementary call is
  duplicate-only at this state and work.
- `EPISODIC_VAULT_THRESHOLD_REGION_EXHAUSTED`: only the frozen
  `CNF ∧ score ≥ threshold` region is exhausted.
- capacity, process, adapter, reader and publication failures are explicit
  operational terminals.

Whatever the result, do not replay ordinal `4`, sweep phase settings or raise
the horizon blindly. A successor must precommit another explicit operator.
