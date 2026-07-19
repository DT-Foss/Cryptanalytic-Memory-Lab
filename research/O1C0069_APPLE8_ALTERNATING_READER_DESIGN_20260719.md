# O1C-0069 — APPLE8 alternating-reader composition design

- **Recorded:** 2026-07-19T16:50:23+02:00 (`Europe/Berlin`).
- **Attempt:** `O1C-0069`.
- **Invocation:** `O1C-0069-apple8-alternating-reader-v1-call-0005`.
- **Scientific calls authorized:** exactly `1`.
- **Fresh target/truth/reveal/refit/MPS/GPU calls:** `0/0/0/0/0/0`.

## Question

O1C-0067 reached a duplicate-only fixed point under the phase-1 trajectory.
O1C-0068 then applied the complementary phase-0 reader to the same exact
threshold mechanism and discovered `190` novel clauses. O1C-0069 asks the
next composition question: does an explicit phase-1 reader applied to that
larger sealed state expose another exact exclusion population?

This is not a replay or a phase sweep. Both scientific inputs changed relative
to O1C-0067: the imported vault grew from `12` to `202` clauses, and the
reader is now explicitly identified and forced as phase 1. Exactly one call is
allowed.

## Sealed parent and lineage

The parent is O1C-0068 at source commit
`8446414d73e871de829c182ca4cd5b500e4d9d14`:

- authoritative result SHA-256
  `d494887d2be96516211acf09ff8852a88a44576044723223b9057942fd7aea80`;
- capsule
  `runs/20260719_161838_O1C-0068_apple8-complementary-phase-v1`;
- capsule manifest SHA-256
  `dd0236774c1352238cce86458a8f01380aa32dc538dbe80a3c1744b0f126a745`;
- output sidecar `episodes/00/vault-output.bin`, SHA-256
  `cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858`;
- retained state `202` clauses / `599,728` literals / `2,399,911 B`.

O1C-0068 consumed lineage ordinal `4`; O1C-0069 uses local ordinal `0`
and lineage ordinal `5`. Neither ordinal `4` nor `5` may be replayed.
Invocation and intent are durable before the native process begins. The intent
authorizes one fresh process and no retry.

Completed calls with known billing total `2,051` conflicts before O1C-0069.
The failed O1C-0066 ordinal `2` remains unbilled, so the complete lineage
actual remains `null`; no missing work is inferred.

## Alternating reader

Native v8 preserves the frozen native-v6 CNF, potential, grouping, vault,
propagation, termination and accounting path while making phase 1 explicit.
Adapter v11 independently validates the added reader identity:

- schema `o1-256-cadical-forced-initial-phase-reader-v1`;
- operator `forced-initial-phase`;
- CaDiCaL configuration `plain`, phase before override `1`;
- seed/quiet/factor/rephase `0/1/0/0`;
- `forcephase=true`, `phase=1`, `lucky=false`, `walk=false`;
- complement pair ID `forced-initial-phase-v1`;
- reader-spec SHA-256
  `ce039b56a647cbc67deea1fa70db7e755ea00a6dd183015a43e94c032b5706cc`.

Config, preflight, invocation, intent, native result and publication all bind
that exact reader object. A wrong value or JSON scalar type is a terminal
post-call result error and cannot authorize another call.

## Target-free authorization gates

No Full-256 call is authorized until all of these public, target-free gates
pass:

1. Native v8 with explicit phase 1 must normalize to the frozen native-v6
   behavior exactly, including deterministic repeated executions; only the
   newly explicit reader identity may differ.
2. On the public fixture `(-1 ∨ -2)` with unary `x1/x2` potentials
   `0/10` and `tau=15`, a complete native-v7 phase-0 vault must
   deterministically perturb repeated native-v8 phase-1 execution. The sealed
   composition is expected to reach root UNSAT with no emission on that fixture.
3. The O1C-0068 parent vault must pass both independent parsers, its exact hash
   and capacity reservation must match, all source/build identities must be
   frozen to a clean commit, and the process/resource preflight must pass.

Failure of any gate blocks the Full-256 call; it does not consume ordinal `5`.

## Capacity reservation

The imported vault remains below all hard caps. For planning only, O1C-0069
reserves the complete observed O1C-0068 emitted envelope as though all `195`
clauses and `579,526` literals were additive:

| quantity | imported | observed envelope | projected | hard cap |
|---|---:|---:|---:|---:|
| clauses | 202 | 195 | **397** | 512 |
| literals | 599,728 | 579,526 | **1,179,254** | 1,600,000 |
| serialized bytes | 2,399,911 | 2,318,884 | **4,718,795** | 8,388,608 |

This is a matched observed-envelope reservation, not a formal maximum for a
512-conflict process. Preflight fails closed if the reservation or cap identity
drifts. The adapter's three hard vault caps remain authoritative if the actual
call emits more than the reservation.

## Work and evidence contract

Requested work is the same `512`-conflict soft horizon:

```text
solve_conflicts = conflicts - conflicts_before_solve
unused          = max(requested - solve_conflicts, 0)
overshoot       = max(solve_conflicts - requested, 0)
billed          = solve_conflicts
```

There is no numeric overshoot ceiling. Hard process limits remain `45 s` wall
time and `536,870,912 B` RSS. Failures retain command, return code, full
stream counts and hashes, with at most `1 MiB` retained from each stream.

The runner records exact clause/literal growth, duplicates, decisions,
propagations, minimum/root upper bounds, conflicts, native wall/CPU and RSS.
A candidate is verified only against the eight public blocks. No truth artifact
is read.

## Status 20 and recovery

Native status `20` is exceptional evidence only for exhaustion of the frozen
`CNF ∧ score ≥ threshold` region. It is not CNF-only UNSAT, global key-space
UNSAT, or key recovery. Any clauses emitted before the exact UNSAT conclusion
are still fully validated in memory and their derived-vault identity is audited,
but the runner archives no derived output vault. It seals the exact imported
vault as final state and never retries.

If publication fails after the call, zero-call recovery revalidates the
journaled invocation, intent, imported vault, native result, vault telemetry,
archived output vault, or bounded failure evidence. The status-20 branch also
revalidates its retained-input/no-output shape. Recovery cannot reconstruct or
reissue ordinal `5`. A publication-only failure never relabels the scientific
outcome: classification and stop reason remain unchanged, while the recovery
event is sealed separately with zero-call provenance.

## Result boundary

- `PUBLIC_EXACT_RECOVERY`: a SAT candidate verifies on all eight public blocks.
- `EPISODIC_VAULT_ALTERNATING_READER_GAIN`: at least one novel exact clause.
- `EPISODIC_VAULT_ALTERNATING_READER_NO_GAIN`: zero novel eligible clauses.
- `EPISODIC_VAULT_THRESHOLD_REGION_EXHAUSTED`: exceptional audited exhaustion
  of only the frozen score-threshold region.
- Capacity, native, adapter, reader and publication failures are explicit
  no-retry operational terminals.

After this call, do not replay ordinal `5`, start a phase sweep, increase the
horizon blindly, or authorize a second alternation. A successor must precommit
another explicit operator using the sealed terminal evidence.
