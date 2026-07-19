# O1C-0070 — APPLE8 vault-conditioned phase-reader design

- **Recorded:** 2026-07-19 (`Europe/Berlin`).
- **Attempt:** `O1C-0070`.
- **Invocation:** `O1C-0070-apple8-vault-phase-reader-v1-call-0006`.
- **Scientific calls authorized:** exactly `1`, only after the final frozen gate.
- **Fresh target/truth/reveal/refit/MPS/GPU calls:** `0/0/0/0/0/0`.
- **Current state:** final target-free gate passed and frozen; no Full-256 call.

## Question

O1C-0068 added 190 exact threshold no-goods to O1C-0067's sealed
12-clause state. O1C-0069 then made one explicit phase-1 call from the
resulting 202-clause state and emitted only a duplicate. O1C-0070 asks a
different, precommitted question: does a polarity field derived from the exact
190-clause addition expose a novel exact population when applied once to the
same sealed 202-clause state?

This is not a phase sweep, another alternation, a horizon increase, or a
retry. The reader is frozen before science from public vault clauses, and only
one local-0 / lineage-6 native process may consume the intent.

## Sealed parent and lineage

The parent is the sealed O1C-0069 terminal at source commit
`d6dfc06f3e7d6dfcc29d696829927b132bad23aa`:

- authoritative result SHA-256
  `43512370d7243d57bb3ffaed445ee9196315e350d3ee1169ee0c0d8ad94ba89b`;
- capsule
  `runs/20260719_170824_O1C-0069_apple8-alternating-reader-v1`;
- manifest SHA-256
  `2a78e568f0be7eafad4d117cd84aeadd0d495d19296d8ba85676496219377cb8`;
- retained `episodes/00/vault-output.bin` SHA-256
  `cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858`;
- retained state `202` clauses / `599,728` literals / `2,399,911 B`;
- classification `EPISODIC_VAULT_ALTERNATING_READER_NO_GAIN`;
- observed O1C-0069 billing `514` conflicts.

O1C-0069 consumed lineage ordinal `5`. O1C-0070 uses local ordinal `0`
and lineage ordinal `6`; neither ordinal may be replayed. Known completed
billing is `2,565` conflicts before O1C-0070. The failed O1C-0066 ordinal `2`
remains unbilled, so complete lineage actual billing remains `null`.

## Exact phase population

The phase source base is O1C-0067's sealed 12-clause vault:

- path
  `runs/20260719_152601_O1C-0067_apple8-vault-continuation-v1/episodes/00/vault-output.bin`;
- SHA-256
  `371dd8454e46eb6c53549efa53e6412f5798b22a06e6f96c927ab74df2ba687a`;
- `12` clauses / `35,061` literals / `140,483 B`;
- aggregate clause SHA-256
  `76d5bab1665fdfafa6ff7d8d7de6a830f3fa94f8742105f6ee41bcc192d05ff0`.

Preflight dual-parses both vaults and proves that the 12 base clauses are the
exact first 12 clauses of the current vault, with identical frozen identity.
The only admitted population is current clauses `[12, 202)`:

- `190` clauses and `564,667` literals;
- canonical clause-record bytes `2,259,428`;
- canonical record SHA-256
  `cbec487e215b70a22f91b0424f05809a06c0f6cdd5c3fa259bcab0b710e74521`.

Using all 202 clauses would mix the prior reader's 12-clause cohort into the
new phase-0 population and changes variables 59, 60 and 115. O1C-0070 uses
only the auditable suffix to avoid that reader-mixture ambiguity.

## Frozen reader

For key variables `v=1..256`, the reader computes

```text
delta(v) = count(+v) - count(-v)
phase(v) = +v if delta(v)>0; -v if delta(v)<0; no call if delta(v)=0
```

The orientation satisfies the majority cut literal and therefore opposes the
majority excluded-witness spin. The 256 signed phase literals serialize as
little-endian `int32` values:

- field bytes `1,024`;
- field SHA-256
  `5d7fd1cfca56c1ab29f9e1490d28e16d3f5def611dad2f52c4ea4015678605fe`;
- `139` positive, `116` negative and one zero vote (variable `241`);
- `255` calls to `Solver::phase(int literal)`;
- the zero vote retains verified global fallback phase `1`;
- effective bitpack SHA-256
  `6381f90ee279a8075d4279ecfec5a3560e910afc12c891cb0bd86dac0ad511ec`.

The exact 847-byte reader specification has SHA-256
`3dba50d3a376c2c025e2edbcc47215f19610547ad5bd6260221c82a1641df075`.
Config, analysis, final target-free gate, invocation, intent, native result,
episode and publication all bind the complete reader object.

### Explicit limitation

CaDiCaL's `phase` API sets persistent per-variable polarity preference. It
does not control variable ordering and carries no confidence magnitude. The
190-clause vote margin is used only for its sign. O1C-0070 cannot support a
claim about ordering, calibrated confidence, probability, entropy, or key
recovery unless the native call returns a model that independently verifies on
all eight public blocks.

## Target-free gates

The recorded derivation analysis is
`research/O1C0070_TARGET_FREE_VAULT_PHASE_ANALYSIS_20260719.json`, schema
`o1-256-o1c70-target-free-vault-phase-analysis-v1`, SHA-256
`af28f9639b4dec9e861fc250d9cf43cd81c10ddfe19e88256dbebeb72135c53d`.
The runner independently reproduces the prefix, suffix records and production
field, then validates these stability facts:

1. raw occurrence signs and inverse-clause-length-weighted signs are identical;
2. no supported variable is tied;
3. all 190 single-clause jackknifes cause zero phase flips;
4. variable 241 is unsupported and retains only the explicit fallback.

Science additionally requires a separate frozen artifact at
`research/O1C0070_TARGET_FREE_PHASE_READER_PREFLIGHT_20260719.json`. It must
prove all of the following with zero Full-256 calls:

1. native-v9 and adapter-v12 independently reproduce the exact field and
   complete reader object;
2. a public synthetic fixture demonstrates a phase consequence, with at least
   two deterministic repeats;
3. native source and production executable rebuild identities are frozen;
4. the sealed parent, exact prefix, vault caps and runtime resource gates pass;
5. the one-call/no-retry/no-sweep journal and phase-only claim boundary pass.

The config left source, executable and final-gate hashes `PENDING` during
implementation. They are now frozen; science preflight fails closed if any
returns to pending, becomes absent or dirty, or is not commit-bound. The final
gate SHA-256 is
`37dce5e768de10c36edf06d0d233ae20a0dd92dc3d19ec9be3f0de6f46c63af9`;
three independent production-basename builds reproduced executable SHA-256
`b8271ce334a00f40ca830861080aed33a257cd5893ad4bfda9c06cb944e7bfe5`.

The run captures the exact config byte sequence whose SHA-256 passed that
commit-bound preflight. The same bytes drive the in-memory protocol and become
the capsule `config.json`; there is no later filesystem reread that can change
the archived protocol.

## Threshold and upper-bound semantics

The frozen threshold `tau = 14.606178797892962` and O1C-0066 episode 1's
observed minimum upper bound `7.973483108047071` use the same compiled score
function and the same retained direction, `score >= tau`. They are not the same
population or statistic; O1C-0068's actual minimum is `12.8607806294803`.
`tau` was frozen from the maximum score among 4,096
complete decoys with the precommitted margin/rounding rule. The minimum upper
bound is `min U(a)` over partial trails actually visited in one bounded native
episode.

For each visited trail `a`, the grouped bound is admissible:

```text
for every completion k extending a: score(k) <= U(a)
```

Therefore `U(a) < tau` proves that no completion of that particular trail can
satisfy the augmented search condition `CNF and score >= tau`; pruning that
trail is formally safe. The scalar minimum `7.973...` only proves that at least
one visited trail met this condition. It does not prove that every root branch
did: the same episode's root upper bound was
`262.68644197084643 > tau`. It is consequently neither a global prune nor
CNF-only UNSAT, key-space exhaustion or key recovery.

## Capacity and resource contract

For planning only, the reservation reuses one observed complete O1C-0068
emission envelope. It is explicitly non-formal:

| quantity | imported | one observed envelope | projected | hard cap |
|---|---:|---:|---:|---:|
| clauses | 202 | 195 | **397** | 512 |
| literals | 599,728 | 579,526 | **1,179,254** | 1,600,000 |
| serialized bytes | 2,399,911 | 2,318,884 | **4,718,795** | 8,388,608 |

The three hard adapter/native vault caps remain authoritative. Requested work
is a `512`-conflict soft horizon, with no numeric overshoot ceiling:

```text
solve_conflicts = conflicts - conflicts_before_solve
unused          = max(requested - solve_conflicts, 0)
overshoot       = max(solve_conflicts - requested, 0)
billed          = solve_conflicts
```

Hard process limits remain `45 s` wall time and `536,870,912 B` RSS.
Operational failure evidence records return code, command, complete stream
lengths and hashes, while retaining at most `1 MiB` per stream. The persistent
capsule limit is `64 MiB`.

## One-call and result contract

Invocation and intent must be durable before native-v9 begins. Exactly one
fresh process is then consumed, whether it returns, times out, exceeds a hard
resource limit, or returns an invalid result. No branch authorizes a retry.

- `PUBLIC_EXACT_RECOVERY`: a returned model verifies on all eight public blocks.
- `EPISODIC_VAULT_ACTIVE_PHASE_READER_GAIN`: at least one novel exact clause.
- `EPISODIC_VAULT_ACTIVE_PHASE_READER_NO_GAIN`: zero novel eligible clauses.
- `EPISODIC_VAULT_THRESHOLD_REGION_EXHAUSTED`: native status 20, limited only
  to exhaustion of the frozen `CNF ∧ score ≥ threshold` region.
- Capacity, process, adapter, reader and result failures are explicit no-retry
  operational terminals.

Status 20 is not CNF-only UNSAT, global key-space exhaustion, or key recovery.
Any derived next-vault identity is audited in memory, but the runner archives
no derived output and retains the exact imported vault as final state.

## Publication recovery

After the call, the runner writes a publication source beside all completed
sidecars. If sealing fails, zero-call recovery revalidates invocation, intent,
imported vault, native result, telemetry, output vault or bounded failure
evidence before publication. It cannot reconstruct or reissue ordinal `6`.
Science classification and stop reason are re-derived from those persisted
sidecars rather than trusted from the top-level publication source, then
preserved. Publication recovery is recorded separately with
`native_calls_issued_during_recovery=0`.

## Null handoff

If the one call emits zero novel clauses, phase-only is closed. There is no
second phase call, polarity sweep or horizon sweep. The next operator is a
separate, newly precommitted confidence-ranked `cb_decide` handoff; that
successor is outside O1C-0070 and receives no authorization from this design.
