# O1C-0071 — APPLE8 vault-ranked decision design

## Decision

O1C-0071 is a new TEST attempt, not a retry of O1C-0070. It authorizes exactly
one fresh native-v10 process on local episode ordinal `0` and lineage call
ordinal `7`. The only scientific change is the target-free `cb_decide` order.
The CNF, potential, exact width-6 grouping, threshold, seed, conflict horizon,
vault, timeout, and memory cap remain frozen.

No science call is authorized while any source/build seal or target-free final
preflight seal is `PENDING`. Filling those fields is an integration step; it is
not permission to change the operator or perform an exploratory call.

## Sealed parent and input

- Parent result:
  `research/O1C0070_APPLE8_VAULT_PHASE_READER_RESULT_20260719.json`
- Parent result SHA-256:
  `778d2b91935ff2ae663ea706e5b7b66c8cfed2f02007ba8359e8c1cb7ff45cd7`
- Parent capsule:
  `runs/20260719_181048_O1C-0070_apple8-vault-phase-reader-v1`
- Parent manifest SHA-256:
  `ca5e0dfc724dc541b5311e2fc1453fc017f4ccd562d510aad341a53188d194c2`
- Parent source commit:
  `c5ad5c40f0ac84f65d281cf2366d2ca6b6c49a52`
- Retained vault SHA-256:
  `cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858`
- Retained vault shape: `202` clauses, `599728` literals, `2399911` bytes.
- Known completed lineage billing before O1C-0071: `3079` conflicts.
- Full lineage actual billing remains unknown (`null`) because the historical
  failed ordinal has no defensible actual-billing value.

The parent result, manifest inventory, capsule result mirror, retained vault,
and the vault's independent and adapter parses must all agree before a capsule
is created. The invocation path checks the CNF, potential, grouping, vault, and
rank derivation again immediately before entering the native adapter. This
second check closes the preflight-to-invocation TOCTOU window.

## Exact target-free rank rule

For each key variable `v` in `1..256`, derive the signed vault vote

`delta(v) = occurrences(+v) - occurrences(-v)`.

Variable `241` has zero delta and is omitted. No fallback sign is invented.
Each remaining variable receives the signed literal

`literal(v) = sign(delta(v)) * v`.

The 255 literals are sorted by this exact total order:

1. `abs(delta(v))`, descending;
2. the exact singleton grouped-upper-bound gap, descending;
3. variable number, ascending.

The singleton gap is the absolute difference between the exact grouped upper
bounds under the positive and negative singleton assignments. Each grouped
bound uses the frozen binary64 lattice rule and is rounded once toward positive
infinity. The sort consumes that canonical finite binary64 gap. No target,
truth key, reveal, learned outcome, timing observation, or native science result
participates in the rank.

The production seals are:

- reader specification bytes: `674`;
- reader specification SHA-256:
  `974d0f915ef827ecaa453f795a649f78b72bd38be7f413c8eb2c104de58e4543`;
- ranked literal encoding: 255 signed little-endian `i32` values;
- ranked literal bytes: `1020`;
- ranked literal SHA-256:
  `26c0063f4eed586ef67535cccabacc07d945587a603cbb56dbb3b2225a32a2f5`;
- rank table encoding: 255 rows of little-endian
  `(u32 variable, i64 delta, f64 U+, f64 U-, f64 gap)`;
- rank table bytes: `9180`;
- rank table SHA-256:
  `d3a007ebee7c515289d33be30757f769b2c1fde618fb5c6c312ea9f3509380ae`.

The reader calls `cb_decide` only. It does not call `phase`, change a polarity
default, encode a phase fallback, or perform a rank/parameter sweep.

## Frozen call contract

The one call uses:

- unchanged APPLE8 CNF SHA-256
  `e1fc0ac93724004291c960ea06e5584c598853b9ea8370552be09f29e73e2432`;
- unchanged potential SHA-256
  `8c6101b49c7050caf895bd9c496c05bcea9f43a2b27f378d7306be38b00d5390`;
- unchanged grouping SHA-256
  `3da85bae132d829252a68f0e3fd99220ea7d1ef365042806af810ff02f75f636`;
- unchanged threshold `14.606178797892962`;
- seed `0`;
- requested conflict soft horizon `512`;
- process timeout `45` seconds;
- process RSS cap `536870912` bytes (`512 MiB`);
- one fresh process and one native solver call;
- actual nonnegative solve conflicts as billing, with no invented overshoot cap;
- zero fresh targets, entropy calls, truth/reveal reads, refits, MPS calls, and
  GPU calls.

The invocation and intent journals are made durable before the call. Once the
intent exists, the call is consumed whether the process succeeds, fails,
times out, exceeds the memory cap, or returns an invalid payload. Neither the
same ordinal nor a replacement ordinal may be issued by this attempt.

## Target-free integration gate

Before science, a final immutable preflight artifact must bind all of the
following:

1. the canonical public rank fixture passes independently;
2. repeated native runs on the public fixture are byte-for-byte deterministic;
3. repeated adapter runs on that fixture are byte-for-byte deterministic;
4. native and adapter reader/spec/order/table identities equal the production
   derivation;
5. variable `241` is omitted and exactly 255 signed literals remain;
6. native decision telemetry proves the ranked callback was installed and
   actually used on an active-search fixture;
7. the production vault, potential, grouping, capacity envelope, 45-second
   timeout, and 512-MiB cap are frozen;
8. exactly one science call and no rank sweep, phase call, retry, or replay is
   authorized.

Source hashes and these final-preflight digests may remain `PENDING` during
integration. Draft preflight is read-only and reports the unresolved fields;
science preflight fails closed until every field is a lowercase SHA-256 digest,
the evidence artifact is present, and the selected source tree is clean and
commit-bound.

The configuration names the historical APPLE8 seals
`apple8_baseline_sha256` and records
`apple8_baseline_attempt_id = APPLE-VIEW-0008-MATCHED`. The runner constructs a
fresh compatibility mapping containing the old `frozen_sha256` key only for
the inherited APPLE8 baseline validator. It never mutates the O1C-0071 config
or publishes the ambiguous alias.

## Classification and stop rules

The result is accepted only when the native-v10 schema, ranked reader identity,
vault telemetry, decision telemetry, soft-conflict ledger, input vault, output
vault, resource caps, and public-model rules all validate.

- `PUBLIC_EXACT_RECOVERY`: status `10`, a present model verifies all eight
  public blocks, and ranked decision telemetry is active.
- `EPISODIC_VAULT_ACTIVE_RANKED_DECISION_GAIN`: status `0`, at least one novel
  exact threshold no-good clause is emitted, and ranked decision telemetry is
  active.
- `EPISODIC_VAULT_ACTIVE_RANKED_DECISION_NO_GAIN`: status `0`, no public model
  is present, zero novel exact clauses are emitted, and ranked decision
  telemetry is active.
- `EPISODIC_VAULT_THRESHOLD_REGION_EXHAUSTED`: status `20` only. This means
  exhaustion solely within the frozen CNF-and-score-greater-than-or-equal-to-
  threshold region. It is not a global CNF UNSAT claim. The imported vault is
  retained and any derived output vault is not archived.
- A valid vault-capacity terminal is preserved as its own terminal result.
- Missing/inactive decision telemetry, a wrong rank seal, a non-SAT key, a
  failed public verification, or any other returned-result mismatch becomes an
  invalid-result terminal after the already-consumed call.
- Process or resource failure becomes an operational terminal with bounded
  stdout/stderr evidence.

All paths are terminal for this attempt. No retry, replay, second reader call,
phase call, or rank sweep follows a gain, no-gain, status-20, capacity,
invalid-result, or operational outcome.

## Durable publication and recovery

Publication follows the O1C-0070 lifecycle:

1. capture the exact preflight-bound config bytes;
2. re-hash all selected sources and revalidate the final target-free gate after
   the native build but before capsule creation;
3. persist config, preflight, build, grouping, imported vault, invocation, and
   intent;
4. consume the single call;
5. persist native result, vault telemetry, decision telemetry, output vault (if
   allowed), episode, and `publication_source.json`;
6. converge the persistent-byte ledger, generate the complete manifest, publish
   authoritative result and manifest atomically, and make the capsule immutable.

If sealing fails after the science sidecars exist, recovery issues zero native
calls. It revalidates the publication source against the persisted episode and
every journaled sidecar hash, re-derives the only permissible classification
from status/model/novel-clause/decision-telemetry evidence, preserves the
science classification and stop reason, records publication-recovery evidence,
and seals the capsule. Drifted, missing, symlinked, forged, or semantically
inconsistent sidecars fail closed; they are never used to synthesize a new
science conclusion.

## Required tests before hash freeze

- production and public-fixture rank derivation, including exact ordering,
  signed literals, omission of `241`, order/table hashes, and tie breaks;
- deterministic repeated native and adapter executions on the public fixture;
- normal no-gain, novel-clause gain, and public 8/8 recovery with active
  decision telemetry;
- inactive/wrong decision telemetry and other invalid-result terminals;
- status `20` retaining the imported vault and archiving no derived vault;
- operational failure with bounded evidence and no retry;
- completed/status-20/invalid/operational publication recovery with zero calls;
- recovery rejection after any journaled sidecar drift;
- config-byte and selected-source TOCTOU rejection;
- CNF, potential, grouping, vault, or rank tampering immediately before the
  invoker, proving the native adapter is not entered;
- capacity/resource gates, one-call/no-sweep ordinals, and immutable manifest
  publication.

O1C-0071 remains a TEST. A no-gain result closes this exact ranked reader; it
does not authorize tuning the rank or spending another call.
