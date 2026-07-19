# O1C-0067 — sealed-vault single-call continuation

- **Recorded:** 2026-07-19T14:56:58+02:00 (`Europe/Berlin`)
- **Attempt:** `O1C-0067`
- **Invocation:** `O1C-0067-apple8-vault-continuation-v1-call-0003`
- **Scientific calls authorized:** exactly `1`
- **Target/truth/reveal/refit/GPU calls during build:** `0/0/0/0/0`

## Question

O1C-0066 proved that exact score-threshold exclusions compound across fresh
solver processes: its two completed episodes grew the bounded vault
`0 → 6 → 12` clauses. Its third native process returned, but adapter v8 rejected
the result because an earlier observed `+1` conflict overshoot had been promoted
to an unsupported universal ceiling; the rejection proves the third call reached
at least `514` solve conflicts, but its raw output was not retained.

O1C-0067 asks one narrow, high-ROI question:

> Starting from the last sealed 12-clause state, does one new, correctly billed
> fresh process add further exact exclusions, saturate, exhaust the frozen
> threshold region, or return a publicly verifiable key?

It is deliberately one call, not a speculative multi-episode series. Its
terminal decides the next mechanism.

## Lineage and no-replay boundary

O1C-0066 consumed lineage ordinals `0`, `1`, and `2`; ordinal `2` is terminal
even though its adapter rejected the returned payload. O1C-0067 therefore uses:

- local episode ordinal `0`;
- lineage call ordinal `3`;
- `parent_ordinal_replay_authorized=false`;
- `episode_is_retry=false`.

Both `invocation.json` and `episodes/00/intent.json` must exist before the
native process begins. No second invocation path exists. A completed episode is
also journaled before terminal publication; recovery may seal those exact
sidecars after a publication failure but is tested to issue zero native calls.

## Sealed parent state

- O1C-0066 result SHA-256:
  `b8b61d0f2feaa9c544c1fef30cba4c7cead90c390a577a444405d45ad85000e3`
- capsule manifest SHA-256:
  `b0022997a1c316e71131268b3e3e5524aee4de8167013463f845646c8982d562`
- failed ordinal-2 intent SHA-256:
  `7a2fb83611fbc6108e2e3503f406141c13b1087a951a075147cdb679fedd62ed`
- ordinal-2 failure SHA-256:
  `0915eb4220000bf80a3326b6533976220e4f08eba1ee98fd69296e856ea64834`
- retained sidecar:
  `episodes/01/vault-output.bin`
- retained-vault SHA-256:
  `371dd8454e46eb6c53549efa53e6412f5798b22a06e6f96c927ab74df2ba687a`
- retained state: `12` clauses, `35,061` literals, `140,483` bytes;
  aggregate clause SHA-256
  `76d5bab1665fdfafa6ff7d8d7de6a830f3fa94f8742105f6ee41bcc192d05ff0`.

Preflight verifies the parent result, manifest inventory, failed intent,
terminal failure, regular-file status, and sidecar hash. The sidecar is parsed
independently by both the O1C-0066 canonical parser and the shared vault-v1
parser. CNF, potential, grouping, observed-variable, bound-rule, and exact
binary64 threshold identities must agree. The exact bytes are copied to the
new capsule and parsed again; only that capsule copy reaches native code.

## Adapter-v9 work contract

Native v6 and the vault-v1 binary format remain unchanged. Adapter v9 changes
only the work/evidence boundary:

```text
solve_conflicts = conflicts - conflicts_before_solve
unused          = max(requested - solve_conflicts, 0)
overshoot       = max(solve_conflicts - requested, 0)
billed          = solve_conflicts
```

There is no numeric overshoot or billed-conflict maximum. The requested `512`
conflicts are a soft horizon. Exactly one process, `45 s` wall time, and
`536,870,912` bytes RSS are the hard limits. Parent ordinal 2's exact billing is
unknown and stays `null`; no fictitious lineage sum is published.

Completed-process evidence survives stable-input, JSON, native-payload, and
ledger failures. Failure streams are persisted at at most `1 MiB` each while
their complete byte length and SHA-256 remain recorded.

## Target-free authorization gates

Before any scientific call:

1. native counters `514/512` normalize to billed `514`, overshoot `2`;
2. forged conflict deltas, types, signs, or algebra fail closed;
3. every post-process failure path retains command, return code, stdout,
   stderr, and bounded RSS samples;
4. a `>1 MiB` synthetic stream records full size/hash and bounded sidecar;
5. parent/vault hash, identity, manifest, and parser tampering fail closed;
6. a fake call observes invocation and intent already on disk, local ordinal
   `0`, lineage ordinal `3`, and can be invoked only once;
7. simulated post-call publication failure rolls back partial publication and
   seals only the completed sidecars with zero additional native calls;
8. preflight reports zero native calls, files written, target/truth reads,
   reveal/entropy/refit/MPS/GPU work;
9. adapter, runner, config, design, and gate artifact are commit-bound before
   science; memory, disk, load, W52, and native-process probes are green.

## Result interpretation

- `PUBLIC_EXACT_RECOVERY`: candidate independently matches all eight public
  ChaCha20 blocks.
- `EPISODIC_VAULT_CONTINUATION_GAIN`: at least one new exact clause survives.
- `EPISODIC_VAULT_SATURATED_NO_GAIN`: no novel clause at this state/work.
- `EPISODIC_VAULT_THRESHOLD_REGION_EXHAUSTED`: only the frozen
  `CNF ∧ score ≥ threshold` region is exhausted; this is not key-space UNSAT.
- capacity/resource/adapter terminals remain operational boundaries.

Decisions, propagations, minimum upper bound, actual conflicts, new/duplicate
clauses, literal growth, vault bytes, native wall/CPU, and peak RSS are reported.
Exact 256-bit recovery remains the highest gate; reproducible cumulative exact
branch removal is meaningful sub-recovery progress.
