# O1C-0090 — Page-13 parent-centered continuation

Recorded 2026-07-20 19:57:03 CEST. O1C-0090 consumed fresh Page 13 / local
episode 0 / lineage 26 exactly once and is terminal
`PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN`.

## Result

- Requested/actual/billed conflicts are `128/46/46`; 82 requested conflicts
  remain unused. Native work is 540 decisions and 1,369,570 propagations.
- The unchanged O(256) one-shot operator returns 255 failure-first actions and
  records 33,890 exact probes / 67,780 child-bound evaluations. It fully emits
  260 trail-upper-bound no-goods / 743,794 literals.
- All 260 emitted clause identities and witness identities are distinct. An
  independent sorted SHA-256 set comparison against the complete O1C-0089 attic
  gives `baseline_unique=1291`, `emitted_unique=260`, `intersection=0`.
- Witness upper bounds range `13.057051120644449..14.605986705470585`; all are
  strictly below `tau=14.606178797892962`. The closest strict margin is
  `0.0001920924223774989`.
- Native wall is 0.661900 s, CPU 1.418933 s and peak RSS 381,517,824 bytes. The
  build-once archival runner used 41.3517715 s wall end to end.

## State and capacity

The complete 260-clause harvest is archived even though no combined successor
vault is serialized. The reason is exact clause capacity:

```text
Page-13 input 253 + emitted 260 = 513 > maximum 512
```

The call reaches the first overflowing emission after 46 conflicts. It is
capacity-censored, not an observed yield fixed point. No pending clause is
exported and no empty clause occurs.

The 24,576-byte priority bank evolves to SHA-256
`715bfbc22fa2162ec8546eed21cf609318d3c5be806092dc4fe4b07cc4d9d654`;
the canonical priority-state receipt is 52,016 bytes, SHA-256
`4e13df322e5c30b0022e4a6346ceb4db239628d317f4c9480cb81177b8ab53dd`.
Independent conservation closes exactly:

```text
bank count       215,781 -> 249,671  (delta 33,890)
probe count                              33,890
outcomes        153 + 33,693 + 35 + 9 = 33,890
child evaluations                        67,780 = 2 * probes
sole zero coordinate                     241
```

The minimum nonzero count becomes 224. Variable 15 has the maximum count 2,180.
The action ledger records 11 releases, zero unobserved release and one action
coincident with a base-sieve pending clause; no action is rearmed.

## Claim boundary

Science gain is exact global clause novelty only. `threshold_prunes=260`
records the safe trail-upper-bound path that emitted the clauses. The separate
action-specific field remains `actual_certified_prunes=0`; none of the 255
failure-first actions itself becomes a certified crossing. There is no key,
complete model, closure, key-bit posterior, or attacker-valid entropy/domain
reduction.

No target bytes, truth-key bytes, reveal, refit, retry, replay, MPS or GPU were
used. Page 13 and lineage 26 are burned permanently.

## Efficiency interpretation

O1C-0090 raises conflict efficiency from O1C-0088's `4.7091` to `5.6522`
clauses per billed conflict. Probe efficiency is essentially flat, moving from
`7.7515` to `7.6719` clauses per 1,000 probes, while absolute yield increases
`259 -> 260` and again reaches the exact cap boundary. This supports continued
fresh-page compounding; it does not by itself identify whether live-bank state
or the changed resident clause subset causes the gain.

The next transition is zero-call ingestion of all 260 clauses and the
`715bfbc2...` bank into the immutable attic, followed by fresh Page 14 /
lineage 27 at active limit 252. This preserves 260 clause slots of headroom.
Do not replay Page 13, rearm crossings or increase cap/RAM.

## Provenance

The authoritative result is 11,092 bytes, SHA-256
`7089f78809de90007a4914f0cdaebeef7491d04a46871d05e8a2598e30676886`.
The sealed capsule is
`runs/20260720_195618_030937_O1C-0090_apple8-parent-centered-continuation-v1`;
its 29-row artifact-manifest SHA-256 is
`d4088eddb3cf671b908ebbc2d19e6e0159eac149b4b882bb21cca62635df1df0`.
All rows verify and the capsule result is byte-identical to the authoritative
result. Intent SHA-256 is
`ae909af9e74c6d722e5bc14da9e4c4875d2506c67afad1335aa12bc0fe9ff679`;
invocation SHA-256 is
`0dfe66b44596383fa9a26c3e51641b6097a8f15fc22cf2b8b7c226bccf32c6bc`.

The pre-burn gate passed 13 focused tests, Ruff and Pyright. An orchestration
race issued two read-only CLI preflight invocations instead of one; both
returned zero solver calls, capsules and intents. No further preflight followed,
and production was invoked exactly once. Record this as reversible efficiency
debt, not a science or provenance defect.
