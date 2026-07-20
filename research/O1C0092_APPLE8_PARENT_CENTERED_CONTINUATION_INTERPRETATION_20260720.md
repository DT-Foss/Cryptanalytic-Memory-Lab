# O1C-0092 — Page-14 parent-centered continuation

Recorded 2026-07-20 20:57:45 CEST. O1C-0092 consumed fresh Page 14 / local
episode 0 / lineage 27 exactly once and is terminal
`PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN`.

## Result

- Requested/actual/billed conflicts are `128/10/10`; 118 requested conflicts
  remain unused. Native work is 521 decisions and 2,074,835 propagations.
- The unchanged O(256) one-shot operator returns 255 failure-first actions and
  records 33,398 exact probes / 66,796 child-bound evaluations. It fully emits
  261 trail-upper-bound no-goods / 756,414 literals.
- Independent reconstruction validates 261 distinct clause identities and 261
  distinct witness identities. Exact set intersection against the complete
  O1C-0091 1,551-clause attic is zero.
- Witness upper bounds range `11.553303084092308..14.038279700095462`; all are
  strictly below `tau=14.606178797892962`. The smallest margin is
  `0.5678990977975005`, median margin `1.4443174838336663`. Unlike O1C-0090's
  near-threshold tail, no O1C-0092 witness lies within 0.1 of the threshold.
- Native wall is 0.701334 s, CPU 1.472248 s and peak RSS 377,815,040 bytes. The
  build-once archival runner used 42.482507 s wall end to end.

## State and capacity

The complete 261-clause harvest is archived even though no combined successor
vault is serialized. The reason is exact clause capacity:

```text
Page-14 input 252 + emitted 261 = 513 > maximum 512
```

The call reaches the first overflowing emission after only 10 conflicts. It is
capacity-censored, not an observed yield fixed point. No pending clause is
exported and no empty clause occurs. Literal capacity would remain in range at
`704,145+756,414=1,460,559 < 1,600,000`; clause count alone terminates the
combined vault. The hypothetical serialized payload is 5,844,479 B, leaving
2,544,129 B below its cap.

The 24,576-byte priority bank evolves to SHA-256
`97a325c91b9a853a094fcc8b7fd9fafdafe6b5ec4022952e1a86af068c834fca`;
the canonical priority-state receipt is 52,014 bytes, SHA-256
`1c69bb329819ff873758e72ccfd69649310e5dd089c68665c34d0a287821c1e6`.
Independent conservation closes exactly:

```text
bank count       249,671 -> 283,069  (delta 33,398)
probe count                              33,398
outcomes        2 + 33,394 + 1 + 1 =     33,398
child evaluations                        66,796 = 2 * probes
sole zero coordinate                     241
```

The minimum nonzero count becomes 227 at variable 188. Variable 15 remains the
maximum and reaches 2,675. The action ledger records 10 releases, zero
unobserved release and zero action coincident with a pending base-sieve clause;
no action is rearmed.

## Claim boundary

Science gain is exact global clause novelty only. `threshold_prunes=261`
records the safe trail-upper-bound path that emitted the clauses. The separate
action-specific field remains `actual_certified_prunes=0`; none of the 255
failure-first actions itself becomes a certified crossing. There is no key,
complete model, closure, key-bit posterior, or attacker-valid entropy/domain
reduction.

No target bytes, truth-key bytes, reveal, refit, retry, replay, MPS or GPU were
used. Page 14 and lineage 27 are burned permanently.

## Efficiency interpretation

O1C-0092 raises conflict efficiency from O1C-0090's `5.6522` to `26.1`
clauses per billed conflict, a `4.6177x` increase. Probe efficiency rises from
`7.6719` to `7.8148` clauses per 1,000 probes (`+1.863%`). Absolute yield also
increases `260→261` and again reaches the exact cap boundary.

The read-only five-burst audit finds zero clause/witness repetition and zero
cross-burst subsumption. O1C-0092 is closest to O1C-0090 but remains fresh
signed geometry: nearest-predecessor signed Jaccard ranges
`0.752734..0.776911`, median `0.762909`. Its robust margins, stable probe yield,
sharply higher conflict yield and censored endpoint select another unchanged
continuation rather than a residency pivot.

The next transition is zero-call ingestion of all 261 clauses and the
`97a325c9...` bank into the immutable attic, followed by fresh Page 15 /
lineage 28 at active limit 251. This preserves 261 clause slots of headroom.
Do not replay Page 14, rearm crossings or increase cap/RAM.

## Provenance

The authoritative result is 11,768 bytes, SHA-256
`04c4d7673898dd35d9c613ed0f1676dd8f3a60f01b04167b02660b93adfcc16c`.
The sealed capsule is
`runs/20260720_205659_306771_O1C-0092_apple8-parent-centered-continuation-v1`;
its 29-row artifact-manifest SHA-256 is
`b91e23706c1a019c30f4de016f4f78e8da3494416e9a5fc69043b5c2fb890eae`.
All rows verify and the capsule result is byte-identical to the authoritative
result. The complete capsule is 51,373,837 B, leaving 82,843,891 B below its
artifact cap. Intent SHA-256 is
`a2c3f9704755d47bf7cd8158b42cedce423a24e10b5a901f2e43e0f3864fc66e`;
invocation SHA-256 is
`af35bf94ca2b67c723d5bdeba0f5e464bf0d4835cd918476ab3405b24bf9b6d3`.

The pre-burn gate passed 60 combined tests, Ruff and Pyright. Exactly one
read-only CLI preflight returned zero solver calls, capsules and intents;
production was invoked exactly once. Native v25 source SHA-256 is
`4119466d0412886d67edd8b11bb04d3b59abc85894f0b33c95b156c4f542e141`;
the sealed executable is 1,696,712 bytes, SHA-256
`bbbd53c71d102b1b2dabfd0d4cfe5ce278763d1336344070f135e08271bee29d`.
