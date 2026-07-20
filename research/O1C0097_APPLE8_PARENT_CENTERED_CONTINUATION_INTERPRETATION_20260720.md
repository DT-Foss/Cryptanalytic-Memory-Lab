# O1C-0097 — APPLE8 Page-16 parent-centered continuation

- **Started:** `2026-07-20T22:46:43.192925+02:00` (`Europe/Berlin`).
- **Recorded:** `2026-07-20T22:47:24.306887+02:00` (`Europe/Berlin`).
- **Additive audit closed:** `2026-07-20T22:58:48+02:00` (`Europe/Berlin`).
- **Classification:** `PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN`.
- **Stop reason:** `globally-novel-clause`.
- **Capsule:**
  [`runs/20260720_224639_665221_O1C-0097_apple8-parent-centered-continuation-v1`](../runs/20260720_224639_665221_O1C-0097_apple8-parent-centered-continuation-v1/RUN.md).
- **Seals:** authoritative 11,922-byte result SHA-256
  `19b47ac6512c073d8f2b646d864d81cedfa8f1c2b2a9999f974c119779ae79e3`;
  capsule artifact-manifest SHA-256
  `b7d8712b2ade9e5b75ff0d2f76c11907fbcafb3f01cf6e260e82303c08ff0f42`;
  intent SHA-256
  `956c3f5f0dfa56b7b2cab9f89da962038ceb116d6d59c672ea9ff41c56738888`.

## Result

O1C-0097 consumes fresh Page 16 / local episode 0 / lineage 29 exactly once.
The repaired native-v27 / adapter-v30 transport returns and persists the complete
science payload. Requested/actual/billed conflicts are `128/21/21`, leaving 107
requested conflicts unused. Native work is 533 decisions and 2,835,645
propagations.

The unchanged O(256) parent-centered operator performs 33,243 exact probes and
returns 255 failure-first actions. None is a certified direct crossing:
`actual_certified_prunes=0`. The separate trail-upper-bound path records 263
threshold prunes and fully emits 263 clauses. Of these, 262 are new to active
Page 16 and 262 are globally novel against the complete 1,812-clause baseline.
That exact global novelty is sufficient for `science_gain=true`.

The retained result intentionally distinguishes the three counters:

```text
fully emitted clauses       263
active-Page-16-new clauses  262
globally novel clauses      262
```

The additive audit closes the counter difference exactly. The 263 emitted
occurrences contain 262 unique clauses. Indices 6 and 7 are the sole
run-internal duplicate pair, with identical 2,859 literals, identical witness
`UB=13.293490727958314` and SHA-256
`d479f1335c455aa61873154205c94b1a98cb050a0851fc8df65a5ed536baee2f`.
That clause is absent from both Page 16 and the prior attic, so it is one of the
262 globally novel unique clauses despite occurring twice in the run.

All 263 witness occurrences are strict certificates under
`tau=14.606178797892962`. Witness UBs have minimum
`12.444402499433698`, median `13.715761374687974` and maximum
`14.600199452723347`; the closest strict margin is
`0.005979345169615513`.

## Living state

The 24,576-byte continuation bank evolves from
`97a325c91b9a853a094fcc8b7fd9fafdafe6b5ec4022952e1a86af068c834fca`
to
`8100bccf7e463c11b41d97a07017202c5e7ffc37763a76d38114c3044f9fa2fc`.
The new bank is a continuation/proof-mining state, not a key-bit posterior.
Its exact count conservation is `283,069→316,312`, delta `+33,243`, equal to
the probe count. All 255 eligible records evolve and variable 241 remains the
sole zero coordinate. The 52,011-byte output priority-state JSON has SHA-256
`050551fc658de62b54b7856996fba0418194c3c2f2608e04a8e9ccc2f51fedad`.
No unrecorded state from O1C-0095 is imported.

The complete native stdout is 12,555,982 bytes, SHA-256
`b6d96e8752b6bd146f6ae99cf846c8a73b89c7464ae88e73d4162b8fb849233d`.
The parsed native result is 12,555,454 bytes, SHA-256
`c43e2ab845a204c47d2ce2056ed13f178adec458d32d8639e4b4b15368dabc2a`.
Their persistence closes O1C-0095's exact producer/consumer transport failure.

## Claim boundary

Science gain is the 262 globally novel exact clauses only. The 255
failure-first actions and differential priority are operational proof-mining
choices; zero actions certify a direct one-bit crossing. There is no key,
complete model, closure, key-bit posterior or attacker-valid entropy/domain
reduction.

No target bytes, truth-key bytes, reveal, refit, retry, replay, MPS or GPU were
used. Page 16 / lineage 29 is burned permanently and must never be retried or
replayed.

## Hypothesis and next action

O1C-0096 supplied fresh Page 16 and O1C-0097 both closes the exact transport
contract and produces a persisted science-positive result. This supports
`H-PARENT-CENTERED-PAGE16-CONTRACT-RECOVERY-096` at exact-clause level.

The exact rollover payload is now closed: serialize one immutable 262-clause /
745,152-literal / 2,981,847-byte chunk, append all 263 occurrences, and obtain
the predicted attic totals 2,074 unique clauses / 2,083 occurrences / 9
duplicate occurrences. Preserve the evolved `8100bccf…` bank.

O1C-0098 next derives one fresh bounded Page 17 without solver work. Its active
limit is `249`: unlike retrospective `250 + 262 = 512`, it also preserves the
observed 263-emission ceiling if the next burst has no internal duplicate
(`249 + 263 = 512`, whereas `250 + 263 = 513`). The one additional displaced
clause is ordinary undominated debt, not a root or pinned clause, and remains in
the attic. Do not reduce to 248 without evidence of more than 263 emissions.
There is no evidence-based
reason to change the operator, tau, 128-conflict request, cap, RAM or residency
semantics.

## Resources and provenance

Native wall is `0.771569 s`, CPU `1.501722 s` and peak RSS `378,994,688 B`.
Runner wall is `41.114287083008094 s`; runner CPU is
`39.455071000000004 s`. Exactly one native call was consumed.

The authoritative machine result is
[`O1C0097_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json`](O1C0097_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json).
The sealed capsule is
[`runs/20260720_224639_665221_O1C-0097_apple8-parent-centered-continuation-v1`](../runs/20260720_224639_665221_O1C-0097_apple8-parent-centered-continuation-v1/RUN.md).
