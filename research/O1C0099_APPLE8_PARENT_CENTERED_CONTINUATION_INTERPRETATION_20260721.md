# O1C-0099 — APPLE8 Page-17 parent-centered continuation

- **Started:** `2026-07-21T00:40:05.191277+02:00` (`Europe/Berlin`).
- **Recorded:** `2026-07-21T00:40:25.076700+02:00` (`Europe/Berlin`).
- **Classification:** `PARENT_CENTERED_CONTINUATION_OPERATIONAL_TERMINAL`.
- **Stop reason:** `burned-terminal-failure-no-retry`.
- **Capsule:**
  [`runs/20260721_004001_986566_O1C-0099_apple8-parent-centered-continuation-v1`](../runs/20260721_004001_986566_O1C-0099_apple8-parent-centered-continuation-v1/RUN.md).

## Exact terminal boundary

O1C-0099 persisted its sole Page-17 / local-0 / lineage-30 intent and therefore
burned Page 17 before issuing one authorized native call. Native v28 then
returned status 1 after `19.82277620799141 s` with empty stdout and exact stderr:

```text
cadical_o1_joint_score_sieve_v28: decision ownership event cap exceeded
```

The runner terminated fail-closed after `19.8852734999964 s`. Requested work is
128 conflicts; actual and billed conflicts remain `null`. One native call was
consumed, no native result returned, and retry/replay are both false. Page 17 /
lineage 30 is permanently burned and is never reconstructed, retried or replayed.

This is an instrumentation terminal, not a cryptanalytic negative. No retained
measurement exists for actions, probes, bounds, prunes, emitted clauses, model,
key, closure or attacker-valid entropy/domain gain. `science_gain=false` records
that absence; it does not say the unchanged scientific operator failed.

## Root cause

The immutable ownership ledger records every assignment notification as a full
event and hard-stops at 65,536 entries. Native v28 sends assignments for all
2,981 potential variables into that ledger. An assignment without a live action
token becomes a `FOREIGN_ASSIGNMENT` record even though it cannot affect the
solver decision, priority bank, bound or emitted clause.

The preceding successful O1C-0097 call already retained 47,005 ownership events
at only 21 conflicts. Of those, 46,231 (`98.35%`) were foreign assignments and
45,713 referred to internal variables above 256. Page 17 changed the propagation
trajectory enough to cross the fixed event ceiling. The event vector is audit
telemetry rather than an input to the scientific operator, but its exception is
fatal inside the callback; therefore no partial post-failure state is admissible.

Merely raising the cap would move the failure and permit output growth beyond the
128-MiB artifact contract. The successor must version the producer and consumer
together, retain the bounded owned-token lifecycle exactly, and stream
non-claiming assignment observations into exact counts plus a canonical digest.
The sealed v28/header bytes remain unchanged.

## Preserved certified state

O1C-0099 contributes no clause, occurrence, priority update or state transition.
The admissible state remains exactly O1C-0098:

- 19 immutable attic chunks;
- 2,074 unique clauses / 5,835,680 literals / 23,351,207 bytes;
- 2,083 occurrences / 9 duplicate occurrences / 14 strict relations;
- 2,063 undominated clauses;
- union SHA-256
  `fbe18682bae134784684e4676dbb1fce1b78d4da27182fb67679a7317b3e9646`;
- 24,576-byte bank SHA-256
  `8100bccf7e463c11b41d97a07017202c5e7ffc37763a76d38114c3044f9fa2fc`;
- 52,011-byte receipt SHA-256
  `050551fc658de62b54b7856996fba0418194c3c2f2608e04a8e9ccc2f51fedad`.

The correct transition is a zero-call reprojection of that same certified attic
onto fresh Page 18 / lineage 31, carrying only the exact O1C-0099 failure receipt
as provenance and importing no O1C-0099 science output.

## Provenance

The authoritative [result](O1C0099_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json)
is 32,091 bytes, SHA-256
`2f60c3dc12adea0157534cd67296a0839ac9e17303868f121b1593d36a50611b`,
and is byte-identical to the capsule result. The 33-entry capsule manifest is
3,440 bytes, SHA-256
`93fdb7eb7ce828fd6c41a327a5ab1c7c58305e6a6be752dc0812b214b1fbbf9e`;
all entries verify. Intent and invocation SHA-256 values are respectively
`7791ed49d63abf3dd80707380ba1da233856324d45aaa7046245255f612dd939`
and `66c1f8ad609cd818bd89840bbabfb004b82d15b5fbe88e4945f115d1976b7b8e`.
Native stdout is exactly zero bytes at the empty SHA-256, while the 72-byte
stderr has SHA-256
`c9d1f777e9922c61d2951155b36a6b3eb2406b8a0e478ecffcf17b73aa18c3b6`.

Peak watched RSS was 360,120,320 bytes, below the configured 512-MiB boundary.
Target bytes, truth-key bytes, reveal, refit, MPS and GPU calls all remain zero.
