# O1C-0095 — APPLE8 Page-15 parent-centered continuation

- **Started:** `2026-07-20T22:00:56.648042+02:00` (`Europe/Berlin`).
- **Recorded:** `2026-07-20T22:01:17.757888+02:00` (`Europe/Berlin`).
- **Classification:** `PARENT_CENTERED_CONTINUATION_OPERATIONAL_TERMINAL`.
- **Stop reason:** `burned-terminal-failure-no-retry`.
- **Capsule:**
  [`runs/20260720_220052_433697_O1C-0095_apple8-parent-centered-continuation-v1`](../runs/20260720_220052_433697_O1C-0095_apple8-parent-centered-continuation-v1/RUN.md).
- **Seals:** authoritative result SHA-256
  `7838ce882a696ce932b36fa11af190aaff0ee0a7673e12bbfdac1b272b2e8c93`
  (`10,003 B`); capsule artifact-manifest SHA-256
  `10c2b0f2f2745bb2a101c116d1ecf9af5c090cf627bf334d96f01e46998d26a6`;
  persisted intent SHA-256
  `089d65e7270f579c78d5d4ac15d1987cc18d82566ed233039d9e2030b3cb0bad`.

## Terminal boundary

O1C-0095 persisted the sole Page-15 / local-0 / lineage-28 intent and thereby
burned Page 15 before issuing its one authorized native call. Native v26 ran the
solver to completion, exited with code 0 and returned parsed JSON. Adapter v29
then rejected the exact `priority_seed` field set:

```text
joint-score-sieve-v29 priority seed fields differs
```

Native v26 correctly added
`source_priority_state_receipt_sha256` and
`source_priority_state_receipt_bytes`; adapter v29's `_SEED_FIELDS` omitted
those two fields. The rejection occurred after native execution but before the
runner persisted stdout or a science result. The terminal receipt consequently
records requested conflicts `128`, actual/billed conflicts `null`, one consumed
native call, `native_result_returned=false` and `science_gain=false`.

This is an exact native-output/adapter-contract composition failure. It is not
a cryptanalytic negative: no retained measurement exists for actions, probes,
bounds, prunes, emitted clauses, model, key, closure or attacker-valid entropy/
domain gain. The missing science payload cannot be reconstructed from the
terminal receipt and must not be inferred from native process success.

## What remains unchanged

No O1C-0095 output is admissible for ingestion. The immutable causal attic
therefore remains at 18 chunks / 1,812 unique clauses / 1,820 occurrences / 14
strict relations / 1,801 undominated clauses. The 24,576-byte continuation bank
remains byte-identical at SHA-256
`97a325c91b9a853a094fcc8b7fd9fafdafe6b5ec4022952e1a86af068c834fca`;
its canonical receipt remains 52,014 bytes, SHA-256
`1c69bb329819ff873758e72ccfd69649310e5dd089c68665c34d0a287821c1e6`.

Page 15 SHA-256
`71f4b544fd74c7979386bf607d82902dc03c4fe1485404fe8fb7111e970ecfe2`
and lineage 28 are permanently burned by the persisted intent. Never retry or
replay them. Target bytes and truth-key bytes were not read; reveal, refit, MPS
and GPU calls remain zero.

## Contract breadcrumb

The pre-burn focused gate passed 65/65 tests, but those tests validated native
v26 and adapter v29 separately. They did not compose the actual native JSON
output with the adapter's exact schema validator. The regression gap is narrow:
fixture-level field lists agreed with themselves while the producer added two
receipt-provenance fields that the consumer did not admit.

The repair is one exact producer-to-consumer contract regression. It must run
the native output shape through adapter validation and explicitly cover both
receipt fields. This replaces a class of parallel unit checks; it does not
justify another broad review, a mechanism change or a comfort-control cycle.

## Hypothesis disposition and successor

`H-PARENT-CENTERED-PAGE15-ROLLOVER-COMPOUNDING-094` is refuted at its
operational transport gate only. O1C-0093 achieved its preparation half, but
O1C-0095 produced no retained science payload, so the cryptanalytic proposition
remains untested.

Activate `H-PARENT-CENTERED-PAGE16-CONTRACT-RECOVERY-096`:

1. Derive fresh Page 16 / lineage 29 with zero solver work from the unchanged
   1,812-clause attic and unchanged `97a325c9…` continuation bank. Import no
   O1C-0095 output.
2. Repair adapter admission of the exact native-v26 `priority_seed` schema and
   add one end-to-end native-output/adapter-contract regression covering
   `source_priority_state_receipt_sha256` and
   `source_priority_state_receipt_bytes`.
3. After one focused irreversible gate and one owned real preflight, authorize
   exactly one fresh Page-16 / lineage-29 call with the scientific operator,
   seed, threshold, conflict request, caps and RAM unchanged.

The fresh call, not the transport repair, may test further exact-clause novelty,
closure/model/key or attacker-valid entropy/domain gain. Never retry Page 15,
recover hidden stdout, alter the operator, enlarge caps or pivot residency on
this operational terminal.

## Resources and provenance

Runner wall is `21.10997600000701 s`, CPU `19.494059999999998 s`; child
user/system totals are `1.4725379999999997/0.06852799999999998 s`. These costs
include the one completed native process, but no auditable solver telemetry
survived the adapter rejection. Requested work is 128; actual and billed work
remain `null` rather than estimates.

The authoritative machine result is
[`O1C0095_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json`](O1C0095_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json).
The sealed capsule is
[`runs/20260720_220052_433697_O1C-0095_apple8-parent-centered-continuation-v1`](../runs/20260720_220052_433697_O1C-0095_apple8-parent-centered-continuation-v1/RUN.md).
