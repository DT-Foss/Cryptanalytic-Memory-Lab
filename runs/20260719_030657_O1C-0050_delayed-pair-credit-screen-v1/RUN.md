# O1C-0050 — delayed trail-owner pair credit

- **Recorded:** 2026-07-19T03:06:57+02:00
- **Classification:** `DELAYED_PAIR_CREDIT_STRICT_W10_GAIN`
- **Gate:** passed (`strict-w10-conflict-gain`)
- **Boundary:** consumed Full20 target, exact post-reveal W10 completion with 246
  correct key bits fixed; one native call, no fresh target/sibling/GPU/MPS
- **State:** 630-byte group ledger + 504-byte owner levels = exactly 1,134 bytes
- **Resources:** 4.558947 s wall, 64,356,352 B peak RSS, one 512-conflict call

## Exact effect

| W10 primary | Exact key | Conflicts | Decisions | Propagations |
|---|---|---:|---:|---:|
| frozen static O1C-0049 baseline | yes | 310 | 315 | 7,339,177 |
| delayed trail-owner credit | yes | **302** | **307** | **7,141,980** |

The prospective gate required the exact W10 key with fewer than 310 conflicts.
Delayed credit uses eight fewer conflicts (`-2.58%`) and passes. Telemetry and
wall time could not satisfy the gate.

## Mechanism

Each externally chosen pair member owns its CaDiCaL decision level until that
level is actually removed. On backtrack, an undone owner receives fixed weight

```text
w = 32 >> min(current_level - owner_level, 4)
credit -= (1 + conflict_since_previous_backtrack) * w
```

The run records 307 owner bindings, 302 conflict-bearing owner undos and zero
assignment/propagation credit. Seven groups receive nonzero credit, ranging down
to -14,528; O1C-0049's uniform positive-credit collapse is absent. Five owners
remain live in the final bounded state.

The first operational invocation exposed a callback-mirror mismatch before any
result was written: 151 owner bindings in the final run are not echoed through
`notify_assignment`. Source commit `b61aef3` correctly makes owner level—the
event emitted directly by `cb_decide`/`notify_new_decision_level`—authoritative
and uses the assignment mirror only when present. The identical frozen one-call
screen then completed above.

This is an absolute exact-search gain below Full-256, not key recovery from
public output alone. Per the frozen next action, run one W11 primary call next.
Only exact W11 completion earns matched static/rotation controls and attacker-
valid Full-256 calls; no credit or pair tuning intervenes.

Authoritative JSON SHA-256:
`2f23214b98c4483344660b016c86f03a2a4285733d10b19b5acd8a6fc8767888`.
