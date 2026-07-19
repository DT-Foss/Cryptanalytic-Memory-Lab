# O1C-0052 — exact pattern-action credit screen

- **Started:** 2026-07-19T04:02:42+02:00
- **Recorded:** 2026-07-19T04:02:47+02:00
- **Source commit:** `b32608d5cebbd547582a6dc8c371482e191e08a5`
- **Classification:** `PATTERN_ACTION_CREDIT_NO_EXACT_W11_CLOSE`
- **Gate:** failed (`no-exact-pattern-primary-w11`)
- **Boundary:** consumed Full20 target, post-reveal W11 with 245 correct key
  bits fixed; one 512-conflict call, no fresh target/sibling/GPU/MPS work
- **Resources:** 5.098155667 s wall, 128,303,104 B peak RSS

## Result

| Primary W11 mechanism | Status | Exact key | Conflicts | Decisions | Propagations |
|---|---|---:|---:|---:|---:|
| O1C-0051 unary group credit | UNKNOWN | no | 512 | 513 | 11,983,327 |
| O1C-0052 four-action credit | UNKNOWN | no | 512 | 513 | 12,066,879 |

The sole prospective call did not recover the key before the unchanged cap.
The exact gate therefore failed and the runner skipped static W11, both rotated
W11 arms and all three Full256 calls. The result is one native call and 512
requested conflicts, not the seven-call promotion maximum.

## What changed and why it was insufficient

The 2,646-byte state did alter the live route. It split every one of the 63 pair
groups into four addressed mask cells, attributed owner undos to the exact mask,
and reordered 162 of 448 credit-modulated selections. Eighteen action cells in
seven groups were distinguished. Nevertheless, repeated external decisions
remain exactly `502/513`, and the run is still cap-censored.

The dominant `(59,60)` group exposes the failure directly:

| Mask | Visits | Conflict-owner undos | Final credit |
|---:|---:|---:|---:|
| `00` | 29 | 48 | -3,072 |
| `01` | 37 | 50 | -3,200 |
| `10` | 35 | 48 | -3,072 |
| `11` | 34 | 51 | -3,264 |

All four actions are cycled and penalized almost uniformly. Across the whole
run every one of the 18 visited action cells receives negative credit. A
post-result truth diagnostic also finds that the true mask is visited and
penalized in six of the eight active groups. Conflict-bearing undo therefore
does not identify which selected action caused the conflict; this update is a
bounded anti-repetition rule, not a key-polarity evidence channel.

Close negative-only exact-mask credit on these fixed pairs. Do not tune its
scale, groups, sign mixture or cap. The cheapest distinct successor reverses the
question: on each conflict backjump, give positive support only to the deepest
externally owned action that remains on the trail. That tests whether survival
is a useful live proxy for the retained causal/proof frontier before paying for
exact conflict-antecedent instrumentation.

Authoritative JSON SHA-256:
`7ef0f0416ef9d884c2041d8e6396291f4b3991e9cc5e485d2a6aa3cd36bea8de`.
